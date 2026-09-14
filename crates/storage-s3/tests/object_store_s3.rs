//! S3-specific adversarial tests for `S3ObjectStore`: conditional-request
//! races, stale-generation preservation, delete-error regression (the
//! accepted parity lesson), status classification per operation, physical
//! prefix isolation, and multi-round-trip pagination.

use std::num::NonZeroUsize;
use std::sync::Arc;

use bytes::Bytes;
use storage_core::ObjectKey;
use storage_core::object_store::{
    ConditionalDeleteOutcome, CreateOutcome, Durability, ObjectStore, PageToken, ReplaceOutcome,
    StoreError,
};
use storage_s3::S3ObjectStore;
use storage_s3::mock::MockS3Client;

fn key(s: &str) -> ObjectKey {
    ObjectKey::parse(s).expect("valid key")
}

fn nz(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).unwrap()
}

fn store_over(client: Arc<MockS3Client>, prefix: Option<&str>) -> S3ObjectStore {
    S3ObjectStore::new(client, prefix).expect("construct")
}

async fn seed(store: &S3ObjectStore, k: &ObjectKey, bytes: &'static [u8]) {
    store
        .write(k, Bytes::from_static(bytes), Durability::Durable)
        .await
        .expect("seed write");
}

// ------------------------------------------------------------------- races

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_write_if_absent_exactly_one_winner() {
    let client = Arc::new(MockS3Client::new());
    let store = Arc::new(store_over(client.clone(), None));
    let k = key("contend/create-once");

    let mut handles = Vec::new();
    for i in 0..8u32 {
        let store = store.clone();
        let k = k.clone();
        handles.push(tokio::spawn(async move {
            store
                .write_if_absent(
                    &k,
                    Bytes::from(format!("writer-{i}").into_bytes()),
                    Durability::Durable,
                )
                .await
                .expect("classifies")
        }));
    }
    let mut created = 0;
    let mut exists = 0;
    let mut winner_payload = None;
    for (i, h) in handles.into_iter().enumerate() {
        match h.await.unwrap() {
            CreateOutcome::Created(_) => {
                created += 1;
                winner_payload = Some(format!("writer-{i}"));
            }
            CreateOutcome::AlreadyExists { .. } => exists += 1,
        }
    }
    assert_eq!(created, 1, "exactly one Created");
    assert_eq!(exists, 7, "seven AlreadyExists");
    let got = store.read(&k, 1 << 16).await.unwrap().unwrap();
    assert_eq!(
        got.bytes,
        Bytes::from(winner_payload.unwrap().into_bytes()),
        "winning payload intact"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_replace_if_version_exactly_one_winner() {
    let client = Arc::new(MockS3Client::new());
    let store = Arc::new(store_over(client.clone(), None));
    let k = key("contend/cas");
    seed(&store, &k, b"base").await;
    let v = store
        .read_with_version(&k, 1 << 16)
        .await
        .unwrap()
        .unwrap()
        .version;

    let mut handles = Vec::new();
    for i in 0..8u32 {
        let store = store.clone();
        let k = k.clone();
        let v = v.clone();
        handles.push(tokio::spawn(async move {
            (
                i,
                store
                    .replace_if_version(
                        &k,
                        &v,
                        Bytes::from(format!("winner-{i}").into_bytes()),
                        Durability::Durable,
                    )
                    .await
                    .expect("classifies"),
            )
        }));
    }
    let mut replaced = 0;
    let mut precondition = 0;
    let mut winner = None;
    for h in handles {
        let (i, outcome) = h.await.unwrap();
        match outcome {
            ReplaceOutcome::Replaced(_) => {
                replaced += 1;
                winner = Some(i);
            }
            ReplaceOutcome::PreconditionFailed { .. } => precondition += 1,
            ReplaceOutcome::Absent => panic!("present throughout"),
        }
    }
    assert_eq!(replaced, 1, "exactly one Replaced");
    assert_eq!(precondition, 7);
    let got = store.read(&k, 1 << 16).await.unwrap().unwrap();
    assert_eq!(
        got.bytes,
        Bytes::from(format!("winner-{}", winner.unwrap()).into_bytes()),
        "final object is exactly the single winning payload"
    );
}

// -------------------------------------------- stale-generation preservation

#[tokio::test(flavor = "multi_thread")]
async fn replacement_survives_stale_replace_and_stale_delete() {
    let store = store_over(Arc::new(MockS3Client::new()), None);
    let k = key("cas/object");
    seed(&store, &k, b"generation-a").await;
    let va = store
        .read_with_version(&k, 1 << 16)
        .await
        .unwrap()
        .unwrap()
        .version;
    // Replace with B behind the observation.
    seed(&store, &k, b"generation-b").await;

    match store
        .replace_if_version(
            &k,
            &va,
            Bytes::from_static(b"generation-c"),
            Durability::Durable,
        )
        .await
        .unwrap()
    {
        ReplaceOutcome::PreconditionFailed { .. } => {}
        other => panic!("stale replace must fail closed, got {other:?}"),
    }
    match store.delete_if_version(&k, &va).await.unwrap() {
        ConditionalDeleteOutcome::PreconditionFailed { .. } => {}
        other => panic!("stale conditional delete must fail closed, got {other:?}"),
    }
    let got = store.read(&k, 1 << 16).await.unwrap().unwrap();
    assert_eq!(
        got.bytes,
        Bytes::from_static(b"generation-b"),
        "generation B survives both stale attempts"
    );
}

// ------------------------------------------------- delete-error regression

#[tokio::test(flavor = "multi_thread")]
async fn unconditional_delete_error_classification_regression() {
    let client = Arc::new(MockS3Client::new());
    let store = store_over(client.clone(), None);
    let k = key("del/target");
    seed(&store, &k, b"payload").await;

    // AccessDenied must remain an error — never silent success.
    client.set_hook(|op, _key| {
        if op == "delete" {
            Some((403, "AccessDenied", "injected access denied"))
        } else {
            None
        }
    });
    let err = store.delete(&k).await.expect_err("403 must surface");
    assert!(
        matches!(err, StoreError::PermissionDenied { .. }),
        "AccessDenied -> PermissionDenied, got {err:?}"
    );

    // 5xx / throttling must remain errors.
    client.set_hook(|op, _key| {
        if op == "delete" {
            Some((503, "SlowDown", "injected throttle"))
        } else {
            None
        }
    });
    let err = store.delete(&k).await.expect_err("503 must surface");
    assert!(matches!(err, StoreError::Backend { .. }), "got {err:?}");

    client.clear_hook();
    assert!(store.head(&k).await.unwrap().is_some(), "object survived");
    store.delete(&k).await.expect("clean delete succeeds");
    store
        .delete(&k)
        .await
        .expect("absent delete is idempotent success");
}

#[tokio::test(flavor = "multi_thread")]
async fn status_classification_across_operations() {
    let client = Arc::new(MockS3Client::new());
    let store = store_over(client.clone(), None);
    let k = key("cls/obj");
    seed(&store, &k, b"x").await;
    let v = store
        .read_with_version(&k, 1 << 16)
        .await
        .unwrap()
        .unwrap()
        .version;

    // Transport-ish / 5xx on each op class -> Backend.
    client.set_hook(|op, _| (op == "head").then_some((500, "InternalError", "injected 500")));
    let err = store.head(&k).await.expect_err("head 500");
    assert!(matches!(err, StoreError::Backend { .. }), "head: {err:?}");

    client.set_hook(|op, _| (op == "get").then_some((500, "InternalError", "injected 500")));
    let err = store.read(&k, 1 << 16).await.expect_err("get 500");
    assert!(matches!(err, StoreError::Backend { .. }), "get: {err:?}");

    client.set_hook(|op, _| (op == "put").then_some((500, "InternalError", "injected 500")));
    let err = store
        .write(&k, Bytes::from_static(b"y"), Durability::Visible)
        .await
        .expect_err("put 500");
    assert!(matches!(err, StoreError::Backend { .. }), "put: {err:?}");

    client.set_hook(|op, _| (op == "list").then_some((500, "InternalError", "injected 500")));
    let err = store
        .list_page(Some(&key("cls")), None, nz(5))
        .await
        .expect_err("list 500");
    assert!(matches!(err, StoreError::Backend { .. }), "list: {err:?}");
    client.clear_hook();

    // 403 on GET -> PermissionDenied, never absence.
    client.set_hook(|op, _| {
        if op == "get" {
            Some((403, "AccessDenied", "denied"))
        } else {
            None
        }
    });
    let err = store.read(&k, 1 << 16).await.expect_err("403 surfaces");
    assert!(matches!(err, StoreError::PermissionDenied { .. }));
    client.clear_hook();

    // Stale conditional ops still classify as outcomes (not errors).
    seed(&store, &k, b"z").await;
    match store
        .replace_if_version(&k, &v, Bytes::from_static(b"w"), Durability::Durable)
        .await
        .unwrap()
    {
        ReplaceOutcome::PreconditionFailed { .. } => {}
        other => panic!("stale -> PreconditionFailed, got {other:?}"),
    }
}

// ------------------------------------------------- physical prefix isolation

#[tokio::test(flavor = "multi_thread")]
async fn physical_prefix_is_invisible_and_isolating() {
    let client = Arc::new(MockS3Client::new());
    // Foreign keys OUTSIDE the configured prefix.
    client.raw_insert("other-tenant/objects/ns/foreign", b"foreign");
    client.raw_insert("toplevel-noise", b"noise");
    // A sibling key that shares the string prefix but not the '/' boundary.
    client.raw_insert("tenant-a/objectsXtrap", b"trap");

    let store = store_over(client.clone(), Some("tenant-a/objects"));
    let k = key("ns/mine");
    seed(&store, &k, b"mine").await;

    // Physical placement is exactly prefix + '/' + key.
    assert_eq!(
        client.raw_bytes("tenant-a/objects/ns/mine").unwrap(),
        Bytes::from_static(b"mine")
    );

    // Reads/lists cannot see foreign keys.
    assert!(
        store
            .read(&key("ns/foreign"), 1 << 16)
            .await
            .unwrap()
            .is_none()
            || {
                // foreign lives under ANOTHER tenant's prefix — unreachable name
                // through this store entirely.
                false
            }
    );
    let page = store
        .list_page(Some(&key("ns")), None, nz(10))
        .await
        .unwrap();
    let leaves: Vec<&str> = page.objects.iter().map(|r| r.leaf.as_str()).collect();
    assert_eq!(leaves, vec!["mine"], "only in-prefix objects listed");
    let root_page = store.list_page(None, None, nz(10)).await.unwrap();
    assert!(
        root_page.objects.is_empty(),
        "root listing sees namespaces only, no foreign/trap rows: {root_page:?}"
    );

    // Deleting through the store touches only in-prefix keys.
    store.delete(&k).await.unwrap();
    assert!(
        client
            .raw_bytes("other-tenant/objects/ns/foreign")
            .is_some()
    );
    assert!(client.raw_bytes("tenant-a/objectsXtrap").is_some());
}

// -------------------------------------------------------------- pagination

#[tokio::test(flavor = "multi_thread")]
async fn pagination_across_server_pages_boundary_and_failure() {
    let client = Arc::new(MockS3Client::new());
    *client.list_server_max.lock().unwrap() = 2; // force many round trips
    let store = store_over(client.clone(), None);

    for i in 0..7u32 {
        seed(&store, &key(&format!("pg/leaf-{i}")), b"row").await;
    }
    // Nested namespace must not appear as a row.
    seed(&store, &key("pg/sub/nested"), b"row").await;

    // Walk with page size 3: exactly-once, ordered, boundary-exact.
    let mut seen = Vec::new();
    let mut after: Option<PageToken> = None;
    loop {
        let page = store
            .list_page(Some(&key("pg")), after.as_ref(), nz(3))
            .await
            .unwrap();
        assert!(!(page.objects.is_empty() && page.next.is_some()));
        for r in &page.objects {
            seen.push(r.leaf.clone());
        }
        match page.next {
            Some(t) => after = Some(t),
            None => break,
        }
    }
    assert_eq!(
        seen,
        (0..7).map(|i| format!("leaf-{i}")).collect::<Vec<_>>(),
        "seven leaves exactly once, ordered; nested namespace excluded"
    );

    // Exact-boundary: limit equal to remaining rows yields no token.
    let page = store
        .list_page(Some(&key("pg")), None, nz(7))
        .await
        .unwrap();
    assert_eq!(page.objects.len(), 7);
    assert!(page.next.is_none(), "no token at the exact end");

    // Injected failure mid-pagination surfaces (never silent truncation).
    client.set_hook(|op, _| {
        if op == "list" {
            Some((500, "InternalError", "injected list failure"))
        } else {
            None
        }
    });
    let err = store
        .list_page(Some(&key("pg")), None, nz(3))
        .await
        .expect_err("mid-pagination failure surfaces");
    assert!(matches!(err, StoreError::Backend { .. }));
    client.clear_hook();
}

// ------------------------------------------------------------ token opacity

#[tokio::test(flavor = "multi_thread")]
async fn quoted_multipart_etags_round_trip_opaquely() {
    // The mock issues quoted multipart-style ETags ("mock-N-3"); the whole
    // conditional lifecycle must work without any caller unquoting/parsing.
    let store = store_over(Arc::new(MockS3Client::new()), None);
    let k = key("etag/opaque");
    seed(&store, &k, b"v1").await;
    let v1 = store
        .read_with_version(&k, 1 << 16)
        .await
        .unwrap()
        .unwrap()
        .version;
    match store
        .replace_if_version(&k, &v1, Bytes::from_static(b"v2"), Durability::Durable)
        .await
        .unwrap()
    {
        ReplaceOutcome::Replaced(v2) => match store.delete_if_version(&k, &v2).await.unwrap() {
            ConditionalDeleteOutcome::Deleted => {}
            other => panic!("fresh token deletes, got {other:?}"),
        },
        other => panic!("fresh token replaces, got {other:?}"),
    }
    assert!(store.head(&k).await.unwrap().is_none());
}

// -------------------------------------- bounded-listing exhaustion (fix)

/// Filtered physical direct-child rows: valid S3 keys whose LEAF is not a
/// valid generic key component (contains U+0001), sorting BETWEEN "a" and
/// "b" so they sit exactly where the discovery loop must traverse them.
fn insert_filtered_run(client: &MockS3Client, dir: &str, n: usize) {
    for i in 0..n {
        client.raw_insert_string_key(format!("{dir}a\u{1}filtered{i:02}"), b"junk");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn budget_exhaustion_with_hidden_later_valid_row_errors() {
    // a, <filtered run>, b — with limit=1, server page 1, budget 3: the
    // adapter cannot prove whether more logical rows exist; it must FAIL,
    // never claim `[a], next=None` while `b` exists.
    let client = Arc::new(MockS3Client::new());
    *client.list_server_max.lock().unwrap() = 1;
    client.raw_insert("bud/a", b"row");
    insert_filtered_run(&client, "bud/", 6);
    client.raw_insert("bud/b", b"row");

    let store = store_over(client.clone(), None).with_internal_list_budget(3);
    let err = store
        .list_page(Some(&key("bud")), None, nz(1))
        .await
        .expect_err("budget exhaustion must error, not truncate");
    match &err {
        StoreError::Backend { message, .. } => assert!(
            message.contains("budget") && message.contains("round trips"),
            "budget-exhaustion diagnostics, got: {message}"
        ),
        other => panic!("budget exhaustion -> Backend resource failure, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn budget_exhaustion_under_configured_prefix_errors_too() {
    let client = Arc::new(MockS3Client::new());
    *client.list_server_max.lock().unwrap() = 1;
    client.raw_insert("tenant-a/objects/bud/a", b"row");
    insert_filtered_run(&client, "tenant-a/objects/bud/", 6);
    client.raw_insert("tenant-a/objects/bud/b", b"row");
    // Foreign sibling stays invisible regardless.
    client.raw_insert("tenant-b/objects/bud/foreign", b"row");

    let store = store_over(client.clone(), Some("tenant-a/objects")).with_internal_list_budget(3);
    let err = store
        .list_page(Some(&key("bud")), None, nz(1))
        .await
        .expect_err("prefixed budget exhaustion must error");
    assert!(matches!(err, StoreError::Backend { .. }), "got {err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn true_exhaustion_after_filtered_rows_is_authoritative_none() {
    // a, <filtered run>, then the physical namespace GENUINELY ends within
    // the budget: `[a], next=None` is correct and required.
    let client = Arc::new(MockS3Client::new());
    *client.list_server_max.lock().unwrap() = 1;
    client.raw_insert("fin/a", b"row");
    insert_filtered_run(&client, "fin/", 2);

    let store = store_over(client.clone(), None).with_internal_list_budget(10);
    let page = store
        .list_page(Some(&key("fin")), None, nz(1))
        .await
        .unwrap();
    let leaves: Vec<&str> = page.objects.iter().map(|r| r.leaf.as_str()).collect();
    assert_eq!(leaves, vec!["a"]);
    assert!(page.next.is_none(), "authoritative exhaustion -> None");
}

#[tokio::test(flavor = "multi_thread")]
async fn next_valid_row_found_before_budget_continues_exactly_once() {
    // a, <one filtered>, b — b proves continuation within budget; walking
    // returns each valid row exactly once.
    let client = Arc::new(MockS3Client::new());
    *client.list_server_max.lock().unwrap() = 1;
    client.raw_insert("cont/a", b"row");
    insert_filtered_run(&client, "cont/", 1);
    client.raw_insert("cont/b", b"row");

    let store = store_over(client.clone(), None).with_internal_list_budget(10);
    let p1 = store
        .list_page(Some(&key("cont")), None, nz(1))
        .await
        .unwrap();
    assert_eq!(p1.objects[0].leaf, "a");
    let tok = p1.next.expect("b proves continuation");
    let p2 = store
        .list_page(Some(&key("cont")), Some(&tok), nz(1))
        .await
        .unwrap();
    assert_eq!(p2.objects[0].leaf, "b");
    assert!(p2.next.is_none(), "nothing after b");
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_logical_page_exhaustion_vs_budget() {
    // Only filtered physical rows exist.
    let client = Arc::new(MockS3Client::new());
    *client.list_server_max.lock().unwrap() = 1;
    insert_filtered_run(&client, "emp/", 2);

    // (i) authoritative exhaustion within budget: [], None.
    let store = store_over(client.clone(), None).with_internal_list_budget(10);
    let page = store
        .list_page(Some(&key("emp")), None, nz(5))
        .await
        .unwrap();
    assert!(page.objects.is_empty());
    assert!(page.next.is_none());

    // (ii) budget expires while still truncated: truthful error, never a
    // "complete" empty result.
    let client2 = Arc::new(MockS3Client::new());
    *client2.list_server_max.lock().unwrap() = 1;
    insert_filtered_run(&client2, "emp/", 6);
    let store2 = store_over(client2, None).with_internal_list_budget(3);
    let err = store2
        .list_page(Some(&key("emp")), None, nz(5))
        .await
        .expect_err("budget expiry on empty logical page must error");
    assert!(matches!(err, StoreError::Backend { .. }), "got {err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn no_forward_progress_truncated_page_is_distinct_corrupt_error() {
    // A misbehaving backend returning empty-but-truncated pages hits the
    // separate no-forward-progress guard (distinguishable from budget
    // exhaustion), and cannot loop forever.
    let client = Arc::new(MockS3Client::new());
    client.raw_insert("np/a", b"row");
    *client.force_empty_truncated.lock().unwrap() = 1;

    let store = store_over(client, None).with_internal_list_budget(10);
    let err = store
        .list_page(Some(&key("np")), None, nz(1))
        .await
        .expect_err("no-progress truncated page must error");
    match &err {
        StoreError::Corrupt { message } => assert!(
            message.contains("no forward progress"),
            "distinct no-progress diagnostics, got: {message}"
        ),
        other => panic!("no-progress -> Corrupt guard, got {other:?}"),
    }
}
