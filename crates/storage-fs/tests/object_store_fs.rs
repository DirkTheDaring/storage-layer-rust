//! Filesystem-specific adversarial tests for the `FsObjectStore` adapter:
//! properties not expressible in the generic contract suite — containment,
//! root pinning/replacement, conditional stale-preservation under real
//! replacement, concurrency of the lock-serialized conditional operations,
//! durability-strength error propagation (fault injection), and
//! observation side-effect freedom.

use std::num::NonZeroUsize;
use std::sync::Arc;

use bytes::Bytes;
use storage_core::ObjectKey;
use storage_core::object_store::{
    ConditionalDeleteOutcome, CreateOutcome, Durability, ObjectStore, ReplaceOutcome, StoreError,
};
use storage_fs::FsObjectStore;
use tempfile::TempDir;

fn key(s: &str) -> ObjectKey {
    ObjectKey::parse(s).expect("valid key")
}

fn nz(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).unwrap()
}

async fn seed(store: &FsObjectStore, k: &ObjectKey, bytes: &'static [u8]) {
    store
        .write(k, Bytes::from_static(bytes), Durability::Durable)
        .await
        .expect("seed write");
}

// ---------------------------------------------------------------- containment

#[tokio::test(flavor = "multi_thread")]
async fn symlinked_intermediate_component_fails_closed() {
    let root = TempDir::new().unwrap();
    let external = TempDir::new().unwrap();
    std::fs::write(external.path().join("victim"), b"external-bytes").unwrap();
    std::os::unix::fs::symlink(external.path(), root.path().join("ns")).unwrap();

    let store = FsObjectStore::open(root.path()).unwrap();
    let k = key("ns/victim");

    // Reads fail closed (never absence, never the external bytes).
    let err = store.read(&k, 1 << 16).await.expect_err("must fail closed");
    assert!(
        matches!(err, StoreError::PermissionDenied { .. }),
        "containment refusal classifies as PermissionDenied, got {err:?}"
    );
    // Writes fail closed and do not touch the external tree.
    let err = store
        .write(&k, Bytes::from_static(b"attack"), Durability::Durable)
        .await
        .expect_err("write through symlink must fail closed");
    assert!(matches!(err, StoreError::PermissionDenied { .. }));
    // Listing beneath the symlinked component fails closed too.
    let err = store
        .list_page(Some(&key("ns")), None, nz(10))
        .await
        .expect_err("listing through symlink must fail closed");
    assert!(matches!(err, StoreError::PermissionDenied { .. }));

    assert_eq!(
        std::fs::read(external.path().join("victim")).unwrap(),
        b"external-bytes",
        "external target untouched"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn symlinked_leaf_fails_closed_and_target_untouched() {
    let root = TempDir::new().unwrap();
    let external = TempDir::new().unwrap();
    let target = external.path().join("target");
    std::fs::write(&target, b"external-bytes").unwrap();
    std::fs::create_dir_all(root.path().join("ns")).unwrap();
    std::os::unix::fs::symlink(&target, root.path().join("ns/obj")).unwrap();

    let store = FsObjectStore::open(root.path()).unwrap();
    let k = key("ns/obj");

    let err = store.read(&k, 1 << 16).await.expect_err("must fail closed");
    assert!(matches!(err, StoreError::PermissionDenied { .. }));
    let err = store
        .read_with_version(&k, 1 << 16)
        .await
        .expect_err("must fail closed");
    assert!(matches!(err, StoreError::PermissionDenied { .. }));

    // The symlinked leaf is excluded from listings as structural.
    let page = store
        .list_page(Some(&key("ns")), None, nz(10))
        .await
        .unwrap();
    assert!(
        page.objects.is_empty(),
        "symlink leaf must not be listed as an object"
    );

    assert_eq!(std::fs::read(&target).unwrap(), b"external-bytes");
    assert!(
        root.path()
            .join("ns/obj")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

// ------------------------------------------------------------ root replacement

#[tokio::test(flavor = "multi_thread")]
async fn root_replacement_retained_adapter_stays_on_original_root() {
    let holder = TempDir::new().unwrap();
    let root_path = holder.path().join("store-root");
    std::fs::create_dir(&root_path).unwrap();

    let store = FsObjectStore::open(&root_path).unwrap();
    let k = key("ns/pinned-object");
    seed(&store, &k, b"tree-a-generation").await;

    // Replace the ambient pathname: tree A keeps living at a moved path,
    // tree B takes over the original pathname.
    let moved_a = holder.path().join("store-root-moved-a");
    std::fs::rename(&root_path, &moved_a).unwrap();
    std::fs::create_dir_all(root_path.join("ns")).unwrap();
    std::fs::write(root_path.join("ns/pinned-object"), b"tree-b-generation").unwrap();

    // Retained adapter continues to observe and mutate tree A only.
    let got = store
        .read(&k, 1 << 16)
        .await
        .unwrap()
        .expect("present in A");
    assert_eq!(got.bytes, Bytes::from_static(b"tree-a-generation"));
    store
        .write(
            &k,
            Bytes::from_static(b"tree-a-updated"),
            Durability::Durable,
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(moved_a.join("ns/pinned-object")).unwrap(),
        b"tree-a-updated",
        "retained adapter mutates the pinned tree"
    );
    assert_eq!(
        std::fs::read(root_path.join("ns/pinned-object")).unwrap(),
        b"tree-b-generation",
        "ambient replacement tree untouched by the retained adapter"
    );

    // A NEW adapter constructed afterwards resolves the replacement root.
    let store_b = FsObjectStore::open(&root_path).unwrap();
    let got_b = store_b
        .read(&k, 1 << 16)
        .await
        .unwrap()
        .expect("present in B");
    assert_eq!(got_b.bytes, Bytes::from_static(b"tree-b-generation"));
}

// ------------------------------------- conditional stale-preservation (races)

#[tokio::test(flavor = "multi_thread")]
async fn stale_replace_and_delete_preserve_replacement_generation() {
    let root = TempDir::new().unwrap();
    let store = FsObjectStore::open(root.path()).unwrap();
    let k = key("cas/object");
    seed(&store, &k, b"observed-generation").await;
    let v1 = store
        .read_with_version(&k, 1 << 16)
        .await
        .unwrap()
        .unwrap()
        .version;

    // The object is replaced after the observation.
    seed(&store, &k, b"replacement-generation").await;

    match store
        .replace_if_version(&k, &v1, Bytes::from_static(b"usurper"), Durability::Durable)
        .await
        .unwrap()
    {
        ReplaceOutcome::PreconditionFailed { .. } => {}
        other => panic!("stale replace must fail closed, got {other:?}"),
    }
    match store.delete_if_version(&k, &v1).await.unwrap() {
        ConditionalDeleteOutcome::PreconditionFailed { .. } => {}
        other => panic!("stale conditional delete must fail closed, got {other:?}"),
    }
    let got = store.read(&k, 1 << 16).await.unwrap().unwrap();
    assert_eq!(
        got.bytes,
        Bytes::from_static(b"replacement-generation"),
        "replacement generation byte-preserved through both stale attempts"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_write_if_absent_has_exactly_one_winner() {
    let root = TempDir::new().unwrap();
    let store = Arc::new(FsObjectStore::open(root.path()).unwrap());
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
    for h in handles {
        match h.await.unwrap() {
            CreateOutcome::Created(_) => created += 1,
            CreateOutcome::AlreadyExists { .. } => exists += 1,
        }
    }
    assert_eq!(created, 1, "exactly one creator wins");
    assert_eq!(exists, 7);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_replace_if_version_same_observation_single_winner() {
    let root = TempDir::new().unwrap();
    let store = Arc::new(FsObjectStore::open(root.path()).unwrap());
    let k = key("contend/cas");
    seed(&store, &k, b"base-generation").await;
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
            store
                .replace_if_version(
                    &k,
                    &v,
                    Bytes::from(format!("winner-{i}").into_bytes()),
                    Durability::Durable,
                )
                .await
                .expect("classifies")
        }));
    }
    let mut replaced = 0;
    let mut precondition = 0;
    for h in handles {
        match h.await.unwrap() {
            ReplaceOutcome::Replaced(_) => replaced += 1,
            ReplaceOutcome::PreconditionFailed { .. } => precondition += 1,
            ReplaceOutcome::Absent => panic!("object present throughout"),
        }
    }
    assert_eq!(replaced, 1, "one CAS winner under the per-leaf lock");
    assert_eq!(precondition, 7, "losers observe the successor generation");
}

// ------------------------------------------------- observation side effects

#[tokio::test(flavor = "multi_thread")]
async fn observations_of_absent_namespaces_create_no_directories() {
    let root = TempDir::new().unwrap();
    let store = FsObjectStore::open(root.path()).unwrap();
    let k = key("never/created/object");

    assert!(store.head(&k).await.unwrap().is_none());
    assert!(store.read(&k, 1 << 16).await.unwrap().is_none());
    assert!(
        store
            .read_with_version(&k, 1 << 16)
            .await
            .unwrap()
            .is_none()
    );
    store.delete(&k).await.unwrap();
    let page = store
        .list_page(Some(&key("never/created")), None, nz(5))
        .await
        .unwrap();
    assert!(page.objects.is_empty() && page.next.is_none());

    assert!(
        !root.path().join("never").exists(),
        "no namespace directories created by observations/deletes"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn namespace_collision_names_are_ordinary_generic_objects() {
    // Names resembling the OLD adapter bookkeeping (and the primitive's temp
    // grammar) are valid generic keys and must be full citizens.
    let root = TempDir::new().unwrap();
    let store = FsObjectStore::open(root.path()).unwrap();

    let names = [
        ".hidden",
        ".tmp.foo",
        ".fsos.lock.foo",
        "a/.hidden",
        "a/.tmp.foo",
        "a/.fsos.lock.foo",
    ];
    for n in names {
        let k = key(n);
        store
            .write(
                &k,
                Bytes::from(format!("payload:{n}").into_bytes()),
                Durability::Durable,
            )
            .await
            .unwrap_or_else(|e| panic!("write {n}: {e:?}"));
        let got = store.read(&k, 1 << 16).await.unwrap().expect("present");
        assert_eq!(got.bytes, Bytes::from(format!("payload:{n}").into_bytes()));
        let v = store
            .read_with_version(&k, 1 << 16)
            .await
            .unwrap()
            .unwrap()
            .version;
        match store
            .replace_if_version(&k, &v, Bytes::from_static(b"mutated"), Durability::Durable)
            .await
            .unwrap()
        {
            ReplaceOutcome::Replaced(_) => {}
            other => panic!("conditional mutation on {n} must work, got {other:?}"),
        }
    }

    // Root-level listing shows the dot-prefixed root objects; the internal
    // bookkeeping tree (control-char name) is structurally invisible.
    let page = store.list_page(None, None, nz(20)).await.unwrap();
    let leaves: Vec<&str> = page.objects.iter().map(|r| r.leaf.as_str()).collect();
    assert_eq!(leaves, vec![".fsos.lock.foo", ".hidden", ".tmp.foo"]);
    let nested = store
        .list_page(Some(&key("a")), None, nz(20))
        .await
        .unwrap();
    let leaves: Vec<&str> = nested.objects.iter().map(|r| r.leaf.as_str()).collect();
    assert_eq!(leaves, vec![".fsos.lock.foo", ".hidden", ".tmp.foo"]);

    // No bookkeeping is confused with the objects: internal tree exists on
    // disk (locks were used) but is unreachable/invisible generically.
    assert!(
        root.path().join("\u{1}fsos.internal").exists()
            || root
                .path()
                .join(storage_fs::object_store::INTERNAL_DIR)
                .exists(),
        "internal tree exists after conditional ops"
    );
    for n in names {
        store.delete(&key(n)).await.unwrap();
        assert!(store.head(&key(n)).await.unwrap().is_none());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn lock_identities_of_key_and_lock_lookalike_key_are_disjoint() {
    // Simultaneous conditional operations on "foo" and ".fsos.lock.foo"
    // (both valid generic keys) must use DISTINCT lock identities and both
    // succeed independently.
    let root = TempDir::new().unwrap();
    let store = Arc::new(FsObjectStore::open(root.path()).unwrap());
    let k1 = key("ns/foo");
    let k2 = key("ns/.fsos.lock.foo");
    seed(&store, &k1, b"one").await;
    seed(&store, &k2, b"two").await;
    let v1 = store
        .read_with_version(&k1, 1 << 16)
        .await
        .unwrap()
        .unwrap()
        .version;
    let v2 = store
        .read_with_version(&k2, 1 << 16)
        .await
        .unwrap()
        .unwrap()
        .version;

    let s1 = store.clone();
    let s2 = store.clone();
    let (k1c, k2c) = (k1.clone(), k2.clone());
    let (r1, r2) = tokio::join!(
        async move {
            s1.replace_if_version(&k1c, &v1, Bytes::from_static(b"one2"), Durability::Durable)
                .await
        },
        async move {
            s2.replace_if_version(&k2c, &v2, Bytes::from_static(b"two2"), Durability::Durable)
                .await
        }
    );
    assert!(matches!(r1.unwrap(), ReplaceOutcome::Replaced(_)));
    assert!(matches!(r2.unwrap(), ReplaceOutcome::Replaced(_)));
    assert_eq!(
        store.read(&k1, 64).await.unwrap().unwrap().bytes,
        Bytes::from_static(b"one2")
    );
    assert_eq!(
        store.read(&k2, 64).await.unwrap().unwrap().bytes,
        Bytes::from_static(b"two2")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn adapter_writes_never_stage_in_object_directories() {
    // A pre-existing generic object matching the primitive temp grammar is
    // untouched by adapter writes to a sibling key, and object directories
    // never contain adapter staging names (adapter stages internally).
    let root = TempDir::new().unwrap();
    let store = FsObjectStore::open(root.path()).unwrap();
    let lookalike = key("ns/.tmp.target.1.2.3");
    seed(&store, &lookalike, b"i-look-like-a-temp").await;

    for i in 0..16u32 {
        store
            .write(
                &key("ns/target"),
                Bytes::from(format!("gen-{i}").into_bytes()),
                Durability::Durable,
            )
            .await
            .unwrap();
    }
    assert_eq!(
        store
            .read(&lookalike, 1 << 16)
            .await
            .unwrap()
            .unwrap()
            .bytes,
        Bytes::from_static(b"i-look-like-a-temp"),
        "temp-lookalike object never damaged by adapter writes"
    );
    // Ambient inspection: the object directory contains exactly the two
    // objects — no staging residue.
    let mut names: Vec<String> = std::fs::read_dir(root.path().join("ns"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![".tmp.target.1.2.3".to_string(), "target".to_string()],
        "no adapter staging names inside the object directory"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn internal_tree_cannot_be_redirected_through_symlink() {
    use std::os::unix::ffi::OsStrExt as _;
    let root = TempDir::new().unwrap();
    let external = TempDir::new().unwrap();
    // Pre-plant a SYMLINK at the internal control-char name.
    let internal_name =
        std::ffi::OsStr::from_bytes(storage_fs::object_store::INTERNAL_DIR.as_bytes());
    std::os::unix::fs::symlink(external.path(), root.path().join(internal_name)).unwrap();

    let store = FsObjectStore::open(root.path()).unwrap();
    // Conditional ops need the internal tree; resolution must fail closed
    // (never follow the symlink into the external tree).
    let k = key("ns/obj");
    seed_expect_err_or_external_untouched(&store, &k, external.path()).await;
}

async fn seed_expect_err_or_external_untouched(
    store: &FsObjectStore,
    k: &storage_core::ObjectKey,
    external: &std::path::Path,
) {
    // Plain write also uses the internal staging tree.
    let res = store
        .write(k, Bytes::from_static(b"x"), Durability::Durable)
        .await;
    assert!(
        matches!(
            res,
            Err(StoreError::PermissionDenied { .. }) | Err(StoreError::Backend { .. })
        ),
        "internal-tree symlink must fail closed, got {res:?}"
    );
    let leaked: Vec<_> = std::fs::read_dir(external).unwrap().collect();
    assert!(
        leaked.is_empty(),
        "no bookkeeping leaked into the external symlink target"
    );
}

// -------------------------------------------------- durability strengths

#[cfg(feature = "fault-injection")]
mod durability_faults {
    use super::*;
    use storage_fs::mutate::fault::{self, FaultPoint};

    // The fault table (and `fault::reset`) is process-global: serialize the
    // fault tests so one test's teardown cannot clear another's armed rules.
    static FAULT_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    // Both strengths report publish failures truthfully (neither is a
    // best-effort mode), and the Durable-only destination-directory barrier
    // is now fault-distinguishable: Durable propagates an injected
    // publication-directory sync failure while Visible never executes that
    // barrier at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn durable_and_visible_strengths_are_truthful_and_distinct() {
        let _serial = FAULT_TEST_LOCK.lock().await;
        let root = TempDir::new().unwrap();
        let store = FsObjectStore::open(root.path()).unwrap();
        let k = key("zzfaultdir/zzfaultwtarget");

        // Publish rename failure surfaces for BOTH strengths; no partial
        // object is published (staging is cleaned up internally).
        fault::arm(FaultPoint::RenameLeaf, Some("zzfaultwtarget"), 1, libc::EIO);
        let err = store
            .write(&k, Bytes::from_static(b"x"), Durability::Durable)
            .await
            .expect_err("Durable publish failure must surface");
        assert!(matches!(err, StoreError::Backend { .. }), "got {err:?}");
        fault::arm(FaultPoint::RenameLeaf, Some("zzfaultwtarget"), 1, libc::EIO);
        let err = store
            .write(&k, Bytes::from_static(b"x"), Durability::Visible)
            .await
            .expect_err("Visible publish failure must surface too");
        assert!(matches!(err, StoreError::Backend { .. }), "got {err:?}");
        assert!(
            store.head(&k).await.unwrap().is_none(),
            "no partial object published by failed writes"
        );

        // Durable-only barrier: the destination-directory sync. Durable
        // consumes the injected failure and reports it (the rename is
        // already visible — no rollback is claimed); Visible never executes
        // the barrier, so with the same rule armed it succeeds.
        fault::arm(FaultPoint::DirSync, Some("zzfaultdir"), 1, libc::EIO);
        let err = store
            .write(&k, Bytes::from_static(b"d"), Durability::Durable)
            .await
            .expect_err("Durable must propagate the publication-dir sync failure");
        assert!(matches!(err, StoreError::Backend { .. }), "got {err:?}");
        fault::arm(FaultPoint::DirSync, Some("zzfaultdir"), 1, libc::EIO);
        store
            .write(&k, Bytes::from_static(b"v"), Durability::Visible)
            .await
            .expect("Visible executes no publication-dir barrier and succeeds");
        fault::reset();

        store
            .write(&k, Bytes::from_static(b"ok"), Durability::Durable)
            .await
            .expect("clean Durable write succeeds after faults cleared");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unconditional_delete_propagates_backend_failure() {
        let _serial = FAULT_TEST_LOCK.lock().await;
        let root = TempDir::new().unwrap();
        let store = FsObjectStore::open(root.path()).unwrap();
        let k = key("faults/zzfaultdtarget");
        store
            .write(&k, Bytes::from_static(b"x"), Durability::Durable)
            .await
            .unwrap();

        fault::arm(FaultPoint::Unlink, Some("zzfaultdtarget"), 1, libc::EIO);
        let err = store
            .delete(&k)
            .await
            .expect_err("delete failure must surface, never silent success");
        assert!(matches!(err, StoreError::Backend { .. }), "got {err:?}");
        fault::reset();

        assert!(store.head(&k).await.unwrap().is_some(), "object survives");
        store.delete(&k).await.expect("clean delete succeeds");
        assert!(store.head(&k).await.unwrap().is_none());
    }
}
