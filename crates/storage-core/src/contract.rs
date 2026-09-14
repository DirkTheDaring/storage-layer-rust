//! Reusable backend contract-test suite for [`ObjectStore`] implementations
//! (feature `contract-tests`).
//!
//! The SIGNATURES of `ObjectStore` are not the contract — these checks are.
//! Each adapter crate runs [`run_core_suite`] (and the granular checks)
//! against a FRESH instance of its real implementation; this crate runs the
//! same suite against [`model::ModelObjectStore`], an in-memory reference
//! model that exists ONLY to validate the suite and the contracts themselves.
//! The model is feature-gated and must never be wired as a production
//! backend.
//!
//! Checks use keys under distinct `contract-…` prefixes so a fresh store per
//! suite run is sufficient isolation.

use std::num::NonZeroUsize;

use bytes::Bytes;

use crate::key::ObjectKey;
use crate::object_store::{
    ConditionalDeleteOutcome, CreateOutcome, Durability, ObjectStore, PageToken, ReplaceOutcome,
    StoreError,
};

fn key(s: &str) -> ObjectKey {
    ObjectKey::parse(s).expect("contract suite uses valid keys")
}

fn nz(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).expect("non-zero")
}

/// 1. write then read: bytes, meta, and version round-trip.
pub async fn check_write_then_read(store: &dyn ObjectStore) {
    let k = key("contract-basic/write-read");
    let v = store
        .write(&k, Bytes::from_static(b"generation-1"), Durability::Durable)
        .await
        .expect("write");
    let got = store
        .read_with_version(&k, 1 << 16)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(got.bytes, Bytes::from_static(b"generation-1"));
    assert_eq!(got.meta.size, 12);
    assert_eq!(
        got.version, v,
        "write-returned version equals read-observed"
    );
    let head = store.head(&k).await.expect("head").expect("present");
    assert_eq!(head.size, 12);
    assert!(store.read(&k, 1 << 16).await.expect("read").is_some());
}

/// 2+3. write_if_absent: creation succeeds; conflict preserves the original.
pub async fn check_write_if_absent(store: &dyn ObjectStore) {
    let k = key("contract-create/only-once");
    match store
        .write_if_absent(&k, Bytes::from_static(b"first"), Durability::Durable)
        .await
        .expect("create")
    {
        CreateOutcome::Created(_) => {}
        other => panic!("fresh key must create, got {other:?}"),
    }
    match store
        .write_if_absent(&k, Bytes::from_static(b"usurper"), Durability::Durable)
        .await
        .expect("second create attempt classifies")
    {
        CreateOutcome::AlreadyExists { .. } => {}
        other => panic!("existing key must refuse, got {other:?}"),
    }
    let got = store
        .read(&k, 1 << 16)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(
        got.bytes,
        Bytes::from_static(b"first"),
        "loser must not overwrite"
    );
}

/// 4. read_with_version: stable across idle re-reads; changes after replace.
pub async fn check_version_observation(store: &dyn ObjectStore) {
    let k = key("contract-version/observe");
    store
        .write(&k, Bytes::from_static(b"aaa"), Durability::Durable)
        .await
        .expect("write");
    let v1 = store
        .read_with_version(&k, 1 << 16)
        .await
        .expect("read")
        .expect("present")
        .version;
    let v1_again = store
        .read_with_version(&k, 1 << 16)
        .await
        .expect("read")
        .expect("present")
        .version;
    assert_eq!(v1, v1_again, "idle object keeps its observed version");
    store
        .write(&k, Bytes::from_static(b"bbb"), Durability::Durable)
        .await
        .expect("replace");
    let v2 = store
        .read_with_version(&k, 1 << 16)
        .await
        .expect("read")
        .expect("present")
        .version;
    assert_ne!(v1, v2, "payload change must change the version");
}

/// 5+6. replace_if_version: matching observation replaces; stale observation
/// preserves the current object; absent key is Absent (no resurrection).
pub async fn check_replace_if_version(store: &dyn ObjectStore) {
    let k = key("contract-cas/replace");
    store
        .write(&k, Bytes::from_static(b"one"), Durability::Durable)
        .await
        .expect("seed");
    let v1 = store
        .read_with_version(&k, 1 << 16)
        .await
        .expect("read")
        .expect("present")
        .version;
    match store
        .replace_if_version(&k, &v1, Bytes::from_static(b"two"), Durability::Durable)
        .await
        .expect("cas")
    {
        ReplaceOutcome::Replaced(_) => {}
        other => panic!("matching observation must replace, got {other:?}"),
    }
    // v1 is now stale: the current object ("two") must be preserved.
    match store
        .replace_if_version(&k, &v1, Bytes::from_static(b"three"), Durability::Durable)
        .await
        .expect("stale cas classifies")
    {
        ReplaceOutcome::PreconditionFailed { .. } => {}
        other => panic!("stale observation must fail closed, got {other:?}"),
    }
    let got = store
        .read(&k, 1 << 16)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(got.bytes, Bytes::from_static(b"two"));
    let absent = key("contract-cas/never-existed");
    match store
        .replace_if_version(&absent, &v1, Bytes::from_static(b"x"), Durability::Durable)
        .await
        .expect("absent cas classifies")
    {
        ReplaceOutcome::Absent => {}
        other => panic!("absent key must report Absent, got {other:?}"),
    }
    assert!(store.head(&absent).await.expect("head").is_none());
}

/// 7+8. Unconditional delete is idempotent make-absent: present key ->
/// success and absent afterwards; absent key -> success; repeated delete ->
/// success. The contract deliberately exposes NO prior-existence knowledge
/// (the return type is `()` — pinned here by the compiler); callers needing
/// observed-removal semantics use read_with_version + delete_if_version.
pub async fn check_delete_idempotent(store: &dyn ObjectStore) {
    let k = key("contract-delete/outcomes");
    store
        .write(&k, Bytes::from_static(b"doomed"), Durability::Durable)
        .await
        .expect("seed");
    let () = store.delete(&k).await.expect("delete of present key");
    assert!(store.head(&k).await.expect("head").is_none(), "key absent");
    let () = store.delete(&k).await.expect("delete of absent key");
    let () = store.delete(&k).await.expect("repeated delete");
    assert!(store.head(&k).await.expect("head").is_none());
}

/// 9+10. delete_if_version: matching observation deletes; a stale observation
/// must never delete the replacement object; absent is Absent.
pub async fn check_delete_if_version(store: &dyn ObjectStore) {
    let k = key("contract-cas/delete");
    store
        .write(&k, Bytes::from_static(b"victim"), Durability::Durable)
        .await
        .expect("seed");
    let v1 = store
        .read_with_version(&k, 1 << 16)
        .await
        .expect("read")
        .expect("present")
        .version;
    // Replace behind the observation: v1 becomes stale.
    store
        .write(&k, Bytes::from_static(b"replacement"), Durability::Durable)
        .await
        .expect("replace");
    match store
        .delete_if_version(&k, &v1)
        .await
        .expect("stale conditional delete classifies")
    {
        ConditionalDeleteOutcome::PreconditionFailed { .. } => {}
        other => panic!("stale observation must not delete, got {other:?}"),
    }
    let got = store
        .read(&k, 1 << 16)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(
        got.bytes,
        Bytes::from_static(b"replacement"),
        "replacement survives the stale conditional delete"
    );
    let v2 = store
        .read_with_version(&k, 1 << 16)
        .await
        .expect("read")
        .expect("present")
        .version;
    assert_eq!(
        store
            .delete_if_version(&k, &v2)
            .await
            .expect("matching conditional delete"),
        ConditionalDeleteOutcome::Deleted
    );
    assert_eq!(
        store.delete_if_version(&k, &v2).await.expect("absent"),
        ConditionalDeleteOutcome::Absent
    );
}

/// 11+12+13. Listing: ordering, strictly-after continuation covering every
/// row exactly once, absent prefix behavior, and no empty-page-with-token.
pub async fn check_listing(store: &dyn ObjectStore) {
    let prefix = key("contract-list/ns");
    for leaf in ["delta", "alpha", "echo", "bravo", "charlie"] {
        let k = key(&format!("contract-list/ns/{leaf}"));
        store
            .write(&k, Bytes::from_static(b"row"), Durability::Durable)
            .await
            .expect("seed row");
    }

    let mut seen: Vec<String> = Vec::new();
    let mut after: Option<PageToken> = None;
    loop {
        let page = store
            .list_page(Some(&prefix), after.as_ref(), nz(2))
            .await
            .expect("list page");
        assert!(
            !(page.objects.is_empty() && page.next.is_some()),
            "no empty page with a continuation token"
        );
        for row in &page.objects {
            assert_eq!(
                row.key.as_str(),
                format!("contract-list/ns/{}", row.leaf),
                "row key composes prefix + leaf"
            );
            seen.push(row.leaf.clone());
        }
        match page.next {
            Some(tok) => after = Some(tok),
            None => break,
        }
    }
    assert_eq!(
        seen,
        vec!["alpha", "bravo", "charlie", "delta", "echo"],
        "ascending leaf order, exactly once across the token walk"
    );

    let absent = key("contract-list/never-created");
    let page = store
        .list_page(Some(&absent), None, nz(10))
        .await
        .expect("absent prefix lists");
    assert!(page.objects.is_empty());
    assert!(page.next.is_none());
}

/// 14. Bounded reads: an object larger than the ceiling fails with TooLarge
/// and nothing is truncated.
pub async fn check_read_bound(store: &dyn ObjectStore) {
    let k = key("contract-bounds/large");
    store
        .write(&k, Bytes::from(vec![7u8; 64]), Durability::Durable)
        .await
        .expect("seed");
    match store.read(&k, 63).await {
        Err(StoreError::TooLarge { limit: 63 }) => {}
        other => panic!("over-limit read must fail TooLarge, got {other:?}"),
    }
    let full = store.read(&k, 64).await.expect("read").expect("present");
    assert_eq!(
        full.bytes.len(),
        64,
        "at-limit read returns the full payload"
    );
}

/// 15. Invalid keys are unrepresentable via [`ObjectKey::parse`]; pin the
/// grammar here so adapters cannot loosen it accidentally.
pub fn check_invalid_key_rejection() {
    for bad in ["", "/abs", "trail/", "a//b", "a/../b", ".", "a\\b", "C:x"] {
        assert!(
            ObjectKey::parse(bad).is_err(),
            "key grammar must reject {bad:?}"
        );
    }
}

/// Dot-prefixed components are ordinary generic keys (the grammar forbids
/// only "." and ".." traversal segments). Backends must give them full
/// citizenship: write/read/list/conditional-mutate/delete — no backend may
/// reserve, hide, or reject them for backend-private bookkeeping reasons.
pub async fn check_dot_prefixed_keys_are_ordinary_objects(store: &dyn ObjectStore) {
    for k in ["contract-dot/.hidden", "contract-dot/nest/.tmp.foo"] {
        let k = key(k);
        assert!(
            store.head(&k).await.expect("head").is_none(),
            "fresh dot key absent"
        );
        store
            .write(&k, Bytes::from_static(b"dot-payload"), Durability::Durable)
            .await
            .expect("dot-prefixed key must be writable");
        let got = store
            .read_with_version(&k, 1 << 16)
            .await
            .expect("read")
            .expect("present");
        assert_eq!(got.bytes, Bytes::from_static(b"dot-payload"));
        match store
            .replace_if_version(
                &k,
                &got.version,
                Bytes::from_static(b"dot-payload-2"),
                Durability::Durable,
            )
            .await
            .expect("cas classifies")
        {
            ReplaceOutcome::Replaced(_) => {}
            other => panic!("dot key conditional mutation must work, got {other:?}"),
        }
        let () = store.delete(&k).await.expect("dot key deletable");
        assert!(store.head(&k).await.expect("head").is_none());
    }

    // Listing must include dot-prefixed leaves alongside ordinary ones.
    let prefix = key("contract-dot/list");
    for leaf in [".hidden", ".lockish", "plain"] {
        store
            .write(
                &key(&format!("contract-dot/list/{leaf}")),
                Bytes::from_static(b"row"),
                Durability::Durable,
            )
            .await
            .expect("seed");
    }
    let page = store
        .list_page(Some(&prefix), None, nz(10))
        .await
        .expect("list");
    let leaves: Vec<&str> = page.objects.iter().map(|r| r.leaf.as_str()).collect();
    assert_eq!(
        leaves,
        vec![".hidden", ".lockish", "plain"],
        "dot-prefixed generic objects are listed, in order, unfiltered"
    );
}

/// Runs every core contract check against a FRESH store instance.
pub async fn run_core_suite(store: &dyn ObjectStore) {
    check_invalid_key_rejection();
    check_write_then_read(store).await;
    check_write_if_absent(store).await;
    check_version_observation(store).await;
    check_replace_if_version(store).await;
    check_delete_idempotent(store).await;
    check_delete_if_version(store).await;
    check_listing(store).await;
    check_read_bound(store).await;
    check_dot_prefixed_keys_are_ordinary_objects(store).await;
}

pub mod model {
    //! In-memory REFERENCE MODEL of the [`ObjectStore`] contract.
    //!
    //! Test scaffolding only: it exists so the contract suite itself can be
    //! validated and so higher layers can unit-test compositions without a
    //! real backend. It is feature-gated (`contract-tests`) precisely so it
    //! cannot quietly become a third production backend.

    use std::collections::BTreeMap;
    use std::num::NonZeroUsize;
    use std::sync::Mutex;
    use std::time::SystemTime;

    use async_trait::async_trait;
    use bytes::Bytes;

    use crate::key::ObjectKey;
    use crate::object_store::{
        ConditionalDeleteOutcome, CreateOutcome, Durability, ListPage, ListedObject, ObjectMeta,
        ObjectRead, ObjectStore, ObjectVersion, PageToken, ReplaceOutcome, StoreError,
        VersionedRead, adapter,
    };

    #[derive(Clone)]
    struct Stored {
        bytes: Bytes,
        generation: u64,
        modified: SystemTime,
    }

    /// See module docs: reference model, not a backend.
    #[derive(Default)]
    pub struct ModelObjectStore {
        objects: Mutex<BTreeMap<String, Stored>>,
        counter: Mutex<u64>,
    }

    impl ModelObjectStore {
        pub fn new() -> Self {
            Self::default()
        }

        fn next_generation(&self) -> u64 {
            let mut c = self.counter.lock().unwrap();
            *c += 1;
            *c
        }

        fn version_of(generation: u64) -> ObjectVersion {
            adapter::object_version(format!("model:{generation}"))
        }
    }

    #[async_trait]
    impl ObjectStore for ModelObjectStore {
        async fn head(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>, StoreError> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .get(key.as_str())
                .map(|s| ObjectMeta {
                    size: s.bytes.len() as u64,
                    modified: Some(s.modified),
                }))
        }

        async fn read(
            &self,
            key: &ObjectKey,
            max_len: u64,
        ) -> Result<Option<ObjectRead>, StoreError> {
            match self.read_with_version(key, max_len).await? {
                Some(v) => Ok(Some(ObjectRead {
                    meta: v.meta,
                    bytes: v.bytes,
                })),
                None => Ok(None),
            }
        }

        async fn read_with_version(
            &self,
            key: &ObjectKey,
            max_len: u64,
        ) -> Result<Option<VersionedRead>, StoreError> {
            let objects = self.objects.lock().unwrap();
            let Some(s) = objects.get(key.as_str()) else {
                return Ok(None);
            };
            if s.bytes.len() as u64 > max_len {
                return Err(StoreError::TooLarge { limit: max_len });
            }
            Ok(Some(VersionedRead {
                meta: ObjectMeta {
                    size: s.bytes.len() as u64,
                    modified: Some(s.modified),
                },
                version: Self::version_of(s.generation),
                bytes: s.bytes.clone(),
            }))
        }

        async fn write(
            &self,
            key: &ObjectKey,
            bytes: Bytes,
            _durability: Durability,
        ) -> Result<ObjectVersion, StoreError> {
            let generation = self.next_generation();
            self.objects.lock().unwrap().insert(
                key.as_str().to_string(),
                Stored {
                    bytes,
                    generation,
                    modified: SystemTime::now(),
                },
            );
            Ok(Self::version_of(generation))
        }

        async fn write_if_absent(
            &self,
            key: &ObjectKey,
            bytes: Bytes,
            _durability: Durability,
        ) -> Result<CreateOutcome, StoreError> {
            let generation = self.next_generation();
            let mut objects = self.objects.lock().unwrap();
            if let Some(existing) = objects.get(key.as_str()) {
                return Ok(CreateOutcome::AlreadyExists {
                    current: Some(Self::version_of(existing.generation)),
                });
            }
            objects.insert(
                key.as_str().to_string(),
                Stored {
                    bytes,
                    generation,
                    modified: SystemTime::now(),
                },
            );
            Ok(CreateOutcome::Created(Self::version_of(generation)))
        }

        async fn replace_if_version(
            &self,
            key: &ObjectKey,
            expected: &ObjectVersion,
            bytes: Bytes,
            _durability: Durability,
        ) -> Result<ReplaceOutcome, StoreError> {
            let generation = self.next_generation();
            let mut objects = self.objects.lock().unwrap();
            let Some(existing) = objects.get(key.as_str()) else {
                return Ok(ReplaceOutcome::Absent);
            };
            if Self::version_of(existing.generation) != *expected {
                return Ok(ReplaceOutcome::PreconditionFailed {
                    current: Some(Self::version_of(existing.generation)),
                });
            }
            objects.insert(
                key.as_str().to_string(),
                Stored {
                    bytes,
                    generation,
                    modified: SystemTime::now(),
                },
            );
            Ok(ReplaceOutcome::Replaced(Self::version_of(generation)))
        }

        async fn delete(&self, key: &ObjectKey) -> Result<(), StoreError> {
            self.objects.lock().unwrap().remove(key.as_str());
            Ok(())
        }

        async fn delete_if_version(
            &self,
            key: &ObjectKey,
            expected: &ObjectVersion,
        ) -> Result<ConditionalDeleteOutcome, StoreError> {
            let mut objects = self.objects.lock().unwrap();
            let Some(existing) = objects.get(key.as_str()) else {
                return Ok(ConditionalDeleteOutcome::Absent);
            };
            if Self::version_of(existing.generation) != *expected {
                return Ok(ConditionalDeleteOutcome::PreconditionFailed {
                    current: Some(Self::version_of(existing.generation)),
                });
            }
            objects.remove(key.as_str());
            Ok(ConditionalDeleteOutcome::Deleted)
        }

        async fn list_page(
            &self,
            prefix: Option<&ObjectKey>,
            after: Option<&PageToken>,
            limit: NonZeroUsize,
        ) -> Result<ListPage, StoreError> {
            let prefix_path = prefix.map(|p| format!("{}/", p.as_str()));
            let objects = self.objects.lock().unwrap();

            let mut rows: Vec<ListedObject> = Vec::new();
            let mut more = false;
            for (stored_key, s) in objects.iter() {
                let leaf = match &prefix_path {
                    Some(p) => match stored_key.strip_prefix(p.as_str()) {
                        Some(rest) => rest,
                        None => continue,
                    },
                    None => stored_key.as_str(),
                };
                // Direct children only: structurally nested entries excluded.
                if leaf.is_empty() || leaf.contains('/') {
                    continue;
                }
                if let Some(tok) = after
                    && leaf <= adapter::page_token_value(tok)
                {
                    continue;
                }
                if rows.len() == limit.get() {
                    more = true;
                    break;
                }
                rows.push(ListedObject {
                    key: ObjectKey::parse(stored_key)
                        .map_err(|e| StoreError::corrupt(format!("model key invalid: {e}")))?,
                    leaf: leaf.to_string(),
                    size: s.bytes.len() as u64,
                    modified: Some(s.modified),
                    version: adapter::listing_version(format!("model:{}", s.generation)),
                });
            }
            let next = if more {
                rows.last().map(|r| adapter::page_token(r.leaf.clone()))
            } else {
                None
            };
            Ok(ListPage {
                objects: rows,
                next,
            })
        }
    }
}
