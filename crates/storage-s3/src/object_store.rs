//! S3 [`ObjectStore`] adapter (STORAGE-LAYER-MIGRATION Phase 2).
//!
//! Implements the accepted backend-neutral `storage-core` object-store
//! contract over S3-native request semantics through the [`S3Client`] seam.
//! The adapter knows generic keys, bytes, versions, listings, durability
//! and store errors — and nothing about registries or filesystems.
//!
//! # Key mapping (exact, reversible, unreserved)
//! `physical key = [configured prefix "/"] + ObjectKey`. The identity of a
//! generic key is preserved byte-for-byte (no normalization, no escaping —
//! every `ObjectKey`-valid byte sequence is a valid S3 key); dot-prefixed
//! components are ordinary keys; nothing is reserved (this backend needs no
//! bookkeeping names at all). The configured prefix is invisible above the
//! boundary: listings strip it, and no operation can address keys outside
//! it.
//!
//! # Version tokens (backend-private semantics)
//! `ObjectVersion` and `ListingVersion` both encode the object's S3 ETag
//! (normalized by trimming quotes) — an OPAQUE service-issued precondition
//! token, possibly a multipart `...-N` form, never a content digest. The
//! read-grade token comes from the SAME GET response as the returned bytes;
//! the listing-grade token from the LIST row. They remain distinct generic
//! types with no conversion (the accepted two-stage model); that both are
//! ETag-backed here is a backend-private coincidence callers cannot rely
//! on.
//!
//! # Conditional mutations
//! Service-atomic preconditions carry the whole guarantee: `If-None-Match:
//! *` for create-if-absent, `If-Match` for conditional replace/delete. No
//! observe-then-unconditionally-mutate sequence exists anywhere in this
//! adapter; a stale token can never overwrite or delete the current
//! generation. The `current` field of precondition outcomes is filled by a
//! best-effort FOLLOW-UP head (informational diagnostics only — it is not
//! part of the atomic decision and is documented as such).
//!
//! # Durability
//! Successful S3 publication (acknowledged PUT) already satisfies the
//! backend's accepted persistence model, so [`Durability::Durable`] and
//! [`Durability::Visible`] map to the SAME operation — Visible permits a
//! weaker guarantee, it does not require one. Both report failures
//! truthfully. Unconditional `delete` keeps the accepted classification:
//! absence (404/NoSuchKey) is idempotent success; AccessDenied is
//! PermissionDenied; every other failure surfaces.

use std::num::NonZeroUsize;

use async_trait::async_trait;
use bytes::Bytes;

use storage_core::ObjectKey;
use storage_core::object_store::{
    ConditionalDeleteOutcome, CreateOutcome, Durability, ListPage, ListedObject, ListingVersion,
    ObjectMeta, ObjectRead, ObjectStore, ObjectVersion, PageToken, ReplaceOutcome, StoreError,
    VersionedRead, adapter,
};

use crate::client::{
    GetResult, ObjectStat, PutPrecondition, RawConditionalDelete, S3ApiError, S3Client,
    parse_too_large_sentinel,
};

/// Defensive ceiling on internal listing round-trips per `list_page` call
/// (exhaustion is a truthful error, never truncation).
const MAX_LIST_ROUND_TRIPS: usize = 10_000;

/// Server-side page size requested per internal listing round-trip.
const LIST_FETCH_SIZE: usize = 1000;

/// S3 implementation of the backend-neutral [`ObjectStore`].
pub struct S3ObjectStore {
    client: std::sync::Arc<dyn S3Client>,
    /// Physical key prefix (no trailing slash) — validated as an
    /// `ObjectKey` so its own grammar can never smuggle traversal or
    /// control bytes. `None` roots the store at the bucket root.
    prefix: Option<String>,
    /// Internal per-call listing round-trip budget (see
    /// [`MAX_LIST_ROUND_TRIPS`]). Backend-private; overridable only through
    /// the doc-hidden test seam.
    list_round_trip_budget: usize,
}

impl S3ObjectStore {
    pub fn new(
        client: std::sync::Arc<dyn S3Client>,
        prefix: Option<&str>,
    ) -> Result<Self, StoreError> {
        let prefix = match prefix {
            None | Some("") => None,
            Some(p) => Some(
                ObjectKey::parse(p)
                    .map_err(|e| {
                        StoreError::invalid_input(format!("invalid physical prefix: {e}"))
                    })?
                    .as_str()
                    .to_string(),
            ),
        };
        Ok(Self {
            client,
            prefix,
            list_round_trip_budget: MAX_LIST_ROUND_TRIPS,
        })
    }

    /// Test-support seam: shrink the internal listing round-trip budget so
    /// bounded-exhaustion behavior is deterministically testable without
    /// thousands of round trips. Backend-private, not a generic contract
    /// surface, never registry-visible configuration; the production value
    /// is [`MAX_LIST_ROUND_TRIPS`].
    #[doc(hidden)]
    pub fn with_internal_list_budget(mut self, budget: usize) -> Self {
        self.list_round_trip_budget = budget.max(1);
        self
    }

    fn physical(&self, key: &ObjectKey) -> String {
        match &self.prefix {
            Some(p) => format!("{p}/{}", key.as_str()),
            None => key.as_str().to_string(),
        }
    }

    /// Directory-style physical prefix for listing (`…/` or empty).
    fn physical_dir(&self, prefix: Option<&ObjectKey>) -> String {
        match (&self.prefix, prefix) {
            (Some(p), Some(k)) => format!("{p}/{}/", k.as_str()),
            (Some(p), None) => format!("{p}/"),
            (None, Some(k)) => format!("{}/", k.as_str()),
            (None, None) => String::new(),
        }
    }

    /// Best-effort informational observation of the current generation for
    /// precondition-outcome diagnostics (never part of the atomic decision).
    async fn current_version_hint(&self, physical: &str) -> Option<ObjectVersion> {
        match self.client.head_object(physical).await {
            Ok(Some(stat)) => Some(version_from_etag(&stat.etag)),
            _ => None,
        }
    }
}

fn normalize_etag(raw: &str) -> String {
    raw.trim_matches('"').to_string()
}

fn version_from_etag(raw: &str) -> ObjectVersion {
    adapter::object_version(format!("s3e:{}", normalize_etag(raw)))
}

fn listing_version_from_etag(raw: &str) -> ListingVersion {
    adapter::listing_version(format!("s3l:{}", normalize_etag(raw)))
}

/// Recover the raw ETag from an [`ObjectVersion`] issued by THIS adapter.
/// Foreign tokens yield `InvalidInput` (they cannot silently mutate).
fn etag_from_version(version: &ObjectVersion) -> Result<String, StoreError> {
    adapter::object_version_token(version)
        .strip_prefix("s3e:")
        .map(str::to_owned)
        .ok_or_else(|| StoreError::invalid_input("object version was not issued by this S3 store"))
}

fn meta_from_stat(stat: &ObjectStat) -> ObjectMeta {
    ObjectMeta {
        size: stat.size,
        modified: stat.modified,
    }
}

/// One centralized classification of raw S3 failures into the generic
/// taxonomy for non-conditional operations (conditional signals are
/// interpreted per-operation BEFORE reaching this).
fn classify(err: S3ApiError) -> StoreError {
    if let Some(limit) = parse_too_large_sentinel(err.code.as_deref()) {
        return StoreError::TooLarge { limit };
    }
    if err.is_permission() {
        return StoreError::PermissionDenied {
            message: err.message.clone(),
            source: Some(Box::new(err)),
        };
    }
    StoreError::Backend {
        message: err.message.clone(),
        source: Some(Box::new(err)),
    }
}

#[async_trait]
impl ObjectStore for S3ObjectStore {
    async fn head(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>, StoreError> {
        let physical = self.physical(key);
        match self.client.head_object(&physical).await {
            Ok(Some(stat)) => Ok(Some(meta_from_stat(&stat))),
            Ok(None) => Ok(None),
            Err(e) => Err(classify(e)),
        }
    }

    async fn read(&self, key: &ObjectKey, max_len: u64) -> Result<Option<ObjectRead>, StoreError> {
        let physical = self.physical(key);
        match self.client.get_object(&physical, max_len).await {
            Ok(Some(GetResult { stat, bytes })) => Ok(Some(ObjectRead {
                meta: meta_from_stat(&stat),
                bytes,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(classify(e)),
        }
    }

    async fn read_with_version(
        &self,
        key: &ObjectKey,
        max_len: u64,
    ) -> Result<Option<VersionedRead>, StoreError> {
        let physical = self.physical(key);
        match self.client.get_object(&physical, max_len).await {
            Ok(Some(GetResult { stat, bytes })) => Ok(Some(VersionedRead {
                meta: meta_from_stat(&stat),
                version: version_from_etag(&stat.etag),
                bytes,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(classify(e)),
        }
    }

    async fn write(
        &self,
        key: &ObjectKey,
        bytes: Bytes,
        _durability: Durability,
    ) -> Result<ObjectVersion, StoreError> {
        // Both durability strengths: one acknowledged PUT (see module docs).
        let physical = self.physical(key);
        match self
            .client
            .put_object(&physical, bytes, PutPrecondition::None)
            .await
        {
            Ok(etag) => Ok(version_from_etag(&etag)),
            Err(e) => Err(classify(e)),
        }
    }

    async fn write_if_absent(
        &self,
        key: &ObjectKey,
        bytes: Bytes,
        _durability: Durability,
    ) -> Result<CreateOutcome, StoreError> {
        let physical = self.physical(key);
        match self
            .client
            .put_object(&physical, bytes, PutPrecondition::IfNoneMatchAny)
            .await
        {
            Ok(etag) => Ok(CreateOutcome::Created(version_from_etag(&etag))),
            Err(e) if e.is_precondition() => Ok(CreateOutcome::AlreadyExists {
                current: self.current_version_hint(&physical).await,
            }),
            Err(e) => Err(classify(e)),
        }
    }

    async fn replace_if_version(
        &self,
        key: &ObjectKey,
        expected: &ObjectVersion,
        bytes: Bytes,
        _durability: Durability,
    ) -> Result<ReplaceOutcome, StoreError> {
        let physical = self.physical(key);
        let etag = etag_from_version(expected)?;
        match self
            .client
            .put_object(&physical, bytes, PutPrecondition::IfMatch(etag))
            .await
        {
            Ok(new_etag) => Ok(ReplaceOutcome::Replaced(version_from_etag(&new_etag))),
            Err(e) if e.is_absence() => Ok(ReplaceOutcome::Absent),
            Err(e) if e.is_precondition() => Ok(ReplaceOutcome::PreconditionFailed {
                current: self.current_version_hint(&physical).await,
            }),
            Err(e) => Err(classify(e)),
        }
    }

    async fn delete(&self, key: &ObjectKey) -> Result<(), StoreError> {
        // Accepted classification: absence == idempotent success (handled
        // inside the client seam); AccessDenied / backend failures surface.
        let physical = self.physical(key);
        self.client.delete_object(&physical).await.map_err(classify)
    }

    async fn delete_if_version(
        &self,
        key: &ObjectKey,
        expected: &ObjectVersion,
    ) -> Result<ConditionalDeleteOutcome, StoreError> {
        let physical = self.physical(key);
        let etag = etag_from_version(expected)?;
        match self.client.delete_object_if_match(&physical, &etag).await {
            Ok(RawConditionalDelete::Deleted) => Ok(ConditionalDeleteOutcome::Deleted),
            Ok(RawConditionalDelete::NotFound) => Ok(ConditionalDeleteOutcome::Absent),
            Ok(RawConditionalDelete::PreconditionFailed) => {
                Ok(ConditionalDeleteOutcome::PreconditionFailed {
                    current: self.current_version_hint(&physical).await,
                })
            }
            Err(e) => Err(classify(e)),
        }
    }

    async fn list_page(
        &self,
        prefix: Option<&ObjectKey>,
        after: Option<&PageToken>,
        limit: NonZeroUsize,
    ) -> Result<ListPage, StoreError> {
        let dir = self.physical_dir(prefix);
        // Strictly-after: the generic PageToken carries the last returned
        // LEAF; translate it to a physical start-after boundary. AWS
        // continuation tokens are never exposed and never needed — the
        // semantic contract is leaf-lexical strictly-after.
        let mut start_after: Option<String> =
            after.map(|t| format!("{dir}{}", adapter::page_token_value(t)));

        let mut rows: Vec<ListedObject> = Vec::new();
        let mut more = false;
        // Explicit termination model: `more` = a further valid logical row
        // was PROVEN; `exhausted` = the backend authoritatively reported the
        // physical namespace end (`truncated == false`). Falling out of the
        // bounded loop with NEITHER proven means the internal discovery
        // budget expired — which is not evidence of exhaustion and must
        // fail truthfully instead of claiming `next = None`.
        let mut exhausted = false;
        'outer: for _ in 0..self.list_round_trip_budget {
            let page = self
                .client
                .list_direct_children(&dir, start_after.as_deref(), LIST_FETCH_SIZE)
                .await
                .map_err(classify)?;
            let mut progressed = false;
            for (physical_key, stat) in &page.objects {
                let Some(leaf) = physical_key.strip_prefix(&dir) else {
                    return Err(StoreError::corrupt(format!(
                        "listing returned key outside its prefix: {physical_key}"
                    )));
                };
                start_after = Some(physical_key.clone());
                progressed = true;
                // Structural filter by the backend-neutral grammar: only
                // names that are valid single generic key components are
                // objects of this store (directory-marker keys, nested
                // shapes and foreign names fall out here — never silently
                // AS failures, they are simply not generic objects).
                if leaf.is_empty() || leaf.contains('/') || ObjectKey::parse(leaf).is_err() {
                    continue;
                }
                if rows.len() == limit.get() {
                    more = true;
                    break 'outer;
                }
                let key = match prefix {
                    Some(p) => {
                        ObjectKey::parse(&format!("{}/{leaf}", p.as_str())).map_err(|e| {
                            StoreError::corrupt(format!("listing composed invalid key: {e}"))
                        })?
                    }
                    None => ObjectKey::parse(leaf).map_err(|e| {
                        StoreError::corrupt(format!("listing composed invalid key: {e}"))
                    })?,
                };
                rows.push(ListedObject {
                    key,
                    leaf: leaf.to_string(),
                    size: stat.size,
                    modified: stat.modified,
                    version: listing_version_from_etag(&stat.etag),
                });
            }
            if !page.truncated {
                exhausted = true;
                break;
            }
            if !progressed {
                return Err(StoreError::corrupt(
                    "listing made no forward progress on a truncated page",
                ));
            }
        }
        if !more && !exhausted {
            // Deterministic bounded-discovery exhaustion. Classified as a
            // backend resource failure (the taxonomy's truthful class for
            // adapter enumeration limits, matching the filesystem adapter's
            // enumeration-limit mapping) — never absence, corruption, or a
            // silent `next = None`.
            return Err(StoreError::backend(format!(
                "listing discovery budget of {} round trips exhausted before the                  namespace end could be proven (bounded enumeration, not an                  authoritative end-of-list)",
                self.list_round_trip_budget
            )));
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
