//! Filesystem [`ObjectStore`] adapter (STORAGE-LAYER-MIGRATION Phase 1,
//! namespace-corrected).
//!
//! Implements the backend-neutral `storage-core` object-store contract over
//! the EXISTING contained filesystem primitives of this crate. The adapter
//! knows generic keys, bytes, versions, listings, durability and store
//! errors — and nothing about registry concepts.
//!
//! # Authority model
//! A [`FsObjectStore`] instance IS a retained contained authority over one
//! configured root: the root directory descriptor is pinned at construction
//! (openat2 `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`
//! resolution beneath it for every operation). Ambient replacement of the
//! root pathname does not redirect an existing instance; a new instance
//! constructed afterwards resolves the replacement. There is no ambient-path
//! code path in this module.
//!
//! # Namespace invariant (structural, not conventional)
//! EVERY valid [`ObjectKey`] is representable: the mapping from generic keys
//! to filesystem locations is the identity mapping onto the root, injective,
//! and DISJOINT from all adapter bookkeeping. Bookkeeping (staging temps and
//! conditional-operation lock files) lives beneath one internal directory
//! whose name contains an ASCII control character
//! ([`INTERNAL_DIR`], `"\u{1}fsos.internal"`): the `storage-core` ObjectKey
//! grammar rejects control characters for backend-neutral reasons, so NO
//! generic key can ever name, traverse into, or collide with the internal
//! tree — no valid generic key is reserved, hidden, or redefined.
//! Dot-prefixed keys (`.hidden`, `a/.tmp.x`, `.fsos.lock.y`, …) are ordinary
//! generic objects.
//!
//! Listings include exactly the entries that are regular files whose names
//! are valid generic key components (generic-grammar validity — a
//! backend-neutral filter, not a filename convention); the internal
//! directory is additionally excluded as a non-regular entry.
//!
//! Transitional note: the lower-level `write_leaf_atomic` primitive stages
//! `.tmp.*` siblings when OTHER writers use it directly on a tree this
//! adapter also lists; the adapter's own writes never stage inside object
//! directories (they stage under the internal tree and publish with one
//! contained cross-directory rename), and the primitive's temp protocol is
//! collision-safe against pre-existing objects (O_EXCL creation retried
//! with fresh entropy on collision; cleanup unlinks only the exact name it
//! itself created).
//!
//! # Version tokens (backend-private semantics)
//! `ObjectVersion` is derived on an OPENED leaf descriptor as
//! `fs1:{len}:{mtime_nanos}:{sha256(payload)}` — the token shape already
//! accepted for filesystem conditional revalidation. `ListingVersion` is the
//! weaker enumeration-grade `fsl:{mtime_nanos}:{len}`. Both are opaque above
//! this adapter.
//!
//! # Conditional mutations
//! `write_if_absent`, `replace_if_version` and `delete_if_version` acquire a
//! per-key advisory lock — a lock file under the internal tree named by the
//! SHA-256 of the full key, so lock identity is deterministic per key and
//! can never collide with another key's lock or with any object — and
//! perform their whole observe → validate → act sequence inside ONE
//! `run_locked` body against the object-parent authority captured from the
//! pinned root BEFORE locking. Validation and action never act through
//! independently re-resolved namespaces, and adapter conditional operations
//! on the same key serialize among themselves (exactly one lock per
//! operation; no lock-ordering concerns). This is NOT an atomic
//! compare-and-swap against writers that bypass the lock (plain
//! `write`/`delete`, non-adapter mutators): those interleavings are
//! excluded by the caller's supported coordination envelope, exactly as in
//! the accepted campaign model.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use async_trait::async_trait;
use bytes::Bytes;
use sha2::Digest as _;

use storage_core::object_store::{
    ConditionalDeleteOutcome, CreateOutcome, Durability, ListPage, ListedObject, ListingVersion,
    ObjectMeta, ObjectRead, ObjectStore, ObjectVersion, PageToken, ReplaceOutcome, StoreError,
    VersionedRead, adapter,
};
use storage_core::{ObjectKey, ObjectKeyError};

use crate::dir::DirEnumerationLimits;
use crate::mutate::{BlockingDir, ContainedDir, FileName, FsMutateError};
use crate::reader::FsMetadataReader;

/// Default per-directory enumeration budget for `list_page` (entries,
/// cumulative name bytes). Retained for backwards compatibility.
#[deprecated(note = "enumeration limits are removed; list_page uses bounded streaming")]
pub const DEFAULT_LIST_ENUMERATION_LIMITS: (usize, usize) = (100_000, 10_000_000);

/// Internal bookkeeping directory name. Contains `U+0001`, which the
/// backend-neutral `ObjectKey` grammar rejects (control character), making
/// the internal tree structurally unaddressable and un-listable through the
/// generic contract without reserving any valid generic key.
pub const INTERNAL_DIR: &str = "\u{1}fsos.internal";
const INTERNAL_LOCKS: &str = "locks";
const INTERNAL_TMP: &str = "tmp";

/// Monotonic staging-name discriminator (uniqueness within a process;
/// combined with pid + nanos to decorrelate concurrent store instances).
static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);

/// Filesystem implementation of the backend-neutral [`ObjectStore`].
#[derive(Clone, Debug)]
pub struct FsObjectStore {
    root: ContainedDir,
    enum_limits: Option<DirEnumerationLimits>,
}

impl FsObjectStore {
    /// Pin the store's root authority. The path is resolved once, here; the
    /// instance never re-resolves it.
    pub fn open(root_path: impl AsRef<std::path::Path>) -> Result<Self, StoreError> {
        let reader = FsMetadataReader::open(root_path)
            .map_err(|e| StoreError::backend(format!("open object-store root: {e}")))?;
        let root = reader
            .open_contained_dir_sync("")
            .map_err(map_fs_mutate_err)?;
        Ok(Self {
            root,
            enum_limits: None,
        })
    }

    /// Configuration builder: sets optional single-directory enumeration limits.
    /// By default, enumeration is unbounded streaming (O(limit) space).
    pub fn with_enumeration_limits(mut self, limits: DirEnumerationLimits) -> Self {
        self.enum_limits = Some(limits);
        self
    }

    /// Split a key into validated intermediate components and the leaf.
    /// Every component of a parsed [`ObjectKey`] is a valid [`FileName`] by
    /// construction; this conversion cannot reject a valid generic key.
    fn split_key(key: &ObjectKey) -> Result<(Vec<FileName>, FileName), StoreError> {
        let mut parts: Vec<&str> = key.as_str().split('/').collect();
        let leaf = parts.pop().expect("ObjectKey is non-empty");
        let mut dirs = Vec::with_capacity(parts.len());
        for part in parts {
            dirs.push(FileName::new(part).map_err(map_fs_mutate_err)?);
        }
        Ok((dirs, FileName::new(leaf).map_err(map_fs_mutate_err)?))
    }

    /// Resolve the parent directory of `key` beneath the retained root.
    /// `create = false` never creates namespace directories (observations
    /// stay side-effect free); absence anywhere yields `Ok(None)`.
    async fn resolve_parent(
        &self,
        dirs: &[FileName],
        create: bool,
    ) -> Result<Option<ContainedDir>, StoreError> {
        let mut dir = self.root.clone();
        for name in dirs {
            dir = if create {
                dir.ensure_subdir(name).await.map_err(map_fs_mutate_err)?
            } else {
                match dir.open_subdir(name).await {
                    Ok(d) => d,
                    Err(FsMutateError::NotFound) => return Ok(None),
                    // A regular file occupying an intermediate component:
                    // nothing can exist beneath it.
                    Err(FsMutateError::NotADirectory) => return Ok(None),
                    Err(e) => return Err(map_fs_mutate_err(e)),
                }
            };
        }
        Ok(Some(dir))
    }

    /// Resolve (creating) one internal bookkeeping subtree beneath the
    /// pinned root: `INTERNAL_DIR/<which>`. Always derived from the
    /// retained root authority, so bookkeeping stays coherently pinned with
    /// the object namespace across ambient root replacement.
    async fn internal_dir(&self, which: &str) -> Result<ContainedDir, StoreError> {
        let internal = FileName::new(INTERNAL_DIR).map_err(map_fs_mutate_err)?;
        let sub = FileName::new(which).map_err(map_fs_mutate_err)?;
        let d = self
            .root
            .ensure_subdir(&internal)
            .await
            .map_err(map_fs_mutate_err)?;
        d.ensure_subdir(&sub).await.map_err(map_fs_mutate_err)
    }

    /// Deterministic per-key lock-file name in the internal locks tree:
    /// SHA-256 of the full key. Same key ⇒ same lock; distinct keys cannot
    /// collide (nor collide with any object, which lives outside the
    /// internal tree by construction).
    fn key_lock_name(key: &ObjectKey) -> Result<FileName, StoreError> {
        let h = hex_lower(&sha2::Sha256::digest(key.as_str().as_bytes()));
        FileName::new(h).map_err(map_fs_mutate_err)
    }

    /// Open `leaf` for reading and return the bounded payload plus the
    /// fstat-grade metadata OF THAT SAME opened descriptor. `Ok(None)` iff
    /// absent (or the leaf is not a regular object).
    async fn open_and_read(
        dir: &ContainedDir,
        leaf: &FileName,
        max_len: u64,
    ) -> Result<Option<(ObjectMeta, Vec<u8>)>, StoreError> {
        let handle = match dir.open_leaf_read(leaf).await {
            Ok(h) => h,
            Err(FsMutateError::NotFound) => return Ok(None),
            Err(FsMutateError::NotARegularFile { .. }) => return Ok(None),
            Err(e) => return Err(map_fs_mutate_err(e)),
        };
        tokio::task::spawn_blocking(
            move || -> Result<Option<(ObjectMeta, Vec<u8>)>, StoreError> {
                use std::io::Read as _;
                let mut file = handle.into_file();
                let meta = file
                    .metadata()
                    .map_err(|e| StoreError::backend(format!("fstat: {e}")))?;
                if meta.len() > max_len {
                    return Err(StoreError::TooLarge { limit: max_len });
                }
                let mut bytes = Vec::with_capacity(meta.len() as usize);
                file.read_to_end(&mut bytes)
                    .map_err(|e| StoreError::backend(format!("read: {e}")))?;
                Ok(Some((object_meta_from(&meta), bytes)))
            },
        )
        .await
        .map_err(|e| StoreError::backend(format!("blocking read join: {e}")))?
    }

    /// Observe leaf metadata via `fstat` on an opened descriptor (no payload
    /// read). `Ok(None)` iff absent / not a regular object.
    async fn stat_leaf(
        dir: &ContainedDir,
        leaf: &FileName,
    ) -> Result<Option<ObjectMeta>, StoreError> {
        let handle = match dir.open_leaf_read(leaf).await {
            Ok(h) => h,
            Err(FsMutateError::NotFound) => return Ok(None),
            Err(FsMutateError::NotARegularFile { .. }) => return Ok(None),
            Err(e) => return Err(map_fs_mutate_err(e)),
        };
        tokio::task::spawn_blocking(move || -> Result<Option<ObjectMeta>, StoreError> {
            let file = handle.into_file();
            let meta = file
                .metadata()
                .map_err(|e| StoreError::backend(format!("fstat: {e}")))?;
            Ok(Some(object_meta_from(&meta)))
        })
        .await
        .map_err(|e| StoreError::backend(format!("blocking stat join: {e}")))?
    }

    /// Publish `bytes` at `leaf` WITHOUT staging inside the object
    /// directory: the payload is written atomically (and, for
    /// [`Durability::Durable`], fsynced) to a uniquely named staging leaf
    /// under the internal tmp tree, then published into the object parent
    /// with one contained cross-directory rename; the Durable strength then
    /// fsyncs the destination directory — preserving the audited
    /// payload-before-publication and published-entry barriers. Object
    /// directories therefore never contain adapter staging names.
    async fn publish_and_version(
        &self,
        dir: &ContainedDir,
        leaf: &FileName,
        bytes: &Bytes,
        durability: Durability,
    ) -> Result<ObjectVersion, StoreError> {
        let tmp_dir = self.internal_dir(INTERNAL_TMP).await?;
        let staging = staging_name()?;
        let durable = matches!(durability, Durability::Durable);
        tmp_dir
            .write_leaf_atomic(&staging, bytes.to_vec(), durable)
            .await
            .map_err(map_fs_mutate_err)?;
        if let Err(e) = tmp_dir.rename_leaf(&staging, dir, leaf).await {
            // Best-effort cleanup of the private staging leaf; the failure
            // itself is reported truthfully.
            let _ = tmp_dir.unlink(&staging, true).await;
            return Err(map_fs_mutate_err(e));
        }
        if durable {
            dir.sync().await.map_err(map_fs_mutate_err)?;
        }
        match Self::open_and_read(dir, leaf, u64::MAX).await? {
            Some((meta, payload)) => Ok(object_version_from(&meta, &payload)),
            None => Err(StoreError::backend(
                "published object vanished before version observation",
            )),
        }
    }
}

/// Unique staging leaf name inside the internal tmp tree. Uniqueness within
/// a process is guaranteed by the sequence; pid + nanos decorrelate
/// concurrent store instances. A collision's worst case is a failed publish
/// rename reported truthfully — never object damage.
fn staging_name() -> Result<FileName, StoreError> {
    let seq = STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    FileName::new(format!("stage.{}.{seq}.{nanos}", std::process::id())).map_err(map_fs_mutate_err)
}

fn object_meta_from(meta: &std::fs::Metadata) -> ObjectMeta {
    ObjectMeta {
        size: meta.len(),
        modified: meta.modified().ok(),
    }
}

fn mtime_nanos(modified: Option<SystemTime>) -> u128 {
    modified
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Read-grade token: the established filesystem conditional-revalidation
/// shape (length + mtime nanos + payload sha256), derived from one opened
/// generation.
fn object_version_from(meta: &ObjectMeta, payload: &[u8]) -> ObjectVersion {
    let hash = hex_lower(&sha2::Sha256::digest(payload));
    adapter::object_version(format!(
        "fs1:{}:{}:{hash}",
        meta.size,
        mtime_nanos(meta.modified)
    ))
}

/// Listing-grade token: enumeration-time metadata only.
fn listing_version_from(meta: &ObjectMeta) -> ListingVersion {
    adapter::listing_version(format!("fsl:{}:{}", mtime_nanos(meta.modified), meta.size))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// One mapping from filesystem-native errors to the generic taxonomy.
/// Absence is handled structurally by callers BEFORE this mapping; reaching
/// it with `NotFound` means an operation that required presence lost it
/// mid-sequence, which is a backend-level surprise, not silent absence.
fn map_fs_mutate_err(e: FsMutateError) -> StoreError {
    match e {
        FsMutateError::PermissionDenied => {
            StoreError::permission_denied("contained resolution denied")
        }
        // Containment refusal (symlink/mount escape attempt): fail closed as
        // a permission-class refusal, never absence.
        FsMutateError::ResolutionRejected { raw_os_error } => StoreError::PermissionDenied {
            message: format!("contained path resolution rejected (os error {raw_os_error:?})"),
            source: None,
        },
        FsMutateError::InvalidName { reason } => {
            StoreError::invalid_input(format!("invalid key component: {reason}"))
        }
        FsMutateError::LimitExceeded { limit } => StoreError::TooLarge { limit },
        FsMutateError::EnumerationLimitExceeded => {
            StoreError::backend("directory enumeration exceeded the adapter's limits")
        }
        FsMutateError::NotADirectory => {
            StoreError::corrupt("intermediate component is not a directory")
        }
        other => StoreError::Backend {
            message: format!("filesystem primitive failure: {other}"),
            source: Some(Box::new(other)),
        },
    }
}

fn map_key_err(e: ObjectKeyError) -> StoreError {
    StoreError::invalid_input(format!("invalid object key: {e}"))
}

/// Synchronous observation of the current generation inside a `run_locked`
/// body: bytes + read-grade version from one opened descriptor on the
/// captured object-parent authority. `Ok(None)` iff absent.
fn observe_current_sync(
    dir: &BlockingDir,
    leaf: &FileName,
) -> Result<Option<(ObjectMeta, Vec<u8>, ObjectVersion)>, FsMutateError> {
    let handle = match dir.open_leaf_read(leaf) {
        Ok(h) => h,
        Err(FsMutateError::NotFound) => return Ok(None),
        Err(FsMutateError::NotARegularFile { .. }) => return Ok(None),
        Err(e) => return Err(e),
    };
    use std::io::Read as _;
    let mut file = handle.into_file();
    let meta = file.metadata().map_err(FsMutateError::Io)?;
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.read_to_end(&mut bytes).map_err(FsMutateError::Io)?;
    let om = object_meta_from(&meta);
    let version = object_version_from(&om, &bytes);
    Ok(Some((om, bytes, version)))
}

/// Synchronous staged publication used inside `run_locked` bodies: stage in
/// the captured internal tmp authority, publish with one contained
/// cross-directory rename onto the captured object-parent authority, and
/// (Durable) fsync the destination directory.
fn publish_sync(
    parent: &BlockingDir,
    tmp: &BlockingDir,
    leaf: &FileName,
    staging: &FileName,
    payload: &[u8],
    durable: bool,
) -> Result<(), FsMutateError> {
    tmp.write_leaf_atomic(staging, payload, durable)?;
    if let Err(e) = tmp.rename_leaf(staging, parent, leaf) {
        let _ = tmp.unlink(staging, true);
        return Err(e);
    }
    if durable {
        parent.sync()?;
    }
    Ok(())
}

#[async_trait]
impl ObjectStore for FsObjectStore {
    async fn head(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>, StoreError> {
        let (dirs, leaf) = Self::split_key(key)?;
        let Some(dir) = self.resolve_parent(&dirs, false).await? else {
            return Ok(None);
        };
        Self::stat_leaf(&dir, &leaf).await
    }

    async fn read(&self, key: &ObjectKey, max_len: u64) -> Result<Option<ObjectRead>, StoreError> {
        let (dirs, leaf) = Self::split_key(key)?;
        let Some(dir) = self.resolve_parent(&dirs, false).await? else {
            return Ok(None);
        };
        Ok(Self::open_and_read(&dir, &leaf, max_len)
            .await?
            .map(|(meta, bytes)| ObjectRead {
                meta,
                bytes: Bytes::from(bytes),
            }))
    }

    async fn read_with_version(
        &self,
        key: &ObjectKey,
        max_len: u64,
    ) -> Result<Option<VersionedRead>, StoreError> {
        let (dirs, leaf) = Self::split_key(key)?;
        let Some(dir) = self.resolve_parent(&dirs, false).await? else {
            return Ok(None);
        };
        Ok(Self::open_and_read(&dir, &leaf, max_len)
            .await?
            .map(|(meta, bytes)| {
                let version = object_version_from(&meta, &bytes);
                VersionedRead {
                    meta,
                    version,
                    bytes: Bytes::from(bytes),
                }
            }))
    }

    async fn write(
        &self,
        key: &ObjectKey,
        bytes: Bytes,
        durability: Durability,
    ) -> Result<ObjectVersion, StoreError> {
        let (dirs, leaf) = Self::split_key(key)?;
        let dir = self
            .resolve_parent(&dirs, true)
            .await?
            .expect("create-mode parent resolution always yields an authority");
        self.publish_and_version(&dir, &leaf, &bytes, durability)
            .await
    }

    async fn write_if_absent(
        &self,
        key: &ObjectKey,
        bytes: Bytes,
        durability: Durability,
    ) -> Result<CreateOutcome, StoreError> {
        let (dirs, leaf) = Self::split_key(key)?;
        let dir = self
            .resolve_parent(&dirs, true)
            .await?
            .expect("create-mode parent resolution always yields an authority");
        let locks = self.internal_dir(INTERNAL_LOCKS).await?;
        let tmp = self.internal_dir(INTERNAL_TMP).await?;
        let guard = locks
            .lock(&Self::key_lock_name(key)?)
            .await
            .map_err(map_fs_mutate_err)?;
        let parent = dir.blocking();
        let tmp = tmp.blocking();
        let staging = staging_name()?;
        let payload = bytes.to_vec();
        let durable = matches!(durability, Durability::Durable);
        locks
            .run_locked(guard, move |_locks_dir, _g| {
                match observe_current_sync(&parent, &leaf)? {
                    Some((_, _, current)) => Ok(CreateOutcome::AlreadyExists {
                        current: Some(current),
                    }),
                    None => {
                        publish_sync(&parent, &tmp, &leaf, &staging, &payload, durable)?;
                        match observe_current_sync(&parent, &leaf)? {
                            Some((_, _, version)) => Ok(CreateOutcome::Created(version)),
                            None => Err(FsMutateError::Io(std::io::Error::other(
                                "published object vanished under the creation lock",
                            ))),
                        }
                    }
                }
            })
            .await
            .map_err(map_fs_mutate_err)
    }

    async fn replace_if_version(
        &self,
        key: &ObjectKey,
        expected: &ObjectVersion,
        bytes: Bytes,
        durability: Durability,
    ) -> Result<ReplaceOutcome, StoreError> {
        let (dirs, leaf) = Self::split_key(key)?;
        let Some(dir) = self.resolve_parent(&dirs, false).await? else {
            return Ok(ReplaceOutcome::Absent);
        };
        let locks = self.internal_dir(INTERNAL_LOCKS).await?;
        let tmp = self.internal_dir(INTERNAL_TMP).await?;
        let guard = locks
            .lock(&Self::key_lock_name(key)?)
            .await
            .map_err(map_fs_mutate_err)?;
        let parent = dir.blocking();
        let tmp = tmp.blocking();
        let staging = staging_name()?;
        let payload = bytes.to_vec();
        let durable = matches!(durability, Durability::Durable);
        let expected = expected.clone();
        locks
            .run_locked(guard, move |_locks_dir, _g| {
                let Some((_, _, current)) = observe_current_sync(&parent, &leaf)? else {
                    return Ok(ReplaceOutcome::Absent);
                };
                if current != expected {
                    return Ok(ReplaceOutcome::PreconditionFailed {
                        current: Some(current),
                    });
                }
                publish_sync(&parent, &tmp, &leaf, &staging, &payload, durable)?;
                match observe_current_sync(&parent, &leaf)? {
                    Some((_, _, version)) => Ok(ReplaceOutcome::Replaced(version)),
                    None => Err(FsMutateError::Io(std::io::Error::other(
                        "replaced object vanished under the replacement lock",
                    ))),
                }
            })
            .await
            .map_err(map_fs_mutate_err)
    }

    async fn delete(&self, key: &ObjectKey) -> Result<(), StoreError> {
        let (dirs, leaf) = Self::split_key(key)?;
        // Observation-free: absence of any parent component is already the
        // required end state.
        let Some(dir) = self.resolve_parent(&dirs, false).await? else {
            return Ok(());
        };
        dir.unlink(&leaf, true).await.map_err(map_fs_mutate_err)?;
        // Directory-entry persistence of the removal stays best-effort,
        // matching the accepted deletion-durability policy (the unlink itself
        // succeeded; success guarantees the immediate namespace mutation).
        let _ = dir.sync().await;
        Ok(())
    }

    async fn delete_if_version(
        &self,
        key: &ObjectKey,
        expected: &ObjectVersion,
    ) -> Result<ConditionalDeleteOutcome, StoreError> {
        let (dirs, leaf) = Self::split_key(key)?;
        let Some(dir) = self.resolve_parent(&dirs, false).await? else {
            return Ok(ConditionalDeleteOutcome::Absent);
        };
        let locks = self.internal_dir(INTERNAL_LOCKS).await?;
        let guard = locks
            .lock(&Self::key_lock_name(key)?)
            .await
            .map_err(map_fs_mutate_err)?;
        let parent = dir.blocking();
        let expected = expected.clone();
        locks
            .run_locked(guard, move |_locks_dir, _g| {
                let Some((_, _, current)) = observe_current_sync(&parent, &leaf)? else {
                    return Ok(ConditionalDeleteOutcome::Absent);
                };
                if current != expected {
                    return Ok(ConditionalDeleteOutcome::PreconditionFailed {
                        current: Some(current),
                    });
                }
                parent.unlink(&leaf, false)?;
                let _ = parent.sync();
                Ok(ConditionalDeleteOutcome::Deleted)
            })
            .await
            .map_err(map_fs_mutate_err)
    }

    async fn list_page(
        &self,
        prefix: Option<&ObjectKey>,
        after: Option<&PageToken>,
        limit: NonZeroUsize,
    ) -> Result<ListPage, StoreError> {
        let dir = match prefix {
            None => Some(self.root.clone()),
            Some(p) => {
                let mut dirs = Vec::new();
                for part in p.as_str().split('/') {
                    dirs.push(FileName::new(part).map_err(map_fs_mutate_err)?);
                }
                self.resolve_parent(&dirs, false).await?
            }
        };
        let Some(dir) = dir else {
            return Ok(ListPage {
                objects: Vec::new(),
                next: None,
            });
        };

        let mut current_after = after.map(|t| adapter::page_token_value(t).to_string());
        let mut rows: Vec<ListedObject> = Vec::new();
        let mut more = false;

        // Loop to fill up to `limit` objects, stepping across vanished leaves.
        // Bounded to prevent infinite loops under adversarial concurrent churn.
        for _ in 0..1024 {
            let needed = NonZeroUsize::new(limit.get().saturating_sub(rows.len())).unwrap_or(limit);
            let (leaves, batch_more) = match dir
                .list_page_budgeted(current_after.as_deref(), needed, self.enum_limits)
                .await
            {
                Ok(res) => res,
                Err(FsMutateError::NotFound) => {
                    return Ok(ListPage {
                        objects: Vec::new(),
                        next: None,
                    });
                }
                Err(e) => return Err(map_fs_mutate_err(e)),
            };

            if leaves.is_empty() {
                more = false;
                break;
            }

            let last_leaf_in_batch = leaves.last().cloned();

            for leaf_name in leaves {
                let leaf = FileName::new(&leaf_name).map_err(map_fs_mutate_err)?;
                // A row observed by enumeration may vanish before the per-row
                // stat: benign absence, the row is skipped.
                let Some(meta) = Self::stat_leaf(&dir, &leaf).await? else {
                    continue;
                };
                let key = match prefix {
                    Some(p) => ObjectKey::parse(&format!("{}/{leaf_name}", p.as_str()))
                        .map_err(map_key_err)?,
                    None => ObjectKey::parse(&leaf_name).map_err(map_key_err)?,
                };
                rows.push(ListedObject {
                    key,
                    leaf: leaf_name,
                    size: meta.size,
                    modified: meta.modified,
                    version: listing_version_from(&meta),
                });
                if rows.len() == limit.get() {
                    break;
                }
            }

            if rows.len() == limit.get() || !batch_more {
                more = batch_more && rows.len() == limit.get();
                break;
            }

            current_after = last_leaf_in_batch;
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
