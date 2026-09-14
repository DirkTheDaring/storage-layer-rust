//! # Descriptor-relative contained mutation (`storage_fs::mutate`)
//!
//! Additive, Linux-gated primitives that extend the read-only [`FsMetadataReader`]
//! with **descriptor-relative mutation** anchored on directory descriptors that are
//! *pinned once* and reused for the process lifetime. Every operation resolves its
//! target beneath a captured directory descriptor with Linux `openat2` containment
//! flags (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`), and every
//! `*at` syscall uses that descriptor as its `dirfd` — so no operation resolves a
//! fresh ambient pathname and no operation can be redirected by a later pathname
//! replacement of a pinned ancestor.
//!
//! ## Ownership boundary
//! - **`storage-fs`** (here): generic filesystem *mechanism* — contained directory
//!   acquisition/creation, bounded reads and enumeration, inspection, stable
//!   advisory locking, an *owned* blocking-operation boundary, atomic leaf
//!   replacement, truncation, checked-offset append, and contained rename.
//! - **`registry-rust`**: retains all policy and on-disk record interpretation
//!   (record formats, CAS sharding, membership semantics, recovery contract).
//!
//! ## Authority model (one pinned directory per subtree)
//! [`ContainedDir`] owns an `Arc<OwnedFd>` opened `O_PATH | O_DIRECTORY`. It is
//! usable as the `dirfd` argument of `openat2`/`mkdirat`/`unlinkat`/`renameat`/
//! `fstatat` and is cloned into each blocking task, so the directory outlives
//! in-flight work even if the handle is dropped. Sub-authorities
//! ([`ContainedDir::open_subdir`]/[`ContainedDir::ensure_subdir`]) are opened beneath
//! it with the same containment flags. Because a pinned descriptor follows the inode
//! it was opened on, replacing the *pathname* of a pinned ancestor cannot redirect a
//! subsequent operation — the process keeps operating on the pinned (possibly
//! detached) tree until it is restarted. Callers that need replacement to be honored
//! must re-derive the authority (i.e. restart), which is the deliberate Option A
//! tradeoff documented by the registry.
//!
//! ## Synchronous *and* asynchronous surfaces
//! The real work lives in **synchronous** methods on [`BlockingDir`] (a cheap clone of
//! the same pinned descriptor). [`ContainedDir`]'s async methods are thin wrappers
//! that offload the synchronous work to `tokio::task::spawn_blocking`. The same
//! synchronous surface is handed to the body of [`ContainedDir::run_locked`], so a
//! guarded multi-step operation performs *all* of its steps synchronously on one
//! blocking thread without nested runtime blocking or lock reacquisition.
//!
//! ## Stable advisory locking (retention)
//! [`ContainedDir::lock`]/[`ContainedDir::try_lock`] acquire an advisory exclusive
//! `flock` on a lock-file leaf created beneath the pinned directory if absent and
//! **never unlinked by any operation in this module**. There is deliberately no
//! lock-file removal primitive: acquiring the lock and observing artifact-absence does
//! not exclude a pre-existing unacquired waiter holding a descriptor on the same
//! inode, so online reclamation can split lock identity. Reclamation is therefore only
//! safe under global quiescence and is out of scope here. Retained lock files
//! accumulate one zero-length inode per lock name ever used; this is **unbounded** in
//! the historical count and is not reclaimed online.
//!
//! ## Owned operation boundary and cancellation
//! [`ContainedDir::run_locked`] takes a [`ContainedLockGuard`] **by value** and moves
//! it — together with a cloned directory `Arc` surfaced as a [`BlockingDir`] — into a
//! `spawn_blocking` closure. The guard is dropped *inside* that closure, after the
//! body completes, and its `Drop` issues the explicit `flock(LOCK_UN)`. Dropping or
//! aborting the awaiting future detaches the blocking task but does not abort it: the
//! body runs to completion and only then releases the lock. Releasing on caller
//! cancellation is therefore impossible by construction. A guard carries the
//! authority identity of the directory it was acquired from; `run_locked` rejects a
//! guard that belongs to a different authority so a lock token cannot authorize work
//! against another directory.
//!
//! ## Atomicity vs. durability
//! [`ContainedDir::write_leaf_atomic`] writes an `O_EXCL` temporary sibling beneath the
//! pinned directory and `renameat`s it over the destination, giving atomic
//! **visibility** (a concurrent reader observes either the whole old or the whole new
//! leaf, never a torn one) and unlinking the temporary on any pre-rename failure. With
//! `durable = false` this is **not** crash durability: after power loss the rename or
//! the bytes may not have reached stable storage. `durable = true` additionally
//! `fsync`s the temporary and the parent directory. Secondary cleanup failures are
//! reported honestly and never mask the primary error; residue is bounded to a
//! `.tmp.*` sibling only when even the cleanup unlink fails.
//!
//! ## Platform
//! Descriptor-relative containment requires Linux `openat2`. On non-Linux platforms
//! every entry point returns [`FsMutateError::PlatformUnsupported`]; non-Linux
//! compilation and execution remain unverified.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::dir::{DirEntry, DirEnumerationLimits};
use crate::reader::FsMetadataReader;

#[cfg(target_os = "linux")]
use std::ffi::{CStr, CString};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::sync::Arc;

/// Process-global source of authority identifiers. Each opened [`ContainedDir`] gets a
/// fresh id so a [`ContainedLockGuard`] can be tied to the authority it was acquired
/// from and rejected if presented to a different one.
static AUTHORITY_ID_SEQ: AtomicU64 = AtomicU64::new(1);

/// Process-global monotonic counter contributing to temporary-file name entropy. It is
/// a *contributor* to uniqueness, never the guarantee — uniqueness is enforced by
/// `O_EXCL` creation with bounded retry on `EEXIST`.
static TEMP_NAME_SEQ: AtomicU64 = AtomicU64::new(1);

fn next_authority_id() -> u64 {
    AUTHORITY_ID_SEQ.fetch_add(1, Ordering::Relaxed)
}

/// A validated leaf or subdirectory name: non-empty, no `/`, no NUL, and neither `.`
/// nor `..`. Multi-component paths are intentionally not accepted — callers compose
/// nested authorities with [`ContainedDir::open_subdir`]/[`ContainedDir::ensure_subdir`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileName(String);

impl FileName {
    /// Validate and wrap a single path component.
    pub fn new(name: impl Into<String>) -> Result<Self, FsMutateError> {
        let name = name.into();
        if name.is_empty() {
            return Err(FsMutateError::InvalidName {
                reason: "empty component",
            });
        }
        if name == "." || name == ".." {
            return Err(FsMutateError::InvalidName {
                reason: "dot or dot-dot component",
            });
        }
        if name.contains('/') {
            return Err(FsMutateError::InvalidName {
                reason: "embedded path separator",
            });
        }
        if name.as_bytes().contains(&0) {
            return Err(FsMutateError::InvalidName {
                reason: "embedded NUL",
            });
        }
        Ok(Self(name))
    }

    /// The validated component as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Point-in-time identity of a leaf as observed by `fstat` after contained resolution.
/// `dev`/`ino` support identity revalidation between an inspection and a later guarded
/// action; a single `fstat` is not a snapshot under concurrent mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsFileIdentity {
    /// Size in bytes.
    pub size: u64,
    /// `st_dev` of the inspected inode.
    pub dev: u64,
    /// `st_ino` of the inspected inode.
    pub ino: u64,
    /// Raw `st_mode` (type + permission bits) of the inspected inode.
    pub mode: u32,
}

/// How a writable leaf descriptor is opened by [`ContainedDir::open_leaf_write`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafWriteMode {
    /// Create a new empty leaf; fail with [`FsMutateError::AlreadyExists`] if present
    /// (`O_CREAT | O_EXCL`).
    CreateNew,
    /// Create the leaf if absent, truncating an existing regular file to zero
    /// (`O_CREAT | O_TRUNC`).
    CreateOrTruncate,
    /// Open an existing leaf for appending; the leaf must already exist (`O_APPEND`).
    Append,
}

/// Typed errors for contained mutation. `#[non_exhaustive]` so additive variants do
/// not break callers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FsMutateError {
    /// Target directory entry does not exist (`ENOENT`).
    #[error("contained target not found")]
    NotFound,
    /// A component expected to be a directory was not (`ENOTDIR`).
    #[error("contained target is not a directory")]
    NotADirectory,
    /// Exclusive creation found an existing entry (`EEXIST`).
    #[error("contained target already exists")]
    AlreadyExists,
    /// Access was denied (`EACCES`/`EPERM`).
    #[error("permission denied resolving contained target")]
    PermissionDenied,
    /// The kernel rejected resolution under the containment policy (e.g. a symlink or
    /// mount crossing: `ELOOP`/`EXDEV`). Never reported as absence.
    #[error("contained path resolution rejected (raw_os_error={raw_os_error:?})")]
    ResolutionRejected {
        /// The raw OS error the kernel returned, if any.
        raw_os_error: Option<i32>,
    },
    /// Advisory lock is currently held by another owner (`EWOULDBLOCK`).
    #[error("contained lock is busy")]
    Busy,
    /// A supplied [`FileName`] failed validation.
    #[error("invalid contained name: {reason}")]
    InvalidName {
        /// Why the name was rejected.
        reason: &'static str,
    },
    /// A leaf that must be a regular file was some other object type; special files are
    /// rejected without a blocking open.
    #[error("contained leaf is not a regular file (mode={mode:#o})")]
    NotARegularFile {
        /// Raw `st_mode` of the offending object.
        mode: u32,
    },
    /// A bounded read observed more bytes than the caller permitted.
    #[error("contained read exceeded limit of {limit} bytes")]
    LimitExceeded {
        /// The byte budget that was exceeded.
        limit: u64,
    },
    /// Enumeration exceeded the caller-supplied [`DirEnumerationLimits`].
    #[error("contained enumeration exceeded caller limits")]
    EnumerationLimitExceeded,
    /// A checked-offset append observed a different current size than expected.
    #[error("contained append offset precondition failed (expected={expected}, actual={actual})")]
    OffsetMismatch {
        /// The offset the caller asserted.
        expected: u64,
        /// The size actually observed.
        actual: u64,
    },
    /// A lock guard from a different authority was presented to [`ContainedDir::run_locked`].
    #[error("lock guard does not belong to this authority")]
    LockAuthorityMismatch,
    /// A generic I/O failure preserving the underlying error.
    #[error("contained i/o failure")]
    Io(#[source] std::io::Error),
    /// `openat2` is unavailable on this kernel (`ENOSYS`).
    #[error("openat2 syscall unsupported by kernel")]
    SyscallUnsupported(#[source] std::io::Error),
    /// A secondary cleanup step failed after a primary failure; both are preserved.
    #[error("contained operation failed and cleanup also failed (primary={primary})")]
    CleanupFailed {
        /// The primary failure that triggered cleanup.
        primary: Box<FsMutateError>,
        /// The secondary failure encountered while cleaning up.
        #[source]
        cleanup: std::io::Error,
        /// Residual temporary name left behind, if the cleanup unlink failed.
        residual: Option<String>,
    },
    /// Descriptor-relative containment requires Linux `openat2`.
    #[error("platform unsupported: descriptor-relative containment requires Linux openat2")]
    PlatformUnsupported,
    /// No Tokio runtime was available to offload a blocking operation.
    #[error("tokio runtime required for contained blocking operation")]
    RuntimeMissing(#[source] tokio::runtime::TryCurrentError),
    /// The blocking task failed to join.
    #[error("contained blocking task failed to join")]
    TaskJoinFailed(#[source] tokio::task::JoinError),
}

// ============================================================================
// Deterministic fault injection (test-only, feature-gated)
// ============================================================================

/// Deterministic syscall fault-injection seam for the atomic-write / rename
/// primitives.
///
/// This entire module is compiled **only** under the `fault-injection` Cargo feature,
/// which is off by default and is intended to be enabled exclusively through a
/// downstream crate's *dev-dependency* so that production builds never contain it. A
/// `#[cfg(test)]` gate cannot serve this purpose, because when `storage-fs` is built
/// as a *dependency* of another crate its `cfg(test)` is inactive; a Cargo feature is
/// the only lever a dependent's tests can pull.
///
/// The armed-rule table is process-global (a `Mutex<Vec<Rule>>`) rather than
/// thread-local, because the primitives run on `spawn_blocking` worker threads distinct
/// from the arming test thread. Rules match on an optional substring of the target leaf
/// name so concurrently-running tests keyed on distinct uuids/digests do not collide.
#[cfg(feature = "fault-injection")]
pub mod fault {
    use super::FsMutateError;
    use std::sync::Mutex;

    /// The primitive site at which a fault may be injected.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum FaultPoint {
        /// The temp-file write inside `write_leaf_atomic` (the primary write).
        AtomicWrite,
        /// The publish `renameat` inside `write_leaf_atomic`.
        AtomicRename,
        /// The cleanup `unlinkat` inside `cleanup_after_failure` (the secondary step).
        AtomicCleanup,
        /// The cross-directory `renameat` inside `rename_leaf`.
        RenameLeaf,
        /// The `unlinkat` inside `BlockingDir::unlink` (staging/hash/meta removal).
        Unlink,
    }

    struct Rule {
        point: FaultPoint,
        needle: Option<String>,
        remaining: usize,
        errno: i32,
    }

    static RULES: Mutex<Vec<Rule>> = Mutex::new(Vec::new());

    /// Arm `count` injections at `point` for target names containing `needle`
    /// (or any name when `needle` is `None`), each failing with OS error `errno`.
    pub fn arm(point: FaultPoint, needle: Option<&str>, count: usize, errno: i32) {
        RULES.lock().unwrap().push(Rule {
            point,
            needle: needle.map(str::to_owned),
            remaining: count,
            errno,
        });
    }

    /// Remove every armed rule. Call in test teardown to keep the global table clean.
    pub fn reset() {
        RULES.lock().unwrap().clear();
    }

    /// Consume one matching armed injection for `point`/`name`, if any, returning the
    /// configured [`FsMutateError::Io`]. Matching rules are decremented so a `count` of
    /// N fires exactly N times.
    pub(crate) fn check(point: FaultPoint, name: &str) -> Result<(), FsMutateError> {
        let mut rules = RULES.lock().unwrap();
        for rule in rules.iter_mut() {
            if rule.point == point
                && rule.remaining > 0
                && rule
                    .needle
                    .as_deref()
                    .is_none_or(|needle| name.contains(needle))
            {
                rule.remaining -= 1;
                return Err(FsMutateError::Io(std::io::Error::from_raw_os_error(
                    rule.errno,
                )));
            }
        }
        Ok(())
    }
}

// ============================================================================
// Public handle types
// ============================================================================

/// An async-capable pinned directory authority. Cloning shares the same underlying
/// descriptor and authority identity.
#[derive(Clone, Debug)]
pub struct ContainedDir {
    #[cfg(target_os = "linux")]
    dir_fd: Arc<OwnedFd>,
    authority_id: u64,
    display_path: PathBuf,
}

/// A synchronous view of a pinned directory authority, handed to
/// [`ContainedDir::run_locked`] bodies and used internally to implement the async
/// methods. All of its methods execute on the calling thread with no offload.
#[derive(Clone, Debug)]
pub struct BlockingDir {
    #[cfg(target_os = "linux")]
    dir_fd: Arc<OwnedFd>,
    authority_id: u64,
    display_path: PathBuf,
}

/// An advisory exclusive lock held on a retained lock-file leaf. `Drop` issues an
/// explicit `flock(LOCK_UN)` and then closes the descriptor.
#[derive(Debug)]
pub struct ContainedLockGuard {
    #[cfg(target_os = "linux")]
    lock_fd: Option<OwnedFd>,
    /// Authority the lock was acquired from (see [`FsMutateError::LockAuthorityMismatch`]).
    authority_id: u64,
    /// Lock-file name, for diagnostics.
    name: String,
}

impl ContainedLockGuard {
    /// The authority identifier this guard was acquired from.
    pub fn authority_id(&self) -> u64 {
        self.authority_id
    }

    /// The lock-file leaf name this guard holds.
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(target_os = "linux")]
impl Drop for ContainedLockGuard {
    fn drop(&mut self) {
        if let Some(fd) = self.lock_fd.take() {
            // Explicit unlock before close. close() would also drop the flock, but the
            // explicit LOCK_UN documents the release point and matches the design.
            unsafe {
                libc::flock(fd.as_raw_fd(), libc::LOCK_UN);
            }
            drop(fd);
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for ContainedLockGuard {
    fn drop(&mut self) {}
}

// ============================================================================
// FsMetadataReader entry point
// ============================================================================

impl FsMetadataReader {
    /// Open a directory beneath the pinned root as a contained mutation/enumeration
    /// authority. `relative` is a slash-separated path relative to the root (each
    /// component validated); an empty string opens the root itself. The returned
    /// authority is pinned for its lifetime.
    pub async fn open_contained_dir(&self, relative: &str) -> Result<ContainedDir, FsMutateError> {
        #[cfg(target_os = "linux")]
        {
            let handle =
                tokio::runtime::Handle::try_current().map_err(FsMutateError::RuntimeMissing)?;
            let root_fd = self.root_fd_arc();
            let root_display = self.root_path().to_path_buf();
            let relative = relative.to_owned();
            let join = handle.spawn_blocking(move || {
                open_contained_dir_from_root_sync(&root_fd, &root_display, &relative)
            });
            join.await.map_err(FsMutateError::TaskJoinFailed)?
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = relative;
            Err(FsMutateError::PlatformUnsupported)
        }
    }

    /// Synchronous counterpart of [`open_contained_dir`](Self::open_contained_dir) that
    /// resolves entirely on the calling thread and does **not** require an entered Tokio
    /// runtime. Intended for capturing pinned authorities during synchronous
    /// construction. Each component of `relative` is validated and the whole path is
    /// resolved in a single contained `openat2` beneath the pinned root descriptor.
    pub fn open_contained_dir_sync(&self, relative: &str) -> Result<ContainedDir, FsMutateError> {
        #[cfg(target_os = "linux")]
        {
            open_contained_dir_from_root_sync(&self.root_fd_arc(), self.root_path(), relative)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = relative;
            Err(FsMutateError::PlatformUnsupported)
        }
    }
}

// ============================================================================
// ContainedDir async surface (thin spawn_blocking wrappers over BlockingDir)
// ============================================================================

impl ContainedDir {
    /// The authority identifier of this directory.
    pub fn authority_id(&self) -> u64 {
        self.authority_id
    }

    /// A diagnostic display path (best-effort; not re-resolved).
    pub fn display_path(&self) -> &std::path::Path {
        &self.display_path
    }

    /// A synchronous [`BlockingDir`] view of this authority sharing the same pinned
    /// descriptor and authority identity. Useful inside a [`ContainedDir::run_locked`]
    /// body to operate synchronously on *sibling* authorities (captured elsewhere and
    /// moved into the closure) without re-entering the async runtime.
    pub fn blocking(&self) -> BlockingDir {
        #[cfg(target_os = "linux")]
        {
            self.as_blocking()
        }
        #[cfg(not(target_os = "linux"))]
        {
            BlockingDir {
                authority_id: self.authority_id,
                display_path: self.display_path.clone(),
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn as_blocking(&self) -> BlockingDir {
        BlockingDir {
            dir_fd: Arc::clone(&self.dir_fd),
            authority_id: self.authority_id,
            display_path: self.display_path.clone(),
        }
    }

    #[cfg(target_os = "linux")]
    async fn offload<T, F>(&self, f: F) -> Result<T, FsMutateError>
    where
        F: FnOnce(BlockingDir) -> Result<T, FsMutateError> + Send + 'static,
        T: Send + 'static,
    {
        let handle =
            tokio::runtime::Handle::try_current().map_err(FsMutateError::RuntimeMissing)?;
        let blocking = self.as_blocking();
        let join = handle.spawn_blocking(move || f(blocking));
        join.await.map_err(FsMutateError::TaskJoinFailed)?
    }

    /// Open an existing subdirectory beneath this directory as a nested authority.
    pub async fn open_subdir(&self, name: &FileName) -> Result<ContainedDir, FsMutateError> {
        #[cfg(target_os = "linux")]
        {
            let name = name.clone();
            self.offload(move |b| b.open_subdir(&name).map(BlockingDir::into_contained))
                .await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = name;
            Err(FsMutateError::PlatformUnsupported)
        }
    }

    /// Create `name` as a subdirectory beneath this directory if absent (idempotent on
    /// `EEXIST`) and return it as a pinned nested authority.
    pub async fn ensure_subdir(&self, name: &FileName) -> Result<ContainedDir, FsMutateError> {
        #[cfg(target_os = "linux")]
        {
            let name = name.clone();
            self.offload(move |b| b.ensure_subdir(&name).map(BlockingDir::into_contained))
                .await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = name;
            Err(FsMutateError::PlatformUnsupported)
        }
    }

    /// Enumerate the immediate entries of this directory (fresh enumeration descriptor
    /// per call), bounded by `limits`.
    pub async fn list(&self, limits: DirEnumerationLimits) -> Result<Vec<DirEntry>, FsMutateError> {
        #[cfg(target_os = "linux")]
        {
            self.offload(move |b| b.list(limits)).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = limits;
            Err(FsMutateError::PlatformUnsupported)
        }
    }

    /// Inspect a leaf's identity. `Ok(None)` means the leaf is absent (`ENOENT`);
    /// other resolution failures are typed errors.
    pub async fn inspect(&self, name: &FileName) -> Result<Option<FsFileIdentity>, FsMutateError> {
        #[cfg(target_os = "linux")]
        {
            let name = name.clone();
            self.offload(move |b| b.inspect(&name)).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = name;
            Err(FsMutateError::PlatformUnsupported)
        }
    }

    /// Read a regular-file leaf beneath this directory, up to `limit` bytes. Exceeding
    /// the limit is [`FsMutateError::LimitExceeded`]; special files are rejected without
    /// a blocking open.
    pub async fn read_leaf(&self, name: &FileName, limit: u64) -> Result<Vec<u8>, FsMutateError> {
        #[cfg(target_os = "linux")]
        {
            let name = name.clone();
            self.offload(move |b| b.read_leaf(&name, limit)).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (name, limit);
            Err(FsMutateError::PlatformUnsupported)
        }
    }

    /// Open a regular-file leaf beneath this directory for reading and return the owned
    /// descriptor (for streaming/hash rebuild in the caller). Special files are rejected.
    pub async fn open_leaf_read(&self, name: &FileName) -> Result<OwnedFdHandle, FsMutateError> {
        #[cfg(target_os = "linux")]
        {
            let name = name.clone();
            self.offload(move |b| b.open_leaf_read(&name)).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = name;
            Err(FsMutateError::PlatformUnsupported)
        }
    }

    /// Open (or create) a regular-file leaf beneath this directory for writing and
    /// return the owned descriptor. Special files are rejected without a blocking open.
    pub async fn open_leaf_write(
        &self,
        name: &FileName,
        mode: LeafWriteMode,
    ) -> Result<OwnedFdHandle, FsMutateError> {
        #[cfg(target_os = "linux")]
        {
            let name = name.clone();
            self.offload(move |b| b.open_leaf_write(&name, mode)).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (name, mode);
            Err(FsMutateError::PlatformUnsupported)
        }
    }

    /// Atomically replace a leaf beneath this directory (temp `O_EXCL` + `renameat`).
    /// See the module docs for the visibility-vs-durability boundary.
    pub async fn write_leaf_atomic(
        &self,
        name: &FileName,
        bytes: Vec<u8>,
        durable: bool,
    ) -> Result<(), FsMutateError> {
        #[cfg(target_os = "linux")]
        {
            let name = name.clone();
            self.offload(move |b| b.write_leaf_atomic(&name, &bytes, durable))
                .await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (name, bytes, durable);
            Err(FsMutateError::PlatformUnsupported)
        }
    }

    /// Remove a directory entry beneath this directory. `missing_ok` maps `ENOENT` to
    /// `Ok(())` (idempotent).
    pub async fn unlink(&self, name: &FileName, missing_ok: bool) -> Result<(), FsMutateError> {
        #[cfg(target_os = "linux")]
        {
            let name = name.clone();
            self.offload(move |b| b.unlink(&name, missing_ok)).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (name, missing_ok);
            Err(FsMutateError::PlatformUnsupported)
        }
    }

    /// Truncate a regular-file leaf beneath this directory to `len`.
    pub async fn truncate(&self, name: &FileName, len: u64) -> Result<(), FsMutateError> {
        #[cfg(target_os = "linux")]
        {
            let name = name.clone();
            self.offload(move |b| b.truncate(&name, len)).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (name, len);
            Err(FsMutateError::PlatformUnsupported)
        }
    }

    /// Append `bytes` to a regular-file leaf beneath this directory, but only if its
    /// current size equals `expected_offset` (else [`FsMutateError::OffsetMismatch`]).
    pub async fn append_at(
        &self,
        name: &FileName,
        expected_offset: u64,
        bytes: Vec<u8>,
    ) -> Result<(), FsMutateError> {
        #[cfg(target_os = "linux")]
        {
            let name = name.clone();
            self.offload(move |b| b.append_at(&name, expected_offset, &bytes))
                .await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (name, expected_offset, bytes);
            Err(FsMutateError::PlatformUnsupported)
        }
    }

    /// Rename a leaf beneath this directory to a leaf beneath `dst` (both pinned).
    /// Publishes CAS blobs (`uploads/{uuid}.data` -> `blobs/{algo}/{prefix2}/{hex}`).
    pub async fn rename_leaf(
        &self,
        name: &FileName,
        dst: &ContainedDir,
        dst_name: &FileName,
    ) -> Result<(), FsMutateError> {
        #[cfg(target_os = "linux")]
        {
            let name = name.clone();
            let dst_name = dst_name.clone();
            let dst_blocking = dst.as_blocking();
            self.offload(move |b| b.rename_leaf(&name, &dst_blocking, &dst_name))
                .await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (name, dst, dst_name);
            Err(FsMutateError::PlatformUnsupported)
        }
    }

    /// `fsync` this directory (best-effort durability for prior renames/unlinks when
    /// the caller wants it).
    pub async fn sync(&self) -> Result<(), FsMutateError> {
        #[cfg(target_os = "linux")]
        {
            self.offload(move |b| b.sync()).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(FsMutateError::PlatformUnsupported)
        }
    }

    /// Acquire an advisory exclusive lock on `name` beneath this directory, blocking
    /// until it is available. The lock file is created if absent and retained.
    pub async fn lock(&self, name: &FileName) -> Result<ContainedLockGuard, FsMutateError> {
        #[cfg(target_os = "linux")]
        {
            let name = name.clone();
            self.offload(move |b| b.lock(&name)).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = name;
            Err(FsMutateError::PlatformUnsupported)
        }
    }

    /// Try to acquire an advisory exclusive lock on `name` without blocking. `Ok(None)`
    /// means the lock is currently held elsewhere.
    pub async fn try_lock(
        &self,
        name: &FileName,
    ) -> Result<Option<ContainedLockGuard>, FsMutateError> {
        #[cfg(target_os = "linux")]
        {
            let name = name.clone();
            self.offload(move |b| b.try_lock(&name)).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = name;
            Err(FsMutateError::PlatformUnsupported)
        }
    }

    /// Owned operation boundary: consume `guard` and run `body` on a blocking thread
    /// with a synchronous [`BlockingDir`]. The guard is moved into the closure and
    /// dropped there (after `body`), so the lock is released only on completion —
    /// never on caller cancellation. Rejects a guard from a different authority.
    pub async fn run_locked<T, F>(
        &self,
        guard: ContainedLockGuard,
        body: F,
    ) -> Result<T, FsMutateError>
    where
        F: FnOnce(BlockingDir, ContainedLockGuard) -> Result<T, FsMutateError> + Send + 'static,
        T: Send + 'static,
    {
        if guard.authority_id != self.authority_id {
            return Err(FsMutateError::LockAuthorityMismatch);
        }

        #[cfg(target_os = "linux")]
        {
            let handle =
                tokio::runtime::Handle::try_current().map_err(FsMutateError::RuntimeMissing)?;
            let blocking = self.as_blocking();
            let join = handle.spawn_blocking(move || {
                // `guard` is moved in and dropped at the end of this scope (after
                // `body`), issuing LOCK_UN on this blocking thread.
                body(blocking, guard)
            });
            join.await.map_err(FsMutateError::TaskJoinFailed)?
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (guard, body);
            Err(FsMutateError::PlatformUnsupported)
        }
    }
}

/// An owned regular-file descriptor returned by contained open primitives. It carries a
/// diagnostic name and can be converted into a `std::fs::File` for the caller's own
/// streaming/hashing/truncation logic; the descriptor was resolved beneath a pinned
/// directory, so subsequent operations on it are inherently contained.
#[derive(Debug)]
pub struct OwnedFdHandle {
    #[cfg(target_os = "linux")]
    fd: OwnedFd,
    name: String,
}

impl OwnedFdHandle {
    /// The leaf name this descriptor was opened from.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Convert into a `std::fs::File` for streaming/hashing/truncation in the caller.
    #[cfg(target_os = "linux")]
    pub fn into_file(self) -> std::fs::File {
        std::fs::File::from(self.fd)
    }
}

// ============================================================================
// Synchronous Linux core: BlockingDir methods + free helpers
// ============================================================================

#[cfg(target_os = "linux")]
const RESOLVE_FLAGS: u64 =
    libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;

/// Bounded retry budget for `O_EXCL` temporary-name collisions. `O_EXCL` is the
/// uniqueness *guarantee*; the retry only re-rolls the entropy on the (astronomically
/// rare) `EEXIST`.
#[cfg(target_os = "linux")]
const MAX_TEMP_RETRIES: usize = 32;

#[cfg(target_os = "linux")]
fn cstr(name: &str) -> Result<CString, FsMutateError> {
    CString::new(name).map_err(|_| FsMutateError::InvalidName {
        reason: "embedded NUL",
    })
}

/// Map a raw open/resolve error to a typed [`FsMutateError`]. Resolution rejections
/// (`ELOOP`/`EXDEV`) are never collapsed to absence.
#[cfg(target_os = "linux")]
fn classify_open_err(err: std::io::Error) -> FsMutateError {
    match err.raw_os_error() {
        Some(libc::ENOENT) => FsMutateError::NotFound,
        Some(libc::ENOTDIR) => FsMutateError::NotADirectory,
        Some(libc::EEXIST) => FsMutateError::AlreadyExists,
        Some(libc::EACCES) | Some(libc::EPERM) => FsMutateError::PermissionDenied,
        Some(libc::ENOSYS) => FsMutateError::SyscallUnsupported(err),
        Some(libc::ELOOP) | Some(libc::EXDEV) => FsMutateError::ResolutionRejected {
            raw_os_error: err.raw_os_error(),
        },
        _ => FsMutateError::Io(err),
    }
}

#[cfg(target_os = "linux")]
fn map_dir_err(e: crate::dir::FsDirError) -> FsMutateError {
    use crate::dir::FsDirError as D;
    match e {
        D::NotFound { .. } => FsMutateError::NotFound,
        D::NotADirectory { .. } => FsMutateError::NotADirectory,
        D::PermissionDenied { .. } => FsMutateError::PermissionDenied,
        D::ResolutionRejected { raw_os_error, .. } => FsMutateError::ResolutionRejected {
            raw_os_error: Some(raw_os_error),
        },
        D::SyscallUnsupported(src) => FsMutateError::SyscallUnsupported(src),
        D::LimitExceeded { .. } => FsMutateError::EnumerationLimitExceeded,
        D::EntryDisappeared { .. } => FsMutateError::NotFound,
        D::Io { source } => FsMutateError::Io(source),
        D::RuntimeMissing(e) => FsMutateError::RuntimeMissing(e),
        D::TaskJoinFailed(e) => FsMutateError::TaskJoinFailed(e),
        D::PlatformUnsupported => FsMutateError::PlatformUnsupported,
    }
}

/// `openat2` beneath `dir_fd` with this module's containment flags. Wraps the raw fd
/// immediately so it is closed on every early return.
#[cfg(target_os = "linux")]
fn openat2_beneath(
    dir_fd: RawFd,
    c_path: &CStr,
    flags: libc::c_int,
    mode: u64,
) -> Result<OwnedFd, FsMutateError> {
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = flags as u64;
    how.mode = mode;
    how.resolve = RESOLVE_FLAGS;
    let res = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir_fd,
            c_path.as_ptr(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if res < 0 {
        return Err(classify_open_err(std::io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(res as RawFd) })
}

#[cfg(target_os = "linux")]
fn fstat_fd(fd: RawFd) -> Result<libc::stat, FsMutateError> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::fstat(fd, &mut st) };
    if r != 0 {
        return Err(FsMutateError::Io(std::io::Error::last_os_error()));
    }
    Ok(st)
}

#[cfg(target_os = "linux")]
fn identity_from_stat(st: &libc::stat) -> FsFileIdentity {
    FsFileIdentity {
        size: st.st_size as u64,
        dev: st.st_dev,
        ino: st.st_ino,
        mode: st.st_mode,
    }
}

#[cfg(target_os = "linux")]
fn is_regular(mode: libc::mode_t) -> bool {
    (mode & libc::S_IFMT) == libc::S_IFREG
}

/// Open (optionally creating) a single-component subdirectory beneath `dir_fd` as a
/// pinned `O_PATH | O_DIRECTORY` authority. `mkdirat` is idempotent on `EEXIST`; the
/// subsequent `openat2` re-establishes containment (a symlink planted at `name` is
/// rejected by `RESOLVE_NO_SYMLINKS`).
#[cfg(target_os = "linux")]
fn open_subdir_fd(dir_fd: RawFd, name: &FileName, create: bool) -> Result<OwnedFd, FsMutateError> {
    let c = cstr(name.as_str())?;
    if create {
        let r = unsafe { libc::mkdirat(dir_fd, c.as_ptr(), 0o755) };
        if r != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EEXIST) {
                return Err(classify_open_err(err));
            }
        }
    }
    openat2_beneath(
        dir_fd,
        &c,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )
}

/// Compose a temporary sibling name. `O_EXCL` is the uniqueness guarantee; pid + a
/// process-global counter + nanosecond time only reduce collision probability across
/// concurrent processes and retries.
#[cfg(target_os = "linux")]
fn make_temp_name(base: &str) -> String {
    let pid = std::process::id();
    let seq = TEMP_NAME_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(".tmp.{base}.{pid}.{seq}.{nanos}")
}

#[cfg(target_os = "linux")]
fn write_all_fd(fd: RawFd, mut bytes: &[u8]) -> Result<(), std::io::Error> {
    while !bytes.is_empty() {
        let n = unsafe { libc::write(fd, bytes.as_ptr() as *const libc::c_void, bytes.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "write returned 0",
            ));
        }
        bytes = &bytes[n as usize..];
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn fsync_fd(fd: RawFd) -> Result<(), std::io::Error> {
    let r = unsafe { libc::fsync(fd) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// `fsync` the pinned directory itself. `O_PATH` descriptors cannot be `fsync`ed, so we
/// re-open `"."` beneath the pinned descriptor as a readable directory and sync that.
#[cfg(target_os = "linux")]
fn fsync_pinned_dir(dir_fd: RawFd) -> Result<(), FsMutateError> {
    let c_dot = cstr(".")?;
    let dirf = openat2_beneath(
        dir_fd,
        &c_dot,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )?;
    fsync_fd(dirf.as_raw_fd()).map_err(FsMutateError::Io)
}

/// Best-effort cleanup after a write/rename failure. Preserves the primary error; only
/// escalates to [`FsMutateError::CleanupFailed`] when the cleanup unlink itself fails
/// for a reason other than the temporary already being gone.
#[cfg(target_os = "linux")]
fn cleanup_after_failure(dir_fd: RawFd, temp_name: &str, primary: FsMutateError) -> FsMutateError {
    let c = match cstr(temp_name) {
        Ok(c) => c,
        Err(_) => return primary,
    };
    #[cfg(feature = "fault-injection")]
    if crate::mutate::fault::check(crate::mutate::fault::FaultPoint::AtomicCleanup, temp_name)
        .is_err()
    {
        // Simulate the cleanup `unlinkat` itself failing: preserve the primary error
        // and report the residual temp name, exactly as a real cleanup failure would.
        return FsMutateError::CleanupFailed {
            primary: Box::new(primary),
            cleanup: std::io::Error::from_raw_os_error(libc::EIO),
            residual: Some(temp_name.to_owned()),
        };
    }
    let r = unsafe { libc::unlinkat(dir_fd, c.as_ptr(), 0) };
    if r != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return primary;
        }
        return FsMutateError::CleanupFailed {
            primary: Box::new(primary),
            cleanup: err,
            residual: Some(temp_name.to_owned()),
        };
    }
    primary
}

/// Open a directory beneath the pinned root as a fresh contained authority. `relative`
/// is a slash-separated path; each component is validated and the whole path is resolved
/// in a single contained `openat2` (kernel walks each component under `RESOLVE_BENEATH`).
#[cfg(target_os = "linux")]
fn open_contained_dir_from_root_sync(
    root_fd: &OwnedFd,
    root_display: &std::path::Path,
    relative: &str,
) -> Result<ContainedDir, FsMutateError> {
    let mut display = root_display.to_path_buf();
    let trimmed = relative.trim_matches('/');
    let c_path = if trimmed.is_empty() {
        cstr(".")?
    } else {
        for comp in trimmed.split('/') {
            // Validates non-empty, no `.`/`..`, no NUL (rejects escapes explicitly in
            // addition to the kernel's RESOLVE_BENEATH enforcement).
            let name = FileName::new(comp)?;
            display.push(name.as_str());
        }
        cstr(trimmed)?
    };
    let owned = openat2_beneath(
        root_fd.as_raw_fd(),
        &c_path,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )?;
    Ok(ContainedDir {
        dir_fd: Arc::new(owned),
        authority_id: next_authority_id(),
        display_path: display,
    })
}

#[cfg(target_os = "linux")]
impl BlockingDir {
    /// The authority identifier of this directory.
    pub fn authority_id(&self) -> u64 {
        self.authority_id
    }

    /// A diagnostic display path (best-effort; not re-resolved).
    pub fn display_path(&self) -> &std::path::Path {
        &self.display_path
    }

    /// Convert this synchronous view into an async-capable [`ContainedDir`] sharing the
    /// same pinned descriptor and authority identity.
    pub fn into_contained(self) -> ContainedDir {
        ContainedDir {
            dir_fd: self.dir_fd,
            authority_id: self.authority_id,
            display_path: self.display_path,
        }
    }

    fn child(&self, fd: OwnedFd, name: &FileName) -> BlockingDir {
        let mut display = self.display_path.clone();
        display.push(name.as_str());
        BlockingDir {
            dir_fd: Arc::new(fd),
            authority_id: next_authority_id(),
            display_path: display,
        }
    }

    /// Open an existing subdirectory beneath this directory as a nested authority.
    pub fn open_subdir(&self, name: &FileName) -> Result<BlockingDir, FsMutateError> {
        let fd = open_subdir_fd(self.dir_fd.as_raw_fd(), name, false)?;
        Ok(self.child(fd, name))
    }

    /// Create `name` as a subdirectory if absent (idempotent on `EEXIST`) and return it
    /// as a pinned nested authority.
    pub fn ensure_subdir(&self, name: &FileName) -> Result<BlockingDir, FsMutateError> {
        let fd = open_subdir_fd(self.dir_fd.as_raw_fd(), name, true)?;
        Ok(self.child(fd, name))
    }

    /// Enumerate the immediate entries of this directory (fresh enumeration descriptor
    /// per call) reusing the read-path enumerator, bounded by `limits`.
    pub fn list(&self, limits: DirEnumerationLimits) -> Result<Vec<DirEntry>, FsMutateError> {
        crate::dir::enumerate_dir_sync(
            &self.dir_fd,
            None,
            limits,
            #[cfg(test)]
            None,
        )
        .map_err(map_dir_err)
    }

    /// Inspect a leaf's identity. `Ok(None)` == absent (`ENOENT`); a symlink at `name`
    /// is a resolution rejection, never absence.
    pub fn inspect(&self, name: &FileName) -> Result<Option<FsFileIdentity>, FsMutateError> {
        let c = cstr(name.as_str())?;
        match openat2_beneath(
            self.dir_fd.as_raw_fd(),
            &c,
            libc::O_PATH | libc::O_CLOEXEC,
            0,
        ) {
            Ok(fd) => {
                let st = fstat_fd(fd.as_raw_fd())?;
                Ok(Some(identity_from_stat(&st)))
            }
            Err(FsMutateError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Read a regular-file leaf up to `limit` bytes.
    pub fn read_leaf(&self, name: &FileName, limit: u64) -> Result<Vec<u8>, FsMutateError> {
        use std::io::Read;
        let handle = self.open_leaf_read(name)?;
        let file = handle.into_file();
        let mut buf = Vec::new();
        // Read one extra byte so exceeding the limit is detectable.
        let mut limited = file.take(limit.saturating_add(1));
        limited.read_to_end(&mut buf).map_err(FsMutateError::Io)?;
        if buf.len() as u64 > limit {
            return Err(FsMutateError::LimitExceeded { limit });
        }
        Ok(buf)
    }

    /// Open a regular-file leaf for reading via a two-phase (`O_PATH` type-guard, then
    /// procfs reopen with an `fstat` identity recheck) sequence that never blocks on a
    /// FIFO/device.
    pub fn open_leaf_read(&self, name: &FileName) -> Result<OwnedFdHandle, FsMutateError> {
        let c = cstr(name.as_str())?;
        let path_fd = openat2_beneath(
            self.dir_fd.as_raw_fd(),
            &c,
            libc::O_PATH | libc::O_CLOEXEC,
            0,
        )?;
        let st = fstat_fd(path_fd.as_raw_fd())?;
        if !is_regular(st.st_mode) {
            return Err(FsMutateError::NotARegularFile { mode: st.st_mode });
        }
        let proc = cstr(&format!("/proc/self/fd/{}", path_fd.as_raw_fd()))?;
        let rfd = unsafe {
            libc::open(
                proc.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if rfd < 0 {
            return Err(classify_open_err(std::io::Error::last_os_error()));
        }
        let read_fd = unsafe { OwnedFd::from_raw_fd(rfd) };
        let st2 = fstat_fd(read_fd.as_raw_fd())?;
        if st2.st_dev != st.st_dev || st2.st_ino != st.st_ino || !is_regular(st2.st_mode) {
            return Err(FsMutateError::ResolutionRejected { raw_os_error: None });
        }
        Ok(OwnedFdHandle {
            fd: read_fd,
            name: name.as_str().to_owned(),
        })
    }

    /// Open (or create) a regular-file leaf for writing. `O_NONBLOCK` prevents blocking
    /// on a special file; a post-open `fstat` rejects any non-regular object.
    pub fn open_leaf_write(
        &self,
        name: &FileName,
        mode: LeafWriteMode,
    ) -> Result<OwnedFdHandle, FsMutateError> {
        let c = cstr(name.as_str())?;
        let (flags, create_mode) = match mode {
            LeafWriteMode::CreateNew => (
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o644,
            ),
            LeafWriteMode::CreateOrTruncate => (
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o644,
            ),
            // No O_CREAT: openat2 requires how.mode == 0 unless O_CREAT/O_TMPFILE is set.
            LeafWriteMode::Append => (
                libc::O_WRONLY | libc::O_APPEND | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0,
            ),
        };
        let fd = openat2_beneath(self.dir_fd.as_raw_fd(), &c, flags, create_mode)?;
        let st = fstat_fd(fd.as_raw_fd())?;
        if !is_regular(st.st_mode) {
            return Err(FsMutateError::NotARegularFile { mode: st.st_mode });
        }
        Ok(OwnedFdHandle {
            fd,
            name: name.as_str().to_owned(),
        })
    }

    /// Atomically replace `name` with `bytes` (contained `O_EXCL` temp sibling +
    /// `renameat`). `durable` additionally `fsync`s the temporary and the parent.
    pub fn write_leaf_atomic(
        &self,
        name: &FileName,
        bytes: &[u8],
        durable: bool,
    ) -> Result<(), FsMutateError> {
        let dir = self.dir_fd.as_raw_fd();

        // Exclusive temp creation with bounded retry on EEXIST.
        let mut created: Option<(OwnedFd, String)> = None;
        for _ in 0..MAX_TEMP_RETRIES {
            let cand = make_temp_name(name.as_str());
            let cc = cstr(&cand)?;
            match openat2_beneath(
                dir,
                &cc,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o600,
            ) {
                Ok(fd) => {
                    created = Some((fd, cand));
                    break;
                }
                Err(FsMutateError::AlreadyExists) => continue,
                Err(e) => return Err(e),
            }
        }
        let (temp_fd, temp_name) = created.ok_or(FsMutateError::AlreadyExists)?;

        // Write (and optionally sync) the temp; clean it up on any failure.
        let write_res = (|| -> Result<(), FsMutateError> {
            #[cfg(feature = "fault-injection")]
            crate::mutate::fault::check(
                crate::mutate::fault::FaultPoint::AtomicWrite,
                name.as_str(),
            )?;
            write_all_fd(temp_fd.as_raw_fd(), bytes).map_err(FsMutateError::Io)?;
            if durable {
                fsync_fd(temp_fd.as_raw_fd()).map_err(FsMutateError::Io)?;
            }
            Ok(())
        })();
        if let Err(primary) = write_res {
            drop(temp_fd);
            return Err(cleanup_after_failure(dir, &temp_name, primary));
        }
        drop(temp_fd);

        // Atomically publish over the destination.
        let c_temp = cstr(&temp_name)?;
        let c_dst = cstr(name.as_str())?;
        #[cfg(feature = "fault-injection")]
        if let Err(injected) = crate::mutate::fault::check(
            crate::mutate::fault::FaultPoint::AtomicRename,
            name.as_str(),
        ) {
            return Err(cleanup_after_failure(dir, &temp_name, injected));
        }
        let r = unsafe { libc::renameat(dir, c_temp.as_ptr(), dir, c_dst.as_ptr()) };
        if r != 0 {
            let err = classify_open_err(std::io::Error::last_os_error());
            return Err(cleanup_after_failure(dir, &temp_name, err));
        }
        if durable {
            fsync_pinned_dir(dir)?;
        }
        Ok(())
    }

    /// Remove a directory entry. `missing_ok` maps `ENOENT` to `Ok(())`.
    pub fn unlink(&self, name: &FileName, missing_ok: bool) -> Result<(), FsMutateError> {
        let c = cstr(name.as_str())?;
        #[cfg(feature = "fault-injection")]
        crate::mutate::fault::check(crate::mutate::fault::FaultPoint::Unlink, name.as_str())?;
        let r = unsafe { libc::unlinkat(self.dir_fd.as_raw_fd(), c.as_ptr(), 0) };
        if r != 0 {
            let err = std::io::Error::last_os_error();
            if missing_ok && err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(());
            }
            return Err(classify_open_err(err));
        }
        Ok(())
    }

    /// Truncate an existing regular-file leaf to `len`.
    pub fn truncate(&self, name: &FileName, len: u64) -> Result<(), FsMutateError> {
        let handle = self.open_leaf_write(name, LeafWriteMode::Append)?;
        let r = unsafe { libc::ftruncate(handle.fd.as_raw_fd(), len as libc::off_t) };
        if r != 0 {
            return Err(FsMutateError::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Append `bytes` to an existing regular-file leaf only if its current size equals
    /// `expected_offset`. `O_APPEND` guarantees the bytes land atomically at end-of-file.
    pub fn append_at(
        &self,
        name: &FileName,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), FsMutateError> {
        let handle = self.open_leaf_write(name, LeafWriteMode::Append)?;
        let st = fstat_fd(handle.fd.as_raw_fd())?;
        let actual = st.st_size as u64;
        if actual != expected_offset {
            return Err(FsMutateError::OffsetMismatch {
                expected: expected_offset,
                actual,
            });
        }
        write_all_fd(handle.fd.as_raw_fd(), bytes).map_err(FsMutateError::Io)?;
        Ok(())
    }

    /// Rename a leaf beneath this directory to a leaf beneath `dst` (both pinned; single
    /// contained components on each side).
    pub fn rename_leaf(
        &self,
        name: &FileName,
        dst: &BlockingDir,
        dst_name: &FileName,
    ) -> Result<(), FsMutateError> {
        let c_src = cstr(name.as_str())?;
        let c_dst = cstr(dst_name.as_str())?;
        #[cfg(feature = "fault-injection")]
        crate::mutate::fault::check(
            crate::mutate::fault::FaultPoint::RenameLeaf,
            dst_name.as_str(),
        )?;
        let r = unsafe {
            libc::renameat(
                self.dir_fd.as_raw_fd(),
                c_src.as_ptr(),
                dst.dir_fd.as_raw_fd(),
                c_dst.as_ptr(),
            )
        };
        if r != 0 {
            return Err(classify_open_err(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// `fsync` this pinned directory.
    pub fn sync(&self) -> Result<(), FsMutateError> {
        fsync_pinned_dir(self.dir_fd.as_raw_fd())
    }

    fn open_lock_fd(&self, name: &FileName) -> Result<OwnedFd, FsMutateError> {
        let c = cstr(name.as_str())?;
        openat2_beneath(
            self.dir_fd.as_raw_fd(),
            &c,
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC,
            0o600,
        )
    }

    /// Acquire an advisory exclusive `flock`, blocking until available. The lock file is
    /// created if absent and never unlinked by this module.
    pub fn lock(&self, name: &FileName) -> Result<ContainedLockGuard, FsMutateError> {
        let fd = self.open_lock_fd(name)?;
        loop {
            let r = unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX) };
            if r == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(FsMutateError::Io(err));
        }
        Ok(ContainedLockGuard {
            lock_fd: Some(fd),
            authority_id: self.authority_id,
            name: name.as_str().to_owned(),
        })
    }

    /// Try to acquire the advisory exclusive lock without blocking. `Ok(None)` == held
    /// elsewhere.
    pub fn try_lock(&self, name: &FileName) -> Result<Option<ContainedLockGuard>, FsMutateError> {
        let fd = self.open_lock_fd(name)?;
        let r = unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if r != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Ok(None);
            }
            return Err(FsMutateError::Io(err));
        }
        Ok(Some(ContainedLockGuard {
            lock_fd: Some(fd),
            authority_id: self.authority_id,
            name: name.as_str().to_owned(),
        }))
    }
}
