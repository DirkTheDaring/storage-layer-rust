//! Domain-free, descriptor-relative directory enumeration for `storage-fs`.
//!
//! Provides bounded, single-directory enumeration over a pinned directory descriptor
//! using Linux `openat2` with containment flags:
//! `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
//!
//! ## Architectural Boundaries
//! - **Domain-Free**: Operates on arbitrary filesystem names, preserving raw non-UTF-8 bytes
//!   without lossy string conversions. Does not enforce CAS shard naming, 64-hex digest rules,
//!   or GC candidate translation.
//! - **Single-Directory Only**: Does not recurse across directory hierarchies.
//! - **No Continuation Tokens**: Quality Gate **O-03** remains open; directory iteration
//!   collects all entries in a single directory up to the caller-supplied bounds.
//!
//! ## Resource Accounting & Limits
//! Callers must provide [`DirEnumerationLimits`] specifying:
//! - `max_entries`: Maximum number of directory entries to retain.
//! - `max_total_name_bytes`: Maximum cumulative bytes across all retained entry names.
//!
//! ### Zero-Limit Semantics
//! - An empty directory succeeds under zero limits (`max_entries == 0` or `max_total_name_bytes == 0`),
//!   returning an empty vector (`Ok([])`).
//! - If the directory contains at least one entry, the first entry exceeding either budget returns
//!   a typed [`FsDirError::LimitExceeded`] failure before allocating or retaining the entry name.
//!
//! ### Scope of Bounds
//! Limits bound retained entry counts and raw name bytes in userspace heap memory. They do **not** bound:
//! - Kernel allocations (dentries, inodes, page cache).
//! - Libc/kernel internal buffers (e.g. `getdents64` buffer allocations inside `readdir`).
//! - Concurrent task count.
//! - Blocking filesystem syscall duration.
//!
//! ## Descriptor Ownership and `fdopendir` Safety
//! 1. `openat2` opens a fresh readable directory descriptor (`O_RDONLY | O_DIRECTORY | O_CLOEXEC`)
//!    ensuring an independent Open File Description (OFD) with its own seek position (`f_pos = 0`).
//! 2. The raw descriptor is immediately wrapped in an [`std::os::fd::OwnedFd`] guard.
//! 3. On calling `libc::fdopendir`:
//!    - If `fdopendir` returns `NULL` or acquisition fails, ownership is retained by the
//!      [`std::os::fd::OwnedFd`] guard and closed cleanly upon function exit.
//!    - If `fdopendir` succeeds, ownership transfers to the `DIR*` stream. An internal RAII guard
//!      ensures `libc::closedir` is called upon function exit, safely closing the underlying descriptor.
//!      Double-closing is strictly prevented.
//! 4. `DIR*` state is kept local to the synchronous blocking task and never exposed across threads.
//!
//! ## Non-Guarantees and Mutation Semantics
//! - **Observations, Not Capabilities**: Returned [`DirEntryType`] values are point-in-time observations
//!   of directory entries during iteration. They do not confer access authorization or guarantee
//!   that the filesystem entry will not be replaced, renamed, or deleted before subsequent operations.
//! - **No Snapshot Isolation**: Directory iteration reflects concurrent filesystem modifications.
//!   Entries added or removed during iteration may be partially observed.
//! - **Unlink / Movement**: A pinned descriptor avoids reopening replacement pathnames, but does not
//!   guarantee that directory iteration will succeed if the directory is unlinked or moved.
//! - **Mount Crossing**: `RESOLVE_BENEATH` prevents escaping the pinned root descriptor, but does not
//!   provide mount isolation for child mounts attached beneath the root.
//! - **Cancellation**: Dropping the awaiting future does not cancel in-flight blocking kernel I/O.

use std::collections::BinaryHeap;
use std::ffi::{OsStr, OsString};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;

use storage_core::ObjectKey;

/// Backend-neutral leaf filter: an entry is a candidate generic object iff its name
/// is a valid single-component generic key.
pub(crate) fn is_generic_leaf_name(name: &str) -> bool {
    !name.contains('/') && ObjectKey::parse(name).is_ok()
}

/// Bounded max-heap for streaming lexicographical Top-K selection.
/// Retains at most `capacity` entries.
#[derive(Debug)]
pub(crate) struct BoundedLexicalHeap {
    heap: BinaryHeap<String>,
    capacity: usize,
}

impl BoundedLexicalHeap {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            heap: BinaryHeap::with_capacity(capacity.min(1024)),
            capacity,
        }
    }

    /// Considers `candidate` for inclusion.
    /// If `after` is given, candidates strictly less than or equal to `after` are skipped with zero allocation.
    #[allow(dead_code)]
    pub(crate) fn push_if_after(&mut self, candidate: String, after: Option<&str>) {
        if let Some(a) = after
            && candidate.as_str() <= a
        {
            return;
        }
        if self.capacity == 0 {
            return;
        }
        if self.heap.len() < self.capacity {
            self.heap.push(candidate);
        } else if let Some(max_elem) = self.heap.peek()
            && candidate.as_str() < max_elem.as_str()
        {
            self.heap.pop();
            self.heap.push(candidate);
        }
    }

    pub(crate) fn is_full(&self) -> bool {
        self.heap.len() >= self.capacity
    }

    pub(crate) fn peek(&self) -> Option<&String> {
        self.heap.peek()
    }

    pub(crate) fn push(&mut self, candidate: String) {
        if self.capacity == 0 {
            return;
        }
        if self.heap.len() < self.capacity {
            self.heap.push(candidate);
        } else if let Some(max_elem) = self.heap.peek()
            && candidate.as_str() < max_elem.as_str()
        {
            self.heap.pop();
            self.heap.push(candidate);
        }
    }

    /// Consumes the heap and returns the retained entries in ascending sorted order.
    pub(crate) fn into_sorted_vec(self) -> Vec<String> {
        self.heap.into_sorted_vec()
    }

    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.heap.len()
    }
}

/// Asynchronous stream yielding directory entries with backpressure.
pub struct DirStream {
    rx: tokio::sync::mpsc::Receiver<Result<DirEntry, FsDirError>>,
    _handle: Option<tokio::task::JoinHandle<()>>,
}

impl DirStream {
    pub(crate) fn new(
        rx: tokio::sync::mpsc::Receiver<Result<DirEntry, FsDirError>>,
        handle: Option<tokio::task::JoinHandle<()>>,
    ) -> Self {
        Self {
            rx,
            _handle: handle,
        }
    }

    /// Yields the next directory entry, or `None` when enumeration completes.
    pub async fn next_entry(&mut self) -> Option<Result<DirEntry, FsDirError>> {
        self.rx.recv().await
    }
}

/// Caller-specified resource limits for single-directory enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirEnumerationLimits {
    max_entries: usize,
    max_total_name_bytes: usize,
}

impl DirEnumerationLimits {
    /// Creates a new resource limit configuration for directory enumeration.
    pub fn new(max_entries: usize, max_total_name_bytes: usize) -> Self {
        Self {
            max_entries,
            max_total_name_bytes,
        }
    }

    /// Maximum number of directory entries to retain.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Maximum cumulative bytes across all retained entry names.
    pub fn max_total_name_bytes(&self) -> usize {
        self.max_total_name_bytes
    }
}

/// Point-in-time observation of directory entry type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DirEntryType {
    /// Regular file (`S_IFREG` / `DT_REG`).
    Regular,
    /// Directory (`S_IFDIR` / `DT_DIR`).
    Directory,
    /// Symbolic link (`S_IFLNK` / `DT_LNK`).
    Symlink,
    /// Other filesystem object (FIFO, socket, character or block device).
    Other,
}

/// Domain-free directory entry preserving raw filesystem names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    name: OsString,
    file_type: DirEntryType,
}

impl DirEntry {
    /// Constructs a new directory entry.
    pub fn new(name: OsString, file_type: DirEntryType) -> Self {
        Self { name, file_type }
    }

    /// Returns a reference to the raw entry name.
    pub fn name(&self) -> &OsStr {
        &self.name
    }

    /// Returns the point-in-time observed entry type.
    pub fn file_type(&self) -> DirEntryType {
        self.file_type
    }

    /// Consumes the entry, returning the owned raw entry name.
    pub fn into_name(self) -> OsString {
        self.name
    }
}

/// Specific budget that was exhausted during enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LimitExceededReason {
    /// Entry count limit was exceeded.
    MaxEntries(usize),
    /// Cumulative name bytes limit was exceeded.
    MaxTotalNameBytes(usize),
}

/// Strongly typed errors from descriptor-relative directory enumeration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FsDirError {
    /// Target directory does not exist.
    #[error("target directory not found: {path:?}")]
    NotFound {
        /// Requested relative path, or `None` if targeting the root directory.
        path: Option<String>,
    },

    /// Target path exists but is not a directory.
    #[error("target path is not a directory: {path:?}")]
    NotADirectory {
        /// Requested relative path, or `None` if targeting the root directory.
        path: Option<String>,
    },

    /// Access to target directory was denied.
    #[error("permission denied for directory: {path:?}")]
    PermissionDenied {
        /// Requested relative path, or `None` if targeting the root directory.
        path: Option<String>,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// Kernel containment policy rejected path resolution (e.g. symlink or escape).
    #[error("containment policy rejected path resolution (raw OS error {raw_os_error})")]
    ResolutionRejected {
        /// Raw numeric OS error code returned by `openat2`.
        raw_os_error: i32,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The `openat2` syscall is unsupported in this execution environment (`ENOSYS`).
    #[error("openat2 syscall unsupported in environment")]
    SyscallUnsupported(#[source] std::io::Error),

    /// Enumeration budget exceeded.
    #[error("enumeration budget exceeded: {reason:?}")]
    LimitExceeded {
        /// Exhausted limit.
        reason: LimitExceededReason,
    },

    /// An entry observed during `readdir` disappeared during descriptor-relative type inspection.
    #[error("directory entry disappeared during type inspection: {name:?}")]
    EntryDisappeared {
        /// Name of the missing entry.
        name: OsString,
    },

    /// Unexpected directory I/O error occurred during enumeration.
    #[error("directory I/O error: {source}")]
    Io {
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// A Tokio runtime is required to execute blocking enumeration, but none was entered.
    #[error("tokio runtime required to execute blocking enumeration: {0}")]
    RuntimeMissing(#[source] tokio::runtime::TryCurrentError),

    /// A blocking enumeration task failed to join (e.g. panicked or cancelled during shutdown).
    #[error("blocking enumeration task failed: {0}")]
    TaskJoinFailed(#[source] tokio::task::JoinError),

    /// Platform is unsupported (descriptor-relative containment requires Linux `openat2`).
    #[error("platform unsupported: descriptor-relative containment requires Linux openat2")]
    PlatformUnsupported,
}

impl FsDirError {
    /// Returns `true` if this error represents a not found condition.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }

    /// Returns `true` if this error represents a not-a-directory condition.
    pub fn is_not_a_directory(&self) -> bool {
        matches!(self, Self::NotADirectory { .. })
    }

    /// Returns `true` if this error represents a permission denied condition.
    pub fn is_permission_denied(&self) -> bool {
        matches!(self, Self::PermissionDenied { .. })
    }

    /// Returns `true` if this error represents an exceeded budget limit.
    pub fn is_limit_exceeded(&self) -> bool {
        matches!(self, Self::LimitExceeded { .. })
    }
}

/// Helper to check entry count and cumulative name bytes accounting.
///
/// Returns `Ok(new_total_name_bytes)` if within limits, or `Err(FsDirError::LimitExceeded)`
/// if either entry count or byte limit is exhausted or arithmetic overflows.
pub(crate) fn account_entry(
    current_count: usize,
    current_bytes: usize,
    next_name_len: usize,
    limits: &DirEnumerationLimits,
) -> Result<usize, FsDirError> {
    if current_count >= limits.max_entries() {
        return Err(FsDirError::LimitExceeded {
            reason: LimitExceededReason::MaxEntries(limits.max_entries()),
        });
    }

    match current_bytes.checked_add(next_name_len) {
        Some(new_total) if new_total <= limits.max_total_name_bytes() => Ok(new_total),
        _ => Err(FsDirError::LimitExceeded {
            reason: LimitExceededReason::MaxTotalNameBytes(limits.max_total_name_bytes()),
        }),
    }
}

#[cfg(target_os = "linux")]
struct DirGuard {
    dir: *mut libc::DIR,
    #[cfg(test)]
    on_drop: Option<Arc<dyn Fn(i32, i32) + Send + Sync>>,
}

#[cfg(target_os = "linux")]
impl Drop for DirGuard {
    fn drop(&mut self) {
        if !self.dir.is_null() {
            #[cfg(test)]
            let fd = unsafe { libc::dirfd(self.dir) };
            let close_status = unsafe { libc::closedir(self.dir) };
            #[cfg(test)]
            if let Some(hook) = &self.on_drop {
                hook(fd, close_status);
            }
            #[cfg(not(test))]
            let _ = close_status;
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
type BeforeOpenHook = Arc<dyn Fn() + Send + Sync>;
#[cfg(all(test, target_os = "linux"))]
type AfterOpenat2Hook = Arc<dyn Fn(&OwnedFd) + Send + Sync>;
#[cfg(all(test, target_os = "linux"))]
type SimulateFdopendirErrorHook = Arc<dyn Fn() -> std::io::Error + Send + Sync>;
#[cfg(all(test, target_os = "linux"))]
type OnFdClosedHook = Arc<dyn Fn(i32) + Send + Sync>;
#[cfg(all(test, target_os = "linux"))]
type OnDirClosedHook = Arc<dyn Fn(i32, i32) + Send + Sync>;
#[cfg(all(test, target_os = "linux"))]
type BeforeReaddirHook = Arc<dyn Fn() + Send + Sync>;
#[cfg(all(test, target_os = "linux"))]
type SimulateDtUnknownHook = Arc<dyn Fn(&OsStr) -> bool + Send + Sync>;
#[cfg(all(test, target_os = "linux"))]
type BeforeStatFallbackHook = Arc<dyn Fn(&OsStr) + Send + Sync>;

/// Narrowly scoped test hooks for verifying directory enumeration failure paths and lifecycle.
#[cfg(all(test, target_os = "linux"))]
#[derive(Clone, Default)]
pub(crate) struct DirTestHooks {
    pub(crate) before_open: Option<BeforeOpenHook>,
    pub(crate) after_openat2: Option<AfterOpenat2Hook>,
    pub(crate) simulate_fdopendir_error: Option<SimulateFdopendirErrorHook>,
    pub(crate) on_fd_closed: Option<OnFdClosedHook>,
    pub(crate) on_dir_closed: Option<OnDirClosedHook>,
    pub(crate) before_readdir: Option<BeforeReaddirHook>,
    pub(crate) simulate_dt_unknown: Option<SimulateDtUnknownHook>,
    pub(crate) before_stat_fallback: Option<BeforeStatFallbackHook>,
}

#[cfg(all(test, target_os = "linux"))]
impl std::fmt::Debug for DirTestHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirTestHooks")
            .field("before_open", &self.before_open.is_some())
            .field("after_openat2", &self.after_openat2.is_some())
            .field(
                "simulate_fdopendir_error",
                &self.simulate_fdopendir_error.is_some(),
            )
            .field("on_fd_closed", &self.on_fd_closed.is_some())
            .field("on_dir_closed", &self.on_dir_closed.is_some())
            .field("before_readdir", &self.before_readdir.is_some())
            .field("simulate_dt_unknown", &self.simulate_dt_unknown.is_some())
            .field("before_stat_fallback", &self.before_stat_fallback.is_some())
            .finish()
    }
}

#[cfg(all(test, not(target_os = "linux")))]
#[derive(Clone, Default, Debug)]
pub(crate) struct DirTestHooks;

/// Asynchronously offloads directory enumeration to Tokio's blocking thread pool.
#[cfg(target_os = "linux")]
pub(crate) async fn enumerate_dir_async(
    root_fd: &Arc<OwnedFd>,
    target: Option<&ObjectKey>,
    limits: DirEnumerationLimits,
    #[cfg(test)] hooks: Option<&DirTestHooks>,
) -> Result<Vec<DirEntry>, FsDirError> {
    let handle = match tokio::runtime::Handle::try_current() {
        Ok(h) => h,
        Err(e) => return Err(FsDirError::RuntimeMissing(e)),
    };

    let root_fd = Arc::clone(root_fd);
    let target = target.cloned();
    #[cfg(test)]
    let hooks = hooks.cloned();

    let join_res = handle
        .spawn_blocking(move || {
            enumerate_dir_sync(
                &root_fd,
                target.as_ref(),
                limits,
                #[cfg(test)]
                hooks.as_ref(),
            )
        })
        .await;

    match join_res {
        Ok(res) => res,
        Err(join_err) => Err(FsDirError::TaskJoinFailed(join_err)),
    }
}

/// Synchronously executes descriptor-relative directory opening and entry iteration.
#[cfg(target_os = "linux")]
pub(crate) fn enumerate_dir_sync(
    root_fd: &OwnedFd,
    target: Option<&ObjectKey>,
    limits: DirEnumerationLimits,
    #[cfg(test)] hooks: Option<&DirTestHooks>,
) -> Result<Vec<DirEntry>, FsDirError> {
    #[cfg(test)]
    if let Some(hook) = hooks.and_then(|h| h.before_open.as_ref()) {
        hook();
    }

    let target_str = target.map(|k| k.to_string());

    let c_target = match target {
        None => std::ffi::CString::new(".").expect("dot is valid CString"),
        Some(key) => std::ffi::CString::new(key.as_str()).map_err(|_| FsDirError::Io {
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "key contains embedded NUL byte",
            ),
        })?,
    };

    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    how.mode = 0;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;

    let res = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd.as_raw_fd(),
            c_target.as_ptr(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        )
    };

    if res < 0 {
        let err = std::io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::ENOSYS) => FsDirError::SyscallUnsupported(err),
            Some(libc::ENOENT) => FsDirError::NotFound { path: target_str },
            Some(libc::ENOTDIR) => FsDirError::NotADirectory { path: target_str },
            Some(libc::EACCES) | Some(libc::EPERM) => FsDirError::PermissionDenied {
                path: target_str,
                source: err,
            },
            Some(libc::ELOOP) | Some(libc::EXDEV) => FsDirError::ResolutionRejected {
                raw_os_error: err.raw_os_error().unwrap_or(0),
                source: err,
            },
            _ => FsDirError::Io { source: err },
        });
    }

    let owned_fd = unsafe { OwnedFd::from_raw_fd(res as i32) };

    #[cfg(test)]
    if let Some(hook) = hooks.and_then(|h| h.after_openat2.as_ref()) {
        hook(&owned_fd);
    }

    let raw_fd = owned_fd.as_raw_fd();

    // Acquire directory stream; route simulated failure and real NULL failure through
    // one common acquisition check and ownership cleanup path.
    #[cfg(test)]
    let (dir_ptr, acq_err) = match hooks.and_then(|h| h.simulate_fdopendir_error.as_ref()) {
        Some(inject_fn) => (std::ptr::null_mut(), Some(inject_fn())),
        None => {
            let ptr = unsafe { libc::fdopendir(raw_fd) };
            let err = if ptr.is_null() {
                Some(std::io::Error::last_os_error())
            } else {
                None
            };
            (ptr, err)
        }
    };

    #[cfg(not(test))]
    let (dir_ptr, acq_err) = {
        let ptr = unsafe { libc::fdopendir(raw_fd) };
        let err = if ptr.is_null() {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        (ptr, err)
    };

    if dir_ptr.is_null() {
        // Acquisition failed: OwnedFd retains ownership and closes raw_fd upon drop.
        drop(owned_fd);
        #[cfg(test)]
        if let Some(hook) = hooks.and_then(|h| h.on_fd_closed.as_ref()) {
            hook(raw_fd);
        }
        let source = acq_err.unwrap_or_else(|| std::io::Error::other("fdopendir returned null"));
        return Err(FsDirError::Io { source });
    }

    // fdopendir succeeded: transfer ownership exactly once to DirGuard.
    let _ = owned_fd.into_raw_fd();
    let dir_guard = DirGuard {
        dir: dir_ptr,
        #[cfg(test)]
        on_drop: hooks.and_then(|h| h.on_dir_closed.clone()),
    };
    let dir_fd = unsafe { libc::dirfd(dir_guard.dir) };

    let mut entries = Vec::new();
    let mut total_name_bytes: usize = 0;

    loop {
        #[cfg(test)]
        if let Some(hook) = hooks.and_then(|h| h.before_readdir.as_ref()) {
            hook();
        }

        // POSIX requires zeroing errno immediately before readdir to distinguish EOF from error.
        unsafe {
            *libc::__errno_location() = 0;
        }

        let entry_ptr = unsafe { libc::readdir(dir_guard.dir) };
        if entry_ptr.is_null() {
            // Capture errno immediately before any subsequent operation
            let raw_errno = unsafe { *libc::__errno_location() };
            if raw_errno == 0 {
                break;
            } else {
                let err = std::io::Error::from_raw_os_error(raw_errno);
                return Err(FsDirError::Io { source: err });
            }
        }

        let d_entry = unsafe { &*entry_ptr };
        let c_name = unsafe { std::ffi::CStr::from_ptr(d_entry.d_name.as_ptr()) };
        let name_bytes = c_name.to_bytes();

        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }

        let name_len = name_bytes.len();
        let new_total = account_entry(entries.len(), total_name_bytes, name_len, &limits)?;

        let name = OsStr::from_bytes(name_bytes).to_os_string();

        #[cfg(test)]
        let d_type = if let Some(sim) = hooks.and_then(|h| h.simulate_dt_unknown.as_ref()) {
            if sim(&name) {
                libc::DT_UNKNOWN
            } else {
                d_entry.d_type
            }
        } else {
            d_entry.d_type
        };

        #[cfg(not(test))]
        let d_type = d_entry.d_type;

        let file_type = match d_type {
            libc::DT_REG => DirEntryType::Regular,
            libc::DT_DIR => DirEntryType::Directory,
            libc::DT_LNK => DirEntryType::Symlink,
            libc::DT_UNKNOWN => {
                #[cfg(test)]
                if let Some(hook) = hooks.and_then(|h| h.before_stat_fallback.as_ref()) {
                    hook(&name);
                }

                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                let stat_res = unsafe {
                    libc::fstatat(
                        dir_fd,
                        d_entry.d_name.as_ptr(),
                        &mut st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if stat_res != 0 {
                    let stat_err = std::io::Error::last_os_error();
                    if stat_err.raw_os_error() == Some(libc::ENOENT) {
                        return Err(FsDirError::EntryDisappeared { name });
                    } else {
                        return Err(FsDirError::Io { source: stat_err });
                    }
                }

                match st.st_mode & libc::S_IFMT {
                    libc::S_IFREG => DirEntryType::Regular,
                    libc::S_IFDIR => DirEntryType::Directory,
                    libc::S_IFLNK => DirEntryType::Symlink,
                    _ => DirEntryType::Other,
                }
            }
            _ => DirEntryType::Other,
        };

        entries.push(DirEntry::new(name, file_type));
        total_name_bytes = new_total;
    }

    Ok(entries)
}

/// Asynchronously enumerates a directory and collects up to `limit` lexicographically smallest
/// regular file names strictly after `after`.
#[cfg(target_os = "linux")]
pub(crate) async fn enumerate_dir_page_async(
    root_fd: &Arc<OwnedFd>,
    target: Option<&ObjectKey>,
    after: Option<&str>,
    limit: std::num::NonZeroUsize,
    limits: Option<DirEnumerationLimits>,
    #[cfg(test)] hooks: Option<&DirTestHooks>,
) -> Result<(Vec<String>, bool), FsDirError> {
    let handle = match tokio::runtime::Handle::try_current() {
        Ok(h) => h,
        Err(e) => return Err(FsDirError::RuntimeMissing(e)),
    };

    let root_fd = Arc::clone(root_fd);
    let target = target.cloned();
    let after = after.map(|s| s.to_string());
    #[cfg(test)]
    let hooks = hooks.cloned();

    let join_res = handle
        .spawn_blocking(move || {
            enumerate_dir_page_sync(
                &root_fd,
                target.as_ref(),
                after.as_deref(),
                limit,
                limits,
                #[cfg(test)]
                hooks.as_ref(),
            )
        })
        .await;

    match join_res {
        Ok(res) => res,
        Err(join_err) => Err(FsDirError::TaskJoinFailed(join_err)),
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn enumerate_dir_page_async(
    _root_fd: &Arc<OwnedFd>,
    _target: Option<&ObjectKey>,
    _after: Option<&str>,
    _limit: std::num::NonZeroUsize,
    _limits: Option<DirEnumerationLimits>,
    _hooks: Option<&DirTestHooks>,
) -> Result<(Vec<String>, bool), FsDirError> {
    Err(FsDirError::PlatformUnsupported)
}

/// Synchronously enumerates a directory and collects up to `limit + 1` lexicographically smallest
/// regular file names strictly after `after`.
#[cfg(target_os = "linux")]
pub(crate) fn enumerate_dir_page_sync(
    root_fd: &OwnedFd,
    target: Option<&ObjectKey>,
    after: Option<&str>,
    limit: std::num::NonZeroUsize,
    limits: Option<DirEnumerationLimits>,
    #[cfg(test)] hooks: Option<&DirTestHooks>,
) -> Result<(Vec<String>, bool), FsDirError> {
    #[cfg(test)]
    if let Some(hook) = hooks.and_then(|h| h.before_open.as_ref()) {
        hook();
    }

    let target_str = target.map(|k| k.to_string());

    let c_target = match target {
        None => std::ffi::CString::new(".").expect("dot is valid CString"),
        Some(key) => std::ffi::CString::new(key.as_str()).map_err(|_| FsDirError::Io {
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "key contains embedded NUL byte",
            ),
        })?,
    };

    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    how.mode = 0;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;

    let res = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd.as_raw_fd(),
            c_target.as_ptr(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        )
    };

    if res < 0 {
        let err = std::io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::ENOSYS) => FsDirError::SyscallUnsupported(err),
            Some(libc::ENOENT) => FsDirError::NotFound { path: target_str },
            Some(libc::ENOTDIR) => FsDirError::NotADirectory { path: target_str },
            Some(libc::EACCES) | Some(libc::EPERM) => FsDirError::PermissionDenied {
                path: target_str,
                source: err,
            },
            Some(libc::ELOOP) | Some(libc::EXDEV) => FsDirError::ResolutionRejected {
                raw_os_error: err.raw_os_error().unwrap_or(0),
                source: err,
            },
            _ => FsDirError::Io { source: err },
        });
    }

    let owned_fd = unsafe { OwnedFd::from_raw_fd(res as i32) };

    #[cfg(test)]
    if let Some(hook) = hooks.and_then(|h| h.after_openat2.as_ref()) {
        hook(&owned_fd);
    }

    let raw_fd = owned_fd.as_raw_fd();

    #[cfg(test)]
    let (dir_ptr, acq_err) = match hooks.and_then(|h| h.simulate_fdopendir_error.as_ref()) {
        Some(inject_fn) => (std::ptr::null_mut(), Some(inject_fn())),
        None => {
            let ptr = unsafe { libc::fdopendir(raw_fd) };
            let err = if ptr.is_null() {
                Some(std::io::Error::last_os_error())
            } else {
                None
            };
            (ptr, err)
        }
    };

    #[cfg(not(test))]
    let (dir_ptr, acq_err) = {
        let ptr = unsafe { libc::fdopendir(raw_fd) };
        let err = if ptr.is_null() {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        (ptr, err)
    };

    if dir_ptr.is_null() {
        drop(owned_fd);
        #[cfg(test)]
        if let Some(hook) = hooks.and_then(|h| h.on_fd_closed.as_ref()) {
            hook(raw_fd);
        }
        let source = acq_err.unwrap_or_else(|| std::io::Error::other("fdopendir returned null"));
        return Err(FsDirError::Io { source });
    }

    let _ = owned_fd.into_raw_fd();
    let dir_guard = DirGuard {
        dir: dir_ptr,
        #[cfg(test)]
        on_drop: hooks.and_then(|h| h.on_dir_closed.clone()),
    };
    let dir_fd = unsafe { libc::dirfd(dir_guard.dir) };

    let capacity = limit.get().saturating_add(1);
    let mut heap = BoundedLexicalHeap::new(capacity);
    let mut total_entries: usize = 0;
    let mut total_name_bytes: usize = 0;

    loop {
        #[cfg(test)]
        if let Some(hook) = hooks.and_then(|h| h.before_readdir.as_ref()) {
            hook();
        }

        unsafe {
            *libc::__errno_location() = 0;
        }

        let entry_ptr = unsafe { libc::readdir(dir_guard.dir) };
        if entry_ptr.is_null() {
            let raw_errno = unsafe { *libc::__errno_location() };
            if raw_errno == 0 {
                break;
            } else {
                let err = std::io::Error::from_raw_os_error(raw_errno);
                return Err(FsDirError::Io { source: err });
            }
        }

        let d_entry = unsafe { &*entry_ptr };
        let c_name = unsafe { std::ffi::CStr::from_ptr(d_entry.d_name.as_ptr()) };
        let name_bytes = c_name.to_bytes();

        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }

        if let Some(ref lim) = limits {
            total_name_bytes =
                account_entry(total_entries, total_name_bytes, name_bytes.len(), lim)?;
            total_entries += 1;
        }

        let Ok(name_str) = std::str::from_utf8(name_bytes) else {
            continue;
        };

        if !is_generic_leaf_name(name_str) {
            continue;
        }

        if let Some(a) = after
            && name_str <= a
        {
            continue;
        }

        // Pruning: if the heap is already full and this candidate is >= the current maximum,
        // it can never enter the top-K. Skipping immediately avoids fallback fstatat and String allocation.
        if heap.is_full()
            && let Some(max_elem) = heap.peek()
            && name_str >= max_elem.as_str()
        {
            continue;
        }

        #[cfg(test)]
        let d_type = if let Some(sim) = hooks.and_then(|h| h.simulate_dt_unknown.as_ref()) {
            let os_name = OsStr::from_bytes(name_bytes);
            if sim(os_name) {
                libc::DT_UNKNOWN
            } else {
                d_entry.d_type
            }
        } else {
            d_entry.d_type
        };

        #[cfg(not(test))]
        let d_type = d_entry.d_type;

        let is_reg = if d_type == libc::DT_REG {
            true
        } else if d_type == libc::DT_UNKNOWN {
            #[cfg(test)]
            if let Some(hook) = hooks.and_then(|h| h.before_stat_fallback.as_ref()) {
                hook(OsStr::from_bytes(name_bytes));
            }
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let stat_res = unsafe {
                libc::fstatat(dir_fd, c_name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW)
            };
            if stat_res != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOENT) {
                    continue;
                }
                return Err(FsDirError::Io { source: err });
            }
            (st.st_mode & libc::S_IFMT) == libc::S_IFREG
        } else {
            false
        };

        if !is_reg {
            continue;
        }

        heap.push(name_str.to_string());
    }

    let mut leaves = heap.into_sorted_vec();
    let more = leaves.len() > limit.get();
    if more {
        leaves.truncate(limit.get());
    }

    Ok((leaves, more))
}

/// Asynchronously streams directory entries with backpressure using an internal bounded channel.
#[cfg(target_os = "linux")]
pub fn stream_dir_async(
    root_fd: &Arc<OwnedFd>,
    target: Option<&ObjectKey>,
) -> Result<DirStream, FsDirError> {
    let handle = match tokio::runtime::Handle::try_current() {
        Ok(h) => h,
        Err(e) => return Err(FsDirError::RuntimeMissing(e)),
    };

    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let root_fd = Arc::clone(root_fd);
    let target = target.cloned();

    let task = handle.spawn_blocking(move || {
        stream_dir_sync(
            &root_fd,
            target.as_ref(),
            tx,
            #[cfg(test)]
            None,
        );
    });

    Ok(DirStream::new(rx, Some(task)))
}

#[cfg(not(target_os = "linux"))]
pub fn stream_dir_async(
    _root_fd: &Arc<OwnedFd>,
    _target: Option<&ObjectKey>,
) -> Result<DirStream, FsDirError> {
    Err(FsDirError::PlatformUnsupported)
}

#[cfg(target_os = "linux")]
pub(crate) fn stream_dir_sync(
    root_fd: &OwnedFd,
    target: Option<&ObjectKey>,
    tx: tokio::sync::mpsc::Sender<Result<DirEntry, FsDirError>>,
    #[cfg(test)] hooks: Option<&DirTestHooks>,
) {
    #[cfg(test)]
    if let Some(hook) = hooks.and_then(|h| h.before_open.as_ref()) {
        hook();
    }

    let target_str = target.map(|k| k.to_string());

    let c_target = match target {
        None => std::ffi::CString::new(".").expect("dot is valid CString"),
        Some(key) => match std::ffi::CString::new(key.as_str()) {
            Ok(c) => c,
            Err(_) => {
                let _ = tx.blocking_send(Err(FsDirError::Io {
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "key contains embedded NUL byte",
                    ),
                }));
                return;
            }
        },
    };

    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    how.mode = 0;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;

    let res = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd.as_raw_fd(),
            c_target.as_ptr(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        )
    };

    if res < 0 {
        let err = std::io::Error::last_os_error();
        let mapped = match err.raw_os_error() {
            Some(libc::ENOSYS) => FsDirError::SyscallUnsupported(err),
            Some(libc::ENOENT) => FsDirError::NotFound { path: target_str },
            Some(libc::ENOTDIR) => FsDirError::NotADirectory { path: target_str },
            Some(libc::EACCES) | Some(libc::EPERM) => FsDirError::PermissionDenied {
                path: target_str,
                source: err,
            },
            Some(libc::ELOOP) | Some(libc::EXDEV) => FsDirError::ResolutionRejected {
                raw_os_error: err.raw_os_error().unwrap_or(0),
                source: err,
            },
            _ => FsDirError::Io { source: err },
        };
        let _ = tx.blocking_send(Err(mapped));
        return;
    }

    let owned_fd = unsafe { OwnedFd::from_raw_fd(res as i32) };

    #[cfg(test)]
    if let Some(hook) = hooks.and_then(|h| h.after_openat2.as_ref()) {
        hook(&owned_fd);
    }

    let raw_fd = owned_fd.as_raw_fd();

    #[cfg(test)]
    let (dir_ptr, acq_err) = match hooks.and_then(|h| h.simulate_fdopendir_error.as_ref()) {
        Some(inject_fn) => (std::ptr::null_mut(), Some(inject_fn())),
        None => {
            let ptr = unsafe { libc::fdopendir(raw_fd) };
            let err = if ptr.is_null() {
                Some(std::io::Error::last_os_error())
            } else {
                None
            };
            (ptr, err)
        }
    };

    #[cfg(not(test))]
    let (dir_ptr, acq_err) = {
        let ptr = unsafe { libc::fdopendir(raw_fd) };
        let err = if ptr.is_null() {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        (ptr, err)
    };

    if dir_ptr.is_null() {
        drop(owned_fd);
        #[cfg(test)]
        if let Some(hook) = hooks.and_then(|h| h.on_fd_closed.as_ref()) {
            hook(raw_fd);
        }
        let source = acq_err.unwrap_or_else(|| std::io::Error::other("fdopendir returned null"));
        let _ = tx.blocking_send(Err(FsDirError::Io { source }));
        return;
    }

    let _ = owned_fd.into_raw_fd();
    let dir_guard = DirGuard {
        dir: dir_ptr,
        #[cfg(test)]
        on_drop: hooks.and_then(|h| h.on_dir_closed.clone()),
    };
    let dir_fd = unsafe { libc::dirfd(dir_guard.dir) };

    loop {
        #[cfg(test)]
        if let Some(hook) = hooks.and_then(|h| h.before_readdir.as_ref()) {
            hook();
        }

        unsafe {
            *libc::__errno_location() = 0;
        }

        let entry_ptr = unsafe { libc::readdir(dir_guard.dir) };
        if entry_ptr.is_null() {
            let raw_errno = unsafe { *libc::__errno_location() };
            if raw_errno == 0 {
                break;
            } else {
                let err = std::io::Error::from_raw_os_error(raw_errno);
                let _ = tx.blocking_send(Err(FsDirError::Io { source: err }));
                return;
            }
        }

        let d_entry = unsafe { &*entry_ptr };
        let c_name = unsafe { std::ffi::CStr::from_ptr(d_entry.d_name.as_ptr()) };
        let name_bytes = c_name.to_bytes();

        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }

        let name = OsStr::from_bytes(name_bytes).to_os_string();

        #[cfg(test)]
        let d_type = if let Some(sim) = hooks.and_then(|h| h.simulate_dt_unknown.as_ref()) {
            if sim(&name) {
                libc::DT_UNKNOWN
            } else {
                d_entry.d_type
            }
        } else {
            d_entry.d_type
        };

        #[cfg(not(test))]
        let d_type = d_entry.d_type;

        let file_type = match d_type {
            libc::DT_REG => DirEntryType::Regular,
            libc::DT_DIR => DirEntryType::Directory,
            libc::DT_LNK => DirEntryType::Symlink,
            libc::DT_UNKNOWN => {
                #[cfg(test)]
                if let Some(hook) = hooks.and_then(|h| h.before_stat_fallback.as_ref()) {
                    hook(&name);
                }
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                let stat_res = unsafe {
                    libc::fstatat(dir_fd, c_name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW)
                };
                if stat_res != 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ENOENT) {
                        continue;
                    }
                    let _ = tx.blocking_send(Err(FsDirError::Io { source: err }));
                    return;
                }
                match st.st_mode & libc::S_IFMT {
                    libc::S_IFREG => DirEntryType::Regular,
                    libc::S_IFDIR => DirEntryType::Directory,
                    libc::S_IFLNK => DirEntryType::Symlink,
                    _ => DirEntryType::Other,
                }
            }
            _ => DirEntryType::Other,
        };

        let entry = DirEntry::new(name, file_type);
        if tx.blocking_send(Ok(entry)).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Platform-Independent Unit Tests ---

    #[test]
    fn test_limits_constructors_and_accessors() {
        let limits = DirEnumerationLimits::new(42, 1024);
        assert_eq!(limits.max_entries(), 42);
        assert_eq!(limits.max_total_name_bytes(), 1024);
    }

    #[test]
    fn test_bounded_lexical_heap() {
        let mut heap = BoundedLexicalHeap::new(3);
        for item in ["echo", "bravo", "delta", "alpha", "charlie"] {
            heap.push_if_after(item.to_string(), None);
        }
        let sorted = heap.into_sorted_vec();
        assert_eq!(sorted, vec!["alpha", "bravo", "charlie"]);

        let mut heap_after = BoundedLexicalHeap::new(3);
        for item in ["echo", "bravo", "delta", "alpha", "charlie"] {
            heap_after.push_if_after(item.to_string(), Some("bravo"));
        }
        let sorted_after = heap_after.into_sorted_vec();
        assert_eq!(sorted_after, vec!["charlie", "delta", "echo"]);

        let mut heap_overflow = BoundedLexicalHeap::new(2);
        for item in ["z", "y", "x", "w", "v"] {
            heap_overflow.push_if_after(item.to_string(), None);
        }
        assert_eq!(heap_overflow.into_sorted_vec(), vec!["v", "w"]);
    }

    #[test]
    fn test_dir_entry_constructors_and_accessors() {
        let entry = DirEntry::new(OsString::from("test_entry"), DirEntryType::Regular);
        assert_eq!(entry.name(), "test_entry");
        assert_eq!(entry.file_type(), DirEntryType::Regular);
        assert_eq!(entry.into_name(), OsString::from("test_entry"));
    }

    #[test]
    fn test_fs_dir_error_predicates() {
        let not_found = FsDirError::NotFound {
            path: Some("p".into()),
        };
        assert!(not_found.is_not_found());
        assert!(!not_found.is_not_a_directory());
        assert!(!not_found.is_permission_denied());
        assert!(!not_found.is_limit_exceeded());

        let not_dir = FsDirError::NotADirectory { path: None };
        assert!(!not_dir.is_not_found());
        assert!(not_dir.is_not_a_directory());

        let perm = FsDirError::PermissionDenied {
            path: None,
            source: std::io::Error::from_raw_os_error(libc::EACCES),
        };
        assert!(perm.is_permission_denied());

        let limit = FsDirError::LimitExceeded {
            reason: LimitExceededReason::MaxEntries(0),
        };
        assert!(limit.is_limit_exceeded());
    }

    #[test]
    fn test_account_entry_bounds_and_overflow() {
        let limits = DirEnumerationLimits::new(5, 100);

        // 1. Normal increments within limits
        let total = account_entry(0, 0, 10, &limits).unwrap();
        assert_eq!(total, 10);
        let total = account_entry(1, 10, 20, &limits).unwrap();
        assert_eq!(total, 30);

        // 2. Exact boundary on cumulative bytes
        let total = account_entry(2, 30, 70, &limits).unwrap();
        assert_eq!(total, 100);

        // 3. Exceeded byte budget
        let err_bytes = account_entry(2, 30, 71, &limits).unwrap_err();
        match err_bytes {
            FsDirError::LimitExceeded {
                reason: LimitExceededReason::MaxTotalNameBytes(100),
            } => {}
            other => panic!("expected MaxTotalNameBytes(100), got: {other:?}"),
        }

        // 4. Exact boundary on entry count (current_count == 4 < 5 succeeds)
        let total = account_entry(4, 10, 5, &limits).unwrap();
        assert_eq!(total, 15);

        // 5. Exceeded entry count (current_count == 5 >= 5 fails)
        let err_count = account_entry(5, 10, 5, &limits).unwrap_err();
        match err_count {
            FsDirError::LimitExceeded {
                reason: LimitExceededReason::MaxEntries(5),
            } => {}
            other => panic!("expected MaxEntries(5), got: {other:?}"),
        }

        // 6. Arithmetic overflow in checked_add
        let limits_max = DirEnumerationLimits::new(10, usize::MAX);
        let err_overflow = account_entry(0, usize::MAX - 2, 5, &limits_max).unwrap_err();
        match err_overflow {
            FsDirError::LimitExceeded {
                reason: LimitExceededReason::MaxTotalNameBytes(usize::MAX),
            } => {}
            other => panic!("expected MaxTotalNameBytes(usize::MAX) on overflow, got: {other:?}"),
        }
    }

    // --- Linux-Gated Behavioral and Integration Tests ---

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;
        use crate::reader::FsMetadataReader;
        use std::collections::BTreeSet;
        use std::fs;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;
        use tempfile::TempDir;

        #[tokio::test(flavor = "current_thread")]
        async fn test_enumerate_dir_empty_root_and_subdirectory() {
            let fixture = TempDir::new().unwrap();
            let root = fixture.path().join("root");
            fs::create_dir_all(&root).unwrap();

            let reader = FsMetadataReader::open(&root).unwrap();
            let limits = DirEnumerationLimits::new(100, 10_000);

            // 1. Root is empty
            let entries = reader.enumerate_dir(None, limits).await.unwrap();
            assert!(entries.is_empty());

            // 2. Subdirectory is empty
            let sub = root.join("sub").join("nested");
            fs::create_dir_all(&sub).unwrap();
            let key = ObjectKey::parse("sub/nested").unwrap();
            let entries_sub = reader.enumerate_dir(Some(&key), limits).await.unwrap();
            assert!(entries_sub.is_empty());
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_enumerate_dir_populated_entries_and_types() {
            let fixture = TempDir::new().unwrap();
            let root = fixture.path().join("root");
            fs::create_dir_all(&root).unwrap();

            fs::write(root.join("regular.txt"), b"payload content").unwrap();
            fs::create_dir(root.join("subdir")).unwrap();
            std::os::unix::fs::symlink("regular.txt", root.join("symlink.lnk")).unwrap();

            let fifo_path = root.join("fifo.pipe");
            let c_fifo = std::ffi::CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
            unsafe {
                let res = libc::mkfifo(c_fifo.as_ptr(), 0o600);
                assert_eq!(res, 0);
            }

            let reader = FsMetadataReader::open(&root).unwrap();
            let limits = DirEnumerationLimits::new(100, 10_000);

            let mut entries = reader.enumerate_dir(None, limits).await.unwrap();
            entries.sort_by(|a, b| a.name().cmp(b.name()));

            assert_eq!(entries.len(), 4);

            assert_eq!(entries[0].name(), "fifo.pipe");
            assert_eq!(entries[0].file_type(), DirEntryType::Other);

            assert_eq!(entries[1].name(), "regular.txt");
            assert_eq!(entries[1].file_type(), DirEntryType::Regular);

            assert_eq!(entries[2].name(), "subdir");
            assert_eq!(entries[2].file_type(), DirEntryType::Directory);

            assert_eq!(entries[3].name(), "symlink.lnk");
            assert_eq!(entries[3].file_type(), DirEntryType::Symlink);
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_enumerate_dir_zero_limits_semantics() {
            let fixture = TempDir::new().unwrap();
            let root = fixture.path().join("root");
            fs::create_dir_all(&root).unwrap();

            let reader = FsMetadataReader::open(&root).unwrap();

            // 1. Empty directory succeeds under zero limits
            let limits_zero_entries = DirEnumerationLimits::new(0, 1000);
            let res1 = reader
                .enumerate_dir(None, limits_zero_entries)
                .await
                .unwrap();
            assert!(res1.is_empty());

            let limits_zero_bytes = DirEnumerationLimits::new(1000, 0);
            let res2 = reader.enumerate_dir(None, limits_zero_bytes).await.unwrap();
            assert!(res2.is_empty());

            let limits_both_zero = DirEnumerationLimits::new(0, 0);
            let res3 = reader.enumerate_dir(None, limits_both_zero).await.unwrap();
            assert!(res3.is_empty());

            // 2. Directory with 1 file fails immediately under zero limits
            fs::write(root.join("entry.txt"), b"data").unwrap();

            let err_entries = reader
                .enumerate_dir(None, limits_zero_entries)
                .await
                .unwrap_err();
            assert!(err_entries.is_limit_exceeded());
            match err_entries {
                FsDirError::LimitExceeded {
                    reason: LimitExceededReason::MaxEntries(0),
                } => {}
                other => panic!("expected MaxEntries(0), got: {other:?}"),
            }

            let err_bytes = reader
                .enumerate_dir(None, limits_zero_bytes)
                .await
                .unwrap_err();
            assert!(err_bytes.is_limit_exceeded());
            match err_bytes {
                FsDirError::LimitExceeded {
                    reason: LimitExceededReason::MaxTotalNameBytes(0),
                } => {}
                other => panic!("expected MaxTotalNameBytes(0), got: {other:?}"),
            }
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_enumerate_dir_exact_entry_and_byte_boundaries() {
            let fixture = TempDir::new().unwrap();
            let root = fixture.path().join("root");
            fs::create_dir_all(&root).unwrap();

            // 3 entries with 2-byte names: "aa", "bb", "cc" => 6 bytes total
            fs::write(root.join("aa"), b"").unwrap();
            fs::write(root.join("bb"), b"").unwrap();
            fs::write(root.join("cc"), b"").unwrap();

            let reader = FsMetadataReader::open(&root).unwrap();

            // Max entries exact boundary (3 succeeds, 2 fails)
            let limits_3 = DirEnumerationLimits::new(3, 100);
            let ok_3 = reader.enumerate_dir(None, limits_3).await.unwrap();
            assert_eq!(ok_3.len(), 3);

            let limits_2 = DirEnumerationLimits::new(2, 100);
            let err_2 = reader.enumerate_dir(None, limits_2).await.unwrap_err();
            match err_2 {
                FsDirError::LimitExceeded {
                    reason: LimitExceededReason::MaxEntries(2),
                } => {}
                other => panic!("expected MaxEntries(2), got: {other:?}"),
            }

            // Max total name bytes exact boundary (6 succeeds, 5 fails)
            let limits_6_bytes = DirEnumerationLimits::new(100, 6);
            let ok_6 = reader.enumerate_dir(None, limits_6_bytes).await.unwrap();
            assert_eq!(ok_6.len(), 3);

            let limits_5_bytes = DirEnumerationLimits::new(100, 5);
            let err_5 = reader
                .enumerate_dir(None, limits_5_bytes)
                .await
                .unwrap_err();
            match err_5 {
                FsDirError::LimitExceeded {
                    reason: LimitExceededReason::MaxTotalNameBytes(5),
                } => {}
                other => panic!("expected MaxTotalNameBytes(5), got: {other:?}"),
            }
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_enumerate_dir_raw_non_utf8_names() {
            let fixture = TempDir::new().unwrap();
            let root = fixture.path().join("root");
            fs::create_dir_all(&root).unwrap();

            // Create entry with invalid UTF-8 bytes: b"raw_\xff\xfe_test"
            let invalid_utf8_name = b"raw_\xff\xfe_test";
            let c_name = std::ffi::CString::new(invalid_utf8_name.as_slice()).unwrap();
            let c_root = std::ffi::CString::new(root.as_os_str().as_bytes()).unwrap();

            unsafe {
                let dir_fd = libc::open(c_root.as_ptr(), libc::O_DIRECTORY | libc::O_RDONLY);
                assert!(dir_fd >= 0);
                let fd = libc::openat(
                    dir_fd,
                    c_name.as_ptr(),
                    libc::O_CREAT | libc::O_WRONLY,
                    0o644,
                );
                assert!(fd >= 0);
                libc::close(fd);
                libc::close(dir_fd);
            }

            let reader = FsMetadataReader::open(&root).unwrap();
            let limits = DirEnumerationLimits::new(10, 100);

            let entries = reader.enumerate_dir(None, limits).await.unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].name().as_bytes(), invalid_utf8_name);
            assert_eq!(entries[0].file_type(), DirEntryType::Regular);
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_enumerate_dir_missing_and_not_a_directory_targets() {
            let fixture = TempDir::new().unwrap();
            let root = fixture.path().join("root");
            fs::create_dir_all(&root).unwrap();

            fs::write(root.join("a_file.txt"), b"data").unwrap();

            let reader = FsMetadataReader::open(&root).unwrap();
            let limits = DirEnumerationLimits::new(10, 100);

            // 1. Missing target
            let missing_key = ObjectKey::parse("nonexistent/dir").unwrap();
            let err_missing = reader
                .enumerate_dir(Some(&missing_key), limits)
                .await
                .unwrap_err();
            assert!(err_missing.is_not_found());
            match err_missing {
                FsDirError::NotFound { path } => {
                    assert_eq!(path, Some("nonexistent/dir".to_string()));
                }
                other => panic!("expected NotFound, got: {other:?}"),
            }

            // 2. Target is a regular file, not a directory
            let file_key = ObjectKey::parse("a_file.txt").unwrap();
            let err_notdir = reader
                .enumerate_dir(Some(&file_key), limits)
                .await
                .unwrap_err();
            assert!(err_notdir.is_not_a_directory());
            match err_notdir {
                FsDirError::NotADirectory { path } => {
                    assert_eq!(path, Some("a_file.txt".to_string()));
                }
                other => panic!("expected NotADirectory, got: {other:?}"),
            }
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_enumerate_dir_containment_rejection() {
            let fixture = TempDir::new().unwrap();
            let root = fixture.path().join("root");
            let external = fixture.path().join("external");
            fs::create_dir_all(&root).unwrap();
            fs::create_dir_all(&external).unwrap();

            // Create a symlink pointing outside root
            std::os::unix::fs::symlink(&external, root.join("escape_link")).unwrap();

            let reader = FsMetadataReader::open(&root).unwrap();
            let limits = DirEnumerationLimits::new(10, 100);

            let key = ObjectKey::parse("escape_link").unwrap();
            let err = reader.enumerate_dir(Some(&key), limits).await.unwrap_err();

            match err {
                FsDirError::ResolutionRejected { raw_os_error, .. } => {
                    assert_eq!(raw_os_error, libc::ELOOP);
                }
                other => panic!("expected ResolutionRejected, got: {other:?}"),
            }
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_enumerate_dir_independent_concurrent_positions() {
            let fixture = TempDir::new().unwrap();
            let root = fixture.path().join("root");
            fs::create_dir_all(&root).unwrap();

            let mut expected_names = BTreeSet::new();
            for i in 0..20 {
                let name = format!("file_{:02}.txt", i);
                fs::write(root.join(&name), b"").unwrap();
                expected_names.insert(OsString::from(name));
            }

            // Bounded predicate-based rendezvous to coordinate overlapping execution
            // after acquisition through one shared reader
            struct AcquisitionRendezvous {
                state: std::sync::Mutex<RendezvousState>,
                cvar: std::sync::Condvar,
                timeout: Duration,
            }

            struct RendezvousState {
                arrived: usize,
                released: bool,
                aborted: bool,
            }

            impl AcquisitionRendezvous {
                fn new(timeout: Duration) -> Self {
                    Self {
                        state: std::sync::Mutex::new(RendezvousState {
                            arrived: 0,
                            released: false,
                            aborted: false,
                        }),
                        cvar: std::sync::Condvar::new(),
                        timeout,
                    }
                }

                fn arrive_and_wait(&self) -> Result<(), &'static str> {
                    let deadline = std::time::Instant::now() + self.timeout;
                    let mut state = self.state.lock().map_err(|_| "poisoned mutex")?;

                    if state.aborted {
                        return Err("rendezvous aborted");
                    }

                    state.arrived += 1;
                    if state.arrived == 2 {
                        state.released = true;
                        self.cvar.notify_all();
                        return Ok(());
                    }

                    while !state.released && !state.aborted {
                        let now = std::time::Instant::now();
                        if now >= deadline {
                            state.aborted = true;
                            self.cvar.notify_all();
                            return Err("rendezvous timed out waiting for peer");
                        }
                        let remaining = deadline - now;
                        let (next_state, wait_res) = self
                            .cvar
                            .wait_timeout(state, remaining)
                            .map_err(|_| "poisoned mutex during wait")?;
                        state = next_state;
                        if wait_res.timed_out() && !state.released {
                            state.aborted = true;
                            self.cvar.notify_all();
                            return Err("rendezvous timed out waiting for peer");
                        }
                    }

                    if state.released {
                        Ok(())
                    } else {
                        Err("rendezvous aborted")
                    }
                }
            }

            let rendezvous = Arc::new(AcquisitionRendezvous::new(Duration::from_secs(5)));
            let rz = Arc::clone(&rendezvous);

            let rendezvous_errors = Arc::new(std::sync::Mutex::new(Vec::new()));
            let re = Arc::clone(&rendezvous_errors);

            let hooks = DirTestHooks {
                after_openat2: Some(Arc::new(move |_fd| {
                    if let Err(e) = rz.arrive_and_wait() {
                        re.lock().unwrap().push(e);
                    }
                })),
                ..Default::default()
            };

            // Exactly ONE reader, wrapped in Arc, shared by both concurrent calls
            let reader = Arc::new(
                FsMetadataReader::open(&root)
                    .unwrap()
                    .with_dir_test_hooks(hooks),
            );
            let limits = DirEnumerationLimits::new(100, 10_000);

            let r1 = Arc::clone(&reader);
            let r2 = Arc::clone(&reader);

            let handle1 = tokio::spawn(async move { r1.enumerate_dir(None, limits).await });
            let handle2 = tokio::spawn(async move { r2.enumerate_dir(None, limits).await });

            let (res1, res2) = tokio::join!(handle1, handle2);

            let errors = rendezvous_errors.lock().unwrap().clone();
            assert!(
                errors.is_empty(),
                "acquisition rendezvous failed: {errors:?}"
            );

            let entries1 = res1.unwrap().unwrap();
            let entries2 = res2.unwrap().unwrap();

            let names1: BTreeSet<_> = entries1.into_iter().map(|e| e.into_name()).collect();
            let names2: BTreeSet<_> = entries2.into_iter().map(|e| e.into_name()).collect();

            assert_eq!(names1, expected_names);
            assert_eq!(names2, expected_names);
            assert_eq!(names1, names2);
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_enumerate_dir_deterministic_directory_rename_and_replacement() {
            let fixture = TempDir::new().unwrap();
            let root = fixture.path().join("root");
            fs::create_dir_all(&root).unwrap();

            let target_dir = root.join("target_dir");
            fs::create_dir(&target_dir).unwrap();
            fs::write(target_dir.join("sentinel_orig.txt"), b"").unwrap();

            let target_dir_clone = target_dir.clone();
            let root_clone = root.clone();

            // After openat2 opens target_dir, rename target_dir and create a replacement
            // directory with sentinel_replacement.txt before iteration starts.
            let hooks = DirTestHooks {
                after_openat2: Some(Arc::new(move |_fd| {
                    let moved_dir = root_clone.join("target_dir_renamed");
                    fs::rename(&target_dir_clone, &moved_dir).unwrap();
                    fs::create_dir(&target_dir_clone).unwrap();
                    fs::write(target_dir_clone.join("sentinel_replacement.txt"), b"").unwrap();
                })),
                ..Default::default()
            };

            let reader = FsMetadataReader::open(&root)
                .unwrap()
                .with_dir_test_hooks(hooks);
            let limits = DirEnumerationLimits::new(100, 10_000);
            let key = ObjectKey::parse("target_dir").unwrap();

            // In-flight enumeration operates over the pinned descriptor opened prior to rename
            let in_flight_entries = reader.enumerate_dir(Some(&key), limits).await.unwrap();
            assert_eq!(in_flight_entries.len(), 1);
            assert_eq!(in_flight_entries[0].name(), "sentinel_orig.txt");

            // A subsequent lookup resolves the replacement directory freshly
            let reader_fresh = FsMetadataReader::open(&root).unwrap();
            let replacement_entries = reader_fresh
                .enumerate_dir(Some(&key), limits)
                .await
                .unwrap();
            assert_eq!(replacement_entries.len(), 1);
            assert_eq!(replacement_entries[0].name(), "sentinel_replacement.txt");
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_enumerate_dir_dt_unknown_fallback_and_disappeared_entry() {
            let fixture = TempDir::new().unwrap();
            let root = fixture.path().join("root");
            fs::create_dir_all(&root).unwrap();

            fs::write(root.join("regular.txt"), b"").unwrap();
            std::os::unix::fs::symlink("regular.txt", root.join("symlink_entry.lnk")).unwrap();
            fs::write(root.join("to_disappear.txt"), b"").unwrap();

            // 1. Force DT_UNKNOWN for regular.txt and symlink_entry.lnk without unlinking
            // Verify no-follow fallback correctly identifies regular file and symlink without following
            let fallback_invocations = Arc::new(AtomicUsize::new(0));
            let fi = Arc::clone(&fallback_invocations);
            let hooks_nofol = DirTestHooks {
                simulate_dt_unknown: Some(Arc::new(|name| {
                    name == "regular.txt" || name == "symlink_entry.lnk"
                })),
                before_stat_fallback: Some(Arc::new(move |_name| {
                    fi.fetch_add(1, Ordering::SeqCst);
                })),
                ..Default::default()
            };

            let reader_nofol = FsMetadataReader::open(&root)
                .unwrap()
                .with_dir_test_hooks(hooks_nofol);
            let limits = DirEnumerationLimits::new(100, 10_000);

            let mut entries = reader_nofol.enumerate_dir(None, limits).await.unwrap();
            entries.sort_by(|a, b| a.name().cmp(b.name()));
            assert_eq!(entries.len(), 3);
            assert_eq!(fallback_invocations.load(Ordering::SeqCst), 2);

            let reg = entries.iter().find(|e| e.name() == "regular.txt").unwrap();
            assert_eq!(reg.file_type(), DirEntryType::Regular);

            let sym = entries
                .iter()
                .find(|e| e.name() == "symlink_entry.lnk")
                .unwrap();
            assert_eq!(sym.file_type(), DirEntryType::Symlink);

            // 2. Force DT_UNKNOWN for to_disappear.txt, then unlink it in before_stat_fallback.
            // Verify that the genuine ENOENT from fstatat produces EntryDisappeared.
            let root_for_unlink = root.clone();
            let hooks_disappear = DirTestHooks {
                simulate_dt_unknown: Some(Arc::new(|name| name == "to_disappear.txt")),
                before_stat_fallback: Some(Arc::new(move |name| {
                    if name == "to_disappear.txt" {
                        fs::remove_file(root_for_unlink.join("to_disappear.txt")).unwrap();
                    }
                })),
                ..Default::default()
            };

            let reader_disappear = FsMetadataReader::open(&root)
                .unwrap()
                .with_dir_test_hooks(hooks_disappear);

            let err = reader_disappear
                .enumerate_dir(None, limits)
                .await
                .unwrap_err();
            match err {
                FsDirError::EntryDisappeared { name } => {
                    assert_eq!(name, "to_disappear.txt");
                }
                other => panic!("expected EntryDisappeared from real ENOENT, got: {other:?}"),
            }
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_enumerate_dir_before_readdir_hook_does_not_corrupt_clean_eof() {
            let fixture = TempDir::new().unwrap();
            let root = fixture.path().join("root");
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join("single_file.txt"), b"").unwrap();

            // Hook intentionally clobbers errno to EACCES on every invocation
            let hooks = DirTestHooks {
                before_readdir: Some(Arc::new(|| unsafe {
                    *libc::__errno_location() = libc::EACCES;
                })),
                ..Default::default()
            };

            let reader = FsMetadataReader::open(&root)
                .unwrap()
                .with_dir_test_hooks(hooks);
            let limits = DirEnumerationLimits::new(100, 10_000);

            // Because errno is zeroed immediately before readdir, clean EOF must not be
            // misidentified as an EACCES I/O error.
            let entries = reader.enumerate_dir(None, limits).await.unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].name(), "single_file.txt");
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_enumerate_dir_offload_thread_assertion() {
            let fixture = TempDir::new().unwrap();
            let reader = FsMetadataReader::open(fixture.path()).unwrap();
            let caller_tid = std::thread::current().id();
            let worker_tid_cell = Arc::new(std::sync::Mutex::new(None));
            let wtc = Arc::clone(&worker_tid_cell);

            let hooks = DirTestHooks {
                before_open: Some(Arc::new(move || {
                    *wtc.lock().unwrap() = Some(std::thread::current().id());
                })),
                ..Default::default()
            };

            let reader = reader.with_dir_test_hooks(hooks);
            let limits = DirEnumerationLimits::new(10, 100);
            let _ = reader.enumerate_dir(None, limits).await.unwrap();

            let worker_tid = worker_tid_cell
                .lock()
                .unwrap()
                .expect("worker thread hook must have executed");
            assert_ne!(
                caller_tid, worker_tid,
                "directory enumeration closure must execute on Tokio blocking pool, not caller thread"
            );
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_enumerate_dir_runtime_missing_and_task_join_failed() {
            let fixture = TempDir::new().unwrap();
            let root = fixture.path().join("root");
            fs::create_dir_all(&root).unwrap();

            let reader = FsMetadataReader::open(&root).unwrap();
            let limits = DirEnumerationLimits::new(10, 100);

            // 1. Task JoinError simulation (panic inside blocking closure)
            let hooks_panic = DirTestHooks {
                before_open: Some(Arc::new(|| {
                    panic!("simulated task panic");
                })),
                ..Default::default()
            };

            let reader_panic = FsMetadataReader::open(&root)
                .unwrap()
                .with_dir_test_hooks(hooks_panic);

            let err_panic = reader_panic.enumerate_dir(None, limits).await.unwrap_err();
            match err_panic {
                FsDirError::TaskJoinFailed(e) => assert!(e.is_panic()),
                other => panic!("expected TaskJoinFailed, got: {other:?}"),
            }

            // 2. RuntimeMissing when polled outside an entered runtime
            let thread_join = std::thread::spawn(move || {
                let fut = reader.enumerate_dir(None, limits);
                tokio::pin!(fut);
                let waker = futures_util_waker();
                let mut cx = std::task::Context::from_waker(&waker);
                fut.as_mut().poll(&mut cx)
            })
            .join()
            .unwrap();

            match thread_join {
                std::task::Poll::Ready(Err(FsDirError::RuntimeMissing(_))) => {}
                other => panic!("expected Ready(Err(RuntimeMissing)), got: {other:?}"),
            }
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_enumerate_dir_cleanup_on_failed_acquisition_injected() {
            let fixture = TempDir::new().unwrap();
            let root = fixture.path().join("root");
            fs::create_dir_all(&root).unwrap();

            let opened_raw_fd = Arc::new(std::sync::atomic::AtomicI32::new(-1));
            let closed_fd_record = Arc::new(std::sync::atomic::AtomicI32::new(-1));
            let fd_closed_count = Arc::new(AtomicUsize::new(0));

            let ofd = Arc::clone(&opened_raw_fd);
            let cfd = Arc::clone(&closed_fd_record);
            let fcc = Arc::clone(&fd_closed_count);

            let hooks = DirTestHooks {
                after_openat2: Some(Arc::new(move |owned_fd| {
                    ofd.store(owned_fd.as_raw_fd(), Ordering::SeqCst);
                })),
                simulate_fdopendir_error: Some(Arc::new(|| {
                    std::io::Error::other("injected simulated fdopendir failure")
                })),
                on_fd_closed: Some(Arc::new(move |raw| {
                    cfd.store(raw, Ordering::SeqCst);
                    fcc.fetch_add(1, Ordering::SeqCst);
                })),
                ..Default::default()
            };

            let reader = FsMetadataReader::open(&root)
                .unwrap()
                .with_dir_test_hooks(hooks);
            let limits = DirEnumerationLimits::new(10, 100);

            let err = reader.enumerate_dir(None, limits).await.unwrap_err();
            match err {
                FsDirError::Io { source } => {
                    assert_eq!(source.to_string(), "injected simulated fdopendir failure");
                }
                other => panic!("expected injected Io error, got: {other:?}"),
            }

            let recorded_opened_fd = opened_raw_fd.load(Ordering::SeqCst);
            assert!(
                recorded_opened_fd >= 0,
                "opened descriptor must have been recorded"
            );
            assert_eq!(
                fd_closed_count.load(Ordering::SeqCst),
                1,
                "owned_fd cleanup path must have executed exactly once upon drop"
            );
            assert_eq!(
                closed_fd_record.load(Ordering::SeqCst),
                recorded_opened_fd,
                "cleanup path must have dropped the acquired descriptor"
            );
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_enumerate_dir_cleanup_on_successful_enumeration() {
            let fixture = TempDir::new().unwrap();
            let root = fixture.path().join("root");
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join("file.txt"), b"").unwrap();

            let opened_raw_fd = Arc::new(std::sync::atomic::AtomicI32::new(-1));
            let closed_fd_record = Arc::new(std::sync::atomic::AtomicI32::new(-1));
            let closedir_status_record = Arc::new(std::sync::atomic::AtomicI32::new(-1));
            let dir_closed_count = Arc::new(AtomicUsize::new(0));

            let ofd = Arc::clone(&opened_raw_fd);
            let cfd = Arc::clone(&closed_fd_record);
            let csr = Arc::clone(&closedir_status_record);
            let dcc = Arc::clone(&dir_closed_count);

            let hooks = DirTestHooks {
                after_openat2: Some(Arc::new(move |owned_fd| {
                    ofd.store(owned_fd.as_raw_fd(), Ordering::SeqCst);
                })),
                on_dir_closed: Some(Arc::new(move |fd, status| {
                    cfd.store(fd, Ordering::SeqCst);
                    csr.store(status, Ordering::SeqCst);
                    dcc.fetch_add(1, Ordering::SeqCst);
                })),
                ..Default::default()
            };

            let reader = FsMetadataReader::open(&root)
                .unwrap()
                .with_dir_test_hooks(hooks);
            let limits = DirEnumerationLimits::new(10, 100);

            let entries = reader.enumerate_dir(None, limits).await.unwrap();
            assert_eq!(entries.len(), 1);

            let recorded_opened_fd = opened_raw_fd.load(Ordering::SeqCst);
            assert!(
                recorded_opened_fd >= 0,
                "opened descriptor must have been recorded"
            );
            assert_eq!(
                dir_closed_count.load(Ordering::SeqCst),
                1,
                "DirGuard::drop must have executed exactly once upon completion"
            );
            assert_eq!(
                closed_fd_record.load(Ordering::SeqCst),
                recorded_opened_fd,
                "closed descriptor must match acquired directory descriptor"
            );
            assert_eq!(
                closedir_status_record.load(Ordering::SeqCst),
                0,
                "libc::closedir must return 0 indicating clean descriptor closure"
            );
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_enumerate_dir_cleanup_on_early_error_after_acquisition() {
            let fixture = TempDir::new().unwrap();
            let root = fixture.path().join("root");
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join("file.txt"), b"").unwrap();

            let opened_raw_fd = Arc::new(std::sync::atomic::AtomicI32::new(-1));
            let closed_fd_record = Arc::new(std::sync::atomic::AtomicI32::new(-1));
            let closedir_status_record = Arc::new(std::sync::atomic::AtomicI32::new(-1));
            let dir_closed_count = Arc::new(AtomicUsize::new(0));

            let ofd = Arc::clone(&opened_raw_fd);
            let cfd = Arc::clone(&closed_fd_record);
            let csr = Arc::clone(&closedir_status_record);
            let dcc = Arc::clone(&dir_closed_count);

            let hooks = DirTestHooks {
                after_openat2: Some(Arc::new(move |owned_fd| {
                    ofd.store(owned_fd.as_raw_fd(), Ordering::SeqCst);
                })),
                on_dir_closed: Some(Arc::new(move |fd, status| {
                    cfd.store(fd, Ordering::SeqCst);
                    csr.store(status, Ordering::SeqCst);
                    dcc.fetch_add(1, Ordering::SeqCst);
                })),
                ..Default::default()
            };

            let reader = FsMetadataReader::open(&root)
                .unwrap()
                .with_dir_test_hooks(hooks);
            // limits with max_entries == 0 causes early failure on first entry
            let limits = DirEnumerationLimits::new(0, 100);

            let err = reader.enumerate_dir(None, limits).await.unwrap_err();
            assert!(err.is_limit_exceeded());

            let recorded_opened_fd = opened_raw_fd.load(Ordering::SeqCst);
            assert!(
                recorded_opened_fd >= 0,
                "opened descriptor must have been recorded"
            );
            assert_eq!(
                dir_closed_count.load(Ordering::SeqCst),
                1,
                "DirGuard::drop must have executed on early error exit"
            );
            assert_eq!(
                closed_fd_record.load(Ordering::SeqCst),
                recorded_opened_fd,
                "closed descriptor must match acquired directory descriptor"
            );
            assert_eq!(
                closedir_status_record.load(Ordering::SeqCst),
                0,
                "libc::closedir must return 0 indicating clean descriptor closure on early abort"
            );
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_stream_dir_async_and_cancellation() {
            let fixture = TempDir::new().unwrap();
            let root = fixture.path().join("root");
            fs::create_dir_all(&root).unwrap();

            for i in 0..10 {
                fs::write(root.join(format!("file_{i:02}")), b"content").unwrap();
            }

            let reader = FsMetadataReader::open(&root).unwrap();
            let mut stream = reader.stream_dir(None).unwrap();

            let mut count = 0;
            while let Some(res) = stream.next_entry().await {
                let entry = res.unwrap();
                assert_eq!(entry.file_type(), DirEntryType::Regular);
                count += 1;
                if count == 3 {
                    // Early drop / cancellation
                    break;
                }
            }
            drop(stream);

            // Re-stream all
            let mut stream_all = reader.stream_dir(None).unwrap();
            let mut all_count = 0;
            while let Some(res) = stream_all.next_entry().await {
                let _ = res.unwrap();
                all_count += 1;
            }
            assert_eq!(all_count, 10);
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_enumerate_dir_page_async() {
            use std::num::NonZeroUsize;
            let fixture = TempDir::new().unwrap();
            let root = fixture.path().join("root");
            fs::create_dir_all(&root).unwrap();

            for name in ["alpha", "bravo", "charlie", "delta", "echo"] {
                fs::write(root.join(name), b"test").unwrap();
            }

            let reader = FsMetadataReader::open(&root).unwrap();
            let limit = NonZeroUsize::new(2).unwrap();

            // Page 1
            let (p1, more1) = reader.enumerate_dir_page(None, None, limit).await.unwrap();
            assert_eq!(p1, vec!["alpha", "bravo"]);
            assert!(more1);

            // Page 2
            let (p2, more2) = reader
                .enumerate_dir_page(None, p1.last().map(|s| s.as_str()), limit)
                .await
                .unwrap();
            assert_eq!(p2, vec!["charlie", "delta"]);
            assert!(more2);

            // Page 3
            let (p3, more3) = reader
                .enumerate_dir_page(None, p2.last().map(|s| s.as_str()), limit)
                .await
                .unwrap();
            assert_eq!(p3, vec!["echo"]);
            assert!(!more3);
        }

        fn futures_util_waker() -> std::task::Waker {
            use std::task::{RawWaker, RawWakerVTable, Waker};
            unsafe fn clone(_: *const ()) -> RawWaker {
                dummy_raw_waker()
            }
            unsafe fn wake(_: *const ()) {}
            unsafe fn wake_by_ref(_: *const ()) {}
            unsafe fn drop(_: *const ()) {}
            static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
            fn dummy_raw_waker() -> RawWaker {
                RawWaker::new(std::ptr::null(), &VTABLE)
            }
            unsafe { Waker::from_raw(dummy_raw_waker()) }
        }
    }
}
