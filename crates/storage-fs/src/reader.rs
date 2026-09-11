//! Filesystem metadata reader implementation over a pinned directory descriptor.

#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::sync::Arc;

use async_trait::async_trait;
use storage_core::{
    ObjectKey, ObjectMetadata, ObjectMetadataReader, ObjectPayload, ObjectPayloadReader,
    ObjectStream, ReadError,
};

use crate::error::FsMetadataError;

pub(crate) mod inspect;
pub(crate) mod payload;

pub use inspect::FsFileMetadata;

#[cfg(all(test, target_os = "linux"))]
pub(crate) use payload::PayloadTestHooks;

#[cfg(all(test, target_os = "linux"))]
type BeforeLookupHook = Arc<dyn Fn(&OwnedFd, &ObjectKey) + Send + Sync>;
#[cfg(all(test, target_os = "linux"))]
type OnCompleteHook = Arc<dyn Fn(Result<&ObjectMetadata, &ReadError>) + Send + Sync>;

/// Narrowly scoped test hooks for verifying the internal blocking execution boundary.
#[cfg(all(test, target_os = "linux"))]
#[derive(Clone, Default)]
pub(crate) struct TestHooks {
    pub(crate) before_lookup: Option<BeforeLookupHook>,
    pub(crate) on_complete: Option<OnCompleteHook>,
}

#[cfg(all(test, target_os = "linux"))]
impl std::fmt::Debug for TestHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestHooks")
            .field("before_lookup", &self.before_lookup.is_some())
            .field("on_complete", &self.on_complete.is_some())
            .finish()
    }
}

#[cfg(all(test, target_os = "linux"))]
impl TestHooks {
    pub(crate) fn before<F>(hook: F) -> Self
    where
        F: Fn(&OwnedFd, &ObjectKey) + Send + Sync + 'static,
    {
        Self {
            before_lookup: Some(Arc::new(hook)),
            on_complete: None,
        }
    }
}

/// Standalone filesystem metadata reader enforcing descriptor-relative resolution.
///
/// Operates over a pinned root directory descriptor. On Linux, path queries are resolved
/// beneath this pinned descriptor via `openat2` with
/// `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
///
/// # Execution Boundary and Concurrency
/// - Potentially blocking filesystem operations (`openat2`, `fstat`, `/proc/self/fd` reopening)
///   are offloaded to Tokio's blocking thread pool (`tokio::task::spawn_blocking`) to avoid
///   stalling the async caller's worker thread during initial descriptor resolution.
/// - Invoking [`head`](ObjectMetadataReader::head) requires being called within the context
///   of an entered Tokio runtime. If polled outside a Tokio runtime, the lookup fails immediately
///   with [`FsMetadataError::RuntimeMissing`] wrapped in [`ReadError::Backend`].
/// - Constructor [`open`](Self::open) remains synchronous and performs root directory acquisition
///   on the caller thread.
/// - [`open`](Self::open) opens the directory with `O_PATH` and does not issue `openat2`; thus,
///   successful opening does not establish kernel `openat2` availability. Availability is verified
///   during lookup.
///
/// # Cancellation and Lifecycle Semantics
/// - Each blocking lookup task holds an owned reference ([`Arc<OwnedFd>`]) to the pinned root
///   descriptor and an owned [`ObjectKey`].
/// - Dropping or cancelling the awaiting future returned by [`head`](ObjectMetadataReader::head)
///   does not reliably abort or stop blocking work that has already started on Tokio's blocking pool.
/// - However, the owned task state guarantees descriptor validity and lifetime: even if the reader
///   or future is dropped, the root descriptor remains open until the in-flight blocking task completes.
/// - Runtime shutdown and unresponsive filesystem stalls (e.g. frozen network filesystems) retain
///   standard blocking-task limitations; userspace cannot guarantee bounded syscall completion.
///
/// # Platform Support
/// Requires Linux `openat2`. On non-Linux platforms, construction and lookups fail explicitly
/// with [`FsMetadataError::PlatformUnsupported`]. Non-Linux execution is neither verified nor supported
/// with fallbacks.
#[derive(Debug)]
pub struct FsMetadataReader {
    root_path: PathBuf,
    #[cfg(target_os = "linux")]
    root_fd: Arc<OwnedFd>,
    #[cfg(all(test, target_os = "linux"))]
    test_hooks: Option<TestHooks>,
    #[cfg(all(test, target_os = "linux"))]
    payload_test_hooks: Option<PayloadTestHooks>,
    #[cfg(all(test, target_os = "linux"))]
    dir_test_hooks: Option<crate::dir::DirTestHooks>,
    #[cfg(all(test, target_os = "linux"))]
    inspect_test_hooks: Option<inspect::InspectTestHooks>,
}

impl FsMetadataReader {
    /// Opens an existing configured directory once and pins an owned descriptor.
    ///
    /// # Semantics
    /// - Performs root acquisition synchronously on the caller thread.
    /// - Does not create missing directories.
    /// - An initial symlink configured as root resolves once during this open call;
    ///   the acquired descriptor becomes the sole pinned authority for all subsequent lookups.
    /// - The configured pathname is never re-resolved during subsequent queries.
    /// - Rejects empty paths and paths containing embedded NUL bytes.
    /// - Opening with `O_PATH` does not issue `openat2` and does not establish `openat2` availability.
    ///
    /// # Platform Support
    /// Requires Linux `openat2`. On non-Linux platforms, returns [`FsMetadataError::PlatformUnsupported`].
    pub fn open(root_path: impl AsRef<Path>) -> Result<Self, FsMetadataError> {
        let root_path = root_path.as_ref().to_path_buf();
        if root_path.as_os_str().is_empty() {
            return Err(FsMetadataError::EmptyRootPath);
        }

        #[cfg(target_os = "linux")]
        {
            let c_path = CString::new(root_path.as_os_str().as_bytes())
                .map_err(|_| FsMetadataError::NulInRootPath)?;

            let raw_fd = unsafe {
                libc::open(
                    c_path.as_ptr(),
                    libc::O_DIRECTORY | libc::O_PATH | libc::O_CLOEXEC,
                )
            };
            if raw_fd < 0 {
                let err = std::io::Error::last_os_error();
                return Err(FsMetadataError::RootOpenFailed { source: err });
            }

            let root_fd = Arc::new(unsafe { OwnedFd::from_raw_fd(raw_fd) });
            Ok(Self {
                root_path,
                root_fd,
                #[cfg(all(test, target_os = "linux"))]
                test_hooks: None,
                #[cfg(all(test, target_os = "linux"))]
                payload_test_hooks: None,
                #[cfg(all(test, target_os = "linux"))]
                dir_test_hooks: None,
                #[cfg(all(test, target_os = "linux"))]
                inspect_test_hooks: None,
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = root_path;
            Err(FsMetadataError::PlatformUnsupported)
        }
    }

    /// Returns the configured path of the root directory.
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    /// Probes whether the host kernel and container execution environment permit descriptor-relative `openat2` resolution.
    ///
    /// This is an explicit public backend-specific API on [`FsMetadataReader`] with a private syscall implementation.
    /// No automatic invocation from [`open`](Self::open) or [`head`](storage_core::ObjectMetadataReader::head) is introduced;
    /// downstream integration remains deferred.
    ///
    /// # Scope of Success
    /// Success indicates narrowly that the exact `"."` `openat2` lookup with the specified resolution flags,
    /// followed by directory metadata inspection, succeeded against the pinned root directory descriptor on the
    /// calling thread at that time.
    ///
    /// # Execution Context
    /// - **Synchronous & Potentially Blocking**: This method executes synchronously on the caller thread and may block
    ///   on filesystem operations. It should not be called directly on an async executor worker thread.
    /// - If invoked during application startup (e.g. before network listeners are bound), it provides deterministic
    ///   initialization-time validation without requiring an entered Tokio runtime or thread pool dispatch.
    /// - **Limitations**: If the pinned root directory resides on an unresponsive or stalled network filesystem (e.g. NFS or FUSE),
    ///   the calling thread may block indefinitely, identically to [`open`](Self::open).
    ///
    /// # Important Contract Distinction
    /// - `"."` is rejected as an [`ObjectKey`](storage_core::ObjectKey) by design (`ObjectKeyError::DotSegment`).
    /// - This method is a backend-private syscall probe on [`FsMetadataReader`]; it does **not** construct
    ///   an `ObjectKey` and does not route through the regular-file-only [`head`](storage_core::ObjectMetadataReader::head) method.
    ///   `ObjectKey` validation rules are preserved without weakening.
    ///
    /// # Error Mapping
    /// - [`FsMetadataError::SyscallUnsupported`]: The `openat2` syscall returned `ENOSYS`.
    /// - [`FsMetadataError::ProbeDenied`]: Returned `EACCES` or `EPERM`. This may arise from DAC permissions, LSM restrictions,
    ///   mount options, or container seccomp filters. Note: `EACCES`/`EPERM` cannot be inferred as uniquely caused by seccomp.
    /// - [`FsMetadataError::ProbeFailed`]: An unexpected OS error occurred during `openat2` (e.g. `EMFILE`, `EIO`) or `fstat`.
    /// - [`FsMetadataError::UnsupportedObjectType`]: The opened descriptor unexpectedly did not stat as a directory (`S_IFDIR`).
    /// - [`FsMetadataError::PlatformUnsupported`]: The target platform is not Linux.
    ///
    /// # Boundaries and Non-Guarantees
    /// This probe does **not**:
    /// 1. Establish equivalent permissions or syscall filtering on Tokio blocking-pool threads.
    /// 2. Establish that child paths, subdirectories, or blobs exist or can be created.
    /// 3. Exercise multi-component path resolution across subdirectories.
    /// 4. Verify regular-file lookup (`S_IFREG`), because `"."` is a directory (`S_IFDIR`).
    /// 5. Establish payload read permissions (`O_RDONLY`) or write permissions on child objects (`O_PATH` success is not proof of ordinary read or write permission).
    /// 6. Establish root coherence across pathname-based reads and mutations.
    /// 7. Establish future availability or guarantee against dynamic runtime reconfiguration (e.g. late seccomp loading, remounts, or storage media failures).
    /// 8. Close quality gate **O-05** or establish production readiness.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(target_os = "linux")]
    /// # {
    /// use storage_fs::FsMetadataReader;
    ///
    /// let temp_dir = tempfile::tempdir().unwrap();
    /// let reader = FsMetadataReader::open(temp_dir.path()).unwrap();
    /// reader.probe_capability().unwrap();
    /// # }
    /// ```
    pub fn probe_capability(&self) -> Result<(), FsMetadataError> {
        #[cfg(target_os = "linux")]
        {
            Self::probe_capability_sync(&self.root_fd)
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(FsMetadataError::PlatformUnsupported)
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn with_test_hooks(mut self, hooks: TestHooks) -> Self {
        self.test_hooks = Some(hooks);
        self
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn with_payload_test_hooks(mut self, hooks: PayloadTestHooks) -> Self {
        self.payload_test_hooks = Some(hooks);
        self
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn with_dir_test_hooks(mut self, hooks: crate::dir::DirTestHooks) -> Self {
        self.dir_test_hooks = Some(hooks);
        self
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn with_inspect_test_hooks(mut self, hooks: inspect::InspectTestHooks) -> Self {
        self.inspect_test_hooks = Some(hooks);
        self
    }

    /// Bounded, descriptor-relative directory enumeration over the pinned root descriptor.
    ///
    /// Resolves `target` relative to the pinned root directory descriptor using Linux `openat2`
    /// with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, and collects directory
    /// entries up to the caller-specified resource limits.
    ///
    /// # Target Resolution
    /// - `target: None` targets the pinned root directory itself (`"."`).
    /// - `target: Some(key)` targets a verified relative subdirectory path beneath the root.
    ///
    /// # Resource Accounting & Zero-Limit Semantics
    /// Caller-supplied [`DirEnumerationLimits`](crate::dir::DirEnumerationLimits) constrain the maximum
    /// returned entries and cumulative name bytes. An empty directory succeeds under zero limits;
    /// if non-empty, the first entry exceeding either budget fails closed with
    /// [`FsDirError::LimitExceeded`](crate::dir::FsDirError::LimitExceeded) without partial results.
    ///
    /// # Observation Semantics
    /// Returned [`DirEntryType`](crate::dir::DirEntryType) values are point-in-time observations during iteration,
    /// not capabilities authorizing subsequent pathname access.
    ///
    /// # Platform Support
    /// Requires Linux `openat2`. On non-Linux platforms, returns [`FsDirError::PlatformUnsupported`](crate::dir::FsDirError::PlatformUnsupported).
    pub async fn enumerate_dir(
        &self,
        target: Option<&ObjectKey>,
        limits: crate::dir::DirEnumerationLimits,
    ) -> Result<Vec<crate::dir::DirEntry>, crate::dir::FsDirError> {
        #[cfg(target_os = "linux")]
        {
            crate::dir::enumerate_dir_async(
                &self.root_fd,
                target,
                limits,
                #[cfg(test)]
                self.dir_test_hooks.as_ref(),
            )
            .await
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (target, limits);
            Err(crate::dir::FsDirError::PlatformUnsupported)
        }
    }

    /// Descriptor-relative inspection of filesystem attributes beneath the pinned root.
    ///
    /// Resolves `key` beneath the pinned root directory descriptor via Linux `openat2` with:
    /// `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`
    /// and queries attributes via `fstat` after descriptor acquisition.
    ///
    /// # Error Classification & Boundaries
    /// - Symlinks encountered during resolution are rejected with [`crate::error::FsMetadataError::ResolutionRejected`].
    /// - Only regular files (`S_IFREG`) succeed; acquired non-regular objects (directories, FIFOs,
    ///   character/block devices, sockets) reject with [`crate::error::FsMetadataError::UnsupportedObjectType`].
    ///
    /// # Observation Semantics
    /// - Attributes are observed by `fstat` after descriptor acquisition, not at the instant of `openat2` resolution.
    /// - One `fstat` result does not guarantee an atomic snapshot of all attributes under concurrent mutation.
    ///
    /// # Platform Support
    /// Requires Linux `openat2`. On non-Linux platforms, returns
    /// [`ReadError::Backend`] wrapping [`FsMetadataError::PlatformUnsupported`].
    /// Non-Linux compilation and execution remain unverified in the absence of a cross-compilation environment.
    pub async fn inspect_file_metadata(
        &self,
        key: &ObjectKey,
    ) -> Result<FsFileMetadata, ReadError> {
        #[cfg(target_os = "linux")]
        {
            let handle = match tokio::runtime::Handle::try_current() {
                Ok(h) => h,
                Err(e) => {
                    return Err(ReadError::backend_with_source(
                        "tokio runtime required to execute blocking metadata inspection",
                        Box::new(FsMetadataError::RuntimeMissing(e)),
                    ));
                }
            };

            let root_fd = Arc::clone(&self.root_fd);
            let key = key.clone();
            #[cfg(test)]
            let inspect_test_hooks = self.inspect_test_hooks.clone();

            let join_res = handle
                .spawn_blocking(move || {
                    let res = inspect::inspect_file_metadata_sync(
                        &root_fd,
                        &key,
                        #[cfg(test)]
                        inspect_test_hooks.as_ref(),
                    );

                    #[cfg(test)]
                    if let Some(on_complete) = inspect_test_hooks
                        .as_ref()
                        .and_then(|h| h.on_complete.as_ref())
                    {
                        on_complete(res.as_ref());
                    }

                    res
                })
                .await;

            match join_res {
                Ok(result) => result,
                Err(join_err) => Err(ReadError::backend_with_source(
                    "blocking metadata inspection task failed",
                    Box::new(FsMetadataError::TaskJoinFailed(join_err)),
                )),
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = key;
            Err(ReadError::backend_with_source(
                "platform unsupported: descriptor-relative containment requires Linux openat2",
                Box::new(FsMetadataError::PlatformUnsupported),
            ))
        }
    }
}

#[async_trait]
impl ObjectMetadataReader for FsMetadataReader {
    async fn head(&self, key: &ObjectKey) -> Result<ObjectMetadata, ReadError> {
        #[cfg(target_os = "linux")]
        {
            let handle = match tokio::runtime::Handle::try_current() {
                Ok(handle) => handle,
                Err(err) => {
                    return Err(ReadError::backend_with_source(
                        "tokio runtime required to execute blocking metadata lookup",
                        Box::new(FsMetadataError::RuntimeMissing(err)),
                    ));
                }
            };

            let root_fd = Arc::clone(&self.root_fd);
            let key = key.clone();
            #[cfg(test)]
            let test_hooks = self.test_hooks.clone();

            let join_res = handle
                .spawn_blocking(move || {
                    #[cfg(test)]
                    if let Some(before) = test_hooks.as_ref().and_then(|h| h.before_lookup.as_ref())
                    {
                        before(&root_fd, &key);
                    }

                    let res = Self::head_sync(&root_fd, &key);

                    #[cfg(test)]
                    if let Some(on_complete) =
                        test_hooks.as_ref().and_then(|h| h.on_complete.as_ref())
                    {
                        on_complete(res.as_ref());
                    }

                    res
                })
                .await;

            match join_res {
                Ok(result) => result,
                Err(join_err) => Err(ReadError::backend_with_source(
                    "blocking metadata lookup task failed",
                    Box::new(FsMetadataError::TaskJoinFailed(join_err)),
                )),
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = key;
            Err(ReadError::backend_with_source(
                "platform unsupported: descriptor-relative containment requires Linux openat2",
                Box::new(FsMetadataError::PlatformUnsupported),
            ))
        }
    }
}

#[async_trait]
impl ObjectPayloadReader for FsMetadataReader {
    async fn open_payload(&self, key: &ObjectKey) -> Result<ObjectPayload, ReadError> {
        #[cfg(target_os = "linux")]
        {
            let handle = match tokio::runtime::Handle::try_current() {
                Ok(handle) => handle,
                Err(err) => {
                    return Err(ReadError::backend_with_source(
                        "tokio runtime required to execute blocking payload acquisition",
                        Box::new(FsMetadataError::RuntimeMissing(err)),
                    ));
                }
            };

            let root_fd = Arc::clone(&self.root_fd);
            let key = key.clone();
            #[cfg(test)]
            let payload_test_hooks = self.payload_test_hooks.clone();

            let join_res = handle
                .spawn_blocking(move || {
                    payload::acquire_payload_sync(
                        &root_fd,
                        &key,
                        #[cfg(test)]
                        payload_test_hooks.as_ref(),
                    )
                })
                .await;

            match join_res {
                Ok(Ok((metadata, std_file))) => {
                    let tokio_file = tokio::fs::File::from_std(std_file);
                    let stream: ObjectStream = Box::pin(tokio_file);
                    Ok(ObjectPayload::new(metadata, stream))
                }
                Ok(Err(read_err)) => Err(read_err),
                Err(join_err) => Err(ReadError::backend_with_source(
                    "blocking payload acquisition task failed",
                    Box::new(FsMetadataError::TaskJoinFailed(join_err)),
                )),
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = key;
            Err(ReadError::backend_with_source(
                "platform unsupported: descriptor-relative containment requires Linux openat2",
                Box::new(FsMetadataError::PlatformUnsupported),
            ))
        }
    }
}

#[cfg(target_os = "linux")]
impl FsMetadataReader {
    pub(crate) fn probe_capability_sync(root_fd: &OwnedFd) -> Result<(), FsMetadataError> {
        // Direct C-string representation of ".". ObjectKey strictly rejects ".", but this
        // backend-private syscall probe operates directly with a raw C string.
        let c_dot = c".";

        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
        how.mode = 0;
        how.resolve =
            libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;

        let res = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root_fd.as_raw_fd(),
                c_dot.as_ptr(),
                &how,
                std::mem::size_of::<libc::open_how>(),
            )
        };

        if res < 0 {
            let err = std::io::Error::last_os_error();
            return Err(classify_openat2_probe_error(err));
        }

        // Wrap the target descriptor in OwnedFd immediately to guarantee leak-free cleanup
        let probed_fd = unsafe { OwnedFd::from_raw_fd(res as i32) };

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let stat_res = unsafe { libc::fstat(probed_fd.as_raw_fd(), &mut st) };
        if stat_res != 0 {
            let err = std::io::Error::last_os_error();
            return Err(classify_fstat_probe_error(err));
        }

        let mode_type = st.st_mode & libc::S_IFMT;
        if mode_type != libc::S_IFDIR {
            return Err(FsMetadataError::UnsupportedObjectType { mode: st.st_mode });
        }

        Ok(())
    }

    fn head_sync(root_fd: &OwnedFd, key: &ObjectKey) -> Result<ObjectMetadata, ReadError> {
        // ObjectKey guarantees non-empty, normalized relative structure without
        // leading/trailing/repeated slashes, dot/dot-dot segments, backslashes, or control characters.
        let c_rel = CString::new(key.as_str()).map_err(|_| {
            ReadError::backend_with_source(
                "invalid relative path key",
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "key contains embedded NUL",
                )),
            )
        })?;

        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
        how.mode = 0;
        how.resolve =
            libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;

        let res = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root_fd.as_raw_fd(),
                c_rel.as_ptr(),
                &how,
                std::mem::size_of::<libc::open_how>(),
            )
        };

        if res < 0 {
            let err = std::io::Error::last_os_error();
            return Err(classify_openat2_error(key, err));
        }

        // Wrap the target descriptor in OwnedFd immediately to guarantee leak-free cleanup
        let target_fd = unsafe { OwnedFd::from_raw_fd(res as i32) };

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let stat_res = unsafe { libc::fstat(target_fd.as_raw_fd(), &mut st) };
        if stat_res != 0 {
            let err = std::io::Error::last_os_error();
            return Err(match err.raw_os_error() {
                Some(libc::EACCES) | Some(libc::EPERM) => {
                    ReadError::permission_denied_with_source(key.clone(), Box::new(err))
                }
                _ => ReadError::backend_with_source("metadata stat failure", Box::new(err)),
            });
        }

        check_stat_and_extract_metadata(&st)
    }
}

/// Classifies raw OS errors returned by `openat2` during capability probing.
#[cfg(target_os = "linux")]
pub(crate) fn classify_openat2_probe_error(err: std::io::Error) -> FsMetadataError {
    match err.raw_os_error() {
        Some(libc::ENOSYS) => FsMetadataError::SyscallUnsupported(err),
        Some(libc::EACCES) | Some(libc::EPERM) => FsMetadataError::ProbeDenied(err),
        _ => FsMetadataError::ProbeFailed { source: err },
    }
}

/// Classifies raw OS errors returned by `fstat` during capability probing.
///
/// An `fstat` failure (including `ENOSYS`) represents an unexpected metadata inspection
/// failure on an opened descriptor, not an `openat2` availability rejection.
#[cfg(target_os = "linux")]
pub(crate) fn classify_fstat_probe_error(err: std::io::Error) -> FsMetadataError {
    FsMetadataError::ProbeFailed { source: err }
}

/// Classifies raw OS errors returned by `openat2` without parsing rendered strings.
#[cfg(target_os = "linux")]
pub(crate) fn classify_openat2_error(key: &ObjectKey, err: std::io::Error) -> ReadError {
    match err.raw_os_error() {
        Some(libc::ENOENT) => ReadError::not_found(key.clone()),
        Some(libc::EACCES) | Some(libc::EPERM) => {
            ReadError::permission_denied_with_source(key.clone(), Box::new(err))
        }
        Some(libc::ENOSYS) => ReadError::backend_with_source(
            "openat2 is unavailable in this execution environment",
            Box::new(FsMetadataError::SyscallUnsupported(err)),
        ),
        Some(raw @ libc::EXDEV) | Some(raw @ libc::ELOOP) => ReadError::backend_with_source(
            "resolution rejected by kernel containment policy",
            Box::new(FsMetadataError::ResolutionRejected {
                raw_os_error: raw,
                source: err,
            }),
        ),
        _ => ReadError::backend_with_source("filesystem metadata resolution failed", Box::new(err)),
    }
}

/// Validates the opened descriptor's file type and converts its size.
///
/// Only regular files (`S_IFREG`) are accepted. Any other object type (directories,
/// symlinks, FIFOs, sockets, device nodes) is rejected honestly at the application level
/// as [`FsMetadataError::UnsupportedObjectType`] without fabricating a causal OS errno.
#[cfg(target_os = "linux")]
pub(crate) fn check_stat_and_extract_metadata(
    st: &libc::stat,
) -> Result<ObjectMetadata, ReadError> {
    let mode_type = st.st_mode & libc::S_IFMT;
    if mode_type != libc::S_IFREG {
        return Err(ReadError::backend_with_source(
            "unsupported object type: regular file required",
            Box::new(FsMetadataError::UnsupportedObjectType { mode: st.st_mode }),
        ));
    }

    if st.st_size < 0 {
        return Err(ReadError::backend_with_source(
            "invalid metadata: negative file size",
            Box::new(FsMetadataError::InvalidMetadata {
                message: "negative file size in metadata",
            }),
        ));
    }

    let size = u64::try_from(st.st_size).map_err(|_| {
        ReadError::backend_with_source(
            "invalid metadata: file size conversion failed",
            Box::new(FsMetadataError::InvalidMetadata {
                message: "file size conversion failed",
            }),
        )
    })?;

    Ok(ObjectMetadata::new(size))
}

#[cfg(all(test, not(target_os = "linux")))]
mod non_linux_tests {
    use super::*;

    #[test]
    fn test_fs_metadata_non_linux_platform_unsupported_on_nonempty_path() {
        let err = FsMetadataReader::open("some_nonempty_path").expect_err("must fail on non-linux");
        assert!(matches!(err, FsMetadataError::PlatformUnsupported));
    }

    #[test]
    fn test_fs_metadata_non_linux_empty_path_validation_preserved() {
        let err = FsMetadataReader::open("").expect_err("empty path must fail first");
        assert!(matches!(err, FsMetadataError::EmptyRootPath));
    }

    #[test]
    fn test_fs_metadata_non_linux_probe_capability_platform_unsupported() {
        let reader = FsMetadataReader {
            root_path: PathBuf::from("nonempty_path"),
        };
        let err = reader
            .probe_capability()
            .expect_err("must fail on non-linux");
        assert!(matches!(err, FsMetadataError::PlatformUnsupported));
    }

    #[tokio::test]
    async fn test_fs_metadata_non_linux_inspect_file_metadata_platform_unsupported() {
        let reader = FsMetadataReader {
            root_path: PathBuf::from("nonempty_path"),
        };
        let key = ObjectKey::parse("test.bin").unwrap();
        let err = reader
            .inspect_file_metadata(&key)
            .await
            .expect_err("must fail on non-linux");
        assert!(err.is_backend());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use std::sync::Arc;

    /// RAII guard ensuring fixture directory permissions are restored on both normal path and panic.
    struct PermissionGuard<'a> {
        path: &'a Path,
        original_permissions: std::fs::Permissions,
        restored: bool,
    }

    impl<'a> PermissionGuard<'a> {
        fn new(path: &'a Path, original_permissions: std::fs::Permissions) -> Self {
            Self {
                path,
                original_permissions,
                restored: false,
            }
        }

        fn restore(&mut self) -> std::io::Result<()> {
            if !self.restored {
                std::fs::set_permissions(self.path, self.original_permissions.clone())?;
                self.restored = true;
            }
            Ok(())
        }
    }

    impl Drop for PermissionGuard<'_> {
        fn drop(&mut self) {
            if !self.restored {
                // Avoid secondary panic during unwinding if permission restoration fails.
                let _ = std::fs::set_permissions(self.path, self.original_permissions.clone());
                self.restored = true;
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_fs_metadata_empty_and_nonempty_and_sparse_files() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        std::fs::create_dir_all(&root_dir).expect("create root");
        let reader = FsMetadataReader::open(&root_dir).expect("open reader");

        // 1. Empty file
        let empty_path = root_dir.join("empty.bin");
        std::fs::write(&empty_path, b"").expect("write empty file");
        let empty_key = ObjectKey::parse("empty.bin").unwrap();
        let meta = reader.head(&empty_key).await.expect("head empty");
        assert_eq!(meta.size(), 0);
        assert_eq!(meta.len(), 0);
        assert!(meta.is_empty());

        // 2. Nonempty file
        let nonempty_path = root_dir.join("nonempty.bin");
        let content = b"standalone storage-fs metadata reader";
        std::fs::write(&nonempty_path, content).expect("write nonempty file");
        let nonempty_key = ObjectKey::parse("nonempty.bin").unwrap();
        let meta = reader.head(&nonempty_key).await.expect("head nonempty");
        assert_eq!(meta.size(), content.len() as u64);
        assert_eq!(meta.len(), content.len() as u64);
        assert!(!meta.is_empty());

        // 3. Sparse file above u32::MAX (8 GiB)
        let sparse_path = root_dir.join("sparse.bin");
        let sparse_file = std::fs::File::create(&sparse_path).expect("create sparse file");
        let expected_size: u64 = 8_589_934_592; // 8 GiB
        sparse_file
            .set_len(expected_size)
            .expect("set sparse length");
        let sparse_key = ObjectKey::parse("sparse.bin").unwrap();
        let meta = reader.head(&sparse_key).await.expect("head sparse");
        assert_eq!(meta.size(), expected_size);
        assert_eq!(meta.len(), expected_size);
        assert!(!meta.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_fs_metadata_nested_generic_keys() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        std::fs::create_dir_all(&root_dir).expect("create root");
        let reader = FsMetadataReader::open(&root_dir).expect("open reader");

        let test_cases = [
            ("blobs/sha256/deadbeef", b"blob content 1" as &[u8]),
            ("repos/acme/widget/manifests/v1.0", b"manifest content 2"),
            (
                "deep/hierarchy/level1/level2/level3/file.bin",
                b"deep content 3",
            ),
        ];

        for (raw_key, content) in test_cases {
            let key = ObjectKey::parse(raw_key).expect("parse key");
            let file_path = root_dir.join(raw_key);
            if let Some(parent) = file_path.parent() {
                std::fs::create_dir_all(parent).expect("create parent dirs");
            }
            std::fs::write(&file_path, content).expect("write file");

            let meta = reader.head(&key).await.expect("head on nested key");
            assert_eq!(meta.size(), content.len() as u64);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_fs_metadata_missing_object() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        std::fs::create_dir_all(&root_dir).expect("create root");
        let reader = FsMetadataReader::open(&root_dir).expect("open reader");

        let missing_key = ObjectKey::parse("does/not/exist.bin").unwrap();
        let err = reader
            .head(&missing_key)
            .await
            .expect_err("missing key must fail");

        assert!(err.is_not_found());
        assert!(!err.is_permission_denied());
        assert!(!err.is_backend());
        match err {
            ReadError::NotFound { key, .. } => assert_eq!(key, missing_key),
            other => panic!("expected ReadError::NotFound, got: {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_fs_metadata_final_symlinks_rejected() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        let outside_dir = fixture.path().join("outside");
        std::fs::create_dir_all(&root_dir).expect("create root");
        std::fs::create_dir_all(&outside_dir).expect("create outside");
        let reader = FsMetadataReader::open(&root_dir).expect("open reader");

        // 1. Inside-root symlink
        let inside_target = root_dir.join("inside_target.bin");
        std::fs::write(&inside_target, b"inside").expect("write inside");
        let inside_link = root_dir.join("inside_link.bin");
        std::os::unix::fs::symlink(&inside_target, &inside_link).expect("create inside link");

        // 2. Outside-root symlink
        let outside_target = outside_dir.join("outside_target.bin");
        std::fs::write(&outside_target, b"outside").expect("write outside");
        let outside_link = root_dir.join("outside_link.bin");
        std::os::unix::fs::symlink(&outside_target, &outside_link).expect("create outside link");

        // 3. Dangling symlink
        let dangling_link = root_dir.join("dangling_link.bin");
        std::os::unix::fs::symlink(root_dir.join("missing.bin"), &dangling_link)
            .expect("create dangling link");

        for link_name in ["inside_link.bin", "outside_link.bin", "dangling_link.bin"] {
            let key = ObjectKey::parse(link_name).unwrap();
            let err = reader
                .head(&key)
                .await
                .expect_err("final symlink must be rejected");

            assert!(
                !err.is_not_found(),
                "symlink {link_name} must not be mapped to NotFound"
            );
            assert!(
                err.is_backend(),
                "symlink {link_name} must map to Backend error"
            );

            let source = match err {
                ReadError::Backend { source, .. } => source.expect("source must be preserved"),
                other => panic!("unexpected error variant: {other:?}"),
            };

            let fs_err = source
                .downcast_ref::<FsMetadataError>()
                .expect("downcast to FsMetadataError");
            match fs_err {
                FsMetadataError::ResolutionRejected { raw_os_error, .. } => {
                    assert_eq!(*raw_os_error, libc::ELOOP);
                }
                other => panic!("expected ResolutionRejected with ELOOP, got: {other:?}"),
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_fs_metadata_intermediate_symlink_rejected() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        let outside_dir = fixture.path().join("outside");
        std::fs::create_dir_all(&root_dir).expect("create root");
        std::fs::create_dir_all(&outside_dir).expect("create outside");
        let reader = FsMetadataReader::open(&root_dir).expect("open reader");

        let outside_file = outside_dir.join("secret.bin");
        std::fs::write(&outside_file, b"secret content").expect("write outside file");

        // Symlink inside root pointing to outside directory
        let intermediate_link = root_dir.join("symlink_dir");
        std::os::unix::fs::symlink(&outside_dir, &intermediate_link).expect("create dir symlink");

        let key = ObjectKey::parse("symlink_dir/secret.bin").unwrap();
        let err = reader
            .head(&key)
            .await
            .expect_err("intermediate symlink must be rejected");

        assert!(err.is_backend());
        assert!(!err.is_not_found());
        let source = match err {
            ReadError::Backend { source, .. } => source.expect("source preserved"),
            other => panic!("unexpected error variant: {other:?}"),
        };
        let fs_err = source
            .downcast_ref::<FsMetadataError>()
            .expect("downcast to FsMetadataError");
        assert!(matches!(fs_err, FsMetadataError::ResolutionRejected { .. }));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_fs_metadata_directory_and_fifo_rejected() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        std::fs::create_dir_all(&root_dir).expect("create root");
        let reader = FsMetadataReader::open(&root_dir).expect("open reader");

        // 1. Directory rejection
        let sub_dir = root_dir.join("a_sub_directory");
        std::fs::create_dir_all(&sub_dir).expect("create subdir");
        let dir_key = ObjectKey::parse("a_sub_directory").unwrap();
        let dir_err = reader
            .head(&dir_key)
            .await
            .expect_err("directory must be rejected");

        assert!(dir_err.is_backend());
        let source = match dir_err {
            ReadError::Backend { source, .. } => source.expect("source preserved"),
            other => panic!("unexpected error variant: {other:?}"),
        };
        let fs_err = source
            .downcast_ref::<FsMetadataError>()
            .expect("downcast to FsMetadataError");
        match fs_err {
            FsMetadataError::UnsupportedObjectType { mode } => {
                assert_eq!(mode & libc::S_IFMT, libc::S_IFDIR);
            }
            other => panic!("expected UnsupportedObjectType for dir, got: {other:?}"),
        }

        // 2. FIFO rejection without blocking
        let fifo_path = root_dir.join("test_pipe");
        let c_fifo = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        let mkfifo_res = unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o644) };
        assert_eq!(
            mkfifo_res,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );

        let fifo_key = ObjectKey::parse("test_pipe").unwrap();
        let fifo_err = reader
            .head(&fifo_key)
            .await
            .expect_err("fifo must be rejected");

        assert!(fifo_err.is_backend());
        let source = match fifo_err {
            ReadError::Backend { source, .. } => source.expect("source preserved"),
            other => panic!("unexpected error variant: {other:?}"),
        };
        let fs_err = source
            .downcast_ref::<FsMetadataError>()
            .expect("downcast to FsMetadataError");
        match fs_err {
            FsMetadataError::UnsupportedObjectType { mode } => {
                assert_eq!(mode & libc::S_IFMT, libc::S_IFIFO);
            }
            other => panic!("expected UnsupportedObjectType for FIFO, got: {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_fs_metadata_root_pinning() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let orig_root = fixture.path().join("storage_root");
        std::fs::create_dir_all(&orig_root).expect("create orig root");

        let original_file = orig_root.join("data.bin");
        let original_content = b"original root content";
        std::fs::write(&original_file, original_content).expect("write original file");

        // Pin the root descriptor
        let reader = FsMetadataReader::open(&orig_root).expect("open reader");

        // Rename the original root directory
        let renamed_root = fixture.path().join("renamed_storage_root");
        std::fs::rename(&orig_root, &renamed_root).expect("rename root dir");

        // Create an attacker replacement directory at the original pathname with different file size
        std::fs::create_dir_all(&orig_root).expect("create replacement root");
        let replacement_file = orig_root.join("data.bin");
        let replacement_content = b"attacker replacement data with distinct length!";
        std::fs::write(&replacement_file, replacement_content).expect("write replacement file");

        // Lookup through pinned reader must inspect the original directory inode
        let key = ObjectKey::parse("data.bin").unwrap();
        let meta = reader.head(&key).await.expect("head on pinned root");
        assert_eq!(
            meta.size(),
            original_content.len() as u64,
            "pinned reader must inspect original directory, not new directory at old pathname"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_fs_metadata_configured_root_symlink() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let real_dir = fixture.path().join("real_storage_dir");
        let symlink_dir = fixture.path().join("symlinked_root");
        std::fs::create_dir_all(&real_dir).expect("create real dir");

        let file_path = real_dir.join("file.bin");
        let content = b"content resolved through root symlink";
        std::fs::write(&file_path, content).expect("write file");

        std::os::unix::fs::symlink(&real_dir, &symlink_dir).expect("create root symlink");

        // Initial open follows the configured root symlink and pins the target directory
        let reader = FsMetadataReader::open(&symlink_dir).expect("open reader via symlink");
        let key = ObjectKey::parse("file.bin").unwrap();
        let meta = reader.head(&key).await.expect("head via root symlink");
        assert_eq!(meta.size(), content.len() as u64);

        // Remove the symlink; pinned root descriptor retains authority
        std::fs::remove_file(&symlink_dir).expect("remove root symlink");
        let meta_after = reader.head(&key).await.expect("head after symlink removal");
        assert_eq!(meta_after.size(), content.len() as u64);
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires unprivileged environment where search permission restriction (mode 000) is effective"]
    async fn test_fs_metadata_real_unprivileged_permission_denied() {
        // Enforce prerequisite: this real test must not run as root where DAC restrictions are bypassed.
        let is_root = unsafe { libc::geteuid() == 0 };
        assert!(
            !is_root,
            "test_fs_metadata_real_unprivileged_permission_denied requires unprivileged execution, running as UID 0"
        );

        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        std::fs::create_dir_all(&root_dir).expect("create root");
        let reader = FsMetadataReader::open(&root_dir).expect("open reader");

        let sub_dir = root_dir.join("restricted_dir");
        std::fs::create_dir_all(&sub_dir).expect("create restricted dir");
        let file_path = sub_dir.join("payload.bin");
        std::fs::write(&file_path, b"secret payload").expect("write file");

        // Capture original directory permissions before altering mode
        let orig_perms = std::fs::metadata(&sub_dir)
            .expect("metadata on sub_dir")
            .permissions();

        // Install RAII guard before modifying permissions so cleanup is guaranteed
        let mut guard = PermissionGuard::new(&sub_dir, orig_perms);

        // Remove all search permissions from directory (mode 000)
        let mut no_search_perms = guard.original_permissions.clone();
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            no_search_perms.set_mode(0o000);
        }
        std::fs::set_permissions(&sub_dir, no_search_perms)
            .expect("revoke search permissions on directory");

        let key = ObjectKey::parse("restricted_dir/payload.bin").unwrap();
        let lookup_res = reader.head(&key).await;

        match lookup_res {
            Err(ReadError::PermissionDenied { key: k, source, .. }) => {
                assert_eq!(k, key);
                let src = source.expect("source io::Error must be preserved");
                let io_err = src
                    .downcast_ref::<std::io::Error>()
                    .expect("downcast to io::Error");
                assert_eq!(
                    io_err.raw_os_error(),
                    Some(libc::EACCES),
                    "expected EACCES raw os error"
                );
            }
            other => panic!("expected ReadError::PermissionDenied, got: {other:?}"),
        }

        // Explicit restoration and verification on the normal path
        guard
            .restore()
            .expect("explicit permission restoration must succeed");

        let meta = reader
            .head(&key)
            .await
            .expect("head must succeed after explicit permission restoration");
        assert_eq!(meta.size(), 14);

        // Checked normal-path cleanup
        drop(guard);
        fixture.close().expect("fixture cleanup must succeed");
    }

    #[test]
    fn test_fs_metadata_synthetic_classification() {
        let key = ObjectKey::parse("synthetic/test/key").unwrap();

        // ENOENT -> ReadError::NotFound
        let enoent = std::io::Error::from_raw_os_error(libc::ENOENT);
        let mapped = classify_openat2_error(&key, enoent);
        assert!(mapped.is_not_found());

        // EACCES / EPERM -> ReadError::PermissionDenied (verifying preserved io::Error source and raw errno)
        let eacces = std::io::Error::from_raw_os_error(libc::EACCES);
        let mapped_eacces = classify_openat2_error(&key, eacces);
        assert!(mapped_eacces.is_permission_denied());
        match mapped_eacces {
            ReadError::PermissionDenied { key: k, source, .. } => {
                assert_eq!(k, key);
                let src = source.expect("source io::Error must be preserved");
                let io_err = src
                    .downcast_ref::<std::io::Error>()
                    .expect("downcast to io::Error");
                assert_eq!(io_err.raw_os_error(), Some(libc::EACCES));
            }
            other => panic!("expected PermissionDenied, got: {other:?}"),
        }

        let eperm = std::io::Error::from_raw_os_error(libc::EPERM);
        let mapped_eperm = classify_openat2_error(&key, eperm);
        assert!(mapped_eperm.is_permission_denied());
        match mapped_eperm {
            ReadError::PermissionDenied { key: k, source, .. } => {
                assert_eq!(k, key);
                let src = source.expect("source io::Error must be preserved");
                let io_err = src
                    .downcast_ref::<std::io::Error>()
                    .expect("downcast to io::Error");
                assert_eq!(io_err.raw_os_error(), Some(libc::EPERM));
            }
            other => panic!("expected PermissionDenied, got: {other:?}"),
        }

        // ENOSYS -> ReadError::Backend wrapping SyscallUnsupported with precise diagnostic
        let enosys = std::io::Error::from_raw_os_error(libc::ENOSYS);
        let mapped_enosys = classify_openat2_error(&key, enosys);
        assert!(mapped_enosys.is_backend());
        match mapped_enosys {
            ReadError::Backend {
                message, source, ..
            } => {
                assert_eq!(
                    message,
                    "openat2 is unavailable in this execution environment"
                );
                let fs_err = source.unwrap().downcast::<FsMetadataError>().unwrap();
                match *fs_err {
                    FsMetadataError::SyscallUnsupported(src) => {
                        assert_eq!(src.raw_os_error(), Some(libc::ENOSYS));
                    }
                    other => panic!("expected SyscallUnsupported, got: {other:?}"),
                }
            }
            other => panic!("expected Backend error, got {other:?}"),
        }

        // EXDEV / ELOOP -> ReadError::Backend wrapping ResolutionRejected
        let exdev = std::io::Error::from_raw_os_error(libc::EXDEV);
        let mapped_exdev = classify_openat2_error(&key, exdev);
        assert!(mapped_exdev.is_backend());
        match mapped_exdev {
            ReadError::Backend { source, .. } => {
                let fs_err = source.unwrap().downcast::<FsMetadataError>().unwrap();
                match *fs_err {
                    FsMetadataError::ResolutionRejected { raw_os_error, .. } => {
                        assert_eq!(raw_os_error, libc::EXDEV);
                    }
                    other => panic!("expected ResolutionRejected with EXDEV, got {other:?}"),
                }
            }
            other => panic!("expected Backend error, got {other:?}"),
        }

        let eloop = std::io::Error::from_raw_os_error(libc::ELOOP);
        let mapped_eloop = classify_openat2_error(&key, eloop);
        assert!(mapped_eloop.is_backend());

        // EINVAL / EIO -> ReadError::Backend wrapping causal io::Error
        let einval = std::io::Error::from_raw_os_error(libc::EINVAL);
        assert!(classify_openat2_error(&key, einval).is_backend());

        // Stat mode checking: S_IFLNK, S_IFDIR, S_IFIFO -> UnsupportedObjectType
        let mut symlink_stat: libc::stat = unsafe { std::mem::zeroed() };
        symlink_stat.st_mode = libc::S_IFLNK | 0o777;
        let symlink_res = check_stat_and_extract_metadata(&symlink_stat);
        assert!(symlink_res.is_err());
        match symlink_res.unwrap_err() {
            ReadError::Backend { source, .. } => {
                let fs_err = source.unwrap().downcast::<FsMetadataError>().unwrap();
                match *fs_err {
                    FsMetadataError::UnsupportedObjectType { mode } => {
                        assert_eq!(mode & libc::S_IFMT, libc::S_IFLNK);
                    }
                    other => panic!("expected UnsupportedObjectType, got: {other:?}"),
                }
            }
            other => panic!("expected Backend error, got: {other:?}"),
        }

        // Stat negative size -> InvalidMetadata
        let mut neg_stat: libc::stat = unsafe { std::mem::zeroed() };
        neg_stat.st_mode = libc::S_IFREG | 0o644;
        neg_stat.st_size = -1;
        let neg_res = check_stat_and_extract_metadata(&neg_stat);
        assert!(neg_res.is_err());
        match neg_res.unwrap_err() {
            ReadError::Backend { source, .. } => {
                let fs_err = source.unwrap().downcast::<FsMetadataError>().unwrap();
                assert!(matches!(*fs_err, FsMetadataError::InvalidMetadata { .. }));
            }
            other => panic!("expected Backend error, got: {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_fs_metadata_reader_trait_object_dispatch() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        std::fs::create_dir_all(&root_dir).expect("create root");
        let file_path = root_dir.join("object.txt");
        std::fs::write(&file_path, b"trait object dispatch").expect("write file");

        let reader: Arc<dyn ObjectMetadataReader> =
            Arc::new(FsMetadataReader::open(&root_dir).expect("open reader"));
        let key = ObjectKey::parse("object.txt").unwrap();

        let meta = reader.head(&key).await.expect("head via trait object");
        assert_eq!(meta.size(), 21);
    }

    #[test]
    fn test_fs_metadata_constructor_rejects_empty_and_missing_root() {
        // Empty path
        let err_empty = FsMetadataReader::open("").expect_err("empty root path must fail");
        assert!(matches!(err_empty, FsMetadataError::EmptyRootPath));

        // Missing directory: independent of working directory via fresh temporary directory
        let temp = tempfile::tempdir().expect("create tempdir");
        let missing_child = temp.path().join("nonexistent_child_dir");
        let err_missing =
            FsMetadataReader::open(&missing_child).expect_err("nonexistent root dir must fail");
        assert!(matches!(
            err_missing,
            FsMetadataError::RootOpenFailed { .. }
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_fs_metadata_blocking_execution_thread_differentiation() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        std::fs::create_dir_all(&root_dir).expect("create root");
        let file_path = root_dir.join("thread_test.bin");
        std::fs::write(&file_path, b"thread differentiation test").expect("write file");

        let caller_thread_id = std::thread::current().id();
        let worker_thread_id = Arc::new(std::sync::Mutex::new(None));
        let worker_tid_clone = Arc::clone(&worker_thread_id);

        let reader = FsMetadataReader::open(&root_dir)
            .expect("open reader")
            .with_test_hooks(TestHooks::before(move |_, _| {
                *worker_tid_clone.lock().unwrap() = Some(std::thread::current().id());
            }));

        let key = ObjectKey::parse("thread_test.bin").unwrap();
        let meta = reader.head(&key).await.expect("head must succeed");
        assert_eq!(meta.size(), 27);

        let worker_tid = worker_thread_id
            .lock()
            .unwrap()
            .take()
            .expect("hook must have run");
        assert_ne!(
            caller_thread_id, worker_tid,
            "blocking lookup must execute on a worker pool thread distinct from the current-thread async caller"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_fs_metadata_blocking_execution_does_not_starve_current_thread_task() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        std::fs::create_dir_all(&root_dir).expect("create root");
        let file_path = root_dir.join("progress.bin");
        std::fs::write(&file_path, b"progress").expect("write file");

        let (paused_tx, paused_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

        let release_rx = Arc::new(std::sync::Mutex::new(release_rx));
        let paused_tx = Arc::new(std::sync::Mutex::new(paused_tx));
        let hook_error = Arc::new(std::sync::Mutex::new(None::<String>));
        let task_progress_acknowledged = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let err_slot = Arc::clone(&hook_error);
        let rx_clone = Arc::clone(&release_rx);
        let paused_tx_clone = Arc::clone(&paused_tx);

        let hooks = TestHooks {
            before_lookup: Some(Arc::new(move |_, _| {
                // Signal that the lookup hook has reached its paused wait point
                if let Err(e) = paused_tx_clone.lock().unwrap().send(()) {
                    *err_slot.lock().unwrap() = Some(format!("failed to signal pause: {e:?}"));
                    return;
                }

                // Explicit bounded wait for release; failure to receive release is recorded as test failure
                match rx_clone
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(5))
                {
                    Ok(()) => {}
                    Err(e) => {
                        *err_slot.lock().unwrap() =
                            Some(format!("blocking hook release wait failed: {e:?}"));
                    }
                }
            })),
            on_complete: None,
        };

        let reader = FsMetadataReader::open(&root_dir)
            .expect("open reader")
            .with_test_hooks(hooks);

        // RAII guard ensuring panic-safe release if the test thread panics before explicit release
        struct ReleaseOnDrop(Option<std::sync::mpsc::Sender<()>>);
        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }
        let mut release_guard = ReleaseOnDrop(Some(release_tx));

        let key = ObjectKey::parse("progress.bin").unwrap();

        // Spawn the metadata lookup on the current-thread runtime
        let head_handle = tokio::spawn(async move { reader.head(&key).await });

        // Establish that the lookup hook has entered its paused state before scheduling concurrent task
        let start = std::time::Instant::now();
        loop {
            match paused_rx.try_recv() {
                Ok(()) => break,
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    if start.elapsed() > std::time::Duration::from_secs(5) {
                        panic!("timed out waiting for lookup hook to enter paused state");
                    }
                    tokio::task::yield_now().await;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    panic!("paused_tx disconnected prematurely before pause established");
                }
            }
        }

        // Only now schedule the other current-thread task
        let progress_flag = Arc::clone(&task_progress_acknowledged);
        let other_task = tokio::spawn(async move {
            progress_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        // Require the concurrent task to acknowledge progress before normal release
        other_task
            .await
            .expect("concurrent task on current-thread runtime must join successfully");

        assert!(
            task_progress_acknowledged.load(std::sync::atomic::Ordering::SeqCst),
            "concurrent task must acknowledge progress while lookup is confirmed paused in blocking pool"
        );

        // Verify that the hook has not encountered an error/timeout before normal release
        if let Some(err) = hook_error.lock().unwrap().take() {
            panic!("hook encountered failure prior to normal release: {err}");
        }

        // Send normal release to unblock the lookup worker
        if let Some(tx) = release_guard.0.take() {
            tx.send(()).expect("send explicit release to worker");
        }

        let meta = head_handle
            .await
            .expect("head task must join")
            .expect("head lookup must succeed");
        assert_eq!(meta.size(), 8);

        // Verify hook recorded no errors during release
        if let Some(err) = hook_error.lock().unwrap().take() {
            panic!("hook recorded error during release: {err}");
        }

        fixture.close().expect("fixture cleanup must succeed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_fs_metadata_blocking_task_panic_mapped_to_backend_error() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        std::fs::create_dir_all(&root_dir).expect("create root");
        let file_path = root_dir.join("panic_target.bin");
        std::fs::write(&file_path, b"test").expect("write file");

        let reader = FsMetadataReader::open(&root_dir)
            .expect("open reader")
            .with_test_hooks(TestHooks::before(|_, _| {
                panic!("controlled test panic inside blocking metadata task");
            }));

        let key = ObjectKey::parse("panic_target.bin").unwrap();
        let err = reader
            .head(&key)
            .await
            .expect_err("panicking blocking task must result in Err");

        assert!(err.is_backend(), "panic must map to ReadError::Backend");
        assert!(!err.is_not_found(), "panic must not map to NotFound");
        assert!(
            !err.is_permission_denied(),
            "panic must not map to PermissionDenied"
        );

        let source = match err {
            ReadError::Backend {
                message, source, ..
            } => {
                assert_eq!(message, "blocking metadata lookup task failed");
                source.expect("source JoinError must be preserved")
            }
            other => panic!("expected Backend error, got: {other:?}"),
        };

        let fs_err = source
            .downcast_ref::<FsMetadataError>()
            .expect("source must downcast to FsMetadataError");

        match fs_err {
            FsMetadataError::TaskJoinFailed(join_err) => {
                assert!(
                    join_err.is_panic(),
                    "preserved JoinError must identify task panic"
                );
            }
            other => panic!("expected FsMetadataError::TaskJoinFailed, got: {other:?}"),
        }
    }

    #[test]
    fn test_fs_metadata_head_outside_tokio_runtime_returns_typed_backend_error() {
        use std::future::Future;
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        fn dummy_waker() -> Waker {
            fn noop(_: *const ()) {}
            fn clone(p: *const ()) -> RawWaker {
                RawWaker::new(p, &VTABLE)
            }
            static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
            unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
        }

        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        std::fs::create_dir_all(&root_dir).expect("create root");
        let file_path = root_dir.join("noruntime.bin");
        std::fs::write(&file_path, b"test").expect("write file");

        let reader = FsMetadataReader::open(&root_dir).expect("open reader");
        let key = ObjectKey::parse("noruntime.bin").unwrap();

        let waker = dummy_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = std::pin::pin!(reader.head(&key));

        let poll_res = fut.as_mut().poll(&mut cx);
        match poll_res {
            Poll::Ready(Err(err)) => {
                assert!(err.is_backend(), "must be Backend error");
                let source = match err {
                    ReadError::Backend {
                        message, source, ..
                    } => {
                        assert_eq!(
                            message,
                            "tokio runtime required to execute blocking metadata lookup"
                        );
                        source.expect("source must be present")
                    }
                    other => panic!("expected Backend error, got: {other:?}"),
                };

                let fs_err = source
                    .downcast_ref::<FsMetadataError>()
                    .expect("source must downcast to FsMetadataError");
                assert!(
                    matches!(fs_err, FsMetadataError::RuntimeMissing(_)),
                    "source must be RuntimeMissing, got: {fs_err:?}"
                );
            }
            Poll::Ready(Ok(_)) => panic!("lookup without runtime must not succeed"),
            Poll::Pending => panic!("lookup without runtime must fail immediately without pending"),
        }
    }

    #[test]
    fn test_fs_metadata_controlled_cancellation_descriptor_lifetime() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        std::fs::create_dir_all(&root_dir).expect("create root");
        let file_path = root_dir.join("cancellation.bin");
        std::fs::write(&file_path, b"descriptor lifetime on cancellation").expect("write file");

        let (paused_tx, paused_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (lookup_done_tx, lookup_done_rx) = std::sync::mpsc::channel::<Result<u64, String>>();

        let release_rx = Arc::new(std::sync::Mutex::new(release_rx));
        let paused_tx = Arc::new(std::sync::Mutex::new(paused_tx));
        let lookup_done_tx = Arc::new(std::sync::Mutex::new(lookup_done_tx));
        let hook_error = Arc::new(std::sync::Mutex::new(None::<String>));
        let worker_is_paused = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let err_slot = Arc::clone(&hook_error);
        let rx_clone = Arc::clone(&release_rx);
        let paused_tx_clone = Arc::clone(&paused_tx);
        let is_paused_clone = Arc::clone(&worker_is_paused);

        let hooks = TestHooks {
            before_lookup: Some(Arc::new(move |_, _| {
                is_paused_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                if let Err(e) = paused_tx_clone.lock().unwrap().send(()) {
                    *err_slot.lock().unwrap() = Some(format!("failed to signal pause: {e:?}"));
                    is_paused_clone.store(false, std::sync::atomic::Ordering::SeqCst);
                    return;
                }

                // Explicit bounded wait: timeout or premature disconnect is an explicit failure
                match rx_clone
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(5))
                {
                    Ok(()) => {
                        is_paused_clone.store(false, std::sync::atomic::Ordering::SeqCst);
                    }
                    Err(e) => {
                        is_paused_clone.store(false, std::sync::atomic::Ordering::SeqCst);
                        *err_slot.lock().unwrap() =
                            Some(format!("worker release wait failed: {e:?}"));
                    }
                }
            })),
            on_complete: Some(Arc::new(move |res| {
                let mapped = match res {
                    Ok(meta) => Ok(meta.size()),
                    Err(err) => Err(format!("{err:?}")),
                };
                let _ = lookup_done_tx.lock().unwrap().send(mapped);
            })),
        };

        let reader = FsMetadataReader::open(&root_dir)
            .expect("open reader")
            .with_test_hooks(hooks);

        // RAII guard ensuring panic-safe release in case of test panic before release
        struct ReleaseGuard(Option<std::sync::mpsc::Sender<()>>);
        impl Drop for ReleaseGuard {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }
        let mut guard = ReleaseGuard(Some(release_tx));

        let key = ObjectKey::parse("cancellation.bin").unwrap();

        // Own dedicated current-thread Tokio runtime
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("create dedicated current-thread runtime");

        runtime.block_on(async {
            // Start head lookup and drive it until the worker enters its paused state
            let mut head_fut = reader.head(&key);
            tokio::select! {
                _ = &mut head_fut => {
                    panic!("head future should not complete before cancellation");
                }
                _ = async {
                    let start = std::time::Instant::now();
                    loop {
                        match paused_rx.try_recv() {
                            Ok(()) => break,
                            Err(std::sync::mpsc::TryRecvError::Empty) => {
                                if start.elapsed() > std::time::Duration::from_secs(5) {
                                    panic!("timed out waiting for worker to pause");
                                }
                                tokio::task::yield_now().await;
                            }
                            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                panic!("paused_tx disconnected prematurely");
                            }
                        }
                    }
                } => {}
            }

            // Cancel the lookup by dropping the future and dropping the reader
            drop(head_fut);
            drop(reader);

            // Establish that the worker is STILL paused when awaiting future and reader are dropped
            assert!(
                worker_is_paused.load(std::sync::atomic::Ordering::SeqCst),
                "worker must remain paused when awaiting future and reader are dropped"
            );
            assert!(
                lookup_done_rx.try_recv().is_err(),
                "lookup must not have completed before explicit release"
            );

            // Verify no hook error occurred prior to release
            if let Some(err) = hook_error.lock().unwrap().take() {
                panic!("hook recorded error prior to release: {err}");
            }

            // Release the worker only afterward
            if let Some(tx) = guard.0.take() {
                tx.send(()).expect("send explicit release to worker");
            }

            // Confirm successful lookup after cancellation
            let lookup_outcome = lookup_done_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("lookup must complete after release");

            assert_eq!(
                lookup_outcome,
                Ok(35),
                "worker must successfully inspect metadata via its owned descriptor after caller cancellation"
            );

            // Verify hook recorded no errors during release
            if let Some(err) = hook_error.lock().unwrap().take() {
                panic!("hook recorded error during release: {err}");
            }
        });

        // After block_on returns, drop the owned runtime before fixture.close().
        // This waits for its started blocking tasks to finish and provides an actual
        // completion boundary for this controlled test.
        drop(runtime);

        // Clean up temporary fixtures only after runtime shutdown has joined the blocking worker
        fixture.close().expect("fixture cleanup must succeed");
    }

    #[test]
    fn test_fs_metadata_probe_capability_success_on_valid_root() {
        // Assert synchronous execution outside of an active Tokio runtime
        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "test must execute outside of an active Tokio runtime"
        );

        let temp_dir = tempfile::tempdir().unwrap();
        let reader = FsMetadataReader::open(temp_dir.path()).unwrap();

        let res = reader.probe_capability();
        assert!(
            res.is_ok(),
            "probe_capability must succeed on valid directory root: {res:?}"
        );
    }

    #[test]
    fn test_fs_metadata_probe_capability_does_not_mutate_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("pre_existing.txt");
        let expected_payload = b"verifiable fixture content preserved across probe";
        std::fs::write(&file_path, expected_payload).unwrap();

        let mut entries_before: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        entries_before.sort();
        let content_before = std::fs::read(&file_path).unwrap();

        let reader = FsMetadataReader::open(temp_dir.path()).unwrap();
        reader
            .probe_capability()
            .expect("capability probe must succeed");

        let mut entries_after: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        entries_after.sort();
        let content_after = std::fs::read(&file_path).unwrap();

        assert_eq!(
            entries_before, entries_after,
            "sorted directory entries must remain identical across capability probing"
        );
        assert_eq!(
            content_before, expected_payload,
            "content before probe must match initial fixture payload"
        );
        assert_eq!(
            content_before, content_after,
            "fixture file content must remain identical across capability probing"
        );
    }

    #[test]
    fn test_fs_metadata_head_succeeds_after_probe_capability() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_name = "verified_blob.bin";
        let file_path = temp_dir.path().join(file_name);
        let payload = b"verifiable payload for post-probe head inquiry";
        std::fs::write(&file_path, payload).unwrap();

        let reader = FsMetadataReader::open(temp_dir.path()).unwrap();

        // 1. Probe capability succeeds synchronously on the caller thread
        reader
            .probe_capability()
            .expect("capability probe must succeed on caller thread");

        // 2. Head inquiry executes within an entered Tokio runtime
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let key = ObjectKey::parse(file_name).unwrap();
        let meta = runtime
            .block_on(async { reader.head(&key).await })
            .expect("head must succeed on existing file after probe");

        assert_eq!(
            meta.size(),
            payload.len() as u64,
            "exact metadata size must match written payload length"
        );

        // Explicitly drop runtime and reader before fixture cleanup
        drop(runtime);
        drop(reader);
        temp_dir.close().expect("fixture cleanup must succeed");
    }

    #[test]
    fn test_fs_metadata_probe_capability_synthetic_openat2_classification() {
        // ENOSYS -> FsMetadataError::SyscallUnsupported
        let enosys = std::io::Error::from_raw_os_error(libc::ENOSYS);
        let err_enosys = classify_openat2_probe_error(enosys);
        match err_enosys {
            FsMetadataError::SyscallUnsupported(src) => {
                assert_eq!(src.raw_os_error(), Some(libc::ENOSYS));
            }
            other => panic!("expected SyscallUnsupported, got: {other:?}"),
        }

        // EACCES -> FsMetadataError::ProbeDenied (without inferring seccomp as unique cause)
        let eacces = std::io::Error::from_raw_os_error(libc::EACCES);
        let err_eacces = classify_openat2_probe_error(eacces);
        match err_eacces {
            FsMetadataError::ProbeDenied(src) => {
                assert_eq!(src.raw_os_error(), Some(libc::EACCES));
            }
            other => panic!("expected ProbeDenied for EACCES, got: {other:?}"),
        }

        // EPERM -> FsMetadataError::ProbeDenied (without inferring seccomp as unique cause)
        let eperm = std::io::Error::from_raw_os_error(libc::EPERM);
        let err_eperm = classify_openat2_probe_error(eperm);
        match err_eperm {
            FsMetadataError::ProbeDenied(src) => {
                assert_eq!(src.raw_os_error(), Some(libc::EPERM));
            }
            other => panic!("expected ProbeDenied for EPERM, got: {other:?}"),
        }

        // Other OS errors (e.g. EIO, EMFILE) -> FsMetadataError::ProbeFailed
        let eio = std::io::Error::from_raw_os_error(libc::EIO);
        let err_eio = classify_openat2_probe_error(eio);
        match err_eio {
            FsMetadataError::ProbeFailed { source } => {
                assert_eq!(source.raw_os_error(), Some(libc::EIO));
            }
            other => panic!("expected ProbeFailed for EIO, got: {other:?}"),
        }
    }

    #[test]
    fn test_fs_metadata_probe_capability_synthetic_fstat_classification() {
        // ENOSYS from fstat must map to ProbeFailed, NOT SyscallUnsupported
        let enosys = std::io::Error::from_raw_os_error(libc::ENOSYS);
        let err_enosys = classify_fstat_probe_error(enosys);
        match err_enosys {
            FsMetadataError::ProbeFailed { source } => {
                assert_eq!(source.raw_os_error(), Some(libc::ENOSYS));
            }
            other => panic!("fstat ENOSYS must map to ProbeFailed, got: {other:?}"),
        }

        // EIO from fstat must map to ProbeFailed
        let eio = std::io::Error::from_raw_os_error(libc::EIO);
        let err_eio = classify_fstat_probe_error(eio);
        match err_eio {
            FsMetadataError::ProbeFailed { source } => {
                assert_eq!(source.raw_os_error(), Some(libc::EIO));
            }
            other => panic!("fstat EIO must map to ProbeFailed, got: {other:?}"),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod payload_acquisition_experiment;
