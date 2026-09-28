//! Contained filesystem metadata inspection implementation and focused tests for `storage-fs`.
//!
//! # Architectural Ownership Boundaries
//! - Implements descriptor-relative file attribute inspection for [`crate::FsMetadataReader`].
//! - Uses Linux `openat2` with `O_PATH` and containment flags `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`
//!   beneath the pinned root descriptor.
//! - Wraps the resolved descriptor immediately in [`std::os::fd::OwnedFd`] and inspects attributes via `fstat` after acquisition.
//! - Rejects symlinks encountered during resolution with [`crate::error::FsMetadataError::ResolutionRejected`].
//! - Strictly validates regular-file type (`S_IFREG`), rejecting acquired non-regular objects (directories, FIFOs,
//!   character/block devices, sockets) with typed [`crate::error::FsMetadataError::UnsupportedObjectType`].
//! - Converts `st_size` safely to `u64` and converts POSIX `stat` modification timestamps to [`std::time::SystemTime`]
//!   with nanosecond precision and checked arithmetic.
//! - Returns [`FsFileMetadata`] containing exact byte size and `Some(SystemTime)`.
//!
//! # Observation Semantics and Concurrency
//! - **Observation After Acquisition**: Attributes are observed by `fstat` on the acquired descriptor after acquisition,
//!   not at the instant of `openat2` path resolution.
//! - **No Atomic Snapshot Under Mutation**: A single `fstat` result does not establish an atomic snapshot of all attributes
//!   under concurrent mutation, nor does it guarantee snapshot isolation across multiple operations.
//! - **Replacement Before Inspection**: If a file is replaced by a distinct regular file before inspection, inspection
//!   will observe and report the replacement file's attributes. This demonstrates observation at resolution time,
//!   not snapshot isolation or detection of every concurrent replacement.
//! - **Mount Crossing**: `RESOLVE_BENEATH` does not isolate child mounts attached beneath the root.
//! - **Coherence**: Registry mutations still use pathname resolution; full root coherence is deferred until mutation paths
//!   are migrated.
//! - **Platform Verification**: Descriptor-relative containment requires Linux `openat2`. Non-Linux platforms return
//!   typed `PlatformUnsupported`; non-Linux compilation and execution remain unverified in the absence of a cross-compilation environment.

use std::time::SystemTime;

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(all(test, target_os = "linux"))]
use std::sync::Arc;

use naust_storage_core::{ObjectKey, ReadError};

use crate::error::FsMetadataError;

/// Neutral filesystem attributes container for an inspected regular file.
///
/// Holds the byte size and an optional modification timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsFileMetadata {
    size: u64,
    modified: Option<SystemTime>,
}

impl FsFileMetadata {
    /// Creates a new [`FsFileMetadata`] with the given byte size and optional modification timestamp.
    pub fn new(size: u64, modified: Option<SystemTime>) -> Self {
        Self { size, modified }
    }

    /// Returns the exact file size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the file modification timestamp, if available.
    pub fn modified(&self) -> Option<SystemTime> {
        self.modified
    }
}

/// Converts a POSIX `stat` timestamp (`st_mtime`, `st_mtime_nsec`) into a [`std::time::SystemTime`].
///
/// # Validation & Semantics
/// - Nanoseconds must satisfy `0 <= nsec < 1_000_000_000`.
/// - Signed seconds and fractional nanoseconds are preserved.
/// - Uses checked arithmetic relative to [`std::time::UNIX_EPOCH`].
/// - Avoids signed-minimum absolute value overflow (`sec = i64::MIN`) by using `i128`.
/// - Does not saturate, panic, normalize invalid fields, or substitute epoch.
pub(crate) fn convert_stat_mtime(sec: i64, nsec: i64) -> Result<SystemTime, FsMetadataError> {
    // 1. Validate nanosecond bounds
    if !(0..1_000_000_000).contains(&nsec) {
        return Err(FsMetadataError::InvalidMetadata {
            message: "nanoseconds out of valid range [0, 999_999_999]",
        });
    }

    let nsec_u32 = nsec as u32;

    if sec >= 0 {
        // 2. Post-epoch conversion
        let duration = std::time::Duration::new(sec as u64, nsec_u32);
        std::time::UNIX_EPOCH
            .checked_add(duration)
            .ok_or(FsMetadataError::InvalidMetadata {
                message: "timestamp exceeds supported SystemTime range",
            })
    } else {
        // 3. Pre-epoch conversion (avoiding signed-minimum abs overflow via i128)
        let sec_i128 = sec as i128;
        let (duration_sec, duration_nsec) = if nsec_u32 == 0 {
            ((-sec_i128) as u64, 0)
        } else {
            // sec is negative, e.g. -1 with 500_000_000 ns means -0.5s (0s + 500ms before epoch)
            (((-sec_i128 - 1) as u64), 1_000_000_000 - nsec_u32)
        };

        let duration = std::time::Duration::new(duration_sec, duration_nsec);
        std::time::UNIX_EPOCH
            .checked_sub(duration)
            .ok_or(FsMetadataError::InvalidMetadata {
                message: "pre-epoch timestamp underflows supported SystemTime range",
            })
    }
}

#[cfg(all(test, target_os = "linux"))]
type BeforeOpenat2Hook = Arc<dyn Fn() + Send + Sync>;
#[cfg(all(test, target_os = "linux"))]
type AfterOpenat2Hook = Arc<dyn Fn(&OwnedFd) + Send + Sync>;
#[cfg(all(test, target_os = "linux"))]
type SimulateFstatErrorHook = Arc<dyn Fn() -> std::io::Result<()> + Send + Sync>;
#[cfg(all(test, target_os = "linux"))]
type OnCompleteHook = Arc<dyn Fn(Result<&FsFileMetadata, &ReadError>) + Send + Sync>;

/// Narrowly scoped test hooks for verifying file metadata inspection boundaries and error handling.
#[cfg(all(test, target_os = "linux"))]
#[derive(Clone, Default)]
pub(crate) struct InspectTestHooks {
    pub(crate) before_openat2: Option<BeforeOpenat2Hook>,
    pub(crate) after_openat2: Option<AfterOpenat2Hook>,
    pub(crate) simulate_fstat_error: Option<SimulateFstatErrorHook>,
    pub(crate) on_complete: Option<OnCompleteHook>,
}

#[cfg(all(test, target_os = "linux"))]
impl std::fmt::Debug for InspectTestHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InspectTestHooks")
            .field("before_openat2", &self.before_openat2.is_some())
            .field("after_openat2", &self.after_openat2.is_some())
            .field("simulate_fstat_error", &self.simulate_fstat_error.is_some())
            .field("on_complete", &self.on_complete.is_some())
            .finish()
    }
}

#[cfg(all(test, not(target_os = "linux")))]
#[derive(Clone, Default, Debug)]
pub(crate) struct InspectTestHooks;

/// Synchronously executes descriptor-relative file metadata inspection on Linux.
///
/// # Stages
/// 1. Resolves `key` beneath `root_fd` via `openat2` with `O_PATH | O_CLOEXEC` and containment flags
///    `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
/// 2. Wraps the descriptor immediately in [`OwnedFd`] for leak-free RAII cleanup.
/// 3. Inspects attributes with `fstat` after descriptor acquisition.
/// 4. Validates that the object is a regular file (`S_IFREG`), rejecting acquired non-regular objects.
/// 5. Validates non-negative file size and converts to `u64`.
/// 6. Converts modification timestamp to [`SystemTime`] using checked arithmetic.
#[cfg(target_os = "linux")]
pub(crate) fn inspect_file_metadata_sync(
    root_fd: &OwnedFd,
    key: &ObjectKey,
    #[cfg(test)] hooks: Option<&InspectTestHooks>,
) -> Result<FsFileMetadata, ReadError> {
    #[cfg(test)]
    if let Some(hook) = hooks.and_then(|h| h.before_openat2.as_ref()) {
        hook();
    }

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
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;

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
        return Err(crate::reader::classify_openat2_error(key, err));
    }

    let target_fd = unsafe { OwnedFd::from_raw_fd(res as i32) };

    #[cfg(test)]
    if let Some(hook) = hooks.and_then(|h| h.after_openat2.as_ref()) {
        hook(&target_fd);
    }

    #[cfg(test)]
    if let Some(err) = hooks
        .and_then(|h| h.simulate_fstat_error.as_ref())
        .and_then(|sim| sim().err())
    {
        return Err(ReadError::backend_with_source(
            "failed to stat inspected descriptor",
            Box::new(FsMetadataError::StatFailed {
                stage: "file inspection",
                source: err,
            }),
        ));
    }

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let stat_res = unsafe { libc::fstat(target_fd.as_raw_fd(), &mut st) };
    if stat_res != 0 {
        let err = std::io::Error::last_os_error();
        return Err(ReadError::backend_with_source(
            "failed to stat inspected descriptor",
            Box::new(FsMetadataError::StatFailed {
                stage: "file inspection",
                source: err,
            }),
        ));
    }

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

    let modified_ts =
        convert_stat_mtime(st.st_mtime as i64, st.st_mtime_nsec as i64).map_err(|e| {
            ReadError::backend_with_source(
                "invalid metadata: timestamp conversion failed",
                Box::new(e),
            )
        })?;

    Ok(FsFileMetadata::new(size, Some(modified_ts)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_fs_file_metadata_constructors_and_accessors() {
        let meta_epoch = FsFileMetadata::new(12345, Some(UNIX_EPOCH));
        assert_eq!(meta_epoch.size(), 12345);
        assert_eq!(meta_epoch.modified(), Some(UNIX_EPOCH));

        let meta_none = FsFileMetadata::new(12345, None);
        assert_eq!(meta_none.size(), 12345);
        assert_eq!(meta_none.modified(), None);

        assert_ne!(meta_epoch, meta_none);
        assert_eq!(meta_epoch, meta_epoch);

        // Verify copy semantics
        let meta_copy = meta_epoch;
        assert_eq!(meta_copy.size(), 12345);
        assert_eq!(meta_copy.modified(), Some(UNIX_EPOCH));
    }

    #[test]
    fn test_convert_stat_mtime_pure_vectors() {
        // Vector 1: sec = -1, nsec = 500_000_000 (-0.5s)
        let ts = convert_stat_mtime(-1, 500_000_000).expect("conversion must succeed");
        assert_eq!(ts, UNIX_EPOCH - Duration::from_millis(500));

        // Vector 2: sec = -1, nsec = 999_999_999 (-1ns)
        let ts = convert_stat_mtime(-1, 999_999_999).expect("conversion must succeed");
        assert_eq!(ts, UNIX_EPOCH - Duration::from_nanos(1));

        // Vector 3: sec = 0, nsec = 0 (exact UNIX_EPOCH)
        let ts = convert_stat_mtime(0, 0).expect("conversion must succeed");
        assert_eq!(ts, UNIX_EPOCH);

        // Vector 4: sec = -1, nsec = 0 (-1s)
        let ts = convert_stat_mtime(-1, 0).expect("conversion must succeed");
        assert_eq!(ts, UNIX_EPOCH - Duration::from_secs(1));

        // Vector 5: sec = 1, nsec = 0 (+1s)
        let ts = convert_stat_mtime(1, 0).expect("conversion must succeed");
        assert_eq!(ts, UNIX_EPOCH + Duration::from_secs(1));

        // Vector 6: sec = 123456789, nsec = 987654321
        let ts = convert_stat_mtime(123456789, 987654321).expect("conversion must succeed");
        assert_eq!(ts, UNIX_EPOCH + Duration::new(123456789, 987654321));

        // Vector 7: invalid nanoseconds (< 0)
        let err = convert_stat_mtime(0, -1).expect_err("negative nanoseconds must fail");
        assert!(matches!(
            err,
            FsMetadataError::InvalidMetadata { message } if message.contains("nanoseconds")
        ));

        // Vector 8: invalid nanoseconds (>= 1_000_000_000)
        let err = convert_stat_mtime(0, 1_000_000_000).expect_err("1e9 nanoseconds must fail");
        assert!(matches!(
            err,
            FsMetadataError::InvalidMetadata { message } if message.contains("nanoseconds")
        ));

        let err = convert_stat_mtime(0, 2_000_000_000).expect_err("2e9 nanoseconds must fail");
        assert!(matches!(
            err,
            FsMetadataError::InvalidMetadata { message } if message.contains("nanoseconds")
        ));

        // Vector 9: extreme seconds avoiding overflow
        // Compare with checked platform arithmetic: assert exact equality when
        // representable and typed InvalidMetadata otherwise.
        let min_dur = Duration::new((-(i64::MIN as i128)) as u64, 0);
        match UNIX_EPOCH.checked_sub(min_dur) {
            Some(expected) => {
                assert_eq!(convert_stat_mtime(i64::MIN, 0).unwrap(), expected);
            }
            None => {
                assert!(matches!(
                    convert_stat_mtime(i64::MIN, 0),
                    Err(FsMetadataError::InvalidMetadata { .. })
                ));
            }
        }

        let max_dur = Duration::new(i64::MAX as u64, 0);
        match UNIX_EPOCH.checked_add(max_dur) {
            Some(expected) => {
                assert_eq!(convert_stat_mtime(i64::MAX, 0).unwrap(), expected);
            }
            None => {
                assert!(matches!(
                    convert_stat_mtime(i64::MAX, 0),
                    Err(FsMetadataError::InvalidMetadata { .. })
                ));
            }
        }
    }

    #[cfg(target_os = "linux")]
    mod linux_inspect_tests {
        use super::*;
        use crate::reader::FsMetadataReader;
        use std::path::Path;

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

        impl<'a> Drop for PermissionGuard<'a> {
            fn drop(&mut self) {
                let _ = self.restore();
            }
        }

        #[tokio::test]
        async fn test_inspect_file_metadata_exact_real_file_size_and_mtime() {
            let fixture = tempfile::tempdir().expect("create fixture");
            let file_path = fixture.path().join("exact.bin");
            let data = b"exact-size-and-timestamp-payload-contents-42";
            std::fs::write(&file_path, data).expect("write file");

            let std_meta = std::fs::metadata(&file_path).expect("read std metadata");
            let std_mtime = std_meta.modified().expect("read std mtime");

            let reader = FsMetadataReader::open(fixture.path()).expect("open reader");
            let key = ObjectKey::parse("exact.bin").unwrap();

            let inspected = reader
                .inspect_file_metadata(&key)
                .await
                .expect("inspect file metadata must succeed");

            assert_eq!(inspected.size(), data.len() as u64);
            assert_eq!(inspected.modified(), Some(std_mtime));
        }

        #[tokio::test]
        async fn test_inspect_file_metadata_fractional_timestamp_precision() {
            let fixture = tempfile::tempdir().expect("create fixture");
            let file_path = fixture.path().join("fractional.bin");
            std::fs::write(&file_path, b"fractional-precision-test").expect("write file");

            // Deliberately set a fractional timestamp using standard-library facilities
            let deliberate_ts = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789);
            let file = std::fs::File::options()
                .write(true)
                .open(&file_path)
                .expect("open file for time setting");
            let times = std::fs::FileTimes::new().set_modified(deliberate_ts);
            file.set_times(times).expect("set deliberate file times");
            drop(file);

            // Read back the filesystem-supported timestamp value
            let std_meta = std::fs::metadata(&file_path).expect("read back std metadata");
            let supported_mtime = std_meta.modified().expect("read back supported mtime");

            let reader = FsMetadataReader::open(fixture.path()).expect("open reader");
            let key = ObjectKey::parse("fractional.bin").unwrap();

            let inspected = reader
                .inspect_file_metadata(&key)
                .await
                .expect("inspect file metadata must succeed");

            let inspected_mtime = inspected
                .modified()
                .expect("inspected timestamp must be Some");
            assert_eq!(inspected_mtime, supported_mtime);

            // Compare fractional duration components
            let supported_duration = supported_mtime
                .duration_since(UNIX_EPOCH)
                .expect("post-epoch supported mtime");
            let inspected_duration = inspected_mtime
                .duration_since(UNIX_EPOCH)
                .expect("post-epoch inspected mtime");
            assert_eq!(inspected_duration.as_secs(), supported_duration.as_secs());
            assert_eq!(
                inspected_duration.subsec_nanos(),
                supported_duration.subsec_nanos()
            );
        }

        #[tokio::test]
        async fn test_inspect_file_metadata_missing_target() {
            let fixture = tempfile::tempdir().expect("create fixture");
            let reader = FsMetadataReader::open(fixture.path()).expect("open reader");
            let key = ObjectKey::parse("does_not_exist.bin").unwrap();

            let err = reader
                .inspect_file_metadata(&key)
                .await
                .expect_err("missing target must return Err");

            assert!(err.is_not_found());
            assert_eq!(err.key(), Some(&key));
        }

        #[tokio::test]
        async fn test_inspect_file_metadata_symlink_containment_rejection() {
            let fixture = tempfile::tempdir().expect("create fixture");
            let target_path = fixture.path().join("real_target.bin");
            std::fs::write(&target_path, b"real").expect("write target");

            let symlink_path = fixture.path().join("symlink_inside.bin");
            std::os::unix::fs::symlink(&target_path, &symlink_path).expect("create symlink");

            let reader = FsMetadataReader::open(fixture.path()).expect("open reader");
            let key = ObjectKey::parse("symlink_inside.bin").unwrap();

            let err = reader
                .inspect_file_metadata(&key)
                .await
                .expect_err("symlink must be rejected");

            assert!(err.is_backend());
            let source = match err {
                ReadError::Backend { source, .. } => source.expect("source must exist"),
                other => panic!("expected Backend error, got: {other:?}"),
            };

            let fs_err = source
                .downcast_ref::<FsMetadataError>()
                .expect("source must downcast to FsMetadataError");

            match fs_err {
                FsMetadataError::ResolutionRejected { raw_os_error, .. } => {
                    assert!(
                        *raw_os_error == libc::ELOOP || *raw_os_error == libc::EXDEV,
                        "expected ELOOP or EXDEV, got: {raw_os_error}"
                    );
                }
                other => panic!("expected ResolutionRejected, got: {other:?}"),
            }
        }

        #[tokio::test]
        async fn test_inspect_file_metadata_directory_and_fifo_rejected() {
            let fixture = tempfile::tempdir().expect("create fixture");

            // 1. Directory rejection
            let sub_dir = fixture.path().join("sub_directory");
            std::fs::create_dir(&sub_dir).expect("create sub directory");

            let reader = FsMetadataReader::open(fixture.path()).expect("open reader");
            let dir_key = ObjectKey::parse("sub_directory").unwrap();

            let err = reader
                .inspect_file_metadata(&dir_key)
                .await
                .expect_err("directory must be rejected");

            assert!(err.is_backend());
            let source = match err {
                ReadError::Backend { source, .. } => source.expect("source must exist"),
                other => panic!("expected Backend error, got: {other:?}"),
            };
            let fs_err = source
                .downcast_ref::<FsMetadataError>()
                .expect("source must downcast to FsMetadataError");
            match fs_err {
                FsMetadataError::UnsupportedObjectType { mode } => {
                    assert_eq!(mode & libc::S_IFMT, libc::S_IFDIR);
                }
                other => panic!("expected UnsupportedObjectType, got: {other:?}"),
            }

            // 2. FIFO rejection (O_PATH must not block on open)
            let fifo_path = fixture.path().join("test.fifo");
            let c_fifo_path = CString::new(fifo_path.to_str().unwrap()).unwrap();
            let mkfifo_res = unsafe { libc::mkfifo(c_fifo_path.as_ptr(), 0o600) };
            assert_eq!(
                mkfifo_res,
                0,
                "mkfifo failed: {}",
                std::io::Error::last_os_error()
            );

            struct FifoCleaner<'a>(&'a Path);
            impl<'a> Drop for FifoCleaner<'a> {
                fn drop(&mut self) {
                    let _ = std::fs::remove_file(self.0);
                }
            }
            let _cleaner = FifoCleaner(&fifo_path);

            let fifo_key = ObjectKey::parse("test.fifo").unwrap();
            let err = reader
                .inspect_file_metadata(&fifo_key)
                .await
                .expect_err("fifo must be rejected");

            assert!(err.is_backend());
            let source = match err {
                ReadError::Backend { source, .. } => source.expect("source must exist"),
                other => panic!("expected Backend error, got: {other:?}"),
            };
            let fs_err = source
                .downcast_ref::<FsMetadataError>()
                .expect("source must downcast to FsMetadataError");
            match fs_err {
                FsMetadataError::UnsupportedObjectType { mode } => {
                    assert_eq!(mode & libc::S_IFMT, libc::S_IFIFO);
                }
                other => panic!("expected UnsupportedObjectType, got: {other:?}"),
            }
        }

        #[test]
        fn test_inspect_file_metadata_synthetic_permission_and_resolution_classification() {
            let key = ObjectKey::parse("classified.bin").unwrap();

            // EACCES -> PermissionDenied with source preserved
            let eacces_err = std::io::Error::from_raw_os_error(libc::EACCES);
            let classified = crate::reader::classify_openat2_error(&key, eacces_err);
            assert!(classified.is_permission_denied());
            assert_eq!(classified.key(), Some(&key));
            let src = match classified {
                ReadError::PermissionDenied { source, .. } => source.expect("source preserved"),
                other => panic!("expected PermissionDenied, got: {other:?}"),
            };
            assert_eq!(
                src.downcast_ref::<std::io::Error>().unwrap().raw_os_error(),
                Some(libc::EACCES)
            );

            // EPERM -> PermissionDenied with source preserved
            let eperm_err = std::io::Error::from_raw_os_error(libc::EPERM);
            let classified = crate::reader::classify_openat2_error(&key, eperm_err);
            assert!(classified.is_permission_denied());
            assert_eq!(classified.key(), Some(&key));

            // ELOOP -> Backend carrying ResolutionRejected
            let eloop_err = std::io::Error::from_raw_os_error(libc::ELOOP);
            let classified = crate::reader::classify_openat2_error(&key, eloop_err);
            assert!(classified.is_backend());
            let src = match classified {
                ReadError::Backend { source, .. } => source.expect("source preserved"),
                other => panic!("expected Backend, got: {other:?}"),
            };
            assert!(matches!(
                src.downcast_ref::<FsMetadataError>().unwrap(),
                FsMetadataError::ResolutionRejected {
                    raw_os_error: libc::ELOOP,
                    ..
                }
            ));

            // EXDEV -> Backend carrying ResolutionRejected
            let exdev_err = std::io::Error::from_raw_os_error(libc::EXDEV);
            let classified = crate::reader::classify_openat2_error(&key, exdev_err);
            assert!(classified.is_backend());
            let src = match classified {
                ReadError::Backend { source, .. } => source.expect("source preserved"),
                other => panic!("expected Backend, got: {other:?}"),
            };
            assert!(matches!(
                src.downcast_ref::<FsMetadataError>().unwrap(),
                FsMetadataError::ResolutionRejected {
                    raw_os_error: libc::EXDEV,
                    ..
                }
            ));

            // ENOSYS -> Backend carrying SyscallUnsupported
            let enosys_err = std::io::Error::from_raw_os_error(libc::ENOSYS);
            let classified = crate::reader::classify_openat2_error(&key, enosys_err);
            assert!(classified.is_backend());
            let src = match classified {
                ReadError::Backend { source, .. } => source.expect("source preserved"),
                other => panic!("expected Backend, got: {other:?}"),
            };
            assert!(matches!(
                src.downcast_ref::<FsMetadataError>().unwrap(),
                FsMetadataError::SyscallUnsupported(_)
            ));

            // Other errno (e.g. ENOTDIR) -> Backend preserving raw io::Error
            let enotdir_err = std::io::Error::from_raw_os_error(libc::ENOTDIR);
            let classified = crate::reader::classify_openat2_error(&key, enotdir_err);
            assert!(classified.is_backend());
            let src = match classified {
                ReadError::Backend {
                    message, source, ..
                } => {
                    assert_eq!(message, "filesystem metadata resolution failed");
                    source.expect("source preserved")
                }
                other => panic!("expected Backend, got: {other:?}"),
            };
            assert_eq!(
                src.downcast_ref::<std::io::Error>().unwrap().raw_os_error(),
                Some(libc::ENOTDIR)
            );
        }

        #[tokio::test]
        async fn test_inspect_file_metadata_unexpected_resolution_enotdir() {
            let fixture = tempfile::tempdir().expect("create fixture");
            let regular_file = fixture.path().join("not_a_dir.bin");
            std::fs::write(&regular_file, b"content").expect("write file");

            let enotdir_key = ObjectKey::parse("not_a_dir.bin/child.bin").unwrap();
            let reader = FsMetadataReader::open(fixture.path()).expect("open reader");
            let err = reader
                .inspect_file_metadata(&enotdir_key)
                .await
                .expect_err("ENOTDIR resolution must fail");

            assert!(err.is_backend());
            let source = match err {
                ReadError::Backend { source, .. } => source.expect("source must exist"),
                other => panic!("expected Backend error, got: {other:?}"),
            };

            let io_err = source
                .downcast_ref::<std::io::Error>()
                .expect("source must downcast to std::io::Error");
            assert_eq!(io_err.raw_os_error(), Some(libc::ENOTDIR));
        }

        #[tokio::test]
        #[ignore = "requires unprivileged environment where search permission restriction (mode 000) is effective"]
        async fn test_inspect_file_metadata_real_unprivileged_permission_denied() {
            let fixture = tempfile::tempdir().expect("create fixture");
            let restricted_dir = fixture.path().join("restricted");
            std::fs::create_dir(&restricted_dir).expect("create restricted dir");
            let secret_file = restricted_dir.join("secret.bin");
            std::fs::write(&secret_file, b"secret").expect("write secret");

            let orig_perms = std::fs::metadata(&restricted_dir)
                .expect("get perms")
                .permissions();
            let mut guard = PermissionGuard::new(&restricted_dir, orig_perms);

            let mut no_access = guard.original_permissions.clone();
            use std::os::unix::fs::PermissionsExt;
            no_access.set_mode(0o000);
            std::fs::set_permissions(&restricted_dir, no_access).expect("set 000 permissions");

            let reader = FsMetadataReader::open(fixture.path()).expect("open reader");
            let key = ObjectKey::parse("restricted/secret.bin").unwrap();

            let err = reader
                .inspect_file_metadata(&key)
                .await
                .expect_err("unprivileged access with 000 dir must return PermissionDenied");

            assert!(err.is_permission_denied());
            assert_eq!(err.key(), Some(&key));

            guard.restore().expect("restore permissions");
        }

        #[tokio::test]
        async fn test_inspect_file_metadata_fstat_failure_retains_source() {
            let fixture = tempfile::tempdir().expect("create fixture");
            let file_path = fixture.path().join("fstat_fail.bin");
            std::fs::write(&file_path, b"test").expect("write file");

            let hooks = InspectTestHooks {
                before_openat2: None,
                after_openat2: None,
                simulate_fstat_error: Some(Arc::new(|| {
                    Err(std::io::Error::other("injected fstat inspection error"))
                })),
                on_complete: None,
            };

            let reader = FsMetadataReader::open(fixture.path())
                .expect("open reader")
                .with_inspect_test_hooks(hooks);

            let key = ObjectKey::parse("fstat_fail.bin").unwrap();
            let err = reader
                .inspect_file_metadata(&key)
                .await
                .expect_err("injected fstat failure must fail");

            assert!(err.is_backend());
            let source = match err {
                ReadError::Backend {
                    message, source, ..
                } => {
                    assert_eq!(message, "failed to stat inspected descriptor");
                    source.expect("source must exist")
                }
                other => panic!("expected Backend error, got: {other:?}"),
            };

            let fs_err = source
                .downcast_ref::<FsMetadataError>()
                .expect("source must downcast to FsMetadataError");

            match fs_err {
                FsMetadataError::StatFailed { stage, source } => {
                    assert_eq!(*stage, "file inspection");
                    assert_eq!(source.to_string(), "injected fstat inspection error");
                }
                other => panic!("expected StatFailed, got: {other:?}"),
            }
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_inspect_file_metadata_execution_off_async_worker_thread() {
            let fixture = tempfile::tempdir().expect("create fixture");
            let file_path = fixture.path().join("offload.bin");
            std::fs::write(&file_path, b"offload-thread-test").expect("write file");

            let caller_thread_id = std::thread::current().id();
            let worker_thread_id = Arc::new(std::sync::Mutex::new(None::<std::thread::ThreadId>));
            let worker_tid_clone = Arc::clone(&worker_thread_id);

            let hooks = InspectTestHooks {
                before_openat2: Some(Arc::new(move || {
                    *worker_tid_clone.lock().unwrap() = Some(std::thread::current().id());
                })),
                after_openat2: None,
                simulate_fstat_error: None,
                on_complete: None,
            };

            let reader = FsMetadataReader::open(fixture.path())
                .expect("open reader")
                .with_inspect_test_hooks(hooks);

            let key = ObjectKey::parse("offload.bin").unwrap();
            let meta = reader
                .inspect_file_metadata(&key)
                .await
                .expect("inspect must succeed");
            assert_eq!(meta.size(), 19);

            let worker_tid = worker_thread_id
                .lock()
                .unwrap()
                .take()
                .expect("worker hook must have recorded thread id");

            assert_ne!(
                caller_thread_id, worker_tid,
                "blocking inspection must execute on worker pool thread distinct from async caller"
            );
        }

        #[test]
        fn test_inspect_file_metadata_root_ownership_retained_during_in_flight_work() {
            let fixture = tempfile::tempdir().expect("create fixture");
            let file_path = fixture.path().join("cancellation.bin");
            std::fs::write(&file_path, b"retained-root-descriptor-test-bytes").expect("write file");

            let (paused_tx, paused_rx) = std::sync::mpsc::channel::<()>();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let (done_tx, done_rx) = std::sync::mpsc::channel::<Result<u64, String>>();

            let paused_tx = Arc::new(std::sync::Mutex::new(paused_tx));
            let release_rx = Arc::new(std::sync::Mutex::new(release_rx));
            let done_tx = Arc::new(std::sync::Mutex::new(done_tx));
            let hook_error = Arc::new(std::sync::Mutex::new(None::<String>));

            let p_tx = Arc::clone(&paused_tx);
            let r_rx = Arc::clone(&release_rx);
            let err_slot = Arc::clone(&hook_error);

            let hooks = InspectTestHooks {
                before_openat2: Some(Arc::new(move || {
                    if let Err(e) = p_tx.lock().unwrap().send(()) {
                        *err_slot.lock().unwrap() = Some(format!("failed to signal pause: {e:?}"));
                        return;
                    }

                    // Explicit bounded wait: timeout or disconnect must produce a recorded failure
                    match r_rx.lock().unwrap().recv_timeout(Duration::from_secs(5)) {
                        Ok(()) => {}
                        Err(e) => {
                            *err_slot.lock().unwrap() =
                                Some(format!("worker release wait failed: {e:?}"));
                        }
                    }
                })),
                after_openat2: None,
                simulate_fstat_error: None,
                on_complete: Some(Arc::new(move |res| {
                    let mapped = res.map(|m| m.size()).map_err(|e| format!("{e:?}"));
                    let _ = done_tx.lock().unwrap().send(mapped);
                })),
            };

            let reader = FsMetadataReader::open(fixture.path())
                .expect("open reader")
                .with_inspect_test_hooks(hooks);

            // Declare dedicated runtime BEFORE ReleaseGuard so unwinding drops guard (releasing worker)
            // before runtime teardown joins worker threads.
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("create runtime");

            // Non-panicking RAII cleanup destructor
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

            runtime.block_on(async {
                let mut inspect_fut = Box::pin(reader.inspect_file_metadata(&key));
                tokio::select! {
                    _ = &mut inspect_fut => {
                        panic!("inspect future should not complete before cancellation");
                    }
                    _ = async {
                        let start = std::time::Instant::now();
                        loop {
                            match paused_rx.try_recv() {
                                Ok(()) => break,
                                Err(std::sync::mpsc::TryRecvError::Empty) => {
                                    if start.elapsed() > Duration::from_secs(5) {
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

                // Drop awaiting future and reader
                drop(inspect_fut);
                drop(reader);

                // Explicit synchronization evidence: worker has signaled pause, has not completed,
                // and has not recorded any timeout/disconnect errors prior to release.
                assert_eq!(
                    done_rx.try_recv(),
                    Err(std::sync::mpsc::TryRecvError::Empty),
                    "inspection must remain paused and not have completed before explicit release"
                );

                if let Some(err) = hook_error.lock().unwrap().take() {
                    panic!("hook recorded error prior to release: {err}");
                }

                // Explicit release sent only now
                if let Some(tx) = guard.0.take() {
                    tx.send(()).expect("send explicit release");
                }

                // Verify successful completion occurs strictly after explicit release
                let outcome = done_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("inspection must complete after release");

                assert_eq!(
                    outcome,
                    Ok(35),
                    "worker must successfully inspect metadata via its owned descriptor after caller cancellation"
                );

                if let Some(err) = hook_error.lock().unwrap().take() {
                    panic!("hook recorded error during release wait: {err}");
                }
            });

            // Finish runtime shutdown and join blocking worker before temporary fixture cleanup
            drop(runtime);
            fixture.close().expect("fixture cleanup must succeed");
        }

        #[tokio::test]
        async fn test_inspect_file_metadata_same_name_replacement_before_inspection() {
            use std::os::unix::fs::MetadataExt;

            let fixture = tempfile::tempdir().expect("create fixture");
            let file_path = fixture.path().join("replacement.bin");
            let original_bytes = b"initial-original-file-bytes";
            std::fs::write(&file_path, original_bytes).expect("write initial file");

            // Open original file and keep descriptor open so its inode number cannot be reused
            let original_file = std::fs::File::open(&file_path).expect("open original file");
            let orig_meta = original_file.metadata().expect("stat original file");
            let orig_dev = orig_meta.dev();
            let orig_ino = orig_meta.ino();

            let reader = FsMetadataReader::open(fixture.path()).expect("open reader");
            let key = ObjectKey::parse("replacement.bin").unwrap();

            // Create distinct replacement file at separate path
            let replacement_path = fixture.path().join("replacement.tmp");
            let replacement_bytes = b"distinct-replacement-regular-file-longer-payload";
            std::fs::write(&replacement_path, replacement_bytes).expect("write replacement file");

            // Rename replacement file over original file path before inspection
            std::fs::rename(&replacement_path, &file_path).expect("atomic rename over original");

            let new_meta = std::fs::metadata(&file_path).expect("stat replacement file");
            let new_dev = new_meta.dev();
            let new_ino = new_meta.ino();

            // Inode comparison: replacement file has distinct inode on same filesystem
            assert_eq!(orig_dev, new_dev, "devices must match in same fixture");
            assert_ne!(
                orig_ino, new_ino,
                "replacement file must have distinct inode from open original file"
            );

            let expected_size = replacement_bytes.len() as u64;
            assert_eq!(new_meta.len(), expected_size);
            let expected_mtime = new_meta.modified().expect("read replacement mtime");

            // Inspection observes replacement file attributes at resolution time
            let inspected = reader
                .inspect_file_metadata(&key)
                .await
                .expect("inspection must succeed on replacement file");

            assert_eq!(inspected.size(), expected_size);
            assert_eq!(inspected.modified(), Some(expected_mtime));

            drop(original_file);
        }

        #[test]
        fn test_inspect_file_metadata_missing_tokio_runtime_returns_typed_backend_error() {
            use std::future::Future;
            use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

            fn dummy_raw_waker() -> RawWaker {
                fn no_op(_: *const ()) {}
                fn clone_waker(p: *const ()) -> RawWaker {
                    RawWaker::new(p, &VTABLE)
                }
                static VTABLE: RawWakerVTable =
                    RawWakerVTable::new(clone_waker, no_op, no_op, no_op);
                RawWaker::new(std::ptr::null(), &VTABLE)
            }

            let fixture = tempfile::tempdir().expect("create fixture");
            let reader = FsMetadataReader::open(fixture.path()).expect("open reader");
            let key = ObjectKey::parse("test.bin").unwrap();

            let waker = unsafe { Waker::from_raw(dummy_raw_waker()) };
            let mut cx = Context::from_waker(&waker);

            let mut fut = Box::pin(reader.inspect_file_metadata(&key));
            let poll_result = fut.as_mut().poll(&mut cx);

            match poll_result {
                Poll::Ready(Err(err)) => {
                    assert!(err.is_backend());
                    let source = match err {
                        ReadError::Backend {
                            message, source, ..
                        } => {
                            assert_eq!(
                                message,
                                "tokio runtime required to execute blocking metadata inspection"
                            );
                            source.expect("source must exist")
                        }
                        other => panic!("expected Backend error, got: {other:?}"),
                    };
                    let fs_err = source
                        .downcast_ref::<FsMetadataError>()
                        .expect("source must downcast to FsMetadataError");
                    assert!(matches!(fs_err, FsMetadataError::RuntimeMissing(_)));
                }
                other => panic!("expected Poll::Ready(Err), got: {other:?}"),
            }
        }

        #[tokio::test]
        async fn test_inspect_file_metadata_task_panic_mapped_to_backend_error() {
            let fixture = tempfile::tempdir().expect("create fixture");
            let file_path = fixture.path().join("panic_target.bin");
            std::fs::write(&file_path, b"test").expect("write file");

            let hooks = InspectTestHooks {
                before_openat2: Some(Arc::new(|| {
                    panic!("controlled test panic inside blocking inspection task");
                })),
                after_openat2: None,
                simulate_fstat_error: None,
                on_complete: None,
            };

            let reader = FsMetadataReader::open(fixture.path())
                .expect("open reader")
                .with_inspect_test_hooks(hooks);

            let key = ObjectKey::parse("panic_target.bin").unwrap();
            let err = reader
                .inspect_file_metadata(&key)
                .await
                .expect_err("panicking task must result in Err");

            assert!(err.is_backend());
            let source = match err {
                ReadError::Backend {
                    message, source, ..
                } => {
                    assert_eq!(message, "blocking metadata inspection task failed");
                    source.expect("source JoinError must be preserved")
                }
                other => panic!("expected Backend error, got: {other:?}"),
            };

            let fs_err = source
                .downcast_ref::<FsMetadataError>()
                .expect("source must downcast to FsMetadataError");

            match fs_err {
                FsMetadataError::TaskJoinFailed(join_err) => {
                    assert!(join_err.is_panic());
                }
                other => panic!("expected TaskJoinFailed, got: {other:?}"),
            }
        }
    }
}
