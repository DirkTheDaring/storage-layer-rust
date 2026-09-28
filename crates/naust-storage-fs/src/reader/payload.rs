//! Standalone payload acquisition implementation and focused tests for `storage-fs`.
//!
//! # Architectural Ownership Boundaries
//! - Implements [`naust_storage_core::ObjectPayloadReader`] for [`crate::FsMetadataReader`].
//! - Uses descriptor-relative containment on Linux (`openat2` + `O_PATH`) to validate object type,
//!   followed by readable reopening via `/proc/self/fd/N` (`O_RDONLY`), re-verifying identity (`st_dev`/`st_ino`).
//! - Returns [`naust_storage_core::ObjectPayload`] wrapping initial [`naust_storage_core::ObjectMetadata`]
//!   and a boxed [`tokio::fs::File`] stream as [`naust_storage_core::ObjectStream`].
//!
//! # Explicit Procfs Trust Assumption
//! This implementation operates under the explicit, documented assumption that `/proc/self/fd`
//! is genuine, accessible, and stable during acquisition.
//! Formatting `/proc/self/fd/N` does not verify procfs integrity. The post-open identity check
//! detects target substitutions but cannot prevent kernel side effects that occur during the `open`
//! call itself if `/proc` were compromised or attacker-controlled.
//! A Phase 2 `ENOENT` indicates a failure of the reopening mechanism (e.g. unmounted or restricted procfs);
//! it is never reported as a missing object (`ReadError::NotFound`) or allowed to trigger uncontained pathname fallbacks.

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(all(test, target_os = "linux"))]
use std::sync::Arc;

#[cfg(all(test, target_os = "linux"))]
use std::sync::atomic::AtomicBool;

use naust_storage_core::{ObjectKey, ObjectMetadata, ReadError};

#[cfg(target_os = "linux")]
use crate::error::FsMetadataError;

#[cfg(all(test, target_os = "linux"))]
type TaskStartHook = Arc<dyn Fn() + Send + Sync>;
#[cfg(all(test, target_os = "linux"))]
type Phase1ValidationHook = Arc<dyn Fn(&OwnedFd) + Send + Sync>;
#[cfg(all(test, target_os = "linux"))]
type ReopenOverrideHook = Arc<dyn Fn(i32) -> std::io::Result<OwnedFd> + Send + Sync>;
#[cfg(all(test, target_os = "linux"))]
type OnAcquisitionCompleteHook = Arc<dyn Fn(Result<&ObjectMetadata, &ReadError>) + Send + Sync>;

/// Narrowly scoped test hooks for verifying the payload acquisition boundary.
#[cfg(all(test, target_os = "linux"))]
#[derive(Clone, Default)]
pub(crate) struct PayloadTestHooks {
    /// Invoked at the very beginning of the blocking task, e.g. for panic/JoinError simulation or cancellation synchronization.
    pub(crate) at_task_start: Option<TaskStartHook>,
    /// Invoked in the blocking task after Phase 1 resolution and fstat validation, before Phase 2 reopening.
    pub(crate) after_phase1_validation: Option<Phase1ValidationHook>,
    /// Custom override for reopening `/proc/self/fd/N` in Phase 2 to simulate synthetic errors (ENOENT, EACCES, EPERM, or identity mismatch).
    pub(crate) reopen_override: Option<ReopenOverrideHook>,
    /// Flag set to true when Phase 2 reopening is entered.
    pub(crate) reopen_stage_reached: Option<Arc<AtomicBool>>,
    /// Invoked after Phase 2 readable reopening, final fstat, and identity validation complete.
    pub(crate) on_complete: Option<OnAcquisitionCompleteHook>,
}

#[cfg(all(test, target_os = "linux"))]
impl std::fmt::Debug for PayloadTestHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PayloadTestHooks")
            .field("at_task_start", &self.at_task_start.is_some())
            .field(
                "after_phase1_validation",
                &self.after_phase1_validation.is_some(),
            )
            .field("reopen_override", &self.reopen_override.is_some())
            .field("reopen_stage_reached", &self.reopen_stage_reached.is_some())
            .field("on_complete", &self.on_complete.is_some())
            .finish()
    }
}

#[cfg(target_os = "linux")]
fn open_proc_self_fd(raw_fd: i32) -> Result<OwnedFd, ReadError> {
    let proc_path = format!("/proc/self/fd/{}\0", raw_fd);
    let fd = unsafe {
        libc::open(
            proc_path.as_ptr() as *const libc::c_char,
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(ReadError::backend_with_source(
            "failed to reopen descriptor via procfs",
            Box::new(FsMetadataError::ProcfsReopenFailed { source: err }),
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Synchronously executes the two-phase payload acquisition sequence on Linux.
///
/// # Stages
/// 1. **Phase 1 (Contained Resolution)**: Resolves `key` relative to `root_fd` via `openat2` with
///    `O_PATH | O_CLOEXEC` and `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
///    The descriptor is immediately wrapped in [`OwnedFd`] and inspected with `fstat`.
///    Non-regular objects (`S_IFREG` required) are rejected immediately.
/// 2. **Phase 2 (Readable Reopening)**: Reopens `/proc/self/fd/{phase1_fd}` with `O_RDONLY | O_CLOEXEC`.
///    The readable descriptor is immediately wrapped in [`OwnedFd`] and inspected with `fstat`.
///    Requires regular-file type, identical `st_dev` and `st_ino` matching Phase 1, and valid non-negative size.
///
/// Returns the verified metadata and an owned [`std::fs::File`].
#[cfg(target_os = "linux")]
pub(crate) fn acquire_payload_sync(
    root_fd: &OwnedFd,
    key: &ObjectKey,
    #[cfg(test)] hooks: Option<&PayloadTestHooks>,
) -> Result<(ObjectMetadata, File), ReadError> {
    #[cfg(test)]
    if let Some(hook) = hooks.and_then(|h| h.at_task_start.as_ref()) {
        hook();
    }

    let res = (|| -> Result<(ObjectMetadata, File), ReadError> {
        // -------------------------------------------------------------------------
        // Phase 1: Descriptor-relative O_PATH resolution and type validation
        // -------------------------------------------------------------------------
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
            return Err(crate::reader::classify_openat2_error(key, err));
        }

        // Immediately wrap the descriptor in OwnedFd to ensure leak-free RAII cleanup on failure
        let phase1_fd = unsafe { OwnedFd::from_raw_fd(res as i32) };

        let mut st1: libc::stat = unsafe { std::mem::zeroed() };
        let stat_res1 = unsafe { libc::fstat(phase1_fd.as_raw_fd(), &mut st1) };
        if stat_res1 != 0 {
            let err = std::io::Error::last_os_error();
            return Err(ReadError::backend_with_source(
                "failed to stat Phase 1 descriptor",
                Box::new(FsMetadataError::StatFailed {
                    stage: "Phase 1 contained",
                    source: err,
                }),
            ));
        }

        let mode_type1 = st1.st_mode & libc::S_IFMT;
        if mode_type1 != libc::S_IFREG {
            return Err(ReadError::backend_with_source(
                "unsupported object type: regular file required",
                Box::new(FsMetadataError::UnsupportedObjectType { mode: st1.st_mode }),
            ));
        }

        #[cfg(test)]
        if let Some(hook) = hooks.and_then(|h| h.after_phase1_validation.as_ref()) {
            hook(&phase1_fd);
        }

        // -------------------------------------------------------------------------
        // Phase 2: Descriptor reopening via procfs and identity re-verification
        // -------------------------------------------------------------------------
        #[cfg(test)]
        if let Some(flag) = hooks.and_then(|h| h.reopen_stage_reached.as_ref()) {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }

        #[cfg(test)]
        let readable_fd: OwnedFd =
            if let Some(reopen_fn) = hooks.and_then(|h| h.reopen_override.as_ref()) {
                reopen_fn(phase1_fd.as_raw_fd()).map_err(|err| {
                    ReadError::backend_with_source(
                        "failed to reopen descriptor via procfs",
                        Box::new(FsMetadataError::ProcfsReopenFailed { source: err }),
                    )
                })?
            } else {
                open_proc_self_fd(phase1_fd.as_raw_fd())?
            };

        #[cfg(not(test))]
        let readable_fd: OwnedFd = open_proc_self_fd(phase1_fd.as_raw_fd())?;

        let mut st2: libc::stat = unsafe { std::mem::zeroed() };
        let stat_res2 = unsafe { libc::fstat(readable_fd.as_raw_fd(), &mut st2) };
        if stat_res2 != 0 {
            let err = std::io::Error::last_os_error();
            return Err(ReadError::backend_with_source(
                "failed to stat Phase 2 readable descriptor",
                Box::new(FsMetadataError::StatFailed {
                    stage: "Phase 2 readable",
                    source: err,
                }),
            ));
        }

        let mode_type2 = st2.st_mode & libc::S_IFMT;
        if mode_type2 != libc::S_IFREG {
            return Err(ReadError::backend_with_source(
                "reopened descriptor is not a regular file",
                Box::new(FsMetadataError::UnsupportedObjectType { mode: st2.st_mode }),
            ));
        }

        if (st2.st_dev as u64) != (st1.st_dev as u64) || (st2.st_ino as u64) != (st1.st_ino as u64)
        {
            return Err(ReadError::backend_with_source(
                "reopened descriptor identity mismatch",
                Box::new(FsMetadataError::IdentityMismatch {
                    expected_dev: st1.st_dev as u64,
                    expected_ino: st1.st_ino as u64,
                    actual_dev: st2.st_dev as u64,
                    actual_ino: st2.st_ino as u64,
                }),
            ));
        }

        if st2.st_size < 0 {
            return Err(ReadError::backend_with_source(
                "invalid metadata: negative file size",
                Box::new(FsMetadataError::InvalidMetadata {
                    message: "negative file size in metadata",
                }),
            ));
        }

        let size = u64::try_from(st2.st_size).map_err(|_| {
            ReadError::backend_with_source(
                "invalid metadata: file size conversion failed",
                Box::new(FsMetadataError::InvalidMetadata {
                    message: "file size conversion failed",
                }),
            )
        })?;

        let metadata = ObjectMetadata::new(size);
        let file = File::from(readable_fd);
        // phase1_fd drops here at the end of scope, releasing the O_PATH descriptor.
        // The readable File holds its own independent open-file description and remains valid.
        Ok((metadata, file))
    })();

    #[cfg(test)]
    if let Some(hook) = hooks.and_then(|h| h.on_complete.as_ref()) {
        hook(res.as_ref().map(|(meta, _file)| meta));
    }

    res
}

/// Positions `file` at `offset` and checks that `offset + length` fits in `size`.
///
/// The seek is the range implementation. Callers limit the subsequent read to
/// `length`. This does not read the prefix.
#[cfg(target_os = "linux")]
pub(crate) fn seek_payload_range(
    file: &mut File,
    offset: u64,
    length: u64,
    size: u64,
) -> Result<(), ReadError> {
    use std::io::{Seek, SeekFrom};

    let end = offset
        .checked_add(length)
        .ok_or_else(|| ReadError::backend("byte range exceeds object"))?;
    if end > size {
        return Err(ReadError::backend("byte range exceeds object"));
    }
    file.seek(SeekFrom::Start(offset)).map_err(|err| {
        ReadError::backend_with_source("failed to seek blob payload", Box::new(err))
    })?;
    Ok(())
}

#[cfg(all(test, not(target_os = "linux")))]
mod non_linux_tests {
    use super::*;
    use crate::FsMetadataReader;
    use naust_storage_core::ObjectPayloadReader;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_payload_reader_non_linux_platform_unsupported() {
        let reader = FsMetadataReader {
            root_path: PathBuf::from("nonempty_path"),
        };
        let key = ObjectKey::parse("test.txt").unwrap();
        let err = reader
            .open_payload(&key)
            .await
            .expect_err("must fail on non-linux");
        match err {
            ReadError::Backend { source, .. } => {
                let inner = source.expect("source");
                let fs_err = inner
                    .downcast_ref::<crate::error::FsMetadataError>()
                    .expect("FsMetadataError");
                assert!(matches!(
                    fs_err,
                    crate::error::FsMetadataError::PlatformUnsupported
                ));
            }
            other => panic!("expected Backend(PlatformUnsupported), got: {other:?}"),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) mod tests {
    use super::*;
    use crate::FsMetadataReader;
    use naust_storage_core::{ObjectKey, ObjectPayloadReader, ReadError};
    use std::os::unix::ffi::OsStrExt;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use tokio::io::AsyncReadExt;

    #[test]
    fn seek_payload_range_positions_file_at_offset() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("blob.bin");
        let mut content = vec![7u8; 200];
        content[50] = 9;
        std::fs::write(&path, &content).expect("write");
        let mut file = std::fs::File::open(&path).expect("open");
        seek_payload_range(&mut file, 50, 1, content.len() as u64).expect("seek");
        use std::io::Seek;
        assert_eq!(file.stream_position().expect("position"), 50);
        let mut byte = [0u8; 1];
        assert_eq!(std::io::Read::read(&mut file, &mut byte).expect("read"), 1);
        assert_eq!(byte[0], 9);
    }

    #[tokio::test]
    async fn open_payload_range_returns_the_span_and_full_size() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let mut content = vec![0u8; 64];
        content[40] = 0xAB;
        content[41] = 0xCD;
        std::fs::write(temp_dir.path().join("blob.bin"), &content).expect("write");
        let reader = FsMetadataReader::open(temp_dir.path()).expect("open");
        let key = ObjectKey::parse("blob.bin").expect("key");
        let payload = reader.open_payload_range(&key, 40, 2).await.expect("range");
        assert_eq!(payload.metadata().size(), content.len() as u64);
        let (_meta, mut stream) = payload.into_parts();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read");
        assert_eq!(buf, [0xAB, 0xCD]);
    }

    // -------------------------------------------------------------------------
    // 1. Regular-file metadata, exact bytes, fixed-buffer consumption, and EOF
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_regular_file_payload_metadata_bytes_fixed_buffer_and_eof() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let content = b"Hello, descriptor-relative payload streaming world! 0123456789abcdef";
        std::fs::write(temp_dir.path().join("blob.bin"), content).expect("write");

        let reader = FsMetadataReader::open(temp_dir.path()).expect("open");
        let key = ObjectKey::parse("blob.bin").expect("key");

        let payload = reader.open_payload(&key).await.expect("open_payload");
        assert_eq!(payload.metadata().size(), content.len() as u64);
        assert_eq!(payload.metadata().len(), content.len() as u64);
        assert!(!payload.metadata().is_empty());

        let (metadata, mut stream) = payload.into_parts();
        assert_eq!(metadata.size(), content.len() as u64);

        let mut buf = [0u8; 16];
        let mut collected = Vec::new();
        loop {
            let n = stream.read(&mut buf).await.expect("read chunk");
            if n == 0 {
                break;
            }
            collected.extend_from_slice(&buf[..n]);
        }
        assert_eq!(collected, content);

        // Subsequent read at EOF returns 0
        let n_eof = stream.read(&mut buf).await.expect("read at eof");
        assert_eq!(n_eof, 0);
    }

    // -------------------------------------------------------------------------
    // 2. Returned stream consumption after reader and key are dropped
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_stream_consumption_after_reader_and_key_dropped() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let content = b"Decoupled lifetime payload data that survives reader and key drops cleanly";
        std::fs::write(temp_dir.path().join("decoupled.txt"), content).expect("write");

        let mut stream = {
            let reader = FsMetadataReader::open(temp_dir.path()).expect("open");
            let key = ObjectKey::parse("decoupled.txt").expect("key");
            let payload = reader.open_payload(&key).await.expect("open_payload");
            payload.into_parts().1
            // reader and key are dropped here
        };

        let mut result = Vec::new();
        stream.read_to_end(&mut result).await.expect("read_to_end");
        assert_eq!(result, content);
    }

    // -------------------------------------------------------------------------
    // 3. Metadata and payload operations sharing the pinned root across root replacement
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_shared_pinned_root_across_root_path_relocation() {
        use naust_storage_core::ObjectMetadataReader;

        let parent_dir = tempfile::tempdir().expect("parent tempdir");
        let initial_root = parent_dir.path().join("initial_root");
        std::fs::create_dir(&initial_root).expect("create initial_root");
        let content = b"Pinned root descriptor invariant across path moves";
        std::fs::write(initial_root.join("item.dat"), content).expect("write item.dat");

        let reader = FsMetadataReader::open(&initial_root).expect("open");
        let key = ObjectKey::parse("item.dat").expect("key");

        // Relocate initial_root to moved_root on disk, leaving initial_root path nonexistent
        let moved_root = parent_dir.path().join("moved_root");
        std::fs::rename(&initial_root, &moved_root).expect("rename root directory");
        assert!(!initial_root.exists(), "original path must not exist");

        // Both head and open_payload operate on the pinned root descriptor
        let meta = reader
            .head(&key)
            .await
            .expect("head must succeed via pinned fd");
        assert_eq!(meta.size(), content.len() as u64);

        let payload = reader
            .open_payload(&key)
            .await
            .expect("open_payload must succeed via pinned fd");
        assert_eq!(payload.metadata().size(), content.len() as u64);

        let mut stream = payload.into_parts().1;
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.expect("read_to_end");
        assert_eq!(data, content);
    }

    // -------------------------------------------------------------------------
    // 4. Deterministic pathname replacement between Phase 1 validation and reopening
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_deterministic_pathname_replacement_between_phase1_and_reopen() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let original_path = temp_dir.path().join("race_file.txt");
        let replaced_path = temp_dir.path().join("replacement.txt");
        let original_bytes = b"original pre-race content";
        let replaced_bytes = b"replaced post-race content";
        std::fs::write(&original_path, original_bytes).expect("write original");
        std::fs::write(&replaced_path, replaced_bytes).expect("write replacement");

        let orig_path_clone = original_path.clone();
        let repl_path_clone = replaced_path.clone();

        // Hook called after Phase 1 fstat, before Phase 2 reopen
        let after_phase1 = Arc::new(move |_phase1_fd: &OwnedFd| {
            // Atomically replace race_file.txt with replacement.txt on disk
            std::fs::rename(&repl_path_clone, &orig_path_clone)
                .expect("rename to replace original");
        });

        let hooks = PayloadTestHooks {
            at_task_start: None,
            after_phase1_validation: Some(after_phase1),
            reopen_override: None,
            reopen_stage_reached: None,
            on_complete: None,
        };

        let reader = FsMetadataReader::open(temp_dir.path())
            .expect("open")
            .with_payload_test_hooks(hooks);
        let key = ObjectKey::parse("race_file.txt").expect("key");

        let payload = reader.open_payload(&key).await.expect("open_payload");
        assert_eq!(payload.metadata().size(), original_bytes.len() as u64);

        let mut stream = payload.into_parts().1;
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.expect("read");
        // Procfs reopen reopens the original Phase 1 inode, NOT the replaced disk content!
        assert_eq!(data, original_bytes);
        assert_ne!(data, replaced_bytes);
    }

    // -------------------------------------------------------------------------
    // 5. Directory, final/dangling symlink, and intermediate-symlink rejection
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_rejection_of_directory_and_symlinks() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let root = temp_dir.path();

        // 1. Directory
        std::fs::create_dir(root.join("sub_dir")).expect("create dir");
        // 2. Final symlink to regular file
        std::fs::write(root.join("target.txt"), b"target").expect("write target");
        std::os::unix::fs::symlink(root.join("target.txt"), root.join("link_final.txt"))
            .expect("symlink final");
        // 3. Dangling symlink
        std::os::unix::fs::symlink(root.join("missing.txt"), root.join("link_dangling.txt"))
            .expect("symlink dangling");
        // 4. Intermediate directory symlink
        std::os::unix::fs::symlink(root.join("sub_dir"), root.join("link_dir"))
            .expect("symlink dir");
        std::fs::write(root.join("sub_dir/inner.txt"), b"inner").expect("write inner");

        let reader = FsMetadataReader::open(root).expect("open");

        // Directory rejection: UnsupportedObjectType
        let err_dir = reader
            .open_payload(&ObjectKey::parse("sub_dir").unwrap())
            .await
            .unwrap_err();
        match err_dir {
            ReadError::Backend { source, .. } => {
                let inner = source.expect("inner source");
                let fs_err = inner
                    .downcast_ref::<FsMetadataError>()
                    .expect("FsMetadataError");
                match fs_err {
                    FsMetadataError::UnsupportedObjectType { mode } => {
                        assert_eq!(mode & libc::S_IFMT, libc::S_IFDIR);
                    }
                    other => panic!("expected UnsupportedObjectType for dir, got {other:?}"),
                }
            }
            other => panic!("expected Backend for dir, got {other:?}"),
        }

        // Final symlink rejection: ResolutionRejected (ELOOP)
        let err_final = reader
            .open_payload(&ObjectKey::parse("link_final.txt").unwrap())
            .await
            .unwrap_err();
        match err_final {
            ReadError::Backend { source, .. } => {
                let inner = source.expect("inner source");
                let fs_err = inner
                    .downcast_ref::<FsMetadataError>()
                    .expect("FsMetadataError");
                assert!(
                    matches!(fs_err, FsMetadataError::ResolutionRejected { raw_os_error, .. } if *raw_os_error == libc::ELOOP)
                );
            }
            other => panic!("expected Backend for final symlink, got {other:?}"),
        }

        // Dangling symlink rejection: ResolutionRejected (ELOOP)
        let err_dangling = reader
            .open_payload(&ObjectKey::parse("link_dangling.txt").unwrap())
            .await
            .unwrap_err();
        match err_dangling {
            ReadError::Backend { source, .. } => {
                let inner = source.expect("inner source");
                let fs_err = inner
                    .downcast_ref::<FsMetadataError>()
                    .expect("FsMetadataError");
                assert!(
                    matches!(fs_err, FsMetadataError::ResolutionRejected { raw_os_error, .. } if *raw_os_error == libc::ELOOP)
                );
            }
            other => panic!("expected Backend for dangling symlink, got {other:?}"),
        }

        // Intermediate symlink rejection: ResolutionRejected (ELOOP)
        let err_inter = reader
            .open_payload(&ObjectKey::parse("link_dir/inner.txt").unwrap())
            .await
            .unwrap_err();
        match err_inter {
            ReadError::Backend { source, .. } => {
                let inner = source.expect("inner source");
                let fs_err = inner
                    .downcast_ref::<FsMetadataError>()
                    .expect("FsMetadataError");
                assert!(
                    matches!(fs_err, FsMetadataError::ResolutionRejected { raw_os_error, .. } if *raw_os_error == libc::ELOOP)
                );
            }
            other => panic!("expected Backend for intermediate symlink, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // 6. FIFO rejection before readable reopening in isolated child process
    // -------------------------------------------------------------------------
    #[test]
    fn fifo_child_worker() {
        if std::env::var("STORAGE_FS_FIFO_PAYLOAD_TEST_CHILD").is_err() {
            return;
        }
        let root_str = std::env::var("STORAGE_FS_ROOT_PATH").expect("root path env");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for child");

        rt.block_on(async {
            let stage_flag = Arc::new(AtomicBool::new(false));
            let stage_flag_clone = Arc::clone(&stage_flag);
            let hooks = PayloadTestHooks {
                at_task_start: None,
                after_phase1_validation: None,
                reopen_override: None,
                reopen_stage_reached: Some(stage_flag_clone),
                on_complete: None,
            };
            let reader = FsMetadataReader::open(&root_str)
                .expect("open reader")
                .with_payload_test_hooks(hooks);
            let key = ObjectKey::parse("fifo_fixture").expect("key");

            let result = reader.open_payload(&key).await;

            // Assert Phase 2 reopen stage was never reached
            assert!(
                !stage_flag.load(Ordering::SeqCst),
                "reopen stage must NOT be reached for FIFO"
            );

            match result {
                Err(ReadError::Backend { source, .. }) => {
                    let inner = source.expect("inner source");
                    let fs_err = inner
                        .downcast_ref::<FsMetadataError>()
                        .expect("FsMetadataError");
                    match fs_err {
                        FsMetadataError::UnsupportedObjectType { mode } => {
                            assert_eq!(mode & libc::S_IFMT, libc::S_IFIFO);
                        }
                        other => panic!("expected UnsupportedObjectType for FIFO, got: {other:?}"),
                    }
                }
                other => panic!("expected Backend for FIFO, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_rejection_before_readable_open_fifo_in_child_process() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let root_path = temp_dir.path();
        let fifo_path = root_path.join("fifo_fixture");

        let c_fifo = CString::new(fifo_path.as_os_str().as_bytes()).expect("cstring for fifo");
        let mkfifo_res = unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) };
        if mkfifo_res != 0 {
            panic!(
                "fixture setup failed: mkfifo: {}",
                std::io::Error::last_os_error()
            );
        }

        let current_exe = std::env::current_exe().expect("current test executable");
        let mut child = std::process::Command::new(current_exe)
            .arg("reader::payload::tests::fifo_child_worker")
            .arg("--exact")
            .arg("--nocapture")
            .env("STORAGE_FS_FIFO_PAYLOAD_TEST_CHILD", "1")
            .env("STORAGE_FS_ROOT_PATH", root_path.as_os_str())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .expect("spawn child process");

        let deadline = std::time::Duration::from_secs(5);
        let start = std::time::Instant::now();
        let mut exit_status = None;

        while start.elapsed() < deadline {
            match child.try_wait() {
                Ok(Some(status)) => {
                    exit_status = Some(status);
                    break;
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
                Err(e) => {
                    let kill_err = child.kill().err();
                    let reap_res = child.wait();
                    let cleanup_res = temp_dir.close();
                    panic!(
                        "failed waiting on child process ({e}); kill error: {kill_err:?}, reap result: {reap_res:?}, cleanup result: {cleanup_res:?}"
                    );
                }
            }
        }

        let status = match exit_status {
            Some(s) => s,
            None => {
                // Userspace timeout expired.
                // Note: a userspace deadline cannot guarantee prompt termination of an
                // uninterruptible kernel stall (e.g. D state in an uncontained driver/filesystem).
                let kill_err = child.kill().err();
                let reap_res = child.wait();
                let cleanup_res = temp_dir.close();
                panic!(
                    "FIFO child process exceeded deadline ({deadline:?}); probable blocking open hang. Kill error: {kill_err:?}, reap result: {reap_res:?}, cleanup result: {cleanup_res:?}"
                );
            }
        };

        assert!(status.success(), "FIFO child process failed: {status:?}");
        if let Err(e) = temp_dir.close() {
            panic!("failed to clean up fixture directory after child reaping: {e}");
        }
    }

    // -------------------------------------------------------------------------
    // 7. Missing-object acquisition
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_missing_object_returns_not_found() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let reader = FsMetadataReader::open(temp_dir.path()).expect("open");
        let key = ObjectKey::parse("nonexistent_payload.txt").expect("key");

        let err = reader
            .open_payload(&key)
            .await
            .expect_err("must fail for missing object");
        match err {
            ReadError::NotFound { key: err_key, .. } => {
                assert_eq!(err_key, key);
            }
            other => panic!("expected ReadError::NotFound, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // 8. Synthetic procfs reopen failures (ENOENT, EACCES, EPERM, identity mismatch)
    // -------------------------------------------------------------------------
    // Synthetic tests verify error classification and typed retention without uncontained fallback.
    // They do not simulate an actual unmounted or permission-restricted procfs mount.
    #[tokio::test]
    async fn test_reopen_failures_synthetic_enoent_permission_and_identity_mismatch() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let file_path = temp_dir.path().join("synthetic.txt");
        std::fs::write(&file_path, b"synthetic test content").expect("write");
        let key = ObjectKey::parse("synthetic.txt").expect("key");

        // 8a. Synthetic Phase 2 ENOENT
        let reopen_enoent = Arc::new(|_fd: i32| -> std::io::Result<OwnedFd> {
            Err(std::io::Error::from_raw_os_error(libc::ENOENT))
        });
        let hooks_enoent = PayloadTestHooks {
            at_task_start: None,
            after_phase1_validation: None,
            reopen_override: Some(reopen_enoent),
            reopen_stage_reached: None,
            on_complete: None,
        };
        let reader_enoent = FsMetadataReader::open(temp_dir.path())
            .expect("open")
            .with_payload_test_hooks(hooks_enoent);
        let err_enoent = reader_enoent
            .open_payload(&key)
            .await
            .expect_err("must fail");
        match err_enoent {
            ReadError::Backend {
                message, source, ..
            } => {
                assert!(message.contains("procfs"));
                let inner = source.expect("source");
                let fs_err = inner
                    .downcast_ref::<FsMetadataError>()
                    .expect("FsMetadataError");
                match fs_err {
                    FsMetadataError::ProcfsReopenFailed { source: io_err } => {
                        assert_eq!(io_err.raw_os_error(), Some(libc::ENOENT));
                    }
                    other => panic!("expected ProcfsReopenFailed, got {other:?}"),
                }
            }
            other => panic!("Phase 2 ENOENT must NEVER be NotFound! Got: {other:?}"),
        }

        // 8b. Synthetic Phase 2 EACCES
        let reopen_eacces = Arc::new(|_fd: i32| -> std::io::Result<OwnedFd> {
            Err(std::io::Error::from_raw_os_error(libc::EACCES))
        });
        let hooks_eacces = PayloadTestHooks {
            at_task_start: None,
            after_phase1_validation: None,
            reopen_override: Some(reopen_eacces),
            reopen_stage_reached: None,
            on_complete: None,
        };
        let reader_eacces = FsMetadataReader::open(temp_dir.path())
            .expect("open")
            .with_payload_test_hooks(hooks_eacces);
        let err_eacces = reader_eacces
            .open_payload(&key)
            .await
            .expect_err("must fail");
        match err_eacces {
            ReadError::Backend {
                message, source, ..
            } => {
                assert!(message.contains("procfs"));
                let inner = source.expect("source");
                let fs_err = inner
                    .downcast_ref::<FsMetadataError>()
                    .expect("FsMetadataError");
                match fs_err {
                    FsMetadataError::ProcfsReopenFailed { source: io_err } => {
                        assert_eq!(io_err.raw_os_error(), Some(libc::EACCES));
                    }
                    other => panic!("expected ProcfsReopenFailed, got {other:?}"),
                }
            }
            other => panic!("Phase 2 EACCES must NEVER be PermissionDenied! Got: {other:?}"),
        }

        // 8c. Synthetic Phase 2 EPERM
        let reopen_eperm = Arc::new(|_fd: i32| -> std::io::Result<OwnedFd> {
            Err(std::io::Error::from_raw_os_error(libc::EPERM))
        });
        let hooks_eperm = PayloadTestHooks {
            at_task_start: None,
            after_phase1_validation: None,
            reopen_override: Some(reopen_eperm),
            reopen_stage_reached: None,
            on_complete: None,
        };
        let reader_eperm = FsMetadataReader::open(temp_dir.path())
            .expect("open")
            .with_payload_test_hooks(hooks_eperm);
        let err_eperm = reader_eperm
            .open_payload(&key)
            .await
            .expect_err("must fail");
        match err_eperm {
            ReadError::Backend { source, .. } => {
                let inner = source.expect("source");
                let fs_err = inner
                    .downcast_ref::<FsMetadataError>()
                    .expect("FsMetadataError");
                match fs_err {
                    FsMetadataError::ProcfsReopenFailed { source: io_err } => {
                        assert_eq!(io_err.raw_os_error(), Some(libc::EPERM));
                    }
                    other => panic!("expected ProcfsReopenFailed, got {other:?}"),
                }
            }
            other => panic!("Phase 2 EPERM must NEVER be PermissionDenied! Got: {other:?}"),
        }

        // 8d. Synthetic Phase 2 Identity Mismatch
        let other_file_path = temp_dir.path().join("other.txt");
        std::fs::write(&other_file_path, b"other").expect("write other");
        let other_path_clone = other_file_path.clone();
        let reopen_mismatch = Arc::new(move |_fd: i32| -> std::io::Result<OwnedFd> {
            let f = std::fs::File::open(&other_path_clone)?;
            Ok(f.into())
        });
        let hooks_mismatch = PayloadTestHooks {
            at_task_start: None,
            after_phase1_validation: None,
            reopen_override: Some(reopen_mismatch),
            reopen_stage_reached: None,
            on_complete: None,
        };
        let reader_mismatch = FsMetadataReader::open(temp_dir.path())
            .expect("open")
            .with_payload_test_hooks(hooks_mismatch);
        let err_mismatch = reader_mismatch
            .open_payload(&key)
            .await
            .expect_err("must fail");
        match err_mismatch {
            ReadError::Backend { source, .. } => {
                let inner = source.expect("source");
                let fs_err = inner
                    .downcast_ref::<FsMetadataError>()
                    .expect("FsMetadataError");
                match fs_err {
                    FsMetadataError::IdentityMismatch {
                        expected_ino,
                        actual_ino,
                        ..
                    } => {
                        assert_ne!(expected_ino, actual_ino);
                    }
                    other => panic!("expected IdentityMismatch, got {other:?}"),
                }
            }
            other => panic!("expected Backend for mismatch, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // 9. Missing runtime
    // -------------------------------------------------------------------------
    #[test]
    fn test_missing_runtime_fails_immediately() {
        use std::task::{Context, Poll};

        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp_dir.path().join("test.txt"), b"data").expect("write");
        let reader = FsMetadataReader::open(temp_dir.path()).expect("open");
        let key = ObjectKey::parse("test.txt").expect("key");

        // Execute outside a Tokio runtime
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = std::pin::pin!(reader.open_payload(&key));

        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(Err(err)) => {
                assert!(err.is_backend(), "must be Backend error");
                let source = match err {
                    ReadError::Backend {
                        message, source, ..
                    } => {
                        assert_eq!(
                            message,
                            "tokio runtime required to execute blocking payload acquisition"
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
            Poll::Ready(Ok(_)) => panic!("payload lookup without runtime must not succeed"),
            Poll::Pending => panic!("payload lookup without runtime must fail immediately"),
        }
    }

    // -------------------------------------------------------------------------
    // 10. A genuine JoinError produced through a narrow test hook in the blocking path
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_genuine_join_error_in_blocking_path() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp_dir.path().join("panic.txt"), b"data").expect("write");
        let key = ObjectKey::parse("panic.txt").expect("key");

        let hooks = PayloadTestHooks {
            at_task_start: Some(Arc::new(|| {
                panic!("simulated test panic in blocking payload task");
            })),
            ..Default::default()
        };

        let reader = FsMetadataReader::open(temp_dir.path())
            .expect("open")
            .with_payload_test_hooks(hooks);

        let err = reader.open_payload(&key).await.expect_err("must fail");
        match err {
            ReadError::Backend {
                message, source, ..
            } => {
                assert_eq!(message, "blocking payload acquisition task failed");
                let inner = source.expect("source");
                let fs_err = inner
                    .downcast_ref::<FsMetadataError>()
                    .expect("FsMetadataError");
                match fs_err {
                    FsMetadataError::TaskJoinFailed(join_err) => {
                        assert!(join_err.is_panic(), "join error must be a panic");
                    }
                    other => panic!("expected TaskJoinFailed, got {other:?}"),
                }
            }
            other => panic!("expected Backend(TaskJoinFailed), got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // 11. Controlled cancellation demonstrating owned descriptor lifetime and cleanup
    // -------------------------------------------------------------------------
    #[test]
    fn test_controlled_cancellation_descriptor_lifetime() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        std::fs::create_dir_all(&root_dir).expect("create root");
        let file_path = root_dir.join("cancellation.bin");
        let expected_bytes = b"descriptor lifetime on cancellation";
        std::fs::write(&file_path, expected_bytes).expect("write file");

        let (paused_tx, paused_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (payload_done_tx, payload_done_rx) = std::sync::mpsc::channel::<Result<u64, String>>();

        let release_rx = Arc::new(std::sync::Mutex::new(release_rx));
        let paused_tx = Arc::new(std::sync::Mutex::new(paused_tx));
        let payload_done_tx = Arc::new(std::sync::Mutex::new(payload_done_tx));
        let hook_error = Arc::new(std::sync::Mutex::new(None::<String>));
        let worker_is_paused = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let err_slot = Arc::clone(&hook_error);
        let rx_clone = Arc::clone(&release_rx);
        let paused_tx_clone = Arc::clone(&paused_tx);
        let is_paused_clone = Arc::clone(&worker_is_paused);

        let hooks = PayloadTestHooks {
            at_task_start: Some(Arc::new(move || {
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
            after_phase1_validation: None,
            reopen_override: None,
            reopen_stage_reached: None,
            on_complete: Some(Arc::new({
                let payload_done_tx = Arc::clone(&payload_done_tx);
                move |res| {
                    let mapped = match res {
                        Ok(meta) => Ok(meta.size()),
                        Err(err) => Err(format!("{err:?}")),
                    };
                    let _ = payload_done_tx.lock().unwrap().send(mapped);
                }
            })),
        };

        let reader = FsMetadataReader::open(&root_dir)
            .expect("open reader")
            .with_payload_test_hooks(hooks);

        // RAII guard ensuring panic-safe release even on failure paths
        struct ReleaseGuard(Option<std::sync::mpsc::Sender<()>>);
        impl ReleaseGuard {
            fn release(&mut self) -> Result<(), std::sync::mpsc::SendError<()>> {
                if let Some(tx) = self.0.take() {
                    tx.send(())
                } else {
                    Ok(())
                }
            }
        }
        impl Drop for ReleaseGuard {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }
        let key = ObjectKey::parse("cancellation.bin").unwrap();

        // Dedicated current-thread Tokio runtime declared before ReleaseGuard so that
        // in all unwinding scenarios, guard drops before runtime teardown
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("create dedicated current-thread runtime");
        let mut guard = ReleaseGuard(Some(release_tx));

        let test_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(async {
                // Start open_payload and drive it until the worker enters its paused state
                let mut payload_fut = reader.open_payload(&key);
                tokio::select! {
                    _ = &mut payload_fut => {
                        panic!("payload future should not complete before cancellation");
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
                drop(payload_fut);
                drop(reader);

                // Establish that the worker is STILL paused when awaiting future and reader are dropped
                assert!(
                    worker_is_paused.load(std::sync::atomic::Ordering::SeqCst),
                    "worker must remain paused when awaiting future and reader are dropped"
                );
                assert!(
                    payload_done_rx.try_recv().is_err(),
                    "payload work must not have completed before explicit release"
                );

                // Verify no hook error occurred prior to release
                if let Some(err) = hook_error.lock().unwrap().take() {
                    panic!("hook recorded error prior to release: {err}");
                }

                // Release the worker explicitly
                guard.release().expect("send explicit release to worker");

                // Confirm successful complete acquisition (Phase 1 + Phase 2 + stat + identity)
                let outcome = match payload_done_rx.recv_timeout(std::time::Duration::from_secs(5)) {
                    Ok(res) => res,
                    Err(e) => {
                        let hook_err = hook_error.lock().unwrap().take();
                        panic!("worker failed to report completion within deadline ({e:?}); hook error: {hook_err:?}");
                    }
                };

                match outcome {
                    Ok(size) => {
                        assert_eq!(
                            size,
                            expected_bytes.len() as u64,
                            "worker must successfully complete acquisition and report expected size"
                        );
                    }
                    Err(err) => panic!("worker acquisition failed after release: {err}"),
                }

                // Verify no hook error occurred during or after release
                if let Some(err) = hook_error.lock().unwrap().take() {
                    panic!("hook recorded error during/after release: {err}");
                }
            });
        }));

        // Ensure release guard has dropped before runtime teardown on failure paths as well as normal path
        drop(guard);

        // Explicitly tear down the dedicated runtime outside the async context and after drop(guard).
        // Tokio Runtime::drop blocks and waits for blocking work (including our released worker)
        // to finish before returning.
        // Note: Runtime Drop waiting for blocking work is cooperative and does not impose a hard deadline
        // against an uninterruptible kernel stall.
        drop(runtime);

        // Attempt fixture cleanup after runtime teardown has completed and all descriptors are closed
        let fixture_cleanup_res = fixture.close();

        // If cleanup fails while an earlier test panic is being propagated, report that cleanup
        // failure before resuming the original panic.
        if let Err(payload) = test_result {
            if let Err(cleanup_err) = fixture_cleanup_res {
                eprintln!(
                    "failed to clean up fixture directory during test panic propagation: {cleanup_err}"
                );
            }
            std::panic::resume_unwind(payload);
        }

        if let Err(e) = fixture_cleanup_res {
            panic!("failed to clean up fixture directory: {e}");
        }
    }
}
