//! Experimental Linux test-only two-phase descriptor-relative payload acquisition helper and tests.
//!
//! # Experimental Scope
//! This module implements a bounded test-only experiment for opening regular-file payloads
//! under a pinned root directory descriptor on Linux without uncontained pathname fallback.
//!
//! # Mechanism
//! - **Phase 1**: Resolves an [`ObjectKey`] relative to the pinned `root_fd` using `libc::SYS_openat2`
//!   with `O_PATH | O_CLOEXEC` and containment flags `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
//!   The returned file descriptor is immediately wrapped in an [`OwnedFd`] to guarantee RAII cleanup.
//!   The descriptor is inspected using `libc::fstat` to verify that `st_mode & S_IFMT == S_IFREG`.
//!   Non-regular objects (directories, symlinks, FIFOs, sockets, device nodes) are rejected before any readable open.
//! - **Phase 2**: While retaining the Phase 1 [`OwnedFd`], `/proc/self/fd/{raw_fd}` is opened with `O_RDONLY | O_CLOEXEC`.
//!   The readable descriptor is immediately wrapped in an [`OwnedFd`].
//!   `libc::fstat` is invoked on the readable descriptor to re-verify regular-file type and confirm that
//!   `st_dev` and `st_ino` match the Phase 1 descriptor.
//!   The verified descriptor is returned as an owned [`std::fs::File`] along with [`ObjectMetadata`].
//!
//! # Open-File Description vs. `dup`
//! Opening `/proc/self/fd/{raw_fd}` creates a brand new open-file description (`struct file`) in the Linux kernel
//! with its own access mode (`O_RDONLY`) and offset 0 pointing to the same underlying inode.
//! This differs fundamentally from `dup` (or `fcntl F_DUPFD`), which duplicates the descriptor to point to the
//! existing `struct file` and cannot upgrade an `O_PATH` description to readable access.
//!
//! # Trust Boundary & Procfs Availability
//! This experiment assumes the execution environment provides an accessible, genuine `/proc/self/fd` mount.
//! Formatting `/proc/self/fd/N` does not verify procfs integrity. The post-open `st_dev`/`st_ino` identity check
//! detects target substitutions but cannot prevent kernel side effects that occur during the `open` call itself
//! if `/proc` were compromised or attacker-controlled.
//! A Phase 2 `ENOENT` indicates a failure of the reopening mechanism (e.g. unmounted or restricted procfs);
//! it is never reported as a missing object or allowed to trigger uncontained pathname fallbacks.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};

use storage_core::{ObjectKey, ObjectMetadata};

/// Errors that can occur during experimental two-phase payload acquisition.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AcquisitionExperimentError {
    #[error("failed to create CString for key '{key}': {source}")]
    InvalidKey {
        key: ObjectKey,
        #[source]
        source: std::ffi::NulError,
    },
    #[error("openat2 resolution failed in Phase 1 for key '{key}': {source}")]
    Resolution {
        key: ObjectKey,
        #[source]
        source: io::Error,
    },
    #[error("fstat failed on Phase 1 descriptor: {source}")]
    Phase1Stat {
        #[source]
        source: io::Error,
    },
    #[error("unsupported object type in Phase 1: mode {mode:#o} is not a regular file")]
    UnsupportedObjectType { mode: u32 },
    #[error("procfs reopen failed in Phase 2 with errno {errno}: {source}")]
    ReopenFailed {
        errno: i32,
        #[source]
        source: io::Error,
    },
    #[error("fstat failed on Phase 2 readable descriptor: {source}")]
    Phase2Stat {
        #[source]
        source: io::Error,
    },
    #[error("reopened Phase 2 descriptor mode {mode:#o} is not a regular file")]
    ReopenNotRegularFile { mode: u32 },
    #[error(
        "reopened descriptor identity mismatch: expected dev {expected_dev} ino {expected_ino}, got dev {actual_dev} ino {actual_ino}"
    )]
    ReopenIdentityMismatch {
        expected_dev: u64,
        expected_ino: u64,
        actual_dev: u64,
        actual_ino: u64,
    },
    #[error("invalid metadata on readable descriptor: {message}")]
    InvalidMetadata { message: &'static str },
}

/// Test hooks to control and observe the two-phase acquisition boundary deterministically.
#[derive(Default)]
pub(crate) struct AcquisitionExperimentHooks<'a> {
    /// Synchronous callback executed after Phase 1 fstat validation and before Phase 2 reopening.
    /// Used for deterministic race-condition and pathname replacement testing without sleeps.
    pub(crate) after_phase1_validation: Option<&'a dyn Fn(&OwnedFd)>,
    /// Optional override for the Phase 2 reopen call to simulate synthetic errors (ENOENT, EACCES, EPERM).
    pub(crate) reopen_override: Option<&'a dyn Fn(i32) -> Result<OwnedFd, io::Error>>,
    /// Flag set to true when Phase 2 reopening is entered. Used to verify rejection occurs before readable open.
    pub(crate) reopen_stage_reached: Option<&'a AtomicBool>,
}

/// Synchronously acquires a regular-file payload descriptor relative to `root_fd` using two-phase resolution.
pub(crate) fn acquire_payload_sync(
    root_fd: &OwnedFd,
    key: &ObjectKey,
    hooks: AcquisitionExperimentHooks<'_>,
) -> Result<(ObjectMetadata, File), AcquisitionExperimentError> {
    // -------------------------------------------------------------------------
    // Phase 1: Descriptor-relative O_PATH resolution and type validation
    // -------------------------------------------------------------------------
    let c_rel =
        CString::new(key.as_str()).map_err(|source| AcquisitionExperimentError::InvalidKey {
            key: key.clone(),
            source,
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
        let err = io::Error::last_os_error();
        return Err(AcquisitionExperimentError::Resolution {
            key: key.clone(),
            source: err,
        });
    }

    // Immediately wrap the returned descriptor in OwnedFd to ensure RAII closure on any failure.
    let phase1_fd = unsafe { OwnedFd::from_raw_fd(res as i32) };

    let mut st1: libc::stat = unsafe { std::mem::zeroed() };
    let stat_res1 = unsafe { libc::fstat(phase1_fd.as_raw_fd(), &mut st1) };
    if stat_res1 != 0 {
        let err = io::Error::last_os_error();
        return Err(AcquisitionExperimentError::Phase1Stat { source: err });
    }

    let mode_type1 = st1.st_mode & libc::S_IFMT;
    if mode_type1 != libc::S_IFREG {
        return Err(AcquisitionExperimentError::UnsupportedObjectType { mode: st1.st_mode });
    }

    // Explicit synchronous hook between Phase 1 validation and Phase 2 reopen
    if let Some(hook) = hooks.after_phase1_validation {
        hook(&phase1_fd);
    }

    // -------------------------------------------------------------------------
    // Phase 2: Descriptor reopening via procfs and identity re-verification
    // -------------------------------------------------------------------------
    if let Some(stage_flag) = hooks.reopen_stage_reached {
        stage_flag.store(true, Ordering::SeqCst);
    }

    // Reopen /proc/self/fd/{phase1_fd} while holding phase1_fd open
    let readable_fd: OwnedFd = if let Some(reopen_override) = hooks.reopen_override {
        reopen_override(phase1_fd.as_raw_fd()).map_err(|err| {
            let errno = err.raw_os_error().unwrap_or(0);
            AcquisitionExperimentError::ReopenFailed { errno, source: err }
        })?
    } else {
        let proc_path = format!("/proc/self/fd/{}\0", phase1_fd.as_raw_fd());
        let raw_fd = unsafe {
            libc::open(
                proc_path.as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if raw_fd < 0 {
            let err = io::Error::last_os_error();
            let errno = err.raw_os_error().unwrap_or(0);
            return Err(AcquisitionExperimentError::ReopenFailed { errno, source: err });
        }
        unsafe { OwnedFd::from_raw_fd(raw_fd) }
    };

    // Re-inspect the opened readable descriptor
    let mut st2: libc::stat = unsafe { std::mem::zeroed() };
    let stat_res2 = unsafe { libc::fstat(readable_fd.as_raw_fd(), &mut st2) };
    if stat_res2 != 0 {
        let err = io::Error::last_os_error();
        return Err(AcquisitionExperimentError::Phase2Stat { source: err });
    }

    let mode_type2 = st2.st_mode & libc::S_IFMT;
    if mode_type2 != libc::S_IFREG {
        return Err(AcquisitionExperimentError::ReopenNotRegularFile { mode: st2.st_mode });
    }

    if (st2.st_dev as u64) != (st1.st_dev as u64) || (st2.st_ino as u64) != (st1.st_ino as u64) {
        return Err(AcquisitionExperimentError::ReopenIdentityMismatch {
            expected_dev: st1.st_dev as u64,
            expected_ino: st1.st_ino as u64,
            actual_dev: st2.st_dev as u64,
            actual_ino: st2.st_ino as u64,
        });
    }

    if st2.st_size < 0 {
        return Err(AcquisitionExperimentError::InvalidMetadata {
            message: "negative file size on readable descriptor",
        });
    }

    let metadata = ObjectMetadata::new(st2.st_size as u64);

    let file = File::from(readable_fd);
    // phase1_fd drops here at the end of function scope, releasing the O_PATH descriptor.
    // The readable File holds its own independent open-file description and remains valid.
    Ok((metadata, file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FsMetadataReader;
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    // -------------------------------------------------------------------------
    // A. Regular-file acquisition
    // -------------------------------------------------------------------------
    // Label: Byte correctness and incremental consumption evidence, not proof of
    // an entire future async backend's memory behavior.
    #[test]
    fn test_regular_file_acquisition_metadata_bytes_and_eof() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let root_path = temp_dir.path();

        // 1024-byte deterministic pattern
        let mut fixture_bytes = Vec::with_capacity(1024);
        for i in 0..1024 {
            fixture_bytes.push((i % 251) as u8);
        }
        let file_path = root_path.join("blob.bin");
        std::fs::write(&file_path, &fixture_bytes).expect("write fixture");

        let reader = FsMetadataReader::open(root_path).expect("open reader");
        let key = ObjectKey::parse("blob.bin").expect("valid key");

        let (metadata, mut file) = acquire_payload_sync(&reader.root_fd, &key, Default::default())
            .expect("acquisition must succeed");

        // Verify final-descriptor metadata
        assert_eq!(metadata.size(), 1024);

        // Incremental consumption using a fixed-size buffer
        let mut consumed_bytes = Vec::new();
        let mut buffer = [0u8; 64]; // Fixed 64-byte buffer
        loop {
            let n = file.read(&mut buffer).expect("incremental read");
            if n == 0 {
                break;
            }
            consumed_bytes.extend_from_slice(&buffer[..n]);
        }

        // Verify exact fixture bytes
        assert_eq!(consumed_bytes, fixture_bytes);

        // Verify EOF behavior
        let at_eof = file.read(&mut buffer).expect("read at eof");
        assert_eq!(at_eof, 0);
    }

    // -------------------------------------------------------------------------
    // B. Deterministic pathname replacement
    // -------------------------------------------------------------------------
    #[test]
    fn test_deterministic_pathname_replacement_immunity() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let root_path = temp_dir.path();

        let original_bytes = b"ORIGINAL_OBJECT_PAYLOAD_V1";
        let replacement_bytes = b"REPLACEMENT_ATTACKER_PAYLOAD_V2_LONGER";

        let original_file_path = root_path.join("target.data");
        let renamed_file_path = root_path.join("target.data.renamed");
        std::fs::write(&original_file_path, original_bytes).expect("write original");

        let original_stat = std::fs::metadata(&original_file_path).expect("original stat");
        let original_ino = std::os::unix::fs::MetadataExt::ino(&original_stat);

        let reader = FsMetadataReader::open(root_path).expect("open reader");
        let key = ObjectKey::parse("target.data").expect("valid key");

        // Deterministic pause between Phase 1 and Phase 2
        let after_phase1 = |_phase1_fd: &OwnedFd| {
            // Rename the original file and write a replacement file at the old pathname
            std::fs::rename(&original_file_path, &renamed_file_path).expect("rename original");
            std::fs::write(&original_file_path, replacement_bytes).expect("write replacement");
        };

        let hooks = AcquisitionExperimentHooks {
            after_phase1_validation: Some(&after_phase1),
            reopen_override: None,
            reopen_stage_reached: None,
        };

        let (metadata, mut file) = acquire_payload_sync(&reader.root_fd, &key, hooks)
            .expect("reopen must succeed on original inode");

        // Verify metadata matches original object, NOT replacement
        assert_eq!(metadata.size(), original_bytes.len() as u64);

        // Verify bytes read match original object, NOT replacement
        let mut read_bytes = Vec::new();
        file.read_to_end(&mut read_bytes).expect("read to end");
        assert_eq!(read_bytes, original_bytes);

        // Verify inode of the returned file descriptor matches the original inode
        let returned_stat = file.metadata().expect("file metadata");
        let returned_ino = std::os::unix::fs::MetadataExt::ino(&returned_stat);
        assert_eq!(returned_ino, original_ino);

        // Verify replacement at old path has different inode
        let replacement_stat = std::fs::metadata(&original_file_path).expect("replacement stat");
        let replacement_ino = std::os::unix::fs::MetadataExt::ino(&replacement_stat);
        assert_ne!(returned_ino, replacement_ino);
    }

    // -------------------------------------------------------------------------
    // C. Shared-root behavior
    // -------------------------------------------------------------------------
    #[test]
    fn test_shared_root_resolution_pinned_across_root_replacement() {
        let parent_dir = tempfile::tempdir().expect("parent tempdir");
        let root_path = parent_dir.path().join("root");
        std::fs::create_dir(&root_path).expect("create root");

        let original_root_bytes = b"ORIGINAL_ROOT_PAYLOAD";
        let replacement_root_bytes = b"REPLACEMENT_ROOT_DIFFERENT_PAYLOAD";

        std::fs::write(root_path.join("data.txt"), original_root_bytes).expect("write in root");

        // Construct reader over root_path
        let reader = FsMetadataReader::open(&root_path).expect("open reader");

        // Rename the root directory and create a new directory at the original path
        let renamed_root = parent_dir.path().join("root_renamed");
        std::fs::rename(&root_path, &renamed_root).expect("rename root dir");

        std::fs::create_dir(&root_path).expect("create replacement root");
        std::fs::write(root_path.join("data.txt"), replacement_root_bytes)
            .expect("write in replacement root");

        // Query reader via pinned root_fd
        let key = ObjectKey::parse("data.txt").expect("valid key");
        let (metadata, mut file) = acquire_payload_sync(&reader.root_fd, &key, Default::default())
            .expect("acquisition must resolve via pinned root descriptor");

        assert_eq!(metadata.size(), original_root_bytes.len() as u64);
        let mut content = Vec::new();
        file.read_to_end(&mut content).expect("read content");
        assert_eq!(content, original_root_bytes);
    }

    // -------------------------------------------------------------------------
    // D. Rejection before readable open
    // -------------------------------------------------------------------------
    #[test]
    fn test_rejection_before_readable_open_directory() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let root_path = temp_dir.path();
        std::fs::create_dir(root_path.join("sub_directory")).expect("create subdir");

        let reader = FsMetadataReader::open(root_path).expect("open reader");
        let key = ObjectKey::parse("sub_directory").expect("valid key");

        let stage_flag = AtomicBool::new(false);
        let hooks = AcquisitionExperimentHooks {
            after_phase1_validation: None,
            reopen_override: None,
            reopen_stage_reached: Some(&stage_flag),
        };

        let result = acquire_payload_sync(&reader.root_fd, &key, hooks);
        assert!(
            !stage_flag.load(Ordering::SeqCst),
            "reopen stage must NOT be reached"
        );

        match result {
            Err(AcquisitionExperimentError::UnsupportedObjectType { mode }) => {
                assert_eq!(mode & libc::S_IFMT, libc::S_IFDIR);
            }
            other => panic!("expected UnsupportedObjectType, got: {other:?}"),
        }
    }

    #[test]
    fn test_rejection_before_readable_open_final_and_dangling_symlinks() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let root_path = temp_dir.path();
        std::fs::write(root_path.join("real.txt"), b"real").expect("write real");

        std::os::unix::fs::symlink("real.txt", root_path.join("link_to_real.txt"))
            .expect("symlink");
        std::os::unix::fs::symlink("nonexistent.txt", root_path.join("dangling_link.txt"))
            .expect("dangling symlink");

        let reader = FsMetadataReader::open(root_path).expect("open reader");

        // 1. Final symlink to existing file
        let stage_flag1 = AtomicBool::new(false);
        let hooks1 = AcquisitionExperimentHooks {
            after_phase1_validation: None,
            reopen_override: None,
            reopen_stage_reached: Some(&stage_flag1),
        };
        let key1 = ObjectKey::parse("link_to_real.txt").expect("key1");
        let res1 = acquire_payload_sync(&reader.root_fd, &key1, hooks1);
        assert!(
            !stage_flag1.load(Ordering::SeqCst),
            "reopen stage must NOT be reached"
        );
        match res1 {
            Err(AcquisitionExperimentError::Resolution { source, .. }) => {
                assert_eq!(source.raw_os_error(), Some(libc::ELOOP));
            }
            other => panic!("expected Resolution error with ELOOP, got: {other:?}"),
        }

        // 2. Dangling symlink
        let stage_flag2 = AtomicBool::new(false);
        let hooks2 = AcquisitionExperimentHooks {
            after_phase1_validation: None,
            reopen_override: None,
            reopen_stage_reached: Some(&stage_flag2),
        };
        let key2 = ObjectKey::parse("dangling_link.txt").expect("key2");
        let res2 = acquire_payload_sync(&reader.root_fd, &key2, hooks2);
        assert!(
            !stage_flag2.load(Ordering::SeqCst),
            "reopen stage must NOT be reached"
        );
        match res2 {
            Err(AcquisitionExperimentError::Resolution { source, .. }) => {
                assert_eq!(source.raw_os_error(), Some(libc::ELOOP));
            }
            other => {
                panic!("expected Resolution error with ELOOP for dangling symlink, got: {other:?}")
            }
        }
    }

    #[test]
    fn test_rejection_before_readable_open_intermediate_symlink() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let root_path = temp_dir.path();
        std::fs::create_dir(root_path.join("real_dir")).expect("create dir");
        std::fs::write(root_path.join("real_dir/file.txt"), b"payload").expect("write file");
        std::os::unix::fs::symlink("real_dir", root_path.join("dir_link")).expect("dir link");

        let reader = FsMetadataReader::open(root_path).expect("open reader");
        let key = ObjectKey::parse("dir_link/file.txt").expect("key");

        let stage_flag = AtomicBool::new(false);
        let hooks = AcquisitionExperimentHooks {
            after_phase1_validation: None,
            reopen_override: None,
            reopen_stage_reached: Some(&stage_flag),
        };
        let res = acquire_payload_sync(&reader.root_fd, &key, hooks);
        assert!(
            !stage_flag.load(Ordering::SeqCst),
            "reopen stage must NOT be reached"
        );
        match res {
            Err(AcquisitionExperimentError::Resolution { source, .. }) => {
                assert_eq!(source.raw_os_error(), Some(libc::ELOOP));
            }
            other => panic!("expected Resolution error with ELOOP, got: {other:?}"),
        }
    }

    // Worker test case for child process execution of the FIFO test.
    // When run directly during workspace cargo test, skips immediately.
    #[test]
    fn fifo_child_worker() {
        if std::env::var("STORAGE_FS_FIFO_TEST_CHILD").is_err() {
            return;
        }

        let root_path_str =
            std::env::var("STORAGE_FS_ROOT_PATH").expect("STORAGE_FS_ROOT_PATH env");
        let reader =
            FsMetadataReader::open(Path::new(&root_path_str)).expect("open reader in child");
        let key = ObjectKey::parse("fifo_fixture").expect("valid key for fifo");

        let stage_flag = AtomicBool::new(false);
        let hooks = AcquisitionExperimentHooks {
            after_phase1_validation: None,
            reopen_override: None,
            reopen_stage_reached: Some(&stage_flag),
        };

        let result = acquire_payload_sync(&reader.root_fd, &key, hooks);

        // Assert Phase 2 reopen stage was never reached
        assert!(
            !stage_flag.load(Ordering::SeqCst),
            "reopen stage must NOT be reached for FIFO"
        );

        match result {
            Err(AcquisitionExperimentError::UnsupportedObjectType { mode }) => {
                assert_eq!(mode & libc::S_IFMT, libc::S_IFIFO, "mode must be S_IFIFO");
            }
            other => panic!("expected UnsupportedObjectType for FIFO, got: {other:?}"),
        }
    }

    // Parent test for FIFO rejection: runs the FIFO acquisition in a child process with a parent-enforced deadline.
    // Ensures parent terminates, reaps the child on timeout, and cleans up fixtures.
    #[test]
    fn test_rejection_before_readable_open_fifo_in_child_process() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let root_path = temp_dir.path();
        let fifo_path = root_path.join("fifo_fixture");

        // Create FIFO fixture with no writer
        let c_fifo = CString::new(fifo_path.as_os_str().as_bytes()).expect("cstring for fifo");
        let mkfifo_res = unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) };
        if mkfifo_res != 0 {
            panic!(
                "fixture setup failed: mkfifo: {}",
                io::Error::last_os_error()
            );
        }

        let current_exe = std::env::current_exe().expect("current test executable");
        let mut child = std::process::Command::new(current_exe)
            .arg("reader::payload_acquisition_experiment::tests::fifo_child_worker")
            .arg("--exact")
            .arg("--nocapture")
            .env("STORAGE_FS_FIFO_TEST_CHILD", "1")
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
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("failed waiting on child process: {e}");
                }
            }
        }

        let status = match exit_status {
            Some(s) => s,
            None => {
                // Parent-enforced deadline expired: kill and reap child to prevent orphaned blocked processes
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "FIFO child process exceeded deadline ({deadline:?}); probable blocking open hang"
                );
            }
        };

        assert!(
            status.success(),
            "FIFO child process exited with error status: {status:?}"
        );
        // temp_dir drops here and cleans up the FIFO fixture
    }

    // -------------------------------------------------------------------------
    // E. Reopen failures
    // -------------------------------------------------------------------------
    // Exercises explicitly synthetic Phase 2 failures. These verify error classification
    // and raw errno retention without uncontained fallback. They do not simulate an
    // actual unmounted or permission-restricted procfs environment.
    #[test]
    fn test_reopen_failures_synthetic_enoent_and_permission() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let file_path = temp_dir.path().join("file.txt");
        std::fs::write(&file_path, b"test content").expect("write test file");

        let reader = FsMetadataReader::open(temp_dir.path()).expect("open reader");
        let key = ObjectKey::parse("file.txt").expect("key");

        // 1. Synthetic Phase 2 ENOENT
        let reopen_enoent = |_fd: i32| -> Result<OwnedFd, io::Error> {
            Err(io::Error::from_raw_os_error(libc::ENOENT))
        };
        let hooks_enoent = AcquisitionExperimentHooks {
            after_phase1_validation: None,
            reopen_override: Some(&reopen_enoent),
            reopen_stage_reached: None,
        };
        let res_enoent = acquire_payload_sync(&reader.root_fd, &key, hooks_enoent);
        match res_enoent {
            Err(AcquisitionExperimentError::ReopenFailed { errno, source }) => {
                assert_eq!(errno, libc::ENOENT);
                assert_eq!(source.raw_os_error(), Some(libc::ENOENT));
            }
            other => panic!("expected ReopenFailed with ENOENT, got: {other:?}"),
        }

        // 2. Synthetic Phase 2 EACCES
        let reopen_eacces = |_fd: i32| -> Result<OwnedFd, io::Error> {
            Err(io::Error::from_raw_os_error(libc::EACCES))
        };
        let hooks_eacces = AcquisitionExperimentHooks {
            after_phase1_validation: None,
            reopen_override: Some(&reopen_eacces),
            reopen_stage_reached: None,
        };
        let res_eacces = acquire_payload_sync(&reader.root_fd, &key, hooks_eacces);
        match res_eacces {
            Err(AcquisitionExperimentError::ReopenFailed { errno, source }) => {
                assert_eq!(errno, libc::EACCES);
                assert_eq!(source.raw_os_error(), Some(libc::EACCES));
            }
            other => panic!("expected ReopenFailed with EACCES, got: {other:?}"),
        }

        // 3. Synthetic Phase 2 EPERM
        let reopen_eperm = |_fd: i32| -> Result<OwnedFd, io::Error> {
            Err(io::Error::from_raw_os_error(libc::EPERM))
        };
        let hooks_eperm = AcquisitionExperimentHooks {
            after_phase1_validation: None,
            reopen_override: Some(&reopen_eperm),
            reopen_stage_reached: None,
        };
        let res_eperm = acquire_payload_sync(&reader.root_fd, &key, hooks_eperm);
        match res_eperm {
            Err(AcquisitionExperimentError::ReopenFailed { errno, source }) => {
                assert_eq!(errno, libc::EPERM);
                assert_eq!(source.raw_os_error(), Some(libc::EPERM));
            }
            other => panic!("expected ReopenFailed with EPERM, got: {other:?}"),
        }
    }

    #[test]
    fn test_reopen_failure_synthetic_identity_mismatch() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let file1_path = temp_dir.path().join("file1.txt");
        let file2_path = temp_dir.path().join("file2.txt");
        std::fs::write(&file1_path, b"file 1 bytes").expect("write file1");
        std::fs::write(&file2_path, b"file 2 bytes").expect("write file2");

        let reader = FsMetadataReader::open(temp_dir.path()).expect("open reader");
        let key = ObjectKey::parse("file1.txt").expect("key");

        // Synthetic Phase 2 returning a descriptor opened to file2 instead of file1
        let reopen_mismatch = |_fd: i32| -> Result<OwnedFd, io::Error> {
            let f2 = std::fs::File::open(&file2_path)?;
            Ok(f2.into())
        };
        let hooks = AcquisitionExperimentHooks {
            after_phase1_validation: None,
            reopen_override: Some(&reopen_mismatch),
            reopen_stage_reached: None,
        };

        let res = acquire_payload_sync(&reader.root_fd, &key, hooks);
        match res {
            Err(AcquisitionExperimentError::ReopenIdentityMismatch {
                expected_ino,
                actual_ino,
                ..
            }) => {
                assert_ne!(expected_ino, actual_ino);
            }
            other => panic!("expected ReopenIdentityMismatch, got: {other:?}"),
        }
    }
}
