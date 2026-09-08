//! Filesystem metadata reader implementation over a pinned directory descriptor.

#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;

use async_trait::async_trait;
use storage_core::{ObjectKey, ObjectMetadata, ObjectMetadataReader, ReadError};

use crate::error::FsMetadataError;

/// Standalone filesystem metadata reader enforcing descriptor-relative resolution.
///
/// Operates over a pinned root directory descriptor. On Linux, path queries are resolved
/// beneath this pinned descriptor via `openat2` with
/// `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
#[derive(Debug)]
pub struct FsMetadataReader {
    root_path: PathBuf,
    #[cfg(target_os = "linux")]
    root_fd: OwnedFd,
}

impl FsMetadataReader {
    /// Opens an existing configured directory once and pins an owned descriptor.
    ///
    /// # Semantics
    /// - Does not create missing directories.
    /// - An initial symlink configured as root resolves once during this open call;
    ///   the acquired descriptor becomes the sole pinned authority for all subsequent lookups.
    /// - The configured pathname is never re-resolved during subsequent queries.
    /// - Rejects empty paths and paths containing embedded NUL bytes.
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

            let root_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            Ok(Self { root_path, root_fd })
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
}

#[async_trait]
impl ObjectMetadataReader for FsMetadataReader {
    async fn head(&self, key: &ObjectKey) -> Result<ObjectMetadata, ReadError> {
        #[cfg(target_os = "linux")]
        {
            self.head_linux(key)
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
    fn head_linux(&self, key: &ObjectKey) -> Result<ObjectMetadata, ReadError> {
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
                self.root_fd.as_raw_fd(),
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

        // Use scoped cleanup guard strictly inside the temporary fixture
        let mut guard = PermissionGuard::new(&sub_dir, orig_perms);
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&sub_dir, std::fs::Permissions::from_mode(0o000))
                .expect("set mode 000");
        }

        let key = ObjectKey::parse("restricted_dir/payload.bin").unwrap();
        let err = reader
            .head(&key)
            .await
            .expect_err("head on mode 000 directory must fail with permission denied");

        assert!(
            err.is_permission_denied(),
            "expected PermissionDenied, got: {err:?}"
        );
        match err {
            ReadError::PermissionDenied {
                key: err_key,
                source,
                ..
            } => {
                assert_eq!(err_key, key);
                let src = source.expect("source error must be present");
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
}
