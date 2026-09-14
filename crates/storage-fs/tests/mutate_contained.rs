//! Integration tests for the descriptor-relative contained mutation surface
//! (`storage_fs::mutate`). Linux-gated: the whole surface requires `openat2`.
//!
//! These exercise the *dependency* primitives directly (containment, bounded reads,
//! inspection, stable locking, the owned blocking boundary, atomic replacement,
//! checked-offset append, truncation, contained rename) including a **real Tokio
//! caller-cancellation** proof that a guarded blocking operation retains its lock until
//! completion. Deterministic channel barriers are used throughout; there are no sleeps.

#![cfg(target_os = "linux")]

use std::os::unix::fs::symlink;

use storage_fs::{DirEnumerationLimits, FileName, FsMetadataReader, FsMutateError, LeafWriteMode};

fn reader(dir: &std::path::Path) -> FsMetadataReader {
    FsMetadataReader::open(dir).expect("open reader")
}

fn name(s: &str) -> FileName {
    FileName::new(s).expect("valid name")
}

// --------------------------------------------------------------------------
// Name validation and directory acquisition
// --------------------------------------------------------------------------

#[test]
fn filename_rejects_traversal_and_separators() {
    assert!(matches!(
        FileName::new(".."),
        Err(FsMutateError::InvalidName { .. })
    ));
    assert!(matches!(
        FileName::new("."),
        Err(FsMutateError::InvalidName { .. })
    ));
    assert!(matches!(
        FileName::new("a/b"),
        Err(FsMutateError::InvalidName { .. })
    ));
    assert!(matches!(
        FileName::new(""),
        Err(FsMutateError::InvalidName { .. })
    ));
    assert!(matches!(
        FileName::new("a\0b"),
        Err(FsMutateError::InvalidName { .. })
    ));
    assert_eq!(name("uploads").as_str(), "uploads");
}

#[tokio::test]
async fn open_contained_dir_rejects_dotdot_component() {
    let tmp = tempfile::tempdir().unwrap();
    let r = reader(tmp.path());
    let err = r.open_contained_dir("uploads/../etc").await.unwrap_err();
    assert!(matches!(err, FsMutateError::InvalidName { .. }));
}

#[tokio::test]
async fn ensure_subdir_is_idempotent_and_lists_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let r = reader(tmp.path());
    let root = r.open_contained_dir("").await.unwrap();

    let uploads = root.ensure_subdir(&name("uploads")).await.unwrap();
    // Second ensure is a no-op success on EEXIST.
    let uploads_again = root.ensure_subdir(&name("uploads")).await.unwrap();
    assert_eq!(uploads_again.display_path(), uploads.display_path());

    uploads
        .write_leaf_atomic(&name("a.data"), b"aaa".to_vec(), false)
        .await
        .unwrap();
    uploads
        .write_leaf_atomic(&name("b.data"), b"bbb".to_vec(), false)
        .await
        .unwrap();

    let entries = uploads
        .list(DirEnumerationLimits::new(128, 4096))
        .await
        .unwrap();
    let mut names: Vec<String> = entries
        .iter()
        .map(|e| e.name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, vec!["a.data".to_string(), "b.data".to_string()]);
}

// --------------------------------------------------------------------------
// Atomic write / bounded read
// --------------------------------------------------------------------------

#[tokio::test]
async fn write_leaf_atomic_roundtrip_and_replacement() {
    let tmp = tempfile::tempdir().unwrap();
    let r = reader(tmp.path());
    let root = r.open_contained_dir("").await.unwrap();
    let leaf = name("meta.json");

    root.write_leaf_atomic(&leaf, b"first".to_vec(), true)
        .await
        .unwrap();
    assert_eq!(root.read_leaf(&leaf, 4096).await.unwrap(), b"first");

    // Atomic replacement: reader observes the whole new value, and no temp residue.
    root.write_leaf_atomic(&leaf, b"second-longer".to_vec(), true)
        .await
        .unwrap();
    assert_eq!(root.read_leaf(&leaf, 4096).await.unwrap(), b"second-longer");

    let entries = root
        .list(DirEnumerationLimits::new(128, 4096))
        .await
        .unwrap();
    assert!(
        entries
            .iter()
            .all(|e| !e.name().to_string_lossy().starts_with(".tmp.")),
        "no temporary residue after successful atomic writes"
    );
}

#[tokio::test]
async fn read_leaf_enforces_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let r = reader(tmp.path());
    let root = r.open_contained_dir("").await.unwrap();
    let leaf = name("blob");
    root.write_leaf_atomic(&leaf, vec![7u8; 100], false)
        .await
        .unwrap();

    assert_eq!(root.read_leaf(&leaf, 100).await.unwrap().len(), 100);
    assert!(matches!(
        root.read_leaf(&leaf, 99).await,
        Err(FsMutateError::LimitExceeded { limit: 99 })
    ));
}

#[tokio::test]
async fn write_leaf_atomic_over_directory_fails_without_residue() {
    let tmp = tempfile::tempdir().unwrap();
    let r = reader(tmp.path());
    let root = r.open_contained_dir("").await.unwrap();
    // A directory named like the destination makes the final rename fail.
    root.ensure_subdir(&name("occupied")).await.unwrap();

    let err = root
        .write_leaf_atomic(&name("occupied"), b"x".to_vec(), false)
        .await
        .unwrap_err();
    // Rename onto a directory is rejected; the primary error is surfaced.
    assert!(
        !matches!(err, FsMutateError::CleanupFailed { .. }),
        "temp cleanup should have succeeded, got {err:?}"
    );

    let entries = root
        .list(DirEnumerationLimits::new(128, 4096))
        .await
        .unwrap();
    assert!(
        entries
            .iter()
            .all(|e| !e.name().to_string_lossy().starts_with(".tmp.")),
        "failed atomic write must not leave a temporary behind"
    );
}

// --------------------------------------------------------------------------
// Inspection, symlink rejection, special files
// --------------------------------------------------------------------------

#[tokio::test]
async fn inspect_absent_present_and_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let r = reader(tmp.path());
    let root = r.open_contained_dir("").await.unwrap();

    assert!(root.inspect(&name("nope")).await.unwrap().is_none());

    root.write_leaf_atomic(&name("present"), b"hello".to_vec(), false)
        .await
        .unwrap();
    let id = root.inspect(&name("present")).await.unwrap().unwrap();
    assert_eq!(id.size, 5);

    // A symlink leaf is a resolution rejection, never absence or a followed target.
    symlink("present", tmp.path().join("link")).unwrap();
    assert!(matches!(
        root.inspect(&name("link")).await,
        Err(FsMutateError::ResolutionRejected { .. })
    ));
    assert!(matches!(
        root.open_leaf_read(&name("link")).await,
        Err(FsMutateError::ResolutionRejected { .. })
    ));
}

#[tokio::test]
async fn open_leaf_read_rejects_fifo_without_blocking() {
    let tmp = tempfile::tempdir().unwrap();
    let fifo = tmp.path().join("pipe");
    let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o644) };
    assert_eq!(rc, 0, "mkfifo failed");

    let r = reader(tmp.path());
    let root = r.open_contained_dir("").await.unwrap();
    // The O_PATH type-guard rejects the FIFO before any blocking open.
    assert!(matches!(
        root.open_leaf_read(&name("pipe")).await,
        Err(FsMutateError::NotARegularFile { .. })
    ));
}

// --------------------------------------------------------------------------
// Append / truncate / rename
// --------------------------------------------------------------------------

#[tokio::test]
async fn append_at_checks_offset() {
    let tmp = tempfile::tempdir().unwrap();
    let r = reader(tmp.path());
    let root = r.open_contained_dir("").await.unwrap();
    let leaf = name("chunked.data");
    root.open_leaf_write(&leaf, LeafWriteMode::CreateNew)
        .await
        .unwrap();

    root.append_at(&leaf, 0, b"0123".to_vec()).await.unwrap();
    root.append_at(&leaf, 4, b"4567".to_vec()).await.unwrap();
    assert!(matches!(
        root.append_at(&leaf, 4, b"zz".to_vec()).await,
        Err(FsMutateError::OffsetMismatch {
            expected: 4,
            actual: 8
        })
    ));
    assert_eq!(root.read_leaf(&leaf, 4096).await.unwrap(), b"01234567");
}

#[tokio::test]
async fn truncate_shrinks_leaf() {
    let tmp = tempfile::tempdir().unwrap();
    let r = reader(tmp.path());
    let root = r.open_contained_dir("").await.unwrap();
    let leaf = name("t.data");
    root.write_leaf_atomic(&leaf, vec![9u8; 50], false)
        .await
        .unwrap();
    root.truncate(&leaf, 10).await.unwrap();
    assert_eq!(root.read_leaf(&leaf, 4096).await.unwrap().len(), 10);
}

#[tokio::test]
async fn rename_leaf_publishes_across_directories() {
    let tmp = tempfile::tempdir().unwrap();
    let r = reader(tmp.path());
    let root = r.open_contained_dir("").await.unwrap();
    let uploads = root.ensure_subdir(&name("uploads")).await.unwrap();
    let blobs = root.ensure_subdir(&name("blobs")).await.unwrap();

    uploads
        .write_leaf_atomic(&name("u.data"), b"payload".to_vec(), false)
        .await
        .unwrap();
    uploads
        .rename_leaf(&name("u.data"), &blobs, &name("deadbeef"))
        .await
        .unwrap();

    assert!(uploads.inspect(&name("u.data")).await.unwrap().is_none());
    assert_eq!(
        blobs.read_leaf(&name("deadbeef"), 4096).await.unwrap(),
        b"payload"
    );
}

// --------------------------------------------------------------------------
// Stable locking
// --------------------------------------------------------------------------

#[tokio::test]
async fn try_lock_is_busy_while_held_and_lock_file_is_retained() {
    let tmp = tempfile::tempdir().unwrap();
    let r = reader(tmp.path());
    let root = r.open_contained_dir("").await.unwrap();
    let uploads = root.ensure_subdir(&name("uploads")).await.unwrap();
    let lock = name(".lock.session");

    // A second, independent authority on the same directory shares the flock domain.
    let uploads_b = root.ensure_subdir(&name("uploads")).await.unwrap();

    let guard = uploads.lock(&lock).await.unwrap();
    assert!(uploads_b.try_lock(&lock).await.unwrap().is_none());

    let ino_held = uploads.inspect(&lock).await.unwrap().unwrap().ino;
    drop(guard);

    // Released: acquirable again, and the lock file inode is unchanged (never unlinked).
    let g2 = uploads_b.try_lock(&lock).await.unwrap();
    assert!(g2.is_some());
    let ino_after = uploads.inspect(&lock).await.unwrap().unwrap().ino;
    assert_eq!(
        ino_held, ino_after,
        "lock file must be retained, not recreated"
    );
}

#[tokio::test]
async fn run_locked_rejects_cross_authority_guard() {
    let tmp = tempfile::tempdir().unwrap();
    let r = reader(tmp.path());
    let root = r.open_contained_dir("").await.unwrap();
    let a = root.ensure_subdir(&name("a")).await.unwrap();
    let b = root.ensure_subdir(&name("b")).await.unwrap();

    let guard_a = a.lock(&name(".lock.x")).await.unwrap();
    // Presenting A's guard to B's run_locked is rejected.
    let err = b
        .run_locked(guard_a, |_dir, _g| Ok::<(), FsMutateError>(()))
        .await
        .unwrap_err();
    assert!(matches!(err, FsMutateError::LockAuthorityMismatch));
}

// --------------------------------------------------------------------------
// Real caller-cancellation: the guarded blocking op retains its lock until done
// --------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_locked_retains_lock_through_caller_cancellation() {
    let tmp = tempfile::tempdir().unwrap();
    let r = reader(tmp.path());
    let root = r.open_contained_dir("").await.unwrap();
    let a = root.ensure_subdir(&name("uploads")).await.unwrap();
    let probe = root.ensure_subdir(&name("uploads")).await.unwrap();

    let lock = name(".lock.session");
    let marker = name("finalized.marker");

    let guard = a.lock(&lock).await.unwrap();

    let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let marker_body = marker.clone();

    let jh = tokio::spawn(async move {
        a.run_locked(guard, move |dir, _g| {
            // Body owns the guard for its whole duration.
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            dir.write_leaf_atomic(&marker_body, b"done", true)?;
            Ok::<(), FsMutateError>(())
        })
        .await
    });

    // Body has entered and holds the lock.
    started_rx.recv().unwrap();

    // Cancel the awaiting future. The spawn_blocking body is detached, not aborted.
    jh.abort();

    // Despite cancellation, the lock is still held and the mutation is not yet visible.
    assert!(
        probe.try_lock(&lock).await.unwrap().is_none(),
        "lock must remain held after caller cancellation"
    );
    assert!(
        probe.inspect(&marker).await.unwrap().is_none(),
        "guarded mutation must not be visible before completion"
    );

    // Let the body finish; a blocking lock() acquisition returns only once the body
    // drops the guard — deterministic, no sleep.
    release_tx.send(()).unwrap();
    let _g2 = probe.lock(&lock).await.unwrap();

    // The blocking operation ran to completion despite the caller being cancelled.
    assert!(
        probe.inspect(&marker).await.unwrap().is_some(),
        "guarded mutation must complete even though the caller was cancelled"
    );
}
