//! Strongly typed backend errors for `storage-fs`.

use thiserror::Error;

/// Strongly typed errors arising from filesystem metadata operations in `storage-fs`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FsMetadataError {
    /// The configured root path is empty.
    #[error("root path cannot be empty")]
    EmptyRootPath,

    /// The configured root path contains an embedded NUL byte.
    #[error("root path contains embedded NUL byte")]
    NulInRootPath,

    /// Failed to open the root directory.
    #[error("failed to open root directory: {source}")]
    RootOpenFailed {
        /// Underlying I/O error from opening the root directory.
        #[source]
        source: std::io::Error,
    },

    /// The kernel containment policy rejected resolution (e.g. `ELOOP` or `EXDEV`).
    #[error("kernel containment policy rejected resolution: raw OS error {raw_os_error}")]
    ResolutionRejected {
        /// Raw numeric OS error code returned by `openat2`.
        raw_os_error: i32,
        /// Underlying I/O error from resolution failure.
        #[source]
        source: std::io::Error,
    },

    /// The opened filesystem object has an unsupported file type for the requested operation
    /// (e.g. not a regular file `S_IFREG` during metadata inquiry, or not a directory `S_IFDIR`
    /// during capability probing).
    #[error("unsupported object type (mode: {mode:#o})")]
    UnsupportedObjectType {
        /// Raw mode bitmask from `fstat`.
        mode: u32,
    },

    /// The `openat2` syscall is unavailable in the execution environment (`ENOSYS`).
    #[error("openat2 is unavailable in this execution environment")]
    SyscallUnsupported(#[source] std::io::Error),

    /// The inspected metadata contains invalid values (e.g. negative file size).
    #[error("invalid metadata: {message}")]
    InvalidMetadata {
        /// Explanation of why the metadata is invalid.
        message: &'static str,
    },

    /// The platform is unsupported (e.g. non-Linux systems without `openat2`).
    #[error("platform unsupported: descriptor-relative containment requires Linux openat2")]
    PlatformUnsupported,

    /// A Tokio runtime is required to execute blocking metadata operations, but none was entered.
    #[error("tokio runtime required: {0}")]
    RuntimeMissing(#[source] tokio::runtime::TryCurrentError),

    /// A blocking metadata task failed to join (e.g. panicked or cancelled during shutdown).
    #[error("blocking metadata task failed: {0}")]
    TaskJoinFailed(#[source] tokio::task::JoinError),

    /// Execution of the capability probe was denied by kernel DAC, LSM, mount options, or seccomp (`EACCES` or `EPERM`).
    ///
    /// Note: `EACCES`/`EPERM` cannot be inferred as uniquely caused by seccomp without kernel auditing.
    #[error("openat2 capability probe denied: {0}")]
    ProbeDenied(#[source] std::io::Error),

    /// Execution of the capability probe failed due to an unexpected I/O or system error.
    #[error("openat2 capability probe failed: {source}")]
    ProbeFailed {
        /// Underlying I/O error from the capability probe.
        #[source]
        source: std::io::Error,
    },

    /// Failed to inspect descriptor metadata via `fstat` during payload acquisition.
    #[error("failed to stat {stage} descriptor: {source}")]
    StatFailed {
        /// The acquisition stage (e.g. "Phase 1 contained" or "Phase 2 readable").
        stage: &'static str,
        /// Underlying I/O error from `fstat`.
        #[source]
        source: std::io::Error,
    },

    /// Failed to reopen the descriptor via `/proc/self/fd` for reading.
    #[error("failed to reopen descriptor via procfs: {source}")]
    ProcfsReopenFailed {
        /// Underlying I/O error from reopening.
        #[source]
        source: std::io::Error,
    },

    /// The reopened descriptor in Phase 2 did not match the device and inode of the Phase 1 descriptor.
    #[error(
        "reopened descriptor identity mismatch: expected dev {expected_dev} ino {expected_ino}, got dev {actual_dev} ino {actual_ino}"
    )]
    IdentityMismatch {
        /// Expected device number from Phase 1.
        expected_dev: u64,
        /// Expected inode number from Phase 1.
        expected_ino: u64,
        /// Actual device number from Phase 2.
        actual_dev: u64,
        /// Actual inode number from Phase 2.
        actual_ino: u64,
    },
}
