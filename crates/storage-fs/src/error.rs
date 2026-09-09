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
}
