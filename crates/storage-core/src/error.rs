//! Strongly typed error definitions for `storage-core`.

use std::error::Error as StdError;
use thiserror::Error;

use crate::key::ObjectKey;

/// Strongly typed errors arising from [`ObjectKey`] syntax validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Error)]
#[non_exhaustive]
pub enum ObjectKeyError {
    /// The object key string is empty.
    #[error("object key cannot be empty")]
    Empty,

    /// The object key begins with a '/' separator.
    #[error("object key cannot have a leading slash")]
    LeadingSlash,

    /// The object key ends with a '/' separator.
    #[error("object key cannot have a trailing slash")]
    TrailingSlash,

    /// The object key contains repeated '/' separators (empty path segments).
    #[error("object key cannot contain repeated '/' separators")]
    RepeatedSeparator,

    /// The object key contains a '.' (current directory) segment.
    #[error("object key cannot contain '.' segment")]
    DotSegment,

    /// The object key contains a '..' (parent directory) segment.
    #[error("object key cannot contain '..' segment")]
    DotDotSegment,

    /// The object key contains a backslash ('\\').
    #[error("object key cannot contain backslashes")]
    Backslash,

    /// The object key contains a NUL ('\\0') byte.
    #[error("object key cannot contain NUL byte")]
    NulByte,

    /// The object key contains an ASCII or Unicode control character.
    #[error("object key cannot contain control characters")]
    ControlCharacter,

    /// The object key begins with a Windows drive prefix (e.g. 'C:').
    #[error("object key cannot start with a Windows drive prefix")]
    WindowsDrivePrefix,

    /// The object key begins with a UNC prefix (e.g. '//' or '\\\\').
    #[error("object key cannot start with UNC prefix")]
    UncPrefix,
}

/// Strongly typed failure outcomes from object metadata read operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReadError {
    /// The requested object was not found in storage.
    #[error("object not found: {key}")]
    #[non_exhaustive]
    NotFound {
        /// The object key that could not be located.
        key: ObjectKey,
    },

    /// Access to the requested object was denied by storage permissions.
    #[error("permission denied: {key}")]
    #[non_exhaustive]
    PermissionDenied {
        /// The object key for which access was denied.
        key: ObjectKey,
        /// Optional underlying error source.
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// The underlying storage backend encountered an internal or I/O failure.
    #[error("storage backend error: {message}")]
    #[non_exhaustive]
    Backend {
        /// Diagnostic message from the backend adapter.
        message: String,
        /// Optional underlying error source.
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
}

impl ReadError {
    /// Constructs a [`ReadError::NotFound`] for the given key.
    pub fn not_found(key: ObjectKey) -> Self {
        Self::NotFound { key }
    }

    /// Constructs a [`ReadError::PermissionDenied`] without an underlying source.
    pub fn permission_denied(key: ObjectKey) -> Self {
        Self::PermissionDenied { key, source: None }
    }

    /// Constructs a [`ReadError::PermissionDenied`] with an underlying source.
    pub fn permission_denied_with_source(
        key: ObjectKey,
        source: Box<dyn StdError + Send + Sync>,
    ) -> Self {
        Self::PermissionDenied {
            key,
            source: Some(source),
        }
    }

    /// Constructs a [`ReadError::Backend`] with an error message and no underlying source.
    pub fn backend(message: impl Into<String>) -> Self {
        Self::Backend {
            message: message.into(),
            source: None,
        }
    }

    /// Constructs a [`ReadError::Backend`] with an error message and an underlying source.
    pub fn backend_with_source(
        message: impl Into<String>,
        source: Box<dyn StdError + Send + Sync>,
    ) -> Self {
        Self::Backend {
            message: message.into(),
            source: Some(source),
        }
    }

    /// Returns `true` if this error represents an object not found condition.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }

    /// Returns `true` if this error represents a permission denied condition.
    pub fn is_permission_denied(&self) -> bool {
        matches!(self, Self::PermissionDenied { .. })
    }

    /// Returns `true` if this error represents a storage backend error.
    pub fn is_backend(&self) -> bool {
        matches!(self, Self::Backend { .. })
    }

    /// Returns the target [`ObjectKey`] if this error is associated with a specific key.
    pub fn key(&self) -> Option<&ObjectKey> {
        match self {
            Self::NotFound { key, .. } | Self::PermissionDenied { key, .. } => Some(key),
            Self::Backend { .. } => None,
        }
    }
}
