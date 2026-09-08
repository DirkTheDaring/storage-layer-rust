//! Metadata and metadata-read port abstractions for `storage-core`.

use async_trait::async_trait;

use crate::error::ReadError;
use crate::key::ObjectKey;

/// Read-only metadata describing a stored object.
///
/// In Slice 2A, `ObjectMetadata` encapsulates only the object's byte length.
/// Additional metadata properties (e.g. content types, timestamps, version identifiers)
/// remain deferred to subsequent slices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObjectMetadata {
    size: u64,
}

impl ObjectMetadata {
    /// Creates a new `ObjectMetadata` instance with the specified byte size.
    pub fn new(size: u64) -> Self {
        Self { size }
    }

    /// Returns the exact byte length of the object.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the exact byte length of the object (synonym for [`size()`](Self::size)).
    pub fn len(&self) -> u64 {
        self.size
    }

    /// Returns `true` if the object has a byte length of zero.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

/// Object-safe async trait for querying object metadata by key.
///
/// This trait is `Send + Sync` and dynamically dispatchable through trait objects
/// (`dyn ObjectMetadataReader`).
#[async_trait]
pub trait ObjectMetadataReader: Send + Sync {
    /// Retrieves metadata for an object identified by `key`.
    ///
    /// # Errors
    /// Returns strongly typed [`ReadError`] outcomes:
    /// - [`ReadError::NotFound`] if the object does not exist.
    /// - [`ReadError::PermissionDenied`] if storage access is forbidden.
    /// - [`ReadError::Backend`] on internal storage adapter failure.
    async fn head(&self, key: &ObjectKey) -> Result<ObjectMetadata, ReadError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn test_object_metadata_preserves_exact_length_zero() {
        let meta = ObjectMetadata::new(0);
        assert_eq!(meta.size(), 0);
        assert_eq!(meta.len(), 0);
        assert!(meta.is_empty());
    }

    #[test]
    fn test_object_metadata_preserves_exact_length_arbitrary() {
        let size = 104_857_600; // 100 MiB
        let meta = ObjectMetadata::new(size);
        assert_eq!(meta.size(), size);
        assert_eq!(meta.len(), size);
        assert!(!meta.is_empty());
    }

    #[test]
    fn test_object_metadata_preserves_exact_length_max_u64() {
        let meta = ObjectMetadata::new(u64::MAX);
        assert_eq!(meta.size(), u64::MAX);
        assert_eq!(meta.len(), u64::MAX);
        assert!(!meta.is_empty());
    }

    /// In-memory test mock implementing [`ObjectMetadataReader`] to verify dynamic dispatch
    /// and typed error handling.
    struct MockMetadataReader {
        objects: HashMap<ObjectKey, Result<ObjectMetadata, ReadError>>,
    }

    #[async_trait]
    impl ObjectMetadataReader for MockMetadataReader {
        async fn head(&self, key: &ObjectKey) -> Result<ObjectMetadata, ReadError> {
            match self.objects.get(key) {
                Some(Ok(meta)) => Ok(*meta),
                Some(Err(ReadError::NotFound { .. })) => Err(ReadError::not_found(key.clone())),
                Some(Err(ReadError::PermissionDenied { .. })) => {
                    Err(ReadError::permission_denied(key.clone()))
                }
                Some(Err(ReadError::Backend { message, .. })) => {
                    Err(ReadError::backend(message.clone()))
                }
                None => Err(ReadError::not_found(key.clone())),
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_object_metadata_reader_trait_object_success() {
        let key = ObjectKey::parse("blobs/sha256/deadbeef").unwrap();
        let mut objects = HashMap::new();
        objects.insert(key.clone(), Ok(ObjectMetadata::new(4096)));

        let reader: Arc<dyn ObjectMetadataReader> = Arc::new(MockMetadataReader { objects });
        let meta = reader
            .head(&key)
            .await
            .expect("head must succeed for existing object");

        assert_eq!(meta.size(), 4096);
        assert_eq!(meta.len(), 4096);
        assert!(!meta.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_object_metadata_reader_trait_object_not_found_failure() {
        let key = ObjectKey::parse("blobs/sha256/missing").unwrap();
        let objects = HashMap::new();

        let reader: Arc<dyn ObjectMetadataReader> = Arc::new(MockMetadataReader { objects });
        let err = reader
            .head(&key)
            .await
            .expect_err("head must fail for missing object");

        assert!(err.is_not_found());
        assert!(!err.is_permission_denied());
        assert!(!err.is_backend());
        match err {
            ReadError::NotFound { key: err_key, .. } => assert_eq!(err_key, key),
            other => panic!("expected ReadError::NotFound, got: {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_object_metadata_reader_trait_object_permission_denied_failure() {
        let key = ObjectKey::parse("protected/vault/secret").unwrap();
        let mut objects = HashMap::new();
        objects.insert(key.clone(), Err(ReadError::permission_denied(key.clone())));

        let reader: Arc<dyn ObjectMetadataReader> = Arc::new(MockMetadataReader { objects });
        let err = reader
            .head(&key)
            .await
            .expect_err("head must fail with permission denied");

        assert!(err.is_permission_denied());
        assert!(!err.is_not_found());
        assert!(!err.is_backend());
        match err {
            ReadError::PermissionDenied { key: err_key, .. } => assert_eq!(err_key, key),
            other => panic!("expected ReadError::PermissionDenied, got: {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_object_metadata_reader_trait_object_backend_failure() {
        let key = ObjectKey::parse("uploads/session-1/corrupt").unwrap();
        let mut objects = HashMap::new();
        objects.insert(
            key.clone(),
            Err(ReadError::backend("simulated connection reset")),
        );

        let reader: Arc<dyn ObjectMetadataReader> = Arc::new(MockMetadataReader { objects });
        let err = reader
            .head(&key)
            .await
            .expect_err("head must fail with backend error");

        assert!(err.is_backend());
        assert!(!err.is_not_found());
        assert!(!err.is_permission_denied());
        match err {
            ReadError::Backend { message, .. } => {
                assert_eq!(message, "simulated connection reset");
            }
            other => panic!("expected ReadError::Backend, got: {other:?}"),
        }
    }
}
