//! Metadata and metadata-read port abstractions for `storage-core`.

use std::pin::Pin;

use async_trait::async_trait;
use tokio::io::AsyncRead;

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

/// Type alias for an owned, pinned asynchronous byte stream.
///
/// `ObjectStream` is a boxed dynamic [`tokio::io::AsyncRead`] trait object with a `'static` lifetime.
///
/// # Concurrency and Lifetime Semantics
/// - **Owned State**: The stream owns its underlying state and does not borrow from the reader, key,
///   or any intermediate request context. Once acquired, the stream can outlive the reader and key.
/// - **Task Transfer (`Send`)**: The `Send` bound permits transferring or moving the stream across thread
///   or task boundaries. `Sync` is explicitly **not** required, as streaming consumption is inherently sequential.
///   Moving the stream between tasks does not require a Tokio runtime or imply that all `AsyncRead`
///   implementations depend on one.
/// - **Pinning (`Pin<Box<...>>`)**: The `Pin<Box<...>>` indirection ensures that underlying stream implementations
///   that are not [`Unpin`] (e.g. self-referential generator-like streams or stateful decoder structures) remain
///   safely pinned in heap memory. Moving the `ObjectStream` container moves only the pointer wrapper, never the
///   underlying pinned reader.
pub type ObjectStream = Pin<Box<dyn AsyncRead + Send + 'static>>;

/// An acquired object payload combining metadata with an owned byte stream.
///
/// `ObjectPayload` represents the successful acquisition of a readable object, pairing its initial
/// [`ObjectMetadata`] (such as declared byte length) with an active [`ObjectStream`].
///
/// # Architectural Boundaries and Invariants
/// - **No Auto-Validation**: `ObjectPayload` is a neutral carrier pairing supplied metadata with a stream.
///   The constructor [`new`](Self::new) does **not** verify that the stream's eventual content matches the
///   recorded metadata, nor does it enforce or truncate byte lengths.
/// - **Immutability and Mutation Semantics**: Recorded size is an acquisition-time observation, not an absolute
///   guarantee of the eventual byte count produced under concurrent backend mutation, truncation, or append operations.
/// - **Error Demarcation**: Failures during the initial lookup and acquisition phase return [`ReadError`].
///   Once an `ObjectPayload` is successfully returned, subsequent failures encountered while reading the stream
///   are surfaced as [`std::io::Error`] values through [`tokio::io::AsyncRead`], not [`ReadError`].
/// - **Zero Buffering**: The `ObjectPayload` container does not read, preload, or buffer payload bytes into memory;
///   consumption is strictly controlled by the caller.
/// - **Backend Autonomy**: Concrete storage backends own all runtime dispatch, data consistency, transport,
///   and cancellation semantics.
pub struct ObjectPayload {
    metadata: ObjectMetadata,
    stream: ObjectStream,
}

impl ObjectPayload {
    /// Constructs a new `ObjectPayload` from the given metadata and stream.
    ///
    /// This constructor performs no I/O, buffering, or validation between the metadata and stream.
    pub fn new(metadata: ObjectMetadata, stream: ObjectStream) -> Self {
        Self { metadata, stream }
    }

    /// Returns a reference to the payload's metadata.
    pub fn metadata(&self) -> &ObjectMetadata {
        &self.metadata
    }

    /// Deconstructs the payload into its constituent metadata and stream parts.
    pub fn into_parts(self) -> (ObjectMetadata, ObjectStream) {
        (self.metadata, self.stream)
    }
}

impl std::fmt::Debug for ObjectPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectPayload")
            .field("metadata", &self.metadata)
            .field("stream", &"<ObjectStream>")
            .finish()
    }
}

/// Object-safe async trait for opening readable object payload streams by key.
///
/// `ObjectPayloadReader` extends the read-side port abstractions of `storage-core` to provide
/// streaming access to stored data payloads. It is object-safe and dynamically dispatchable
/// via `dyn ObjectPayloadReader`.
///
/// # Concurrency and Lifetime Semantics
/// - **Thread Safety**: Implementations must be `Send + Sync` to permit sharing across concurrent tasks
///   and thread pools.
/// - **Decoupled Stream Lifetime**: The returned [`ObjectPayload`] and its inner [`ObjectStream`] own
///   their state and do not borrow from `&self` or `key`. Dropping the reader or key after acquisition
///   leaves in-flight streams fully operational.
/// - **Error Model**:
///   - **Acquisition Failures**: Returns strongly typed [`ReadError`] outcomes:
///     - [`ReadError::NotFound`] if the object does not exist.
///     - [`ReadError::PermissionDenied`] if storage access is forbidden.
///     - [`ReadError::Backend`] if opening the object fails on the storage backend.
///   - **Stream-Time Failures**: Errors occurring after `open_payload` completes are delivered as [`std::io::Error`]
///     values during stream polling on the returned [`ObjectStream`].
/// - **Execution Ownership**: Specific backend implementations (filesystem, memory, object store) own consistency,
///   runtime requirements, and cancellation behavior. Neither `ObjectPayloadReader` nor `ObjectStream` requires
///   a specific executor simply to exist.
#[async_trait]
pub trait ObjectPayloadReader: Send + Sync {
    /// Opens an object identified by `key` for streaming reading.
    ///
    /// # Errors
    /// Returns [`ReadError::NotFound`] if the object cannot be located,
    /// [`ReadError::PermissionDenied`] if access is denied, or
    /// [`ReadError::Backend`] on internal acquisition failure.
    async fn open_payload(&self, key: &ObjectKey) -> Result<ObjectPayload, ReadError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, ReadBuf};

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

    // =========================================================================
    // Generic Payload-Stream In-Memory Contract Tests
    // =========================================================================

    /// In-memory test mock implementing [`ObjectPayloadReader`] to verify dynamic dispatch,
    /// stream lifetimes, and typed error handling.
    struct MockPayloadReader {
        payloads: HashMap<ObjectKey, Result<(ObjectMetadata, Vec<u8>), ReadError>>,
    }

    #[async_trait]
    impl ObjectPayloadReader for MockPayloadReader {
        async fn open_payload(&self, key: &ObjectKey) -> Result<ObjectPayload, ReadError> {
            match self.payloads.get(key) {
                Some(Ok((meta, bytes))) => {
                    let stream: ObjectStream = Box::pin(std::io::Cursor::new(bytes.clone()));
                    Ok(ObjectPayload::new(*meta, stream))
                }
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

    // A. Trait-object invocation
    #[tokio::test(flavor = "current_thread")]
    async fn test_object_payload_reader_trait_object_invocation() {
        let key = ObjectKey::parse("blobs/sha256/payload-a").unwrap();
        let fixture_bytes = b"Hello, dynamic trait object payload reader!".to_vec();
        let meta = ObjectMetadata::new(fixture_bytes.len() as u64);

        let mut payloads = HashMap::new();
        payloads.insert(key.clone(), Ok((meta, fixture_bytes.clone())));

        let reader: Arc<dyn ObjectPayloadReader> = Arc::new(MockPayloadReader { payloads });
        let payload = reader
            .open_payload(&key)
            .await
            .expect("open_payload must succeed through dyn ObjectPayloadReader");

        assert_eq!(payload.metadata().size(), fixture_bytes.len() as u64);
        assert_eq!(payload.metadata().len(), fixture_bytes.len() as u64);

        let (metadata, mut stream) = payload.into_parts();
        assert_eq!(metadata, meta);

        let mut consumed = Vec::new();
        stream
            .read_to_end(&mut consumed)
            .await
            .expect("read stream");
        assert_eq!(consumed, fixture_bytes);
    }

    // B. Owned lifetime
    #[tokio::test(flavor = "current_thread")]
    async fn test_object_payload_reader_owned_lifetime() {
        let fixture_bytes = b"Payload stream survives reader and key drop".to_vec();
        let meta = ObjectMetadata::new(fixture_bytes.len() as u64);

        let payload = {
            let key = ObjectKey::parse("isolated/session/ephemeral").unwrap();
            let mut payloads = HashMap::new();
            payloads.insert(key.clone(), Ok((meta, fixture_bytes.clone())));
            let reader = MockPayloadReader { payloads };

            reader
                .open_payload(&key)
                .await
                .expect("open_payload should succeed")

            // `reader` and `key` are dropped at the close of this block
        };

        let (metadata, mut stream) = payload.into_parts();
        assert_eq!(metadata.size(), fixture_bytes.len() as u64);

        let mut consumed = Vec::new();
        stream
            .read_to_end(&mut consumed)
            .await
            .expect("stream should be readable after reader/key drop");
        assert_eq!(consumed, fixture_bytes);
    }

    // C. Incremental consumption
    #[tokio::test(flavor = "current_thread")]
    async fn test_object_payload_reader_incremental_consumption() {
        // Contract interoperability test: exercises sequential chunked reads through a fixed buffer
        // and verifies EOF behavior. This is evidence of contract interoperability with AsyncRead,
        // not proof of every backend's internal buffering or memory footprint.
        let key = ObjectKey::parse("chunks/test/pattern").unwrap();
        let fixture_bytes: Vec<u8> = (0..128).map(|i| (i % 251) as u8).collect();
        let meta = ObjectMetadata::new(fixture_bytes.len() as u64);

        let mut payloads = HashMap::new();
        payloads.insert(key.clone(), Ok((meta, fixture_bytes.clone())));
        let reader = MockPayloadReader { payloads };

        let payload = reader.open_payload(&key).await.expect("open_payload");
        let (_meta, mut stream) = payload.into_parts();

        let mut consumed = Vec::new();
        let mut buf = [0u8; 16]; // Small fixed buffer
        loop {
            let n = stream.read(&mut buf).await.expect("incremental read");
            if n == 0 {
                break;
            }
            consumed.extend_from_slice(&buf[..n]);
        }

        assert_eq!(consumed, fixture_bytes);

        // Verify EOF behavior on subsequent read
        let eof_check = stream.read(&mut buf).await.expect("read at EOF");
        assert_eq!(eof_check, 0);
    }

    // D. Read-time error
    #[tokio::test(flavor = "current_thread")]
    async fn test_object_payload_reader_read_time_error_surfaced_as_io_error() {
        let key = ObjectKey::parse("stream/with/late-failure").unwrap();
        let prefix = b"VALID_PREFIX_HEADER".to_vec();
        let meta = ObjectMetadata::new(1024);

        struct PrefixThenErrorReader {
            prefix: Vec<u8>,
            pos: usize,
        }

        impl AsyncRead for PrefixThenErrorReader {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                if self.pos < self.prefix.len() {
                    let remaining = &self.prefix[self.pos..];
                    let to_copy = std::cmp::min(remaining.len(), buf.remaining());
                    buf.put_slice(&remaining[..to_copy]);
                    self.pos += to_copy;
                    std::task::Poll::Ready(Ok(()))
                } else {
                    std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "simulated network connection drop during payload stream",
                    )))
                }
            }
        }

        struct LateErrorPayloadReader {
            key: ObjectKey,
            meta: ObjectMetadata,
            prefix: Vec<u8>,
        }

        #[async_trait]
        impl ObjectPayloadReader for LateErrorPayloadReader {
            async fn open_payload(&self, key: &ObjectKey) -> Result<ObjectPayload, ReadError> {
                if key == &self.key {
                    let stream: ObjectStream = Box::pin(PrefixThenErrorReader {
                        prefix: self.prefix.clone(),
                        pos: 0,
                    });
                    Ok(ObjectPayload::new(self.meta, stream))
                } else {
                    Err(ReadError::not_found(key.clone()))
                }
            }
        }

        let reader = LateErrorPayloadReader {
            key: key.clone(),
            meta,
            prefix: prefix.clone(),
        };

        // Acquisition succeeds without failure
        let payload = reader
            .open_payload(&key)
            .await
            .expect("acquisition must succeed before stream error");
        let (metadata, mut stream) = payload.into_parts();
        assert_eq!(metadata.size(), 1024);

        // Consume prefix using a slice matching prefix length
        let mut prefix_buf = vec![0u8; prefix.len()];
        stream
            .read_exact(&mut prefix_buf)
            .await
            .expect("reading prefix bytes must succeed");
        assert_eq!(prefix_buf, prefix);

        // Later error emerges during stream consumption directly as io::Error
        let mut next_buf = [0u8; 8];
        let err = stream
            .read(&mut next_buf)
            .await
            .expect_err("subsequent read must fail with io::Error");

        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        assert_eq!(
            err.to_string(),
            "simulated network connection drop during payload stream"
        );
    }

    // E. Typed acquisition errors
    #[tokio::test(flavor = "current_thread")]
    async fn test_object_payload_reader_typed_acquisition_errors() {
        let key_missing = ObjectKey::parse("missing/object").unwrap();
        let key_forbidden = ObjectKey::parse("forbidden/object").unwrap();
        let key_broken = ObjectKey::parse("broken/backend").unwrap();

        let mut payloads = HashMap::new();
        payloads.insert(
            key_missing.clone(),
            Err(ReadError::not_found(key_missing.clone())),
        );
        payloads.insert(
            key_forbidden.clone(),
            Err(ReadError::permission_denied(key_forbidden.clone())),
        );
        payloads.insert(
            key_broken.clone(),
            Err(ReadError::backend("simulated storage volume offline")),
        );

        let reader: Arc<dyn ObjectPayloadReader> = Arc::new(MockPayloadReader { payloads });

        // 1. NotFound outcome
        let err_missing = reader
            .open_payload(&key_missing)
            .await
            .expect_err("must fail with NotFound");
        assert!(err_missing.is_not_found());
        assert!(!err_missing.is_permission_denied());
        assert!(!err_missing.is_backend());
        match err_missing {
            ReadError::NotFound { key, .. } => assert_eq!(key, key_missing),
            other => panic!("expected NotFound, got: {other:?}"),
        }

        // 2. PermissionDenied outcome
        let err_forbidden = reader
            .open_payload(&key_forbidden)
            .await
            .expect_err("must fail with PermissionDenied");
        assert!(err_forbidden.is_permission_denied());
        assert!(!err_forbidden.is_not_found());
        assert!(!err_forbidden.is_backend());
        match err_forbidden {
            ReadError::PermissionDenied { key, .. } => assert_eq!(key, key_forbidden),
            other => panic!("expected PermissionDenied, got: {other:?}"),
        }

        // 3. Backend outcome
        let err_broken = reader
            .open_payload(&key_broken)
            .await
            .expect_err("must fail with Backend");
        assert!(err_broken.is_backend());
        assert!(!err_broken.is_not_found());
        assert!(!err_broken.is_permission_denied());
        match err_broken {
            ReadError::Backend { message, .. } => {
                assert_eq!(message, "simulated storage volume offline");
            }
            other => panic!("expected Backend, got: {other:?}"),
        }
    }

    // F. Trait bounds
    #[tokio::test(flavor = "current_thread")]
    async fn test_object_payload_reader_trait_bounds_and_non_sync_non_unpin_support() {
        // 1. Compile-check that ObjectStream and ObjectPayload are Send
        fn assert_send<T: Send>() {}
        assert_send::<ObjectStream>();
        assert_send::<ObjectPayload>();

        // 2. Safe fixture implementing AsyncRead that is Send, but !Sync and !Unpin
        struct NonSyncNonUnpinReader {
            data: Vec<u8>,
            pos: std::cell::Cell<usize>,
            _not_sync: std::marker::PhantomData<std::cell::Cell<()>>,
            _not_unpin: std::marker::PhantomPinned,
        }

        impl NonSyncNonUnpinReader {
            fn new(data: Vec<u8>) -> Self {
                Self {
                    data,
                    pos: std::cell::Cell::new(0),
                    _not_sync: std::marker::PhantomData,
                    _not_unpin: std::marker::PhantomPinned,
                }
            }
        }

        // Compile-time check: NonSyncNonUnpinReader is Send
        assert_send::<NonSyncNonUnpinReader>();

        impl AsyncRead for NonSyncNonUnpinReader {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                // Pin::get_ref() safely returns &Self without requiring Unpin
                let pos = self.pos.get();
                if pos < self.data.len() {
                    let available = &self.data[pos..];
                    let to_copy = std::cmp::min(available.len(), buf.remaining());
                    buf.put_slice(&available[..to_copy]);
                    self.pos.set(pos + to_copy);
                }
                std::task::Poll::Ready(Ok(()))
            }
        }

        // Demonstrate boxing and pinning into ObjectStream and wrapping into ObjectPayload
        let fixture_bytes = b"Non-Sync Non-Unpin byte stream content".to_vec();
        let meta = ObjectMetadata::new(fixture_bytes.len() as u64);
        let raw_reader = NonSyncNonUnpinReader::new(fixture_bytes.clone());
        let stream: ObjectStream = Box::pin(raw_reader);
        let payload = ObjectPayload::new(meta, stream);

        let (metadata, mut stream) = payload.into_parts();
        assert_eq!(metadata.size(), fixture_bytes.len() as u64);

        let mut consumed = Vec::new();
        stream
            .read_to_end(&mut consumed)
            .await
            .expect("reading NonSyncNonUnpinReader must succeed");
        assert_eq!(consumed, fixture_bytes);
    }
}
