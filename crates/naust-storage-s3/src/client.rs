//! S3 client seam: the narrow, injectable request boundary the
//! [`crate::S3ObjectStore`] adapter is built on.
//!
//! The seam speaks PHYSICAL S3 keys and raw backend observations (sizes,
//! timestamps, ETag strings) — no `storage-core` semantics and no registry
//! concepts. Deterministic tests implement [`S3Client`] with an honest mock
//! (atomic conditional evaluation, real pagination/truncation, injectable
//! failures); production uses [`AwsS3Client`] over the AWS SDK. AWS SDK
//! types never cross this module's public boundary except inside
//! [`S3ApiError::source`] diagnostics.

use std::time::SystemTime;

use async_trait::async_trait;
use bytes::Bytes;

/// Raw, unclassified S3 request failure: HTTP status and/or service error
/// code plus diagnostics. Classification into generic outcomes happens in
/// exactly one place per operation (see [`crate::object_store`]).
#[derive(Debug, thiserror::Error)]
#[error("s3 request failure (status={status:?}, code={code:?}): {message}")]
pub struct S3ApiError {
    pub status: Option<u16>,
    pub code: Option<String>,
    pub message: String,
    #[source]
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl S3ApiError {
    pub fn new(status: Option<u16>, code: Option<&str>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.map(str::to_owned),
            message: message.into(),
            source: None,
        }
    }

    /// Absence signals: 404 / NoSuchKey / NotFound.
    pub fn is_absence(&self) -> bool {
        self.status == Some(404)
            || matches!(self.code.as_deref(), Some("NoSuchKey") | Some("NotFound"))
    }

    /// Precondition signals: 412 / PreconditionFailed (and the
    /// If-None-Match conflict shape some services report as 409).
    pub fn is_precondition(&self) -> bool {
        self.status == Some(412)
            || self.status == Some(409)
            || matches!(
                self.code.as_deref(),
                Some("PreconditionFailed") | Some("ConditionalRequestConflict")
            )
    }

    /// Permission signals: 403 / AccessDenied.
    pub fn is_permission(&self) -> bool {
        self.status == Some(403) || matches!(self.code.as_deref(), Some("AccessDenied"))
    }
}

/// Raw per-object observation (HEAD / GET / LIST row).
#[derive(Clone, Debug)]
pub struct ObjectStat {
    pub size: u64,
    pub modified: Option<SystemTime>,
    /// Raw ETag as the service returned it (possibly quoted, possibly a
    /// multipart `"...-N"` form). Opaque precondition token material — never
    /// a content digest.
    pub etag: String,
}

/// GET result: the observation and the complete payload of the SAME
/// response (bytes and ETag belong to one returned object generation).
#[derive(Clone, Debug)]
pub struct GetResult {
    pub stat: ObjectStat,
    pub bytes: Bytes,
}

/// Precondition attached to a PUT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PutPrecondition {
    None,
    /// `If-Match: <etag>` — replace only the observed generation.
    IfMatch(String),
    /// `If-None-Match: *` — create only if absent.
    IfNoneMatchAny,
}

/// Conditional-delete outcome at the raw request level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawConditionalDelete {
    Deleted,
    NotFound,
    PreconditionFailed,
}

/// One raw listing page (delimiter-mode: direct children only).
#[derive(Clone, Debug)]
pub struct RawListPage {
    /// Direct-child objects (full physical keys) with their observations,
    /// in S3's byte-lexical key order.
    pub objects: Vec<(String, ObjectStat)>,
    /// Whether more results exist after this page.
    pub truncated: bool,
}

/// Narrow S3 request boundary. `max_len` caps are enforced WHILE reading
/// bodies (an oversized streamed response cannot evade the bound by lying
/// in Content-Length).
#[async_trait]
pub trait S3Client: Send + Sync + 'static {
    async fn head_object(&self, key: &str) -> Result<Option<ObjectStat>, S3ApiError>;

    /// `Ok(None)` iff absent; `Err` with a `TooLarge`-shaped message never
    /// occurs — oversized payloads are reported via `Ok`-side truncation
    /// being FORBIDDEN: the implementation must fail with an
    /// [`S3ApiError`] whose `code` is `"EntityTooLarge:{max_len}"` sentinel
    /// (mapped by the adapter to the generic bound error) after reading at
    /// most `max_len + 1` bytes.
    async fn get_object(&self, key: &str, max_len: u64) -> Result<Option<GetResult>, S3ApiError>;

    /// PUT with optional precondition. Returns the new generation's raw
    /// ETag. Precondition losses surface as [`S3ApiError`] with
    /// precondition/absence signals, classified by the adapter.
    async fn put_object(
        &self,
        key: &str,
        bytes: Bytes,
        precondition: PutPrecondition,
    ) -> Result<String, S3ApiError>;

    /// Unconditional idempotent delete: absent keys are success (native S3
    /// answers 204; 404-answering S3-compatible backends are normalized by
    /// the implementation). Every other failure surfaces.
    async fn delete_object(&self, key: &str) -> Result<(), S3ApiError>;

    /// `If-Match` conditional delete.
    async fn delete_object_if_match(
        &self,
        key: &str,
        etag: &str,
    ) -> Result<RawConditionalDelete, S3ApiError>;

    /// Delimiter-mode listing of the DIRECT children under `dir_prefix`
    /// (which ends with `/` or is empty), starting strictly after
    /// `start_after` (a full physical key), returning at most `max_keys`
    /// objects. Common prefixes (sub-namespaces) are not returned as
    /// objects.
    async fn list_direct_children(
        &self,
        dir_prefix: &str,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<RawListPage, S3ApiError>;
}

/// Sentinel code carried by [`S3Client::get_object`] implementations when a
/// payload exceeds the caller's bound (see the trait docs).
pub fn too_large_sentinel(max_len: u64) -> String {
    format!("EntityTooLarge:{max_len}")
}

pub(crate) fn parse_too_large_sentinel(code: Option<&str>) -> Option<u64> {
    code.and_then(|c| c.strip_prefix("EntityTooLarge:"))
        .and_then(|v| v.parse().ok())
}

// ============================================================================
// AWS SDK implementation
// ============================================================================

/// Production [`S3Client`] over an injected AWS SDK client. The SDK client
/// (credentials, endpoint, region) is constructed by the embedding
/// application; this crate performs requests only.
pub struct AwsS3Client {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl AwsS3Client {
    pub fn new(client: aws_sdk_s3::Client, bucket: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
        }
    }
}

fn sdk_err<E>(e: &aws_sdk_s3::error::SdkError<E>) -> (Option<u16>, Option<String>)
where
    E: aws_sdk_s3::error::ProvideErrorMetadata + std::fmt::Debug,
{
    match e {
        aws_sdk_s3::error::SdkError::ServiceError(se) => {
            let meta = aws_sdk_s3::error::ProvideErrorMetadata::meta(e);
            (
                Some(se.raw().status().as_u16()),
                meta.code().map(str::to_owned),
            )
        }
        _ => (None, None),
    }
}

fn quote_etag(raw: &str) -> String {
    format!("\"{}\"", raw.trim_matches('"'))
}

#[async_trait]
impl S3Client for AwsS3Client {
    async fn head_object(&self, key: &str) -> Result<Option<ObjectStat>, S3ApiError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(out) => Ok(Some(ObjectStat {
                size: out.content_length().unwrap_or(0).max(0) as u64,
                modified: out
                    .last_modified()
                    .and_then(|t| SystemTime::try_from(*t).ok()),
                etag: out.e_tag().unwrap_or_default().to_string(),
            })),
            Err(e) => {
                let (status, code) = sdk_err(&e);
                let err = S3ApiError {
                    status,
                    code,
                    message: e.to_string(),
                    source: Some(Box::new(e)),
                };
                if err.is_absence() { Ok(None) } else { Err(err) }
            }
        }
    }

    async fn get_object(&self, key: &str, max_len: u64) -> Result<Option<GetResult>, S3ApiError> {
        let resp = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let (status, code) = sdk_err(&e);
                let err = S3ApiError {
                    status,
                    code,
                    message: e.to_string(),
                    source: Some(Box::new(e)),
                };
                return if err.is_absence() { Ok(None) } else { Err(err) };
            }
        };
        let etag = resp.e_tag().unwrap_or_default().to_string();
        let modified = resp
            .last_modified()
            .and_then(|t| SystemTime::try_from(*t).ok());
        // Bound enforced WHILE streaming: never trust Content-Length alone.
        let mut body = resp.body;
        let mut collected: Vec<u8> = Vec::new();
        while let Some(chunk) = body
            .try_next()
            .await
            .map_err(|e| S3ApiError::new(None, None, format!("body stream: {e}")))?
        {
            if (collected.len() as u64 + chunk.len() as u64) > max_len {
                return Err(S3ApiError::new(
                    None,
                    Some(&too_large_sentinel(max_len)),
                    "object exceeds caller byte bound",
                ));
            }
            collected.extend_from_slice(&chunk);
        }
        let size = collected.len() as u64;
        Ok(Some(GetResult {
            stat: ObjectStat {
                size,
                modified,
                etag,
            },
            bytes: Bytes::from(collected),
        }))
    }

    async fn put_object(
        &self,
        key: &str,
        bytes: Bytes,
        precondition: PutPrecondition,
    ) -> Result<String, S3ApiError> {
        let mut req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(aws_sdk_s3::primitives::ByteStream::from(bytes));
        match &precondition {
            PutPrecondition::None => {}
            PutPrecondition::IfMatch(etag) => req = req.if_match(quote_etag(etag)),
            PutPrecondition::IfNoneMatchAny => req = req.if_none_match("*"),
        }
        match req.send().await {
            Ok(out) => Ok(out.e_tag().unwrap_or_default().to_string()),
            Err(e) => {
                let (status, code) = sdk_err(&e);
                Err(S3ApiError {
                    status,
                    code,
                    message: e.to_string(),
                    source: Some(Box::new(e)),
                })
            }
        }
    }

    async fn delete_object(&self, key: &str) -> Result<(), S3ApiError> {
        match self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                let (status, code) = sdk_err(&e);
                let err = S3ApiError {
                    status,
                    code,
                    message: e.to_string(),
                    source: Some(Box::new(e)),
                };
                // Absent object = idempotent success (some S3-compatible
                // backends answer 404 where AWS answers 204).
                if err.is_absence() { Ok(()) } else { Err(err) }
            }
        }
    }

    async fn delete_object_if_match(
        &self,
        key: &str,
        etag: &str,
    ) -> Result<RawConditionalDelete, S3ApiError> {
        match self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .if_match(quote_etag(etag))
            .send()
            .await
        {
            Ok(_) => Ok(RawConditionalDelete::Deleted),
            Err(e) => {
                let (status, code) = sdk_err(&e);
                let err = S3ApiError {
                    status,
                    code,
                    message: e.to_string(),
                    source: Some(Box::new(e)),
                };
                if err.is_absence() {
                    Ok(RawConditionalDelete::NotFound)
                } else if err.is_precondition() {
                    Ok(RawConditionalDelete::PreconditionFailed)
                } else {
                    Err(err)
                }
            }
        }
    }

    async fn list_direct_children(
        &self,
        dir_prefix: &str,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<RawListPage, S3ApiError> {
        let mut req = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(dir_prefix)
            .delimiter("/")
            .max_keys(max_keys.min(1000) as i32);
        if let Some(sa) = start_after {
            req = req.start_after(sa);
        }
        match req.send().await {
            Ok(out) => {
                let mut objects = Vec::new();
                for obj in out.contents() {
                    let Some(key) = obj.key() else { continue };
                    objects.push((
                        key.to_string(),
                        ObjectStat {
                            size: obj.size().unwrap_or(0).max(0) as u64,
                            modified: obj
                                .last_modified()
                                .and_then(|t| SystemTime::try_from(*t).ok()),
                            etag: obj.e_tag().unwrap_or_default().to_string(),
                        },
                    ));
                }
                Ok(RawListPage {
                    objects,
                    truncated: out.is_truncated().unwrap_or(false),
                })
            }
            Err(e) => {
                let (status, code) = sdk_err(&e);
                Err(S3ApiError {
                    status,
                    code,
                    message: e.to_string(),
                    source: Some(Box::new(e)),
                })
            }
        }
    }
}
