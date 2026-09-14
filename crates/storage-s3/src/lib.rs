//! S3 adapter for the backend-neutral `storage-core` object-store contract
//! (STORAGE-LAYER-MIGRATION Phase 2).
//!
//! Layering: `storage-core` owns the [`storage_core::ObjectStore`]
//! semantics; this crate owns S3 request mechanics (conditional PUT/DELETE
//! via `If-Match`/`If-None-Match`, delimiter listing, ETag-backed opaque
//! version tokens, one centralized error classification). It contains no
//! registry-domain concepts and no filesystem concepts; AWS SDK types do
//! not escape its semantic boundary (they survive only as error `source`
//! diagnostics).
//!
//! Construction: the embedding application builds an `aws_sdk_s3::Client`
//! (credentials/region/endpoint are its concern) and wraps it in
//! [`AwsS3Client`]; deterministic tests inject their own [`S3Client`]
//! implementation. Bucket-versioning deployment preflight remains OUTSIDE
//! the generic contract (it is a GC-strategy/deployment validation, not an
//! object-store semantic) and is deliberately not part of this adapter's
//! Phase 2 surface.

pub mod client;
pub mod object_store;

pub use client::{AwsS3Client, S3ApiError, S3Client};
pub use object_store::S3ObjectStore;
