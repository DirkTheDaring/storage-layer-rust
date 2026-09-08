//! # `storage-core`
//!
//! Domain-free core storage contracts and primitives.
//!
//! ## Architecture and Ownership Boundary
//!
//! `storage-core` defines low-level, domain-neutral storage abstractions:
//! - [`ObjectKey`]: Strictly validated, lossless hierarchical object key syntax type.
//! - [`ObjectMetadata`]: Minimal object metadata container preserving byte length.
//! - [`ObjectMetadataReader`]: Object-safe async trait for reading object metadata.
//! - [`ObjectKeyError`]: Strongly typed key syntax validation errors.
//! - [`ReadError`]: Strongly typed read and metadata inquiry errors.
//!
//! ### Boundary Responsibilities
//! - **Owned by `storage-core`**: Validated hierarchical key syntax, minimal object metadata,
//!   and metadata-read contracts ([`ObjectMetadataReader`]).
//! - **Owned by `registry-rust`**: Registry authentication and authorization, tenant and repository
//!   namespace mapping, OCI descriptor and manifest semantics, HTTP request/response mappings,
//!   and outward error translation.
//!
//! ## Open Contract Gates
//! - **O-03 (Object Key Length Validation)**: Maximum key length validation is provisionally omitted
//!   in Slice 2A and tracked as contract gate O-03.
//! - **Release & Distribution**: Marked `publish = false`. Unintegrated and provisional.

pub mod error;
pub mod key;
pub mod read;

pub use error::{ObjectKeyError, ReadError};
pub use key::ObjectKey;
pub use read::{ObjectMetadata, ObjectMetadataReader};
