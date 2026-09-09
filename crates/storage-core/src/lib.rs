//! Core storage domain types, traits, and error primitives.
//!
//! This crate defines minimal, abstract storage interfaces decoupling upper-layer
//! registry services from concrete backend storage drivers.
//!
//! ## Core Primitives
//! - [`ObjectKey`]: Strongly typed, normalized relative path key.
//! - [`ObjectMetadata`]: Read-only metadata describing an object's size.
//! - [`ObjectMetadataReader`]: Object-safe async trait for reading object metadata.
//! - [`ObjectStream`]: Pinned, owned asynchronous byte stream trait object.
//! - [`ObjectPayload`]: Carrier pairing object metadata with an active payload stream.
//! - [`ObjectPayloadReader`]: Object-safe async trait for opening object payload streams.
//! - [`ObjectKeyError`]: Strongly typed key syntax validation errors.
//! - [`ReadError`]: Strongly typed read and metadata inquiry errors.
//!
//! ### Boundary Responsibilities
//! - **Owned by `storage-core`**: Validated hierarchical key syntax, minimal object metadata,
//!   metadata inquiry contracts ([`ObjectMetadataReader`]), and generic payload stream contracts
//!   ([`ObjectPayloadReader`]).
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
pub use read::{
    ObjectMetadata, ObjectMetadataReader, ObjectPayload, ObjectPayloadReader, ObjectStream,
};
