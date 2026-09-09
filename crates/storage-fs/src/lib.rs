//! # `storage-fs`
//!
//! Descriptor-relative filesystem storage adapter implementing [`storage_core::ObjectMetadataReader`].
//!
//! ## Architectural Ownership Boundaries
//! - **`storage-core`**: Defines domain-neutral contracts ([`ObjectKey`](storage_core::ObjectKey),
//!   [`ObjectMetadata`](storage_core::ObjectMetadata), [`ObjectMetadataReader`](storage_core::ObjectMetadataReader),
//!   and [`ReadError`](storage_core::ReadError)).
//! - **`storage-fs`**: Implements filesystem-specific storage operations over a pinned directory descriptor
//!   using Linux `openat2` containment flags, executing blocking operations on Tokio's blocking thread pool.
//! - **`registry-rust`**: Retains namespace routing, quarantine fallback orchestration, and outward
//!   HTTP/OCI API compatibility translation.
//!
//! ## Execution Boundary
//! - Async metadata inquiry ([`head`](reader::FsMetadataReader::head)) offloads blocking filesystem
//!   syscalls (`openat2`, `fstat`) to Tokio's blocking pool (`tokio::task::spawn_blocking`) and requires
//!   an entered Tokio runtime.
//! - Constructor [`open`](reader::FsMetadataReader::open) remains synchronous on the caller thread.
//! - Startup capability probe ([`probe_capability`](reader::FsMetadataReader::probe_capability)) is an explicit,
//!   backend-specific synchronous method executing on the caller thread. It opens `"."` relative to the pinned root
//!   descriptor with `openat2` and verifies directory metadata inspection succeeds on the calling thread at that time.
//!   It is not invoked automatically by `open` or `head`, and should not be called directly on an async executor worker thread.
//!   Downstream registry startup invocation remains deferred.
//!
//! ## Open Quality Gates
//! Quality gate **O-05** remains **OPEN**: this crate implements the standalone metadata inquiry
//! port; payload streams, range requests, directory listings, mutations, quarantine integration, and
//! production cutover are not authorized in this slice.

pub mod error;
pub mod reader;

pub use error::FsMetadataError;
pub use reader::FsMetadataReader;
