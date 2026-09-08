# storage-layer-rust

Standalone Cargo workspace for extracted domain-free storage mechanics. `storage-core` is unpublished and unintegrated. Slice 2A contains only key syntax and metadata-read contracts.

## Architecture and Ownership Boundary

- **`storage-core`**: Owns domain-free storage contracts, key syntax validation, metadata abstractions, and low-level storage mechanics.
- **`registry-rust`**: Retains full ownership of registry-level authorization, repository namespace mapping, tenant isolation, OCI descriptor/manifest semantics, HTTP API status/header translation, and outward compatibility.

`storage-core` contains no dependencies on or references to registry types, OCI specifications, HTTP APIs, or cloud provider SDKs. Outward error compatibility remains in `registry-rust`.

## Current Workspace Crates

- `crates/storage-core`: Minimal, domain-neutral storage contracts and primitives:
  - `ObjectKey`: Validated, lossless relative object key syntax type.
  - `ObjectMetadata`: Read-only metadata container preserving exact byte length.
  - `ObjectMetadataReader`: Object-safe async metadata-read trait.
  - `ObjectKeyError`, `ReadError`: Strongly typed failure categories.

## Open Contract Gates

- **O-03 (Object Key Length Validation)**: Maximum key length validation is provisionally omitted in Slice 2A and tracked as contract gate O-03. This provisional omission is documented explicitly; no claim of complete key validation or production readiness is made in this slice.
- **Release and Distribution**: The workspace and all member crates are marked `publish = false`. Integration with `registry-rust` is deferred to subsequent refactoring slices.

## Deferred Capabilities and Gates

The following capabilities and gates remain deferred beyond Slice 2A:
- Serialization and deserialization contracts (`Serialize`, `Deserialize`)
- Maximum key length validation (O-03)
- Full object reads and streaming payload access
- Bounded byte-range reads
- Object listing, prefix enumeration, and continuation tokens
- Concrete storage backend adapters (`FsStorage`, `S3Storage`)
- Workspace distribution and publication
- Technical Debt D-06 resolution (S3 staged upload architecture and data plane)
