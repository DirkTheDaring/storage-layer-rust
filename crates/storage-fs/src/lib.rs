//! # `storage-fs`
//!
//! Descriptor-relative filesystem storage adapter implementing [`storage_core::ObjectMetadataReader`]
//! and [`storage_core::ObjectPayloadReader`].
//!
//! ## Architectural Ownership Boundaries
//! - **`storage-core`**: Defines domain-neutral contracts ([`ObjectKey`](storage_core::ObjectKey),
//!   [`ObjectMetadata`](storage_core::ObjectMetadata), [`ObjectMetadataReader`](storage_core::ObjectMetadataReader),
//!   [`ObjectPayload`](storage_core::ObjectPayload), [`ObjectPayloadReader`](storage_core::ObjectPayloadReader),
//!   [`ObjectStream`](storage_core::ObjectStream), and [`ReadError`](storage_core::ReadError)).
//! - **`storage-fs`**: Implements filesystem-specific storage operations over a pinned directory descriptor
//!   using Linux `openat2` containment flags, executing blocking operations on Tokio's blocking thread pool.
//! - **`registry-rust`**: Retains namespace routing, quarantine fallback orchestration, and outward
//!   HTTP/OCI API compatibility translation.
//!
//! ## Execution Boundary and Latency
//! - Async metadata inquiry ([`head`](reader::FsMetadataReader::head)), payload opening
//!   ([`open_payload`](storage_core::ObjectPayloadReader::open_payload)), and file metadata inspection
//!   ([`inspect_file_metadata`](reader::FsMetadataReader::inspect_file_metadata)) offload initial blocking filesystem
//!   syscalls (`openat2`, `fstat`, `/proc/self/fd` reopening) to Tokio's blocking pool
//!   (`tokio::task::spawn_blocking`) and require an entered Tokio runtime.
//! - Offloading to `spawn_blocking` avoids stalling worker threads during initial descriptor resolution,
//!   but callers are not guaranteed that asynchronous tasks or worker threads will never experience filesystem
//!   latency, such as during stream polling, runtime task scheduling, or resource teardown.
//! - Constructor [`open`](reader::FsMetadataReader::open) remains synchronous on the caller thread.
//! - Startup capability probe ([`probe_capability`](reader::FsMetadataReader::probe_capability)) is an explicit,
//!   backend-specific synchronous method executing on the caller thread. It opens `"."` relative to the pinned root
//!   descriptor with `openat2` and verifies directory metadata inspection succeeds on the calling thread at that time.
//!   It is not invoked automatically by `open`, `head`, or `open_payload`.
//!
//! ## Capability Probe Boundaries and Non-Guarantees
//! The capability probe does **not**:
//! 1. Establish equivalent permissions or syscall filtering on Tokio blocking-pool threads or future worker threads.
//! 2. Establish that child paths, subdirectories, or blobs exist or can be created.
//! 3. Exercise multi-component path resolution across subdirectories.
//! 4. Verify regular-file lookup (`S_IFREG`), because `"."` is a directory (`S_IFDIR`).
//! 5. Establish payload read permissions (`O_RDONLY`) or write permissions on child objects (`O_PATH` success is not proof of ordinary read or write permission).
//! 6. Establish root coherence across pathname-based reads and mutations.
//! 7. Establish future availability or guarantee against dynamic runtime reconfiguration (e.g. late seccomp loading, remounts, or storage media failures).
//! 8. Close quality gate **O-05** or establish production readiness.
//!
//! ## Two-Phase Payload Acquisition & Explicit Procfs Trust Assumption
//! Payload acquisition executes synchronously inside a Tokio blocking task in two phases:
//! 1. **Phase 1 (Contained Resolution)**: Resolves the key beneath the pinned root descriptor via `openat2`
//!    with `O_PATH` and containment flags `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
//!    The returned descriptor is immediately owned and inspected with `fstat` to reject non-regular objects
//!    before any readable open.
//! 2. **Phase 2 (Readable Reopening)**: Opens `/proc/self/fd/N` with `O_RDONLY | O_CLOEXEC` while retaining the
//!    Phase 1 descriptor. The returned readable descriptor is immediately owned and verified via `fstat` to ensure
//!    regular-file type and matching `st_dev`/`st_ino` identity.
//!
//! **Procfs Trust Assumption**: This standalone implementation is supported only under the documented assumption
//! that `/proc/self/fd` is genuine, accessible, and stable during acquisition. Formatting a descriptor pathname does
//! not verify this assumption, and the post-open identity check cannot undo driver side effects caused by an
//! attacker-substituted procfs target. Procfs trust and availability are prerequisites for any future registry cutover.
//!
//! ## Stream Lifecycle and Delayed Descriptor Closure
//! The returned [`storage_core::ObjectPayload`] and its [`storage_core::ObjectStream`] own their underlying file
//! descriptors and do not borrow from the reader or key. In-flight streams remain fully operational even if the
//! originating reader and key are dropped, provided their required Tokio runtime remains active.
//! Outstanding I/O operations can retain the underlying file handle and delay descriptor closure; no particular
//! cleanup thread or instantaneous descriptor release is guaranteed upon stream drop.
//!
//! ## Bounded Directory Enumeration
//! - Single-directory enumeration ([`enumerate_dir`](reader::FsMetadataReader::enumerate_dir)) operates over the pinned
//!   root descriptor using Linux `openat2` with containment flags:
//!   `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
//! - Resolves root (`None`) via `"."` and subdirectories (`Some(key)`) with identical containment flags.
//! - Callers must provide explicit [`DirEnumerationLimits`](dir::DirEnumerationLimits) bounding maximum entries and cumulative name bytes.
//! - **Zero-Limit Semantics**: An empty directory succeeds under zero limits; if non-empty, the first entry exceeding either budget
//!   fails closed with [`FsDirError::LimitExceeded`](dir::FsDirError::LimitExceeded) without partial results.
//! - **Resource Bounds Scope**: Limits bound retained entry counts and raw name bytes in userspace heap memory. They do not bound
//!   allocator overhead, kernel dentries/inodes, libc internal buffers, concurrent tasks, or blocking syscall duration.
//! - **Cancellation**: Dropping the awaiting future does not cancel in-flight blocking kernel I/O.
//! - **Observations, Not Capabilities**: Returned [`DirEntryType`](dir::DirEntryType) values are point-in-time observations during iteration,
//!   not capabilities authorizing subsequent pathname access.
//! - **Non-Guarantees**: Directory iteration does not provide snapshot isolation. Moving or unlinking a directory does not guarantee
//!   successful iteration. Mount crossing is not prohibited by these flags; no mount isolation is claimed.
//!
//! ## Contained File Metadata Inspection
//! - Single-file metadata inspection ([`inspect_file_metadata`](reader::FsMetadataReader::inspect_file_metadata))
//!   resolves `key` relative to the pinned root directory descriptor using Linux `openat2` with:
//!   `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
//! - **Observation After Acquisition**: Attributes are observed by `fstat` on the acquired descriptor after acquisition,
//!   not at the instant of `openat2` path resolution.
//! - **No Atomic Snapshot Under Mutation**: A single `fstat` result does not guarantee an atomic snapshot of all attributes
//!   under concurrent mutation, nor does it guarantee snapshot isolation across multiple operations.
//! - **Platform Verification**: Descriptor-relative containment requires Linux `openat2`. Non-Linux platforms return
//!   typed `PlatformUnsupported`; non-Linux compilation and execution remain unverified in the absence of a cross-compilation environment.
//!
//! ## Error Model Demarcation
//! - In `head` metadata inquiries, Phase 1 resolution errors map to [`ReadError::NotFound`](storage_core::ReadError::NotFound),
//!   [`ReadError::PermissionDenied`](storage_core::ReadError::PermissionDenied), or [`ReadError::Backend`](storage_core::ReadError::Backend).
//! - In `inspect_file_metadata` inquiries:
//!   - Resolution `ENOENT` maps to [`ReadError::NotFound`](storage_core::ReadError::NotFound).
//!   - Resolution `EACCES`/`EPERM` maps to [`ReadError::PermissionDenied`](storage_core::ReadError::PermissionDenied).
//!   - Symlinks encountered during resolution (`ELOOP`/`EXDEV`) map to [`ReadError::Backend`](storage_core::ReadError::Backend)
//!     wrapping [`FsMetadataError::ResolutionRejected`].
//!   - `openat2` `ENOSYS` maps to [`ReadError::Backend`](storage_core::ReadError::Backend) wrapping [`FsMetadataError::SyscallUnsupported`].
//!   - `fstat` failure maps to [`ReadError::Backend`](storage_core::ReadError::Backend) wrapping [`FsMetadataError::StatFailed`].
//!   - Acquired non-regular objects (directories, FIFOs, character/block devices, sockets) map to
//!     [`ReadError::Backend`](storage_core::ReadError::Backend) wrapping [`FsMetadataError::UnsupportedObjectType`].
//!   - Invalid size or timestamp fields map to [`ReadError::Backend`](storage_core::ReadError::Backend) wrapping [`FsMetadataError::InvalidMetadata`].
//! - In `open_payload` acquisitions, errors are partitioned into distinct stages:
//!   - Phase 1 resolution uses typed resolution classification.
//!   - Non-regular files reject via [`FsMetadataError::UnsupportedObjectType`].
//!   - Phase 1 and Phase 2 `fstat` failures map to [`FsMetadataError::StatFailed`] preserving underlying `std::io::Error`.
//!   - Phase 2 procfs reopening failures map to [`FsMetadataError::ProcfsReopenFailed`]; Phase 2 `ENOENT` is **never**
//!     reported as `NotFound`, and Phase 2 permission errors are **never** reported as `PermissionDenied`.
//!   - Reopened descriptor identity mismatches map to [`FsMetadataError::IdentityMismatch`].
//!   - Stream reading failures occurring after acquisition are delivered as [`std::io::Error`] through `AsyncRead`.
//! - In `enumerate_dir` inquiries, errors map to strongly typed [`FsDirError`](dir::FsDirError) variants distinguishing missing targets,
//!   non-directory targets, permission denial, kernel containment rejections, budget limits, disappeared entries during inspection,
//!   runtime absence, and I/O failures.
//!
//! ## Open Quality Gates
//! Quality gates **O-05**, **O-03**, **O-06**, **O-13**, **O-16**, and **D-06** remain **OPEN**:
//! this crate implements standalone metadata, payload, directory enumeration, and file metadata inspection operations.
//! Registry callers, production routing, range reads, seeking, CAS listing integration, mutations, quarantine integration,
//! and production cutover are not authorized in this slice.

pub mod dir;
pub mod error;
pub mod mutate;
pub mod object_store;
pub mod reader;

pub use dir::{
    DirEntry, DirEntryType, DirEnumerationLimits, DirStream, FsDirError, LimitExceededReason,
};
pub use error::FsMetadataError;
pub use mutate::{
    BlockingDir, ContainedDir, ContainedLockGuard, FileName, FsFileIdentity, FsMutateError,
    LeafWriteMode, OwnedFdHandle,
};
pub use object_store::FsObjectStore;
pub use reader::{FsFileMetadata, FsMetadataReader};
