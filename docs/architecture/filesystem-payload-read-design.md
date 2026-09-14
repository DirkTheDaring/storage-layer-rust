# Architectural Design: Descriptor-Relative Filesystem Payload Reads

**Document Status**: Corrected Architecture & Implementation Plan  
**Target Repository**: `storage-layer-rust` (`crates/storage-core`, `crates/storage-fs`)  
**Downstream Consumer**: `registry-rust` (`src/storage/fs/`, `src/storage/ports/`, `src/application/blob_read.rs`)  
**Quality Gate Alignment**: Evaluates **O-05** (Descriptor-relative directory containment); gates **O-03**, **O-05**, **O-06**, **O-13**, **O-16**, and **D-06** remain open.

---

## 1. Executive Summary & Problem Definition

The storage extraction architecture established in Slice 2A and Slice 2B introduced:
1. Domain-neutral key syntax validation ([`storage_core::ObjectKey`](file:///home/dietmar/devel/rust/storage-layer-rust/crates/storage-core/src/key.rs)) and strongly typed read error taxonomy ([`storage_core::ReadError`](file:///home/dietmar/devel/rust/storage-layer-rust/crates/storage-core/src/error.rs)).
2. An asynchronous metadata-only port ([`storage_core::ObjectMetadataReader`](file:///home/dietmar/devel/rust/storage-layer-rust/crates/storage-core/src/read.rs)).
3. A standalone Linux implementation ([`storage_fs::FsMetadataReader`](file:///home/dietmar/devel/rust/storage-layer-rust/crates/storage-fs/src/reader.rs)) enforcing descriptor-relative `openat2` resolution beneath a pinned directory descriptor with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
4. An explicit startup capability probe ([`FsMetadataReader::probe_capability`](file:///home/dietmar/devel/rust/storage-layer-rust/crates/storage-fs/src/reader.rs#L206)) and verified test-only integration seam in `registry-rust` ([`src/storage/fs/metadata_seam.rs`](file:///home/dietmar/devel/rust/registry-rust/src/storage/fs/metadata_seam.rs)).

However, `storage-core` and `storage-fs` currently support **metadata inquiry only** (`head`). Reading object bytes (payloads) in `registry-rust` is still performed directly by [`FsStorage::open_blob`](file:///home/dietmar/devel/rust/registry-rust/src/storage/fs.rs#L753) using uncontained, pathname-based `tokio::fs::File::open(&path)`. This leaves significant security and architectural gaps:
- **Symlink Vulnerability**: Pathname-based payload opens follow symlinks across directory hierarchies, bypassing root containment.
- **Root Inode Divergence**: If the storage root path is renamed or replaced on disk, pathname-based opens target the new directory while the metadata reader remains pinned to the original inode.
- **Special Object Hazards**: Pathname-based opens on named pipes (FIFOs) block indefinitely when opened without a writer, stalling runtime worker threads.

This document defines the architectural design for streaming payload reads, rigorously reassesses descriptor acquisition safety, establishes the boundaries of the generic core contract, and recommends a focused test-only acquisition experiment prior to public API expansion.

---

## 2. Source-Grounded Inspection of Current Implementations

### 2.1 `storage-core` Current State
- **Contracts**: Only defines [`ObjectMetadataReader`](file:///home/dietmar/devel/rust/storage-layer-rust/crates/storage-core/src/read.rs#L44), exposing `head(&self, key: &ObjectKey) -> Result<ObjectMetadata, ReadError>`.
- **Payload Capability**: None. There is no payload reader trait, byte stream abstraction, or read-oriented port.
- **Dependencies**: Depends only on `async-trait` (`0.1`) and `thiserror` (`2.0`). `tokio` is strictly a `dev-dependency`.
- **Error Taxonomy**: [`ReadError`](file:///home/dietmar/devel/rust/storage-layer-rust/crates/storage-core/src/error.rs#L58) defines:
  - `NotFound { key: ObjectKey }`
  - `PermissionDenied { key: ObjectKey, source: Option<Box<dyn StdError + Send + Sync>> }`
  - `Backend { message: String, source: Option<Box<dyn StdError + Send + Sync>> }`

### 2.2 `storage-fs` Current State
- **Root Ownership**: [`FsMetadataReader`](file:///home/dietmar/devel/rust/storage-layer-rust/crates/storage-fs/src/reader.rs#L76) owns `root_fd: Arc<OwnedFd>` and `root_path: PathBuf`.
  - Constructed synchronously via [`FsMetadataReader::open`](file:///home/dietmar/devel/rust/storage-layer-rust/crates/storage-fs/src/reader.rs#L101), acquiring `root_fd` using `libc::open(..., libc::O_DIRECTORY | libc::O_PATH | libc::O_CLOEXEC)`.
- **Metadata Lookup**: [`FsMetadataReader::head`](file:///home/dietmar/devel/rust/storage-layer-rust/crates/storage-fs/src/reader.rs#L225) dispatches to Tokio's blocking threadpool (`tokio::task::spawn_blocking`).
  - Syscall: `openat2(root_fd, c_rel, &how, ...)` where `how.flags = O_PATH | O_CLOEXEC` and `how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
  - Inspection: `fstat(target_fd, &mut st)`.
  - Type Check: [`check_stat_and_extract_metadata`](file:///home/dietmar/devel/rust/storage-layer-rust/crates/storage-fs/src/reader.rs#L446) requires `S_IFMT == S_IFREG`, rejects negative sizes, and extracts `ObjectMetadata::new(st.st_size as u64)`.
  - Cleanup: `target_fd` is held as an [`std::os::fd::OwnedFd`](file:///home/dietmar/devel/rust/storage-layer-rust/crates/storage-fs/src/reader.rs#L30), guaranteeing `libc::close` upon drop.
- **Capability Probe**: [`FsMetadataReader::probe_capability`](file:///home/dietmar/devel/rust/storage-layer-rust/crates/storage-fs/src/reader.rs#L206) issues a synchronous `openat2` on `.` relative to `root_fd` on the calling thread.
  - *Narrow Scope*: Proves only that `openat2` on `.` succeeded on that thread at that time; does not establish kernel or seccomp support for future worker threads, child path resolution, regular file access, or payload reading.

### 2.3 `registry-rust` Current Payload Behavior
- **Port Definition**: [`src/storage/ports/mod.rs:18-24`](file:///home/dietmar/devel/rust/registry-rust/src/storage/ports/mod.rs#L18)
  ```rust
  #[async_trait]
  pub trait BlobCasReader: Send + Sync {
      async fn head_blob(&self, digest: &Digest) -> Result<BlobMeta, StorageError>;
      async fn open_blob(
          &self,
          digest: &Digest,
      ) -> Result<(BlobMeta, Pin<Box<dyn AsyncRead + Send>>), StorageError>;
  }
  ```
- **Implementation in `FsStorage`**: [`src/storage/fs.rs:753-777`](file:///home/dietmar/devel/rust/registry-rust/src/storage/fs.rs#L753)
  1. Computes live primary path: `self.blob_path(digest)`.
  2. Calls `tokio::fs::File::open(&path).await`.
  3. If `NotFound`, falls back to quarantine path: `self.quarantine_blob_path(digest)`.
  4. If quarantine also returns `NotFound`, returns `Err(StorageError::NotFound)`.
  5. Any other I/O failure returns `Err(StorageError::io(err.to_string()))`.
  6. On open success, calls `file.metadata().await`. If `metadata()` fails, returns `StorageError::io`.
  7. Returns `Ok((BlobMeta { size: meta.len() }, Box::pin(file)))`.
- **Downstream Consumer Flow**:
  - [`BlobReadService::get_blob`](file:///home/dietmar/devel/rust/registry-rust/src/application/blob_read.rs#L130): Calls `open_blob`, then converts the reader into a stream via `tokio_util::io::ReaderStream::new(reader).map(|r| r.map_err(UploadStreamError::Io))`.
  - HTTP Presentation ([`src/http_api/handlers.rs:312-365`](file:///home/dietmar/devel/rust/registry-rust/src/http_api/handlers.rs#L312)): Consumes the stream chunks or streams to the client via `axum::body::Body::from_stream`. If a read-time I/O error occurs, the stream yields `UploadStreamError::Io`, causing the HTTP transfer to terminate.

---

## 3. Generic Stream Contract in `storage-core`

### 3.1 Design Principles
The core contract must remain strictly **domain-neutral and backend-agnostic**:
- Must not mention Linux, file descriptors, `openat2`, `fstat`, directory pinning, or POSIX file modes.
- Expressed exclusively in terms of [`ObjectKey`](file:///home/dietmar/devel/rust/storage-layer-rust/crates/storage-core/src/key.rs), [`ObjectMetadata`](file:///home/dietmar/devel/rust/storage-layer-rust/crates/storage-core/src/read.rs#L11), byte streams, and [`ReadError`](file:///home/dietmar/devel/rust/storage-layer-rust/crates/storage-core/src/error.rs#L58).
- Compatible with memory-bounded streaming ($O(1)$ memory relative to object size).

### 3.2 Proposed Type Definitions (`crates/storage-core/src/read.rs`)

```rust
use std::pin::Pin;
use tokio::io::AsyncRead;

/// Pinned, dynamically dispatchable asynchronous byte stream for payload reads.
pub type ObjectStream = Pin<Box<dyn AsyncRead + Send>>;

/// Container pairing point-in-time object metadata with an active payload read stream.
pub struct ObjectPayload {
    metadata: ObjectMetadata,
    stream: ObjectStream,
}

impl ObjectPayload {
    /// Constructs a new `ObjectPayload` container from supplied metadata and an async stream.
    ///
    /// Note: This constructor does not enforce or verify that the stream will yield
    /// exactly `metadata.size()` bytes; callers and adapters are responsible for pairing
    /// correlated metadata and stream instances.
    pub fn new(metadata: ObjectMetadata, stream: ObjectStream) -> Self {
        Self { metadata, stream }
    }

    /// Returns the metadata acquired during object opening.
    pub fn metadata(&self) -> &ObjectMetadata {
        &self.metadata
    }

    /// Returns the byte length recorded in the object metadata.
    ///
    /// Note: This reports the point-in-time acquired metadata size; it cannot guarantee
    /// the eventual byte count under concurrent mutation of the underlying object.
    pub fn size(&self) -> u64 {
        self.metadata.size()
    }

    /// Decomposes the container into its constituent metadata and async stream.
    pub fn into_parts(self) -> (ObjectMetadata, ObjectStream) {
        (self.metadata, self.stream)
    }

    /// Consumes the container, returning only the async stream.
    pub fn into_stream(self) -> ObjectStream {
        self.stream
    }
}

/// Domain-neutral async trait for reading object byte streams by key.
#[async_trait]
pub trait ObjectPayloadReader: Send + Sync {
    /// Opens an existing object for sequential streaming read.
    ///
    /// # Errors
    /// Returns strongly typed [`ReadError`] outcomes:
    /// - [`ReadError::NotFound`] if the object does not exist.
    /// - [`ReadError::PermissionDenied`] if access is forbidden.
    /// - [`ReadError::Backend`] on system, storage adapter, or format failures.
    async fn open_payload(&self, key: &ObjectKey) -> Result<ObjectPayload, ReadError>;
}
```

### 3.3 Trait & Type Property Analysis
1. **Owned Lifetime (`'static`)**:
   `Box<dyn AsyncRead + Send>` carries an implicit `'static` lifetime bound. The stream does not borrow from the reader instance, allowing it to outlive the specific method call and be moved across tasks or service boundaries.
2. **`Send` Bound**:
   Required because asynchronous streams are driven across `.await` points by multi-threaded task schedulers (such as Tokio's work-stealing runtime).
3. **Pinning and `Unpin`**:
   `ObjectStream` is wrapped in `Pin<Box<...>>`. `Box<T>` implements `Unpin` regardless of whether the inner reader `T` implements `Unpin` (per standard library `Deref` rules). Callers can freely move the `ObjectStream` value.
4. **Omission of `Sync`**:
   `ObjectStream` requires `Send`, but deliberately omits `Sync`. Streaming reads are inherently stateful and sequential, driven by exclusive access (`poll_read(Pin<&mut Self>, ...)`). Imposing `Sync` would unnecessarily prohibit standard readers that use internal un-synchronized buffers or `tokio::fs::File`.
5. **Object Safety**:
   `ObjectPayloadReader` is fully object-safe. Callers can store and invoke `dyn ObjectPayloadReader + Send + Sync`.

---

## 4. Reassessment of Payload Acquisition: The Device & Special-Object Gap

### 4.1 Withdrawal of Direct `O_RDONLY | O_NONBLOCK` Recommendation
The prior design proposed opening objects directly with `libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC` followed by `fstat` validation. **That recommendation is explicitly withdrawn**:
1. **Device Driver Open Side Effects**: In Linux (and POSIX systems), issuing `open()` on a device special file (character or block device) executes the underlying device driver's `open` method *before* `open()` returns a descriptor to userspace.
   - For example, opening a tape device, hardware watchdog, serial port, or loop device may trigger hardware rewinds, line resets, or kernel buffer allocations.
   - Adding `O_NONBLOCK` does not suppress the driver's open routine; it merely requests non-blocking operation from the driver.
   - Performing `fstat` *after* `open` returns and immediately closing the descriptor does **not** undo or reverse side effects already executed by the device driver.
2. **Invalid Environmental Assumptions**: Relying on assumptions that the storage filesystem is mounted `nodev` or that unprivileged containers lack `CAP_MKNOD` is architecturally unsafe:
   - Nested mounts, pre-existing container rootfs fixtures, or bind mounts may place device nodes inside the storage root.
   - `RESOLVE_BENEATH` ensures resolution does not escape the root descriptor; it does **not** prevent resolving to a device node located physically beneath the root.

### 4.2 In-Depth Evaluation of the Two-Phase Acquisition Candidate
To avoid invoking device driver open routines or blocking on FIFOs, the acquisition candidate separates path containment from read capability:

```
[Phase 1: Contained Resolution via O_PATH]
  openat2(root_fd, key, O_PATH | O_CLOEXEC, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)
       │
       ▼
  OwnedFd (target_path_fd)
       │
  fstat(target_path_fd) -> Enforce S_IFMT == S_IFREG (reject S_IFCHR, S_IFBLK, S_IFIFO, S_IFDIR)
       │
       ▼ [Phase 2: Capability Elevation via procfs]
  open(format!("/proc/self/fd/{}", target_path_fd), O_RDONLY | O_CLOEXEC)
       │
       ▼
  OwnedFd (readable_fd)
       │
  fstat(readable_fd) -> Final metadata inspection & verification
       │
  tokio::fs::File::from_std(File::from(readable_fd))
```

#### Detailed Operational Analysis of Two-Phase Candidate:
1. **Contained `O_PATH` Resolution**:
   - `openat2` with `O_PATH` does not obtain data read access (`read()` fails with `EBADF`).
   - `O_PATH` does not execute device driver open routines, does not block on FIFOs, and does not require read permissions on the file.
   - Linux `openat2(2)` strictly enforces `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
2. **Pre-Read Validation**:
   - `fstat(target_path_fd)` inspects `st_mode`. If `st_mode & S_IFMT != S_IFREG`, the descriptor is dropped immediately. Device nodes, FIFOs, and directories are rejected before read opening is ever attempted.
3. **Descriptor-Anchored Reopening via `/proc/self/fd/N`**:
   - Why `dup` fails: Calling `dup(target_path_fd)` creates a new file descriptor referring to the *same open file description*, which retains `O_PATH`. `dup` cannot grant read permissions to an `O_PATH` descriptor.
   - Why path reopening fails: Calling `openat2(root_fd, key, O_RDONLY)` again by path reintroduces the exact TOCTOU race: a concurrent process could replace the verified regular file with a FIFO or device node between the two calls.
   - Procfs Magic-Link Traversal: `/proc/self/fd/N` is a Linux "magic link". Opening it reopens the exact `struct dentry`/`struct inode` currently held by descriptor `N`.
   - **Descriptor Lifetime**: Because `target_path_fd: OwnedFd` remains open throughout Phase 2, descriptor number `N` cannot be closed, reused, or reassigned by the OS to an unrelated file description.
   - **Path Replacement Immunity**: If another process unlinks or replaces `key` in the storage directory after Phase 1, Phase 2 continues to reopen the exact inode pinned by `target_path_fd`, immune to pathname replacement races.
4. **Permission Recheck at Phase 2**:
   - Opening `/proc/self/fd/N` with `O_RDONLY` causes the kernel to re-evaluate DAC and MAC read permissions against the calling process context. If permissions are missing, Phase 2 fails with `EACCES`.
5. **Intentional Magic-Link Scope**:
   - While `RESOLVE_NO_MAGICLINKS` forbids user keys from traversing magic links, Phase 2 is an explicit, internal backend call referencing `/proc/self/fd/<int>`. It does not process user input.

#### Procfs Availability & Trust Assumptions:
- **Procfs Dependency**: Requires `/proc` to be mounted and accessible.
  - In minimal chroots, unshared mount namespaces without procfs, or security profiles where `/proc` is masked, Phase 2 will fail with `ENOENT` or `EACCES`.
- **PID Namespace Coherence**: `/proc/self` must refer to the calling process's own thread group.
- **Filesystem Support**: On rare pseudo-filesystems or certain FUSE drivers, reopening via procfs may return `ENOTSUPP` or `EPERM`.
- **Concurrent Mutation Limits**: Reopening the inode obtains read access to the underlying storage object. If concurrent processes write or truncate that inode, streamed bytes will reflect those mutations.

---

## 5. Descriptor Ownership, Consistency, and Drop Lifecycle

### 5.1 Consistency Dimensions
To avoid ambiguous claims of "guaranteed consistency," the design distinguishes four separate layers:

| Consistency Layer | Mechanism | Guarantees Provided | Explicit Non-Guarantees |
| :--- | :--- | :--- | :--- |
| **1. Root Identity** | `root_fd: Arc<OwnedFd>` pinned at reader creation. | Subsequent queries resolve relative to the original root directory inode, immune to pathname renames (`mv root root_old`). | Does not prevent failures if the root directory is deleted, unmounted, or permissions are revoked. |
| **2. Opened-Object Identity** | Descriptor held through Phase 1 and Phase 2. | Guarantees Phase 2 opens the exact inode validated in Phase 1, immune to pathname replacement races. | Does not guarantee that two separate calls (`head` followed by `open_payload`) observe the same file. |
| **3. Metadata Observation** | `fstat` on `readable_fd` at end of acquisition. | Accurately reports inode attributes (mode, size) at the moment `fstat` executed. | Does not freeze the file size, create a snapshot, or guarantee content stability. |
| **4. Stream Contents** | Sequential `poll_read` on `tokio::fs::File`. | Reads bytes from the kernel file description as scheduled. | If writers append or truncate the file concurrently, reads will reflect those live mutations. |

### 5.2 Drop and Cancellation Semantics
1. **Cancelling the `open_payload` Future**:
   - Dropping the awaiting future on the caller thread drops the receiver half of the channel.
   - It does **not** abort or interrupt a blocking syscall (`openat2`, `fstat`, `open`) that has already begun execution on a Tokio blocking worker thread.
   - The blocking task runs to completion. When it returns, the resulting `OwnedFd` / `std::fs::File` is dropped on the worker thread, closing the descriptor via standard RAII. No descriptors leak.
2. **Dropping the Active Stream (`ObjectPayload` / `ObjectStream`)**:
   - Dropping `ObjectPayload` drops `tokio::fs::File`.
   - In Tokio, if a blocking chunk read is currently in flight on the threadpool, Tokio holds the underlying `std::fs::File` until that blocking operation completes.
   - **Descriptor Closure Delay**: Closure of the underlying descriptor may be delayed until the in-flight worker thread finishes its operation. The design does **not** promise immediate synchronous closure on the calling thread.

---

## 6. Dependency & Crate Feature Analysis

### 6.1 Pinned Workspace Baseline
From `storage-layer-rust/Cargo.lock`:
- `tokio` is pinned at version `1.53.1`.

### 6.2 Feature Breakdown by Crate

| Crate | Requirement | Required Tokio Feature Flags | Architectural Justification |
| :--- | :--- | :--- | :--- |
| `crates/storage-core` | Trait definition `ObjectStream = Pin<Box<dyn AsyncRead + Send>>` | `features = []` (or default-features = false) | In Tokio 1.x, `tokio::io::AsyncRead` is exported by core Tokio without extra features. No normal dependency on `io-util` is required merely to name the trait. |
| `crates/storage-core` (tests) | Test mocks calling `read_to_end()` or `read_exact()` | `dev-dependencies: tokio = { ..., features = ["io-util", "macros"] }` | `AsyncReadExt` utility extension traits require `io-util`. Kept strictly in dev-dependencies. |
| `crates/storage-fs` | Runtime check (`Handle::try_current`) and blocking pool dispatch (`spawn_blocking`) | `features = ["rt"]` | Already present in `crates/storage-fs/Cargo.toml`. |
| `crates/storage-fs` | `tokio::fs::File` stream construction (`File::from_std`) | `features = ["fs", "io-util"]` | `tokio::fs::File` requires `fs` and `io-util`. Must be added to normal dependencies in `crates/storage-fs/Cargo.toml`. |

*Critical Dependency Rule*: Normal library compilation must never rely on workspace dev-dependencies or downstream feature unification. Feature flags for `storage-fs` must be declared explicitly in its `Cargo.toml`.

---

## 7. Compatibility Comparison: Registry `open_blob` vs. Proposed Architecture

| Operational Scenario | Current Registry `FsStorage::open_blob` | Proposed Two-Phase `storage-fs` Architecture | Compatibility & Policy Status |
| :--- | :--- | :--- | :--- |
| **Standard Regular File** | Pathname open (`tokio::fs::File::open`). Follows symlinks. | Pinned `openat2` + procfs reopen. Verifies `S_IFREG`. | **Compatible Payload**: Yields identical bytes. |
| **Missing Object** | Live `NotFound` $\rightarrow$ Quarantine `NotFound` $\rightarrow$ `StorageError::NotFound`. | Core reader returns `ReadError::NotFound`. Quarantine fallback orchestrated in registry seam. | **Compatible**: Preserves primary-then-quarantine search order in registry layer. |
| **Symlinked File/Dir** | Blindly follows symlinks across filesystem boundaries. | Strictly rejected by kernel (`RESOLVE_NO_SYMLINKS`) as `ReadError::Backend { ResolutionRejected }`. | **Intentional Breaking Fix**: Closes directory traversal vulnerability. |
| **Target is Directory** | Opens descriptor; `metadata()` reports directory size; stream fails later with `EISDIR`. | `fstat` detects `S_IFDIR`; rejected in Phase 1 as `ReadError::Backend { UnsupportedObjectType }`. | **Fails Fast**: Immediate error before stream handoff. |
| **Target is FIFO** | **Hangs indefinitely** on open if no writer exists, stalling runtime worker. | `O_PATH` open succeeds instantly without writer; `fstat` detects `S_IFIFO`; rejected without hanging. | **Hang Immunity**: Eliminates denial-of-service vector. |
| **Target is Device Node** | Directly opens device; triggers driver open routines and hardware side effects. | `O_PATH` open does not invoke driver; `fstat` detects `S_IFCHR`/`S_IFBLK`; rejected before read access. | **Driver Safe**: Device open routine never invoked. |
| **Procfs Unmounted** | Unaffected (does not use procfs). | Phase 2 fails with `ReadError::Backend` (`ENOENT`/`EACCES`). | **Known Limitation**: Requires procfs access. |
| **Root Path Renamed** | Re-resolves new path from filesystem root; targets new directory. | Root descriptor remains pinned; operations continue targeting original inode. | **Consistent Inode Authority**: Pinned root identity. |

---

## 8. Corrected Test Strategy

### 8.1 Evidence Classification
To ensure scientific rigor, tests must state what is established experimentally versus what is guaranteed by source inspection:
- **Small-Fixture Round-Trip**: Verifies byte correctness; does **not** prove bounded-memory streaming.
- **Bounded-Memory Streaming**: Established by **source inspection** of `tokio::fs::File::from_std` (which executes incremental chunk reads on the threadpool without whole-file buffering).
- **FIFO Anti-Hang Safety**: Cannot be tested safely with async timeouts alone in the primary test process. If a thread blocks in `open()`, Tokio's test runner will hang indefinitely on shutdown. Requires **process isolation**.

### 8.2 Proposed Focused Test Plan
1. **Regular File Byte-for-Byte Streaming**:
   - Write known byte patterns to a fixture file.
   - Stream content in chunks; verify exact equality and EOF termination.
2. **Deterministic Pathname Replacement Test**:
   - Open target file in Phase 1 (`O_PATH`).
   - Before Phase 2, rename target file (`mv blob blob_old; echo "intruder" > blob`).
   - Execute Phase 2 (`/proc/self/fd/N`).
   - Verify that streamed content reflects the original `blob_old` payload, proving that Phase 2 is immune to pathname replacement races.
3. **Special Object Rejection Tests**:
   - Directory $\rightarrow$ Rejected as `UnsupportedObjectType`.
   - Symlinks (intermediate and final) $\rightarrow$ Rejected as `ResolutionRejected`.
4. **FIFO Anti-Hang Test (Process-Isolated)**:
   - Spawns a dedicated child process with an OS pipe and a parent-enforced deadline (e.g. 2 seconds).
   - Child creates a FIFO (`libc::mkfifo`) and attempts payload acquisition.
   - Parent asserts child completes within deadline with `UnsupportedObjectType`.
   - If child hangs, parent terminates child with `SIGKILL`, preventing test suite stall.
5. **Procfs Absence Simulation (Synthetic)**:
   - Verify error classification when procfs is unavailable or returns `ENOENT`.

---

## 9. Recommended Next Implementation Action: A Test-Only Acquisition Experiment

### 9.1 Rationale
Because the two-phase procfs reopen mechanism introduces environmental assumptions (procfs availability, namespace isolation, permissions), proceeding directly to public API expansion in `storage-core` and production changes in `registry-rust` is premature.

**Recommendation**: Execute a **narrow, test-only Linux acquisition experiment in `storage-fs`** as the immediate next slice (Slice 2C-exp).

### 9.2 Scope of Next Slice (Slice 2C-exp)
1. **Authorized Files in `storage-layer-rust`**:
   - `crates/storage-fs/Cargo.toml` (add `features = ["fs", "io-util"]` to `tokio` dependency with explanation).
   - `crates/storage-fs/src/reader.rs` (add private/internal `open_payload_sync` and experimental test harness).
   - `crates/storage-fs/README.md` (document experimental findings).
2. **Excluded Work**:
   - No modifications to `crates/storage-core` (contract changes remain deferred until acquisition is proven).
   - No modifications to `registry-rust`.
   - No public API additions.
3. **Questions Answered by the Experiment**:
   - Does `/proc/self/fd/N` reopening reliably succeed across standard container mount configurations?
   - Does deterministic pathname replacement between Phase 1 and Phase 2 reliably preserve original object identity?
   - Can FIFO objects be verified safely without risking threadpool hang?
4. **Verification Commands**:
   ```bash
   cargo fmt --check
   cargo check --locked -p storage-fs --all-targets
   cargo clippy --locked -p storage-fs --all-targets -- -D warnings
   cargo test --locked -p storage-fs --test reader -- --nocapture
   git diff --check
   ```
5. **Rollback & Safety**:
   - Changes are internal to `storage-fs` tests; rollback is instantaneous with zero blast radius to core contracts or registry.

---

## 10. Open Quality Gate Tracking

All existing quality gates retain their defined meanings and remain **OPEN**:
- **O-05 (Directory Containment)**: Remains open. Validating payload acquisition mechanics is a prerequisite for closing O-05.
- **O-03, O-06, O-13, O-16, D-06**: Downstream registry storage routing, key length enforcement, and security verification remain open.
