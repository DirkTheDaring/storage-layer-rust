# `storage-fs`

Standalone filesystem metadata and payload reader implementing `storage_core::ObjectMetadataReader` and `storage_core::ObjectPayloadReader` over an owned, pinned directory descriptor.

## 1. Architectural Boundaries

- **`storage-core`**: Defines backend-neutral contracts (`ObjectKey`, `ObjectMetadata`, `ObjectMetadataReader`, `ObjectPayload`, `ObjectPayloadReader`, `ObjectStream`, `ReadError`).
- **`storage-fs`**: Implements kernel-enforced descriptor-relative lookup on Linux (`openat2`), pinning the storage root directory and inspecting metadata or acquiring payload streams without uncontained pathname fallback. Executes blocking filesystem calls on Tokio's blocking thread pool.
- **`registry-rust`**: Retains quarantine fallback orchestration, repository and blob namespace routing, and outward HTTP/OCI API compatibility translation.

## 2. Constructor, Namespace, and Lookup Semantics

### Root Acquisition
- `FsMetadataReader::open(root_path: impl AsRef<Path>) -> Result<Self, FsMetadataError>`
- Remains **synchronous** and performs root acquisition on the caller thread.
- Opens an existing configured directory once with flags `O_DIRECTORY | O_PATH | O_CLOEXEC`.
- Does **not** create missing root directories.
- An initial symlink configured as root resolves once during initialization; the resulting directory descriptor (`std::os::fd::OwnedFd`) is wrapped in an `Arc` and becomes the sole authority for all subsequent lookups.
- The configured pathname is **never** re-resolved during subsequent queries.
- Opening with `O_PATH` does not issue `openat2`; therefore, successful constructor execution does **not** establish `openat2` kernel availability.

### Relative Namespace
- Each `ObjectKey` is interpreted strictly as a relative hierarchy beneath the pinned root.
- No digest parsing, aliases, normalization, or special handling of `blobs/`, `repos/`, or `quarantine/`.
- Syntax is validated by `ObjectKey` prior to any filesystem operation (rejecting empty input, leading/trailing/repeated slashes, `.`/`..` segments, backslashes, NUL, and control characters).

### Internal Blocking Execution Boundary (`tokio::task::spawn_blocking`)
- Async metadata inquiry (`head(&self, key: &ObjectKey)`) and payload opening (`open_payload(&self, key: &ObjectKey)`) require an **entered Tokio runtime**. If polled outside a Tokio runtime context, lookup fails immediately with typed `ReadError::Backend` wrapping `FsMetadataError::RuntimeMissing`.
- Potentially blocking filesystem operations (`openat2`, `fstat`, `/proc/self/fd` reopening) are offloaded to Tokio's blocking pool via `tokio::task::spawn_blocking` to avoid stalling the caller's worker thread during initial descriptor acquisition. However, callers are not guaranteed that asynchronous tasks or worker threads will never experience filesystem latency, such as during stream polling, runtime task scheduling, or resource teardown.
- Each blocking task holds an owned `Arc<OwnedFd>` reference to the pinned root directory descriptor and an owned, cloned `ObjectKey`.
- Join failures (e.g. blocking task panics or runtime cancellations) are awaited and mapped to `ReadError::Backend` wrapping `FsMetadataError::TaskJoinFailed` while preserving the underlying `tokio::task::JoinError`.

### Descriptor-Relative Metadata Lookup & Syscall Flags
- Path resolution inside the blocking task uses Linux `openat2` beneath the pinned root directory descriptor:
  - `flags = O_PATH | O_CLOEXEC`
  - `resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`
- The resulting descriptor is immediately wrapped in `OwnedFd` to ensure deterministic RAII cleanup on all code paths.
- The descriptor is inspected via `fstat`:
  - Enforces `st_mode & S_IFMT == S_IFREG`. Rejects non-regular objects (directories, FIFOs, symlinks, sockets, devices) at the application level as `FsMetadataError::UnsupportedObjectType` without reading payloads or blocking.
  - Converts `st_size` safely to `u64`.

### Two-Phase Payload Acquisition (`open_payload`)
Payload stream acquisition executes inside a single Tokio blocking task in two synchronous stages:
1. **Phase 1: Contained Resolution & Type Validation**:
   - Resolves `key` relative to the pinned `root_fd` using `openat2` with `O_PATH | O_CLOEXEC` and containment flags `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
   - The returned descriptor is immediately wrapped in an `OwnedFd`.
   - `fstat` verifies that `st_mode & S_IFMT == S_IFREG`. Non-regular objects (directories, symlinks, FIFOs, sockets, device nodes) are rejected before any readable open.
2. **Phase 2: Readable Reopening & Identity Verification**:
   - While retaining the Phase 1 `OwnedFd`, `/proc/self/fd/{phase1_fd}` is opened with `O_RDONLY | O_CLOEXEC`.
   - The resulting readable descriptor is immediately wrapped in an `OwnedFd`.
   - `fstat` verifies that the readable descriptor is a regular file (`S_IFREG`) and matches the `st_dev` and `st_ino` observed in Phase 1.
   - `st_size` is validated to be non-negative and converted to `u64` without narrowing.
   - Returns an owned `std::fs::File` and `ObjectMetadata`.
3. **Async Conversion**:
   - Upon successful blocking task completion, the `std::fs::File` is converted into `tokio::fs::File::from_std(file)`, boxed, and pinned as `ObjectStream: Pin<Box<dyn AsyncRead + Send + 'static>>`.
   - Paired with `ObjectMetadata` into an `ObjectPayload`.
   - Stream consumption is decoupled from the reader and key lifetimes.

### Startup Capability Probing (`probe_capability`)
- `FsMetadataReader::probe_capability(&self) -> Result<(), FsMetadataError>`
- **API Boundary**: Explicit public backend-specific API on `FsMetadataReader` with a private syscall implementation.
- **Execution Context**: Executes synchronously on the calling thread. It may block on filesystem operations and must **not** be called directly on an async executor worker thread.
- **No Automatic Invocation**: No automatic invocation from `open`, `head`, or `open_payload` is introduced; downstream registry startup invocation remains deferred.
- **Narrow Success Definition**: Success indicates narrowly that the exact `"."` `openat2` lookup with flags `O_PATH | O_DIRECTORY | O_CLOEXEC` and `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, followed by directory metadata inspection (`fstat`), succeeded against the pinned root directory descriptor on the calling thread at that time.
- **Immediate Cleanup**: The opened descriptor is immediately bound to `OwnedFd`, verified via `fstat` (`S_IFDIR`), and dropped immediately upon return, guaranteeing deterministic RAII closure.
- **Contract Distinction**: `"."` is rejected as an `ObjectKey` by design (`ObjectKeyError::DotSegment`). `probe_capability` is a backend-private syscall probe on `FsMetadataReader` that operates directly on the pinned raw descriptor via the C string `c"."`; it does **not** construct an `ObjectKey` or route through regular-file `head`.

## 3. Error Classification and Contract Mapping

### Metadata Inquiry (`head`) Error Mapping

| Filesystem Condition | Underlying Cause | `storage-core` Contract Mapping | Error Category & Source |
| :--- | :--- | :--- | :--- |
| **Object Missing** | `openat2` returns `ENOENT` | `ReadError::NotFound { key }` | Genuine OS `ENOENT`. |
| **Permission Denial** | `openat2` or `fstat` returns `EACCES` or `EPERM` | `ReadError::PermissionDenied { key, source }` | Authentic OS permission failure boxed as `source`. |
| **Resolution Rejected** | `openat2` returns `ELOOP` (symlink) or `EXDEV` (boundary escape) | `ReadError::Backend { message, source }` | `source` wraps `FsMetadataError::ResolutionRejected`. Never mapped to `NotFound`. |
| **Unsupported Object Type** | Opened object is non-regular (`S_IFDIR`, `S_IFIFO`, `S_IFLNK`, etc.) | `ReadError::Backend { message, source }` | Source-free application-level rejection wrapping `FsMetadataError::UnsupportedObjectType`. |
| **Syscall Unavailable** | `openat2` returns `ENOSYS` | `ReadError::Backend { message, source }` | `source` wraps `FsMetadataError::SyscallUnsupported`. Diagnostic message: `"openat2 is unavailable in this execution environment"`. |
| **Invalid Metadata** | Negative `st_size` or size conversion failure | `ReadError::Backend { message, source }` | Application validation error wrapping `FsMetadataError::InvalidMetadata`. |
| **Ordinary I/O Error** | Other raw OS error (e.g. `EIO`) | `ReadError::Backend { message, source }` | `source` wraps causal `std::io::Error`. |
| **Missing Runtime** | Polled outside an entered Tokio runtime | `ReadError::Backend { message, source }` | `source` wraps `FsMetadataError::RuntimeMissing`. Diagnostic message: `"tokio runtime required to execute blocking metadata lookup"`. |
| **Task Join Failure** | Blocking task panicked or cancelled during shutdown | `ReadError::Backend { message, source }` | `source` wraps `FsMetadataError::TaskJoinFailed`. Causal `tokio::task::JoinError` preserved. |

### Payload Acquisition (`open_payload`) Error Mapping

| Acquisition Condition | Underlying Cause | `storage-core` Contract Mapping | Error Category & Source |
| :--- | :--- | :--- | :--- |
| **Object Missing** | Phase 1 `openat2` returns `ENOENT` | `ReadError::NotFound { key }` | Genuine OS `ENOENT`. |
| **Resolution Permission Denial** | Phase 1 `openat2` returns `EACCES` or `EPERM` | `ReadError::PermissionDenied { key, source }` | Authentic OS permission failure boxed as `source`. |
| **Resolution Rejected** | Phase 1 `openat2` returns `ELOOP` or `EXDEV` | `ReadError::Backend { message, source }` | `source` wraps `FsMetadataError::ResolutionRejected`. Never mapped to `NotFound`. |
| **Unsupported Object Type** | Phase 1 or Phase 2 object is non-regular | `ReadError::Backend { message, source }` | `source` wraps `FsMetadataError::UnsupportedObjectType`. |
| **Phase 1 Stat Failure** | Phase 1 `fstat` fails | `ReadError::Backend { message, source }` | `source` wraps `FsMetadataError::StatFailed { stage: "Phase 1 contained", source }`. |
| **Procfs Reopen Failure** | Opening `/proc/self/fd/N` fails (e.g. procfs unavailable, `ENOENT`, `EACCES`, `EPERM`) | `ReadError::Backend { message, source }` | `source` wraps `FsMetadataError::ProcfsReopenFailed { source }`. Phase 2 `ENOENT` is **never** mapped to `NotFound`; Phase 2 permission errors are **never** mapped to `PermissionDenied`. |
| **Phase 2 Stat Failure** | Phase 2 `fstat` fails | `ReadError::Backend { message, source }` | `source` wraps `FsMetadataError::StatFailed { stage: "Phase 2 readable", source }`. |
| **Identity Mismatch** | Reopened descriptor `st_dev` or `st_ino` differs from Phase 1 | `ReadError::Backend { message, source }` | `source` wraps `FsMetadataError::IdentityMismatch`. |
| **Syscall Unavailable** | Phase 1 `openat2` returns `ENOSYS` | `ReadError::Backend { message, source }` | `source` wraps `FsMetadataError::SyscallUnsupported`. |
| **Invalid Metadata** | Negative `st_size` or size conversion failure | `ReadError::Backend { message, source }` | `source` wraps `FsMetadataError::InvalidMetadata`. |
| **Missing Runtime** | Polled outside an entered Tokio runtime | `ReadError::Backend { message, source }` | `source` wraps `FsMetadataError::RuntimeMissing`. Diagnostic message: `"tokio runtime required to execute blocking payload acquisition"`. |
| **Task Join Failure** | Blocking task panicked or cancelled during shutdown | `ReadError::Backend { message, source }` | `source` wraps `FsMetadataError::TaskJoinFailed`. |
| **Subsequent Stream Error** | Stream read failure after acquisition completes | `std::io::Error` | Delivered directly through `tokio::io::AsyncRead`, never mapped to `ReadError`. |

### Capability Probe Error Classification

`probe_capability` maps raw OS errors directly to strongly typed [`FsMetadataError`](src/error.rs) variants using operation-specific classification:

| Probe Condition | Syscall Outcome | `FsMetadataError` Mapping | Diagnostic Semantics |
| :--- | :--- | :--- | :--- |
| **Success** | `openat2` returns valid fd | `Ok(())` | Descriptor validated as directory and closed immediately. |
| **Syscall Unavailable** | `openat2` returns `ENOSYS` | `FsMetadataError::SyscallUnsupported(err)` | Host kernel returned `ENOSYS` for `openat2(2)`. |
| **Probe Denied** | `openat2` returns `EACCES` or `EPERM` | `FsMetadataError::ProbeDenied(err)` | Denied by DAC, LSM, mount flags, or container seccomp filter (seccomp is not inferred as unique cause). |
| **Unexpected I/O Failure** | Other `openat2` error (`EMFILE`, `EIO`, etc.) or any `fstat` failure | `FsMetadataError::ProbeFailed { source }` | Underlying I/O error preserved. (Note: `fstat` failures, including `ENOSYS`, map to `ProbeFailed`, not `SyscallUnsupported`). |
| **Unsupported Object Type** | Descriptor mode is not `S_IFDIR` | `FsMetadataError::UnsupportedObjectType { mode }` | Root descriptor did not stat as a directory. |
| **Unsupported Platform** | Target platform is not Linux | `FsMetadataError::PlatformUnsupported` | Descriptor-relative containment requires Linux `openat2`. |

## 4. Guarantees and Limitations

1. **Metadata vs. Payload Acquisition**:
   - `head` inspects metadata via `O_PATH` without opening readable file handles or verifying read permissions.
   - `open_payload` uses two-phase acquisition: Phase 1 contained resolution (`O_PATH`) and type validation, followed by Phase 2 readable reopening (`O_RDONLY`) via `/proc/self/fd/N`.
2. **Explicit Procfs Trust Assumption**:
   - Supported only under the documented assumption that `/proc/self/fd` is genuine, accessible, and stable during acquisition.
   - Formatting a descriptor pathname does not verify procfs authenticity.
   - The post-open `st_dev`/`st_ino` identity check detects target substitutions, but cannot prevent kernel side effects that occur during the `open` call itself if `/proc` were compromised or attacker-controlled.
   - Procfs trust and availability are prerequisites for any future registry cutover.
3. **Same-Object Identity vs. Immutable Content**:
   - The Phase 2 identity verification ensures that the readable descriptor points to the identical inode (`st_dev` and `st_ino`) verified during Phase 1.
   - This identity check does **not** guarantee immutable content or agreement between separate `head` and `open_payload` calls under concurrent backend modification, truncation, or replacement.
4. **Shared Root Ownership**:
   - The pinned `Arc<OwnedFd>` is shared across all metadata and payload operations.
   - Lookups remain tied to the originally opened root directory inode even if the root pathname is moved, renamed, or unlinked.
   - However, shared root ownership does not solve pathname-based writes, concurrent uncontained mutations, or deduplication divergence.
5. **Decoupled Stream Lifecycle & Deferred Closure**:
   - The returned `ObjectPayload` and its inner stream own their file descriptors independently of the `FsMetadataReader` and `ObjectKey`. Dropping the reader or key leaves in-flight streams fully operational, provided their required Tokio runtime remains active.
   - Outstanding I/O operations can retain the underlying file handle and delay descriptor closure; no particular cleanup thread or instantaneous descriptor release is guaranteed upon stream drop.
6. **Cancellation and Lifecycle Semantics**:
   - Dropping or cancelling the awaiting future returned by `head` or `open_payload` does **not** abort or interrupt blocking work already in flight on Tokio's blocking thread pool.
   - Owned task state (`Arc<OwnedFd>`) guarantees descriptor validity: the descriptors remain open until the in-flight task completes, preventing `EBADF` or premature reuse.
7. **Mount Crossings & Hard Links**:
   - `RESOLVE_BENEATH` does **not** prohibit mount crossings beneath the root (disallowing mount crossings requires `RESOLVE_NO_XDEV`, which is not enabled).
   - Hard links pointing to data inside or outside the root share the same inode; `openat2` cannot eliminate hard-link aliasing.
8. **Platform Support**:
   - Descriptor-relative containment requires Linux `openat2`.
   - If `openat2` returns `ENOSYS`, `storage-fs` fails closed with diagnostic `"openat2 is unavailable in this execution environment"`.
   - On non-Linux platforms, operations fail explicitly with `FsMetadataError::PlatformUnsupported`. Non-Linux compilation and execution remain unverified in the absence of a cross-compilation toolchain.
9. **Capability Probe Guarantees and Limitations**:
   - **Narrow Scope of Success**:
     - Success establishes only that the exact `"."` `openat2` lookup with the specified containment flags and directory metadata inspection succeeded against the pinned root descriptor on the calling thread at that time.
   - **Properties NOT Established**:
     1. Does not establish equivalent permissions or syscall filtering on Tokio blocking-pool threads or future worker threads.
     2. Does not verify that child paths, subdirectories, or blobs exist or can be created.
     3. Does not exercise multi-component path resolution across nested subdirectories.
     4. Does not verify regular-file lookup (`S_IFREG`), because `"."` is a directory (`S_IFDIR`).
     5. Does not establish payload read permissions (`O_RDONLY`) or write permissions on child objects (`O_PATH` success is not proof of ordinary directory or file read/write permission).
     6. Does not establish root coherence across pathname-based reads and mutations.
     7. Does not establish future availability or guarantee against dynamic runtime reconfiguration (e.g. late seccomp filter installation, filesystem remounts, or storage media failures).
     8. Does not close quality gate **O-05** or establish production readiness.
10. **Open Quality Gates**:
   - Quality gates **O-05**, **O-03**, **O-06**, **O-13**, **O-16**, and **D-06** remain **OPEN**: this crate implements standalone metadata and payload reader ports. Registry callers, production routing, range reads, seeking, directory listings, mutations, quarantine integration, and production cutover are not authorized in this slice.
