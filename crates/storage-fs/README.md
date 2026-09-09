# `storage-fs`

Standalone filesystem metadata reader implementing `storage_core::ObjectMetadataReader` over an owned, pinned directory descriptor.

## 1. Architectural Boundaries

- **`storage-core`**: Defines backend-neutral contracts (`ObjectKey`, `ObjectMetadata`, `ObjectMetadataReader`, `ReadError`).
- **`storage-fs`**: Implements kernel-enforced descriptor-relative lookup on Linux (`openat2`), pinning the storage root directory and inspecting metadata without opening payload streams. Executes blocking filesystem calls on Tokio's blocking thread pool.
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
- Async metadata inquiry (`head(&self, key: &ObjectKey)`) requires an **entered Tokio runtime**. If polled outside a Tokio runtime context, lookup fails immediately with typed `ReadError::Backend` wrapping `FsMetadataError::RuntimeMissing`.
- Potentially blocking filesystem operations (`openat2`, `fstat`) are offloaded to Tokio's blocking pool via `tokio::task::spawn_blocking`, ensuring the async caller's worker thread is never stalled by filesystem latency.
- Each blocking task holds an owned `Arc<OwnedFd>` reference to the pinned root directory descriptor and an owned, cloned `ObjectKey`.
- Join failures (e.g. blocking task panics or runtime cancellations) are awaited and mapped to `ReadError::Backend` wrapping `FsMetadataError::TaskJoinFailed` while preserving the underlying `tokio::task::JoinError`.

### Descriptor-Relative Lookup & Syscall Flags
- Path resolution inside the blocking task uses Linux `openat2` beneath the pinned root directory descriptor:
  - `flags = O_PATH | O_CLOEXEC`
  - `resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`
- The resulting descriptor is immediately wrapped in `OwnedFd` to ensure deterministic RAII cleanup on all code paths.
- The descriptor is inspected via `fstat`:
  - Enforces `st_mode & S_IFMT == S_IFREG`. Rejects non-regular objects (directories, FIFOs, symlinks, sockets, devices) at the application level as `FsMetadataError::UnsupportedObjectType` without reading payloads or blocking.
  - Converts `st_size` safely to `u64`.

### Startup Capability Probing (`probe_capability`)
- `FsMetadataReader::probe_capability(&self) -> Result<(), FsMetadataError>`
- **API Boundary**: Explicit public backend-specific API on `FsMetadataReader` with a private syscall implementation.
- **Execution Context**: Executes synchronously on the calling thread. It may block on filesystem operations and must **not** be called directly on an async executor worker thread.
- **No Automatic Invocation**: No automatic invocation from `open` or `head` is introduced; downstream registry startup invocation (e.g. in `FsStorage::try_new`) remains deferred.
- **Narrow Success Definition**: Success indicates narrowly that the exact `"."` `openat2` lookup with flags `O_PATH | O_DIRECTORY | O_CLOEXEC` and `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, followed by directory metadata inspection (`fstat`), succeeded against the pinned root directory descriptor on the calling thread at that time.
- **Immediate Cleanup**: The opened descriptor is immediately bound to `OwnedFd`, verified via `fstat` (`S_IFDIR`), and dropped immediately upon return, guaranteeing deterministic RAII closure.
- **Contract Distinction**: `"."` is rejected as an `ObjectKey` by design (`ObjectKeyError::DotSegment`). `probe_capability` is a backend-private syscall probe on `FsMetadataReader` that operates directly on the pinned raw descriptor via the C string `c"."`; it does **not** construct an `ObjectKey` or route through regular-file `head`.

## 3. Error Classification and Contract Mapping

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

1. **Metadata-Only Inquiry**:
   - `O_PATH` metadata inspection queries file existence, object type, and size without opening the file for reading.
   - It does **not** prove that read permissions would be granted for payload streams (`O_RDONLY`), nor does it establish legacy permission semantics.
2. **Cancellation and Lifecycle Semantics**:
   - Dropping or cancelling the awaiting future returned by `head` does **not** abort or stop blocking work that has already started on Tokio's blocking thread pool.
   - Owned task state (`Arc<OwnedFd>`) guarantees descriptor validity: even if the reader or caller future is dropped, the root descriptor remains valid until the in-flight blocking task completes, preventing `EBADF`.
   - Runtime shutdown and unresponsive filesystem stalls (e.g. hung network filesystems) retain standard blocking-task limitations; userspace cannot guarantee bounded syscall completion.
3. **Mount Crossings**:
   - `RESOLVE_BENEATH` does **not** prohibit mount crossings beneath the root.
   - `RESOLVE_NO_XDEV` is the separate Linux flag that disallows mount point traversal (including bind mounts); this crate does not enable it. Mount policy remains a later decision.
4. **Hard Links**:
   - Hard links inside the root pointing to external data share the same inode; `openat2` cannot eliminate hard-link aliasing.
5. **Concurrent Renaming**:
   - The kernel enforces lookup constraints during path resolution.
   - Root pinning binds all subsequent lookups to the originally acquired directory inode.
   - However, root pinning does not establish general immunity to every concurrent filesystem change: an opened object can subsequently be renamed outside the root by concurrent processes.
6. **Platform Support**:
   - Descriptor-relative containment requires Linux `openat2`.
   - If `openat2` returns `ENOSYS`, `storage-fs` fails closed with diagnostic `"openat2 is unavailable in this execution environment"`. It does not infer a host kernel version from `ENOSYS` alone, nor does it attempt an insecure path-based fallback.
   - On non-Linux platforms, operations fail explicitly with `FsMetadataError::PlatformUnsupported`. Non-Linux compilation and execution remain unverified in the absence of a cross-compilation toolchain.
7. **Capability Probe Guarantees and Limitations**:
   - **Narrow Scope of Success**:
     - Success establishes only that the exact `"."` `openat2` lookup with the specified containment flags and directory metadata inspection succeeded against the pinned root descriptor on the calling thread at that time.
   - **Properties NOT Established**:
     1. Does not establish equivalent permissions or syscall filtering on Tokio blocking-pool threads.
     2. Does not verify that child paths, subdirectories, or blobs exist or can be created.
     3. Does not exercise multi-component path resolution across nested subdirectories.
     4. Does not verify regular-file lookup (`S_IFREG`), because `"."` is a directory (`S_IFDIR`).
     5. Does not establish payload read permissions (`O_RDONLY`) or write permissions on child objects (`O_PATH` success is not proof of ordinary directory or file read/write permission).
     6. Does not establish root coherence across pathname-based reads and mutations.
     7. Does not establish future availability or guarantee against dynamic runtime reconfiguration (e.g. late seccomp filter installation, filesystem remounts, or storage media failures).
     8. Does not close quality gate **O-05** or establish production readiness.
   - **Syscall Availability Interpretation**:
     - If `openat2` returns `ENOSYS`, the probe reports `FsMetadataError::SyscallUnsupported`. It does not infer a specific kernel version from `ENOSYS` alone.
   - **Execution Context & Latency**:
     - Synchronous execution on the caller thread avoids requiring an entered Tokio runtime or thread pool dispatch during early application startup.
     - Limitation: because it is synchronous, if the root directory resides on an unresponsive or stalled network filesystem (NFS/FUSE), the calling startup thread can block indefinitely, identically to `FsMetadataReader::open`. It must not be called directly on an async executor worker thread.
8. **Open Quality Gates**:
   - Gate **O-05** remains **OPEN**: this crate implements an isolated metadata reader. Production registry integration, quarantine orchestration, outward HTTP compatibility, and distribution gates remain deferred.
