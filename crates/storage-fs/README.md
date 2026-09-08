# `storage-fs`

Standalone filesystem metadata reader implementing `storage_core::ObjectMetadataReader` over an owned, pinned directory descriptor.

## 1. Architectural Boundaries

- **`storage-core`**: Defines backend-neutral contracts (`ObjectKey`, `ObjectMetadata`, `ObjectMetadataReader`, `ReadError`).
- **`storage-fs`**: Implements kernel-enforced descriptor-relative lookup on Linux (`openat2`), pinning the storage root directory and inspecting metadata without opening payload streams.
- **`registry-rust`**: Retains quarantine fallback orchestration, repository and blob namespace routing, and outward HTTP/OCI API compatibility translation.

## 2. Constructor, Namespace, and Lookup Semantics

### Root Acquisition
- `FsMetadataReader::open(root_path: impl AsRef<Path>) -> Result<Self, FsMetadataError>`
- Opens an existing configured directory once with flags `O_DIRECTORY | O_PATH | O_CLOEXEC`.
- Does **not** create missing root directories.
- An initial symlink configured as root resolves once during initialization; the resulting directory descriptor (`std::os::fd::OwnedFd`) becomes the sole authority for all subsequent lookups.
- The configured pathname is **never** re-resolved during subsequent queries.

### Relative Namespace
- Each `ObjectKey` is interpreted strictly as a relative hierarchy beneath the pinned root.
- No digest parsing, aliases, normalization, or special handling of `blobs/`, `repos/`, or `quarantine/`.
- Syntax is validated by `ObjectKey` prior to any filesystem operation (rejecting empty input, leading/trailing/repeated slashes, `.`/`..` segments, backslashes, NUL, and control characters).

### Descriptor-Relative Lookup & Syscall Flags
- Path resolution uses Linux `openat2` beneath the pinned root directory descriptor:
  - `flags = O_PATH | O_CLOEXEC`
  - `resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`
- The resulting descriptor is immediately wrapped in `OwnedFd` to ensure deterministic RAII cleanup on all code paths.
- The descriptor is inspected via `fstat`:
  - Enforces `st_mode & S_IFMT == S_IFREG`. Rejects non-regular objects (directories, FIFOs, symlinks, sockets, devices) at the application level as `FsMetadataError::UnsupportedObjectType` without reading payloads or blocking.
  - Converts `st_size` safely to `u64`.

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

*Note on Error Sources*: The earlier in-tree experiment noted that every `OsError` came from a syscall; that statement was overly broad because negative-size conversion failure produces an application validation error. Here, genuine syscall errors and application-level validation rejections are cleanly distinguished.

## 4. Guarantees and Limitations

1. **Metadata-Only Inquiry**:
   - `O_PATH` metadata inspection queries file existence, object type, and size without opening the file for reading.
   - It does **not** prove that read permissions would be granted for payload streams (`O_RDONLY`), nor does it establish legacy permission semantics.
2. **Mount Crossings**:
   - `RESOLVE_BENEATH` does **not** prohibit mount crossings beneath the root.
   - `RESOLVE_NO_XDEV` is the separate Linux flag that disallows mount point traversal (including bind mounts); this crate does not enable it. Mount policy remains a later decision.
3. **Hard Links**:
   - Hard links inside the root pointing to external data share the same inode; `openat2` cannot eliminate hard-link aliasing.
4. **Concurrent Renaming**:
   - The kernel enforces lookup constraints during path resolution.
   - Root pinning binds all subsequent lookups to the originally acquired directory inode.
   - However, root pinning does not establish general immunity to every concurrent filesystem change: an opened object can subsequently be renamed outside the root by concurrent processes.
5. **Platform Support**:
   - Descriptor-relative containment requires Linux `openat2`.
   - If `openat2` returns `ENOSYS`, `storage-fs` fails closed with diagnostic `"openat2 is unavailable in this execution environment"`. It does not infer a host kernel version from `ENOSYS` alone, nor does it attempt an insecure path-based fallback.
   - On non-Linux platforms, operations fail explicitly with `FsMetadataError::PlatformUnsupported`. Non-Linux compilation and execution remain unverified in the absence of a cross-compilation toolchain.
6. **Open Quality Gates**:
   - Gate **O-05** remains **OPEN**: this crate implements an isolated metadata reader. Production registry integration, quarantine orchestration, outward HTTP compatibility, and distribution gates remain deferred.
