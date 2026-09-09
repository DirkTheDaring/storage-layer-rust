# Filesystem Payload Acquisition Experiment Findings

**Document Status**: Complete Experimental Findings (Test-Only Linux Slice)  
**Date**: 2026-09-09  
**Repository**: `storage-layer-rust`  
**Quality Gates Status**: Open (O-05, O-03, O-06, O-13, O-16, D-06 retain their original definitions and remain open)  
**Deliverable**: Bounded Linux test-only experiment for two-phase payload acquisition. No public API, commit, or push.

---

## 1. Executive Summary and Scope

This document records the findings and empirical observations of a bounded, test-only experiment implementing two-phase descriptor-relative payload acquisition under the Linux operating system.

### Purpose and Scope
The experiment investigates whether two-phase descriptor-relative resolution can reliably acquire regular-file payload descriptors under a pinned root directory without exposing the reader to uncontained pathname escapes, symlink traversal attacks, pathname-replacement races (TOCTOU), or blocking FIFO rendezvous.

### Key Constraints Followed
- **No Public API Additions**: All experimental acquisition helpers, error types, and tests are scoped as internal, test-only code under `crates/storage-fs/src/reader/payload_acquisition_experiment.rs`.
- **Target OS Exclusion**: All experimental code is gated behind `#[cfg(all(test, target_os = "linux"))]` and excluded from normal library compilation.
- **Synchronous Execution**: The experiment exercises synchronous `std::fs::File` descriptor acquisition and fixed-buffer consumption. Tokio stream conversions and async executor additions were excluded to focus strictly on the fundamental OS-level acquisition boundary.
- **Zero Modification to Baselines**: Manifests (`Cargo.toml`), lockfiles (`Cargo.lock`), `storage-core`, and `registry-rust` remain completely unchanged. Preserved architecture assessments and designs are kept unaltered.

---

## 2. Experimental Acquisition Mechanism and Syscall Flags

The acquisition sequence executes in two distinct phases against the reader's existing pinned root descriptor (`Arc<OwnedFd>`). The root pathname is never reopened or resolved anew.

```
+---------------------------------------------------------------------------------------------------+
| Phase 1: Bounded Resolution & Type Validation (O_PATH)                                           |
|                                                                                                   |
|  [root_fd] + [ObjectKey]                                                                         |
|      |                                                                                            |
|      v                                                                                            |
|  SYS_openat2(root_fd, key, flags=O_PATH|O_CLOEXEC, resolve=BENEATH|NO_SYMLINKS|NO_MAGICLINKS)    |
|      |                                                                                            |
|      +--> [res < 0] -------------> Err(Resolution { source })                                     |
|      |                                                                                            |
|      +--> [res >= 0] -> OwnedFd(phase1_fd)                                                        |
|                             |                                                                     |
|                             v                                                                     |
|                         fstat(phase1_fd)                                                          |
|                             |                                                                     |
|                             +--> [st_mode != S_IFREG] -> Err(UnsupportedObjectType { mode })      |
+---------------------------------------------------------------------------------------------------+
                                      |
                                      | (phase1_fd kept open; S_IFREG verified)
                                      v
+---------------------------------------------------------------------------------------------------+
| Phase 2: Readable Reopening & Identity Re-verification (procfs)                                  |
|                                                                                                   |
|  open("/proc/self/fd/{phase1_fd}", O_RDONLY|O_CLOEXEC)                                           |
|      |                                                                                            |
|      +--> [raw_fd < 0] -----------> Err(ReopenFailed { errno, source })                           |
|      |                                                                                            |
|      +--> [raw_fd >= 0] -> OwnedFd(readable_fd)                                                   |
|                                |                                                                  |
|                                v                                                                  |
|                            fstat(readable_fd)                                                     |
|                                |                                                                  |
|                                +--> [st2_mode != S_IFREG]        -> Err(ReopenNotRegularFile)     |
|                                +--> [st2_dev/ino != st1_dev/ino] -> Err(ReopenIdentityMismatch)   |
|                                |                                                                  |
|                                v                                                                  |
|                            Ok((ObjectMetadata, std::fs::File::from(readable_fd)))                |
|                            (phase1_fd dropped and closed automatically)                          |
+---------------------------------------------------------------------------------------------------+
```

### Phase 1: Containment and Type Inspection
1. **Syscall**: `libc::syscall(libc::SYS_openat2, root_fd.as_raw_fd(), c_rel.as_ptr(), &how, sizeof(open_how))`
2. **Flags**:
   - `how.flags = libc::O_PATH | libc::O_CLOEXEC`
   - `how.mode = 0`
   - `how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS`
3. **RAII Ownership**: The returned descriptor integer is immediately wrapped in `std::os::fd::OwnedFd`. No raw descriptors escape unmanaged.
4. **Validation**: `libc::fstat` is called on the `OwnedFd`. If `st_mode & S_IFMT != S_IFREG`, the call returns `AcquisitionExperimentError::UnsupportedObjectType { mode }` and drops the descriptor.
5. **Security Invariant**: No readable open (`O_RDONLY`) is ever attempted against non-regular objects (directories, symlinks, FIFOs, sockets, device nodes).

### Phase 2: Readable Descriptor Reopening
1. **Path Construction**: Formats `/proc/self/fd/{phase1_fd.as_raw_fd()}` as a null-terminated C string.
2. **Syscall**: `libc::open(proc_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)`.
3. **Descriptor Retention**: The Phase 1 `OwnedFd` remains allocated and open throughout the `open` call, ensuring the underlying open-file description and inode cannot be recycled during reopening.
4. **Reopen Error Classification**: If `open` returns `< 0`, the raw errno is captured. A Phase 2 `ENOENT` is classified as `AcquisitionExperimentError::ReopenFailed { errno: libc::ENOENT, source }`. It is **never** translated to a missing object (`ReadError::NotFound`) and **never** triggers a fallback to an uncontained pathname open.
5. **Identity & Regular-File Verification**:
   - The returned readable descriptor is immediately wrapped in an `OwnedFd`.
   - `libc::fstat` is invoked on the readable descriptor.
   - The descriptor is re-verified as `st_mode & S_IFMT == S_IFREG`.
   - Inode identity is asserted: `st_dev` and `st_ino` must match the Phase 1 descriptor exactly. Any mismatch returns `AcquisitionExperimentError::ReopenIdentityMismatch`.
6. **Delivery**: The verified readable `OwnedFd` is converted into an owned `std::fs::File::from(readable_fd)`. The Phase 1 `OwnedFd` goes out of scope and is closed cleanly.

---

## 3. New Open-File Description vs. Shared Object Identity

A crucial finding of this experiment concerns the Linux kernel distinction between file descriptors (`fd`), open-file descriptions (`struct file`), and filesystem inodes (`struct inode`).

1. **`dup` Cannot Upgrade Access**: Calling `libc::dup(phase1_fd)` or `fcntl(phase1_fd, F_DUPFD)` creates a new file descriptor pointing to the *exact same* kernel `struct file`. Because Phase 1 opened the object with `O_PATH`, the existing open-file description lacks `FMODE_READ`. The access mode of a `struct file` is immutable; `dup` cannot grant read permissions to an `O_PATH` description.
2. **Procfs Reopening Creates a New Open-File Description**: Reopening `/proc/self/fd/N` with `O_RDONLY` causes the kernel's procfs magiclink handler (`proc_pid_get_link`) to resolve to the target `struct dentry` and `struct inode`. The kernel then invokes the underlying filesystem's `file_operations->open` and allocates a *new* `struct file` with `FMODE_READ`, `f_pos = 0`, and independent flags.
3. **Shared Inode Identity**: Although the two open-file descriptions are distinct kernel objects, they reference the identical underlying `struct inode` on disk. This shared inode identity is verified by comparing `st_dev` and `st_ino`.

---

## 4. Ownership and RAII Cleanup on Every Failure Path

All descriptor resources are strictly governed by Rust's RAII ownership system. No manual `libc::close` is called on managed descriptors, preventing double-close races across threads.

| Execution Point | Failure Condition | Allocated Resources | RAII Cleanup Action |
| :--- | :--- | :--- | :--- |
| **Phase 1 Resolution** | `SYS_openat2` returns `< 0` | None | No descriptor allocated. Returns `Resolution`. |
| **Phase 1 Inspection** | `fstat` returns `< 0` | `phase1_fd: OwnedFd` | `phase1_fd` drops; closed by OS. Returns `Phase1Stat`. |
| **Phase 1 Type Check** | `st_mode != S_IFREG` | `phase1_fd: OwnedFd` | `phase1_fd` drops; closed by OS. Returns `UnsupportedObjectType`. |
| **Hook / Staging** | Panic or error during pause | `phase1_fd: OwnedFd` | `phase1_fd` drops during stack unwinding. |
| **Phase 2 Reopen** | `libc::open` returns `< 0` | `phase1_fd: OwnedFd` | `phase1_fd` drops; closed by OS. Returns `ReopenFailed`. |
| **Phase 2 Inspection** | `fstat` returns `< 0` | `phase1_fd`, `readable_fd` | Both `OwnedFd`s drop and close. Returns `Phase2Stat`. |
| **Phase 2 Type Check** | `st2_mode != S_IFREG` | `phase1_fd`, `readable_fd` | Both `OwnedFd`s drop and close. Returns `ReopenNotRegularFile`. |
| **Phase 2 Identity** | `st_dev`/`st_ino` mismatch | `phase1_fd`, `readable_fd` | Both `OwnedFd`s drop and close. Returns `ReopenIdentityMismatch`. |
| **Phase 2 Metadata** | Negative size (`st_size < 0`)| `phase1_fd`, `readable_fd` | Both `OwnedFd`s drop and close. Returns `InvalidMetadata`. |
| **Acquisition Success**| All checks pass | `phase1_fd`, `readable_fd` | `readable_fd` transferred to `std::fs::File`. `phase1_fd` drops and closes. |

---

## 5. Observed Results vs. Synthetic Tests and Assumptions

### A. Regular-File Acquisition
- **Observed Result**: Successfully resolved a 1024-byte regular file, extracted correct metadata (`size == 1024`), and incrementally consumed all bytes using fixed-size (64-byte) buffers until EOF (`read` returns 0).
- **Evidentiary Scope**: This demonstrates byte-level correctness and incremental consumption capability. It is **not** proof of an entire future async backend's memory behavior, concurrency limits, or backpressure characteristics under Tokio.

### B. Deterministic Pathname Replacement (TOCTOU Immunity)
- **Observed Result**: Pausing execution after Phase 1 validation using an explicit synchronous callback, the original file was renamed and replaced with a different file containing different contents at the original pathname. Reopening via `/proc/self/fd/N` deterministically opened the *original* file (yielding original bytes and original inode), completely unaffected by the replacement file at the old pathname.
- **Evidentiary Scope**: Avoids sleeps and timing races. Proves that reopening via `/proc/self/fd/N` binds to the open-file description's inode rather than re-resolving the pathname.

### C. Shared-Root Behavior
- **Observed Result**: The reader was constructed over a directory. The root directory was subsequently renamed and replaced by a new directory containing different payload bytes. Queries using the reader's pinned root descriptor resolved through the original directory descriptor, yielding original bytes.
- **Evidentiary Scope**: Confirms descriptor-relative containment is anchored to the kernel directory description, independent of subsequent pathname alterations in the parent filesystem.

### D. Rejection Before Readable Open
- **Observed Result**:
  - Directory (`S_IFDIR`): Phase 1 `fstat` detected non-regular mode; rejected with `UnsupportedObjectType`. Reopen stage was **not** reached.
  - Final Symlink (`link.txt -> target.txt`): Phase 1 `openat2` failed with `ELOOP` under `RESOLVE_NO_SYMLINKS`. Reopen stage was **not** reached.
  - Dangling Symlink (`dangling.txt -> nonexistent`): Phase 1 `openat2` failed with `ELOOP`. Reopen stage was **not** reached.
  - Intermediate Directory Symlink (`dir_link/file.txt`): Phase 1 `openat2` failed with `ELOOP`. Reopen stage was **not** reached.
  - FIFO with No Writer: Verified in an isolated child process with a parent-enforced 5-second deadline. Because `O_PATH` does not wait for a writer rendezvous, Phase 1 `openat2` returned immediately. `fstat` detected `S_IFIFO`; rejected with `UnsupportedObjectType`. Reopen stage was **not** reached. The child process completed in 0.00s and exited cleanly. The parent verified clean exit and cleaned up fixtures.
- **Evidentiary Scope**: Demonstrates that special filesystem objects are caught and rejected prior to any readable open. Running the FIFO test in a child process guarantees that any potential kernel hang would be terminated, reaped, and reported without hanging test harnesses.

### E. Synthetic Reopen Failures (Strictly Distinguished)
- **Synthetic Test**: Hook overrides were used to simulate Phase 2 `libc::open` returning `ENOENT`, `EACCES`, `EPERM`, and target inode identity mismatches.
- **Observed Result**: The helper correctly classified each as `ReopenFailed` (or `ReopenIdentityMismatch`) while preserving raw errno values (`libc::ENOENT`, `libc::EACCES`, `libc::EPERM`).
- **Explicit Boundary**: These synthetic tests verify error routing and raw errno preservation without uncontained fallbacks. They do **not** simulate an actual unmounted or permission-restricted procfs environment.

---

## 6. Trust Boundary and Procfs Limitations

### State of the Trust Boundary
The two-phase acquisition experiment assumes that the execution environment provides an authentic, accessible, and stable `/proc/self/fd` mount.
1. **Formatting Is Not Trust**: Formatting the string `/proc/self/fd/{raw_fd}` does **not** establish trust in procfs.
2. **Pre-Open Side Effects**: The post-open identity check (`st_dev`/`st_ino`) verifies that the reopened descriptor references the expected inode. However, this check occurs *after* the `libc::open` call has already executed. If `/proc` were compromised or pointed to an attacker-controlled filesystem, opening a substituted node could invoke driver-level open routines or kernel side effects that cannot be undone by subsequent rejection.
3. **Not Settled Production Policy**: Procfs trust and namespace configuration cannot be considered settled production policies based on this experiment.

### Host Inspection Record
The experiment was executed on the local development environment with the following observed parameters:
- **Host Kernel**: `Linux thor 7.1.13-200.fc44.x86_64 #1 SMP PREEMPT_DYNAMIC Wed Sep 2 13:58:38 UTC 2026 x86_64`
- **Procfs Mount Options**: `findmnt /proc` reports `TARGET=/proc SOURCE=proc FSTYPE=proc OPTIONS=rw,nosuid,nodev,noexec,relatime`
- **Descriptor Directory Permissions**: `ls -ld /proc/self/fd` reports mode `dr-x------` owned by user `dietmar`.
- **Environment Invariance**: No host mounts, namespaces, privileges, or device nodes were created or altered to run this experiment.
- **Untested Container Configurations**: Environments where `/proc` is unmounted, masked (e.g. read-only or masked proc in strict OCI containers), or where seccomp policies restrict procfs access were **not** tested; success in such configurations is not claimed.

---

## 7. Remaining Content-Mutation and Write-Root Divergence Risks

Even with descriptor-relative two-phase acquisition, the following risks remain unaddressed by the storage layer:
1. **Concurrent In-Place Content Mutation**: The acquired descriptor points directly to the file inode. While immune to pathname replacement (`rename`, `unlink`), it does not prevent concurrent in-place writes (`pwrite`, `ftruncate`) by other processes holding open write descriptors to the same inode. If a file is truncated while reading, subsequent reads may return EOF early or return mutated bytes without checksum invalidation.
2. **Write-Root Divergence**: If upstream writing or ingestion layers operate over ordinary pathnames or divergent directory roots while the reader holds a pinned root, directory hierarchy changes (e.g. moving a subdirectory) may cause readers and writers to see disparate namespaces.

---

## 8. Corrections to Previous Design Inaccuracies

The following inaccuracies identified in earlier design documentation are explicitly corrected here:

1. **Tokio `File` Feature Dependencies**: Tokio `File` does not require the `io-util` crate feature merely for construction. `tokio::fs::File::from_std` requires only the `fs` feature. Pinned dependency features must be verified directly against Tokio source when planning subsequent integration slices.
2. **Tokio `File` Concurrency Semantics**: Tokio `File` is `Send + Sync`. It is not an example of a necessarily non-`Sync` reader.
3. **Descriptor Cleanup Execution**: There is no blanket kernel or runtime promise regarding which thread executes descriptor cleanup upon drop. In async wrappers, drop may occur on worker threads or blocking pool threads; filesystems with delayed writeback or network flushes on `close` (e.g. NFS) can block the dropping thread.
4. **Syscall Latency with `O_PATH`**: While `O_PATH` avoids FIFO writer rendezvous, it does not guarantee that every filesystem operation finishes instantly. Underlying block device stalls, disk I/O latency, filesystem locking, and network timeouts can still cause `openat2` or `fstat` to block.
5. **Inactive `cfg` Branches**: An inactive `#[cfg(not(target_os = "linux"))]` branch is not compiled or typechecked on Linux unless `--target` is explicitly specified; it does not constitute target-specific compilation evidence.

---

## 9. Assessment and Proposed Next Steps

### Experimental Conclusion
The experiment demonstrates that:
1. Two-phase acquisition (`openat2(O_PATH)` -> `/proc/self/fd/N`) reliably prevents path-escape, symlink-traversal, and pathname-replacement races on Linux.
2. Special objects (FIFOs, directories, symlinks) are caught in Phase 1 before readable open, avoiding blocking open calls.
3. Error classification deterministically distinguishes resolution errors from procfs reopening failures, without converting reopen errors into missing objects or triggering uncontained fallbacks.

### Remaining Prerequisites Before Any Production Payload API
- Formal resolution of procfs availability and trust across target container deployment environments.
- Design of the async execution boundary: determining whether payload opening and stream reads occur via `tokio::task::spawn_blocking` or direct Tokio async primitives.
- Formulation of payload traits in `storage-core` (generic payload contracts remain proposed, not finalized).
- Addressing content immutability and write-layer integration.
- Quality gates (O-05, O-03, O-06, O-13, O-16, D-06) remain open and require explicit evaluation before committing production code.
