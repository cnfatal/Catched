# Procfs Scanning

> Detects injected code, hidden processes, and tampered system state by reading virtual filesystem entries under /proc/ that the kernel exposes and userspace cannot fully suppress.

---

## Overview

The Linux procfs (`/proc/`) is a virtual filesystem maintained entirely by the kernel, providing a real-time view of process state, memory layout, network connections, thread information, and security attributes. Each entry is generated dynamically by the kernel when read, meaning the data reflects the actual kernel-level state of the process rather than any userspace abstraction. Injected code — whether shared libraries, hook frameworks, or debugging agents — inevitably modifies kernel-visible state: new memory mappings appear in `/proc/self/maps`, new threads appear in `/proc/self/task/`, new sockets appear in `/proc/net/tcp`, and new mount points appear in `/proc/self/mountinfo`.

From a defender's perspective, procfs is the most information-rich data source available without kernel privileges. While attackers can hook the libc functions used to read procfs, the underlying kernel data structures remain intact. When procfs reads are performed via SVC direct syscalls, the defender obtains unfiltered kernel-level truth about the process environment, making procfs scanning one of the most reliable detection foundations.

---

## Injection Side

### How Attackers Use This Technique

1. **Inject shared library into target process** — The attacker uses ptrace, zygote hooking, or LD_PRELOAD to load a shared library (`.so`) into the target process address space. This creates new memory mappings visible in `/proc/self/maps`.
2. **Spawn worker threads** — The injected code creates threads for its runtime (e.g., JavaScript engine, RPC listener, garbage collector). These threads appear in `/proc/self/task/` with characteristic names in their `comm` file.
3. **Open network listeners** — The injected agent opens TCP or Unix domain sockets for communication. These appear in `/proc/net/tcp` and `/proc/net/unix`.
4. **Mount overlay filesystems** — Root management tools use OverlayFS or bind mounts to hide or replace system files. These mounts appear in `/proc/self/mountinfo` and `/proc/mounts`.
5. **Modify SELinux context** — Some injection frameworks change the process SELinux label. This is visible in `/proc/self/attr/current`.

### Artifacts

| Artifact                        | Location                  | Indicator                                                                                                       |
| ------------------------------- | ------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Injected shared library mapping | `/proc/self/maps`         | Library path containing agent names or unexpected `.so` files in writable directories                           |
| Anonymous executable memory     | `/proc/self/maps`         | `rwxp` or `r-xp` anonymous mappings at unusual addresses (injected code without file backing)                   |
| Hidden ELF headers              | `/proc/self/maps`         | `rw-p` anonymous pages containing ELF magic bytes (`\x7fELF`) — code disguised as data                          |
| Worker thread names             | `/proc/self/task/*/comm`  | Thread names like `gmain`, `gdbus`, `gum-js-loop`, `pool-frida`, or similar patterns                            |
| TCP listener on known ports     | `/proc/net/tcp`           | Local address with hex port `69A2` (27042) or `69A3` (27043)                                                    |
| Unix domain socket              | `/proc/net/unix`          | Socket path containing injection framework identifiers                                                          |
| Overlay/bind mount              | `/proc/self/mountinfo`    | Mount entries with `magisk` keyword or unexpected OverlayFS layers over `/system`                               |
| TracerPid non-zero              | `/proc/self/status`       | `TracerPid` field > 0 indicates another process is ptrace-attached                                              |
| SELinux context anomaly         | `/proc/self/attr/current` | Context string containing unexpected domain labels (e.g., `zygisk`, `magisk`)                                   |
| Open file descriptors           | `/proc/self/fd/*`         | Symlinks pointing to pipes, sockets, or files associated with injection agents                                  |
| Seccomp filter active           | `/proc/self/status`       | `Seccomp:` field = 2 (SECCOMP_MODE_FILTER) — attacker installed BPF filter for syscall interception             |
| Seccomp filter count            | `/proc/self/status`       | `Seccomp_filters:` field > 0 (Linux 5.10+) — number of installed BPF programs                                   |
| Capability anomaly              | `/proc/self/status`       | `CapEff:` / `CapPrm:` fields differ from untampered baseline — elevated capabilities after privilege escalation |
| Inode inconsistency in maps     | `/proc/self/maps`         | Inode in maps entry does not match `stat()` of the backing file — file replaced or bind-mounted                 |

### Injection PoC _(optional)_

```pseudocode
// Attacker injects a shared library that creates detectable procfs artifacts

step_1: inject("agent.so") into target process via ptrace or zygote hook
step_2: agent.so spawns threads: "gum-js-loop", "gmain", "gdbus"
step_3: agent.so opens TCP listener on port 27042
step_4: agent.so maps anonymous RWX pages for JIT-compiled JavaScript

// Result: /proc/self/maps shows agent.so and anon RWX pages
//         /proc/self/task/*/comm shows gum-js-loop, gmain
//         /proc/net/tcp shows 0.0.0.0:69A2 LISTENING
```

### Evasion Techniques

| Evasion                    | Description                                                                                                      |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Hook libc read/open        | Intercept `open()` and `read()` calls for `/proc/` paths, return filtered content that omits incriminating lines |
| Rename threads             | Change thread `comm` to innocuous names (e.g., rename `gum-js-loop` to `AsyncTask #1`)                           |
| Unmap after initialization | Unmap the injected `.so` from memory after initialization, leaving only anonymous pages                          |
| Close listener ports       | Use the injection agent in connect-back mode instead of listen mode, avoiding visible listening ports            |
| memfd_create               | Load code from anonymous file descriptors that show as `/memfd:` entries rather than filesystem paths            |
| SELinux context spoofing   | Reset the SELinux context to the expected domain label after injection                                           |

---

## Detection Side

### Mechanism

The invariant is that every memory mapping, thread, socket, and mount in a process is tracked by the kernel and exposed via procfs regardless of userspace manipulations. Even if an injected library unhooks itself, unmaps its file-backed pages, or renames its threads, residual artifacts remain: anonymous executable pages still exist, TCP sockets in TIME_WAIT linger, and dex elements persist in the ClassLoader. The kernel faithfully reports all of these via the `/proc/` virtual filesystem. When reads are performed via SVC direct syscalls, userspace hooks on `open()` / `read()` are entirely bypassed.

### Anti-Evasion Properties

| Property                    | Explanation                                                                                                                                  |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Resistant to libc hooks     | When procfs reads use SVC wrappers, no libc function is called; hooked `open`/`read` are never invoked                                       |
| Resistant to GOT/PLT hijack | SVC-based file operations bypass the PLT entirely                                                                                            |
| Kernel-sourced data         | Procfs entries are generated by the kernel on each read; userspace cannot modify kernel data structures without a kernel module              |
| Multi-signal correlation    | Combining maps + threads + sockets + mounts provides redundant detection — evading all signals simultaneously is extremely difficult         |
| Remaining bypass surface    | Kernel-level hooks (LKM) can filter procfs output; some artifacts can be removed if the attacker unmaps and cleans up before scanning occurs |

### Detection Strategy

1. **Open procfs files via SVC** — Use `svc_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0)` and similar SVC-wrapped calls to open each procfs entry. This ensures no userspace hook intercepts the open.
2. **Read and buffer contents via SVC** — Use `svc_read()` to read the file contents into a stack-allocated or mmap'd buffer. Avoid heap allocation if the allocator may be hooked.
3. **Parse /proc/self/maps** — For each line, extract the permission flags and pathname. Flag entries with:
   - Execute permission (`x`) in anonymous mappings (no pathname)
   - Pathnames containing known injected library name patterns
   - `rw-p` anonymous pages containing ELF magic bytes (read first 4 bytes of each suspicious page)
4. **Parse /proc/self/task/\*/comm** — Enumerate all task directories, read each `comm` file, compare against known injected thread name patterns.
5. **Parse /proc/net/tcp** — For each line in LISTEN state (state `0A`), extract the local port (hex field). Compare against known agent ports (`69A2`, `69A3`).
6. **Parse /proc/net/unix** — Search socket paths for known injection framework socket name patterns.
7. **Parse /proc/self/mountinfo** — Search for OverlayFS entries or entries with `magisk` in the mount source or filesystem type.
8. **Read /proc/self/status** — Extract `TracerPid` field; if non-zero, a debugger is attached.
9. **Check Seccomp fields in /proc/self/status** — Extract the `Seccomp:` field value. If it equals 2 (`SECCOMP_MODE_FILTER`), a BPF filter is active that can intercept any SVC-based detection. On Linux 5.10+ (Android 12+), also check `Seccomp_filters:` for the count of installed programs. A clean Zygote-forked process should have `Seccomp: 2` with exactly the Android system filter count (typically 1); additional filters indicate injection. See [seccomp-bpf-detection.md](seccomp-bpf-detection.md) for full detection.
10. **Check capability fields in /proc/self/status** — Read `CapEff:` and `CapPrm:` fields. A normal app process should have null (0000000000000000) effective and permitted capabilities. Non-zero values suggest privilege escalation via root exploit or capability injection. Compare against a baseline captured at process startup.
11. **Validate inode consistency for mapped files** — For each file-backed entry in `/proc/self/maps`, extract the inode from the maps line (field 5). Then `stat()` the backing file path (via SVC `newfstatat`) and compare the st_ino. A mismatch indicates the file was replaced after mapping (e.g., OverlayFS bind mount or library hot-swap). This catches attacks that replace system libraries with hooked versions.
12. **Read /proc/self/attr/current** — Check SELinux context for unexpected domain labels.
13. **Enumerate /proc/self/fd/** — Use `svc_readlinkat()` on each fd entry; flag file descriptors pointing to suspicious pipes, deleted files, or agent-related paths.

### Detection PoC _(optional)_

```pseudocode
// Scan /proc/self/maps for injected shared libraries and suspicious anonymous pages
fd = svc_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0)
data = svc_read(fd, buffer, MAX_SIZE)
svc_close(fd)

for each line in data:
    parse(line) -> addr_start, addr_end, perms, offset, dev, inode, pathname

    // Check 1: known injected library names in pathname
    if pathname contains SUSPICIOUS_PATTERNS:
        flag("injected_library", pathname)

    // Check 2: anonymous executable memory
    if pathname is empty AND perms contains 'x':
        flag("anonymous_executable", addr_start)

    // Check 3: hidden ELF in non-executable anonymous pages
    if pathname is empty AND perms == "rw-p":
        page_header = svc_read_memory(addr_start, 4)
        if page_header == "\x7fELF":
            flag("hidden_elf", addr_start)

// Scan /proc/net/tcp for known agent ports
fd = svc_openat(AT_FDCWD, "/proc/net/tcp", O_RDONLY, 0)
data = svc_read(fd, buffer, MAX_SIZE)
svc_close(fd)

for each line in data:
    if state == "0A":  // LISTEN
        port = parse_hex_port(local_address)
        if port in [0x69A2, 0x69A3]:
            flag("agent_listener", port)
```

### False Positive Risks

| Scenario                                                                | Mitigation                                                                                                                                                   |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Legitimate apps using anonymous executable pages (JIT engines, WebView) | Cross-reference with known legitimate JIT regions (e.g., ART JIT code cache has predictable address range); only flag pages outside expected ranges          |
| Thread names colliding with patterns (e.g., app uses "main" thread)     | Use exact-match patterns rather than substring matches; combine thread name detection with other signals                                                     |
| Debug builds with TracerPid set by Android Studio                       | Check `ro.debuggable` system property; suppress TracerPid warnings in debug builds                                                                           |
| VPN apps creating /proc/net/tcp entries on unusual ports                | Verify the listening address is `0.0.0.0` or `127.0.0.1` and correlate with maps-based detection                                                             |
| System apps with legitimate OverlayFS mounts (RRO)                      | Only flag OverlayFS mounts that overlay `/system` partitions with sources outside expected OEM paths                                                         |
| System seccomp policy active by default                                 | Android applies a system seccomp policy at Zygote fork; detect filter count exceeding the baseline (typically 1) rather than mere presence of seccomp mode 2 |
| Library inode changing after system OTA update                          | OTA updates may replace libraries, causing inode mismatch for running processes; re-baseline after detecting a newly booted state                            |

---

## References

- [Linux kernel procfs documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html)
- [proc(5) man page — /proc filesystem](https://man7.org/linux/man-pages/man5/proc.5.html)
- [Understanding /proc/self/maps format](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html)
- [Android process security — SELinux contexts](https://source.android.com/docs/security/features/selinux)
