# Memory Pattern Scan

> Scans process memory regions for byte-level signatures and structural anomalies indicative of injected code, by enumerating `/proc/self/maps` and reading anonymous memory content directly.

---

## Overview

Memory Pattern Scan works by parsing `/proc/self/maps` to build a complete map of all virtual memory regions in the current process, then directly reading the content of specific regions to search for known byte signatures associated with injection frameworks. The technique targets anonymous memory mappings — regions with no backing file — because injected code is frequently loaded into such mappings to avoid appearing as a named shared library. Beyond simple string matching, the technique also performs structural analysis: detecting anonymous executable segments that indicate code loaded outside the normal dynamic linker, verifying that `/memfd:jit-cache` segments have the expected count, and identifying hidden ELF binaries in non-executable anonymous regions.

From a defender's perspective, memory pattern scanning is essential because it operates on ground truth — the actual bytes present in process memory. While an attacker can strip library names from `/proc/self/maps` or modify file paths, the injected code itself must be present and readable in memory to function. This makes memory-resident signatures significantly harder to erase than filesystem or procfs artifacts.

---

## Injection Side

### How Attackers Use This Technique

1. **Inject shared library into target process** — The injection framework loads its agent library into the target process via `ptrace`, `/proc/<pid>/mem` writes, or linker namespace manipulation.
2. **Map code as anonymous memory** — To avoid detection via `/proc/self/maps` filename scanning, the injected library is mapped using `memfd_create` or `mmap` with `MAP_ANONYMOUS`, so no file path appears in the maps listing.
3. **Execute injected code** — The injected code runs within the target process, performing hooking, instrumentation, or data exfiltration. Known frameworks embed identifiable strings in their agent code (e.g., protocol markers, internal function names, event loop identifiers).
4. **Optionally strip execute permission** — Some frameworks map the ELF binary as readable-only (`r--p`), then selectively re-apply execute permission (`r-xp`) to specific pages at runtime, trying to avoid detection scans that focus on executable anonymous regions.
5. **Optionally erase maps entries** — Advanced evasion modifies `/proc/self/maps` output by hooking the `read()` syscall to filter lines, hiding the injected mapping entirely from userspace reads.

### Artifacts

| Artifact                               | Location                 | Indicator                                                                                               |
| -------------------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------- |
| Byte signature strings                 | Anonymous memory regions | "LIBFRIDA", "frida:rpc", "frida-agent", "gum-js-loop", "gmain"                                          |
| Anonymous executable segment           | `/proc/self/maps`        | `r-xp` region with no file path or backed by `/dev/zero`                                                |
| Multiple jit-cache executable segments | `/proc/self/maps`        | More than one `r-xp` region for `/memfd:jit-cache`                                                      |
| Hidden ELF in non-executable region    | Anonymous `r--p` memory  | First 4 bytes are `\x7fELF` (ELF magic number)                                                          |
| Injected shared library mapping        | `/proc/self/maps`        | Named mapping for a library not part of the original APK or system                                      |
| Dobby trampoline signature             | Anonymous `r-xp` memory  | Byte pattern `51 00 00 58 20 02 1F D6` (ARM64: LDR X17, #8; BR X17) repeated in trampoline island pages |
| ShadowHook trampoline signature        | Anonymous `r-xp` memory  | Byte pattern `F1 4F 1F A9 51 00 00 58 20 02 1F D6` (ARM64: STP+LDR X17+BR X17) in hub pages             |
| android-inline-hook trampoline         | Anonymous `r-xp` memory  | Byte pattern `50 00 00 58 00 02 1F D6` (ARM64: LDR X16, #8; BR X16)                                     |
| Hook framework config strings          | Anonymous memory regions | "dobby", "shadowhook", "bytehook", "substrate", "frida-gadget" in mapped code/data                      |

### Injection PoC _(optional)_

```pseudocode
// Attacker injects agent as anonymous mapping to hide from filename-based detection
fd = memfd_create("", MFD_CLOEXEC)
write(fd, agent_elf_bytes, agent_size)
base = mmap(NULL, agent_size, PROT_READ, MAP_PRIVATE, fd, 0)
// Later, selectively add PROT_EXEC to .text pages
mprotect(text_page, text_size, PROT_READ | PROT_EXEC)
// Agent now runs from anonymous memory with no file path in /proc/self/maps
```

### Evasion Techniques

| Evasion              | Description                                                                                                                                          |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| String obfuscation   | XOR-encode or encrypt identifiable strings in the agent binary; decode them only at runtime in registers, never storing plaintext in memory for long |
| Mapping name erasure | Use `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ...)` to set a benign name, or hook `read()` on `/proc/self/maps` to filter lines                       |
| Permission toggling  | Map code as `r--p` initially, flip to `r-xp` only during execution, then flip back — racing the scanner                                              |
| Memory trampolining  | Keep the main payload in a separate process and communicate via IPC; only a small stub resides in the target process                                 |
| JIT mimicry          | Name injected `memfd` regions to mimic legitimate ART JIT cache entries                                                                              |

---

## Detection Side

### Mechanism

The invariant is that a clean process should not contain known injection framework byte signatures in its memory, should not have anonymous executable memory regions that are not part of ART JIT or legitimate JNI code, should have at most one executable `/memfd:jit-cache` segment, and should not have ELF binaries hiding in non-executable anonymous regions. Violation of any of these invariants indicates that foreign code has been injected into the process.

### Anti-Evasion Properties

| Property                         | Explanation                                                                                                                                                                      |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Resistant to filename erasure    | Detection reads actual memory content, not just the filenames listed in `/proc/self/maps`                                                                                        |
| Resistant to permission toggling | ELF magic detection targets `r--p` regions, catching libraries even when execute permission is stripped                                                                          |
| SVC bypass benefit               | Using SVC-based `openat`/`read` to access `/proc/self/maps` and memory content bypasses libc hooks that filter maps output                                                       |
| Multi-signal correlation         | Combining string matching, segment analysis, and ELF detection makes it hard to evade all checks simultaneously                                                                  |
| Remaining bypass surface         | Kernel-level hooks can forge `/proc/self/maps`; in-memory string wiping after initialization can remove signatures; JIT mimicry may blend injected segments with legitimate ones |

### Detection Strategy

1. **Read `/proc/self/maps`** — Open and read the full contents of `/proc/self/maps` (preferably via SVC `openat`/`read` to bypass libc hooks). Parse each line into base address, end address, permissions, offset, device, inode, and pathname.
2. **Scan anonymous executable segments** — Identify all lines with `r-xp` permission that have no pathname or are backed by `/dev/zero`. Flag these as suspicious — legitimate code should be backed by a named file (shared library or ART-generated code in known paths).
3. **Count jit-cache executable segments** — Count the number of `r-xp` entries whose pathname contains `/memfd:jit-cache`. If the count exceeds one, flag as anomalous — a clean ART runtime produces at most one such segment.
4. **Detect hidden ELF binaries** — For each anonymous region with `r--p` permissions (readable, not executable, not writable), read the first 4 bytes of the region's base address. If the bytes match `\x7fELF`, flag the region — a legitimate non-executable anonymous mapping should not contain an ELF header.
5. **Scan for byte signatures** — For each anonymous readable region (`r--p` or `r-xp`), read the region's content and search for known byte patterns: "LIBFRIDA", "frida:rpc", "frida-agent", "gum-js-loop", "gmain". Any match indicates the presence of an injection framework agent.
6. **Scan for native hook trampoline patterns** — For each anonymous executable region (`r-xp`), read the content and search for known trampoline instruction sequences:
   - ARM64 Dobby: `51 00 00 58 20 02 1F D6` (LDR X17, #8; BR X17) followed by 8-byte target addresses — typically repeated at 16-byte intervals in a trampoline island page
   - ARM64 ShadowHook: `F1 4F 1F A9 51 00 00 58 20 02 1F D6` (STP X16,X17 + LDR X17 + BR X17)
   - ARM64 android-inline-hook: `50 00 00 58 00 02 1F D6` (LDR X16, #8; BR X16)
   - ARM32 generic: `04 F0 1F E5` (LDR PC, [PC, #-4]) followed by a 4-byte absolute address
   - ARM32 Thumb: `DF F8 00 F0` (LDR.W PC, [PC, #0]) followed by a 4-byte absolute address
     Multiple trampoline entries in a single anonymous page is a strong indicator of an inline hook framework's trampoline island allocation.
7. **Aggregate results** — Combine all flags. Any single positive signal warrants further investigation; multiple signals provide high-confidence detection.

### Detection PoC _(optional)_

```pseudocode
// Read process memory maps via SVC to bypass libc hooks
fd = svc_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0)
maps_content = svc_read(fd, buffer, MAX_SIZE)
svc_close(fd)

signatures = ["LIBFRIDA", "frida:rpc", "frida-agent", "gum-js-loop", "gmain"]
jit_cache_exec_count = 0

for each line in parse_lines(maps_content):
    (base, end, perms, offset, dev, inode, path) = parse_map_entry(line)

    // Check 1: Anonymous executable segments
    if perms == "r-xp" and (path == "" or path == "/dev/zero"):
        report("suspicious anonymous executable segment", base, end)

    // Check 2: jit-cache segment count
    if perms == "r-xp" and path contains "/memfd:jit-cache":
        jit_cache_exec_count += 1

    // Check 3: Hidden ELF in non-executable anonymous regions
    if perms == "r--p" and path == "":
        magic = read_memory(base, 4)
        if magic == "\x7fELF":
            report("hidden ELF binary in anonymous region", base, end)

    // Check 4: Byte signature scan in anonymous readable regions
    if ("r" in perms) and (path == "" or path == "/dev/zero"):
        content = read_memory(base, end - base)
        for sig in signatures:
            if sig in content:
                report("injection signature found", sig, base)

if jit_cache_exec_count > 1:
    report("abnormal jit-cache segment count", jit_cache_exec_count)
```

### False Positive Risks

| Scenario                                                     | Mitigation                                                                                                                                                |
| ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Legitimate JIT-compiled code in anonymous executable regions | Cross-reference with ART JIT code cache expected address ranges; exclude known ART memory regions                                                         |
| Debug builds with extra memory regions                       | Only flag regions that also match byte signatures or contain ELF headers, not all anonymous executable segments                                           |
| Third-party SDKs using memfd for legitimate purposes         | Maintain an allowlist of known legitimate memfd region name patterns                                                                                      |
| String fragments that partially match signatures             | Use full-string matching with boundary checks rather than substring search where possible                                                                 |
| Legitimate JNI trampoline code in anonymous pages            | ART runtime may generate JIT trampolines with similar byte sequences; validate that the target address of the branch points outside known ART JIT regions |

---

## References

- [Linux procfs documentation — /proc/self/maps](https://www.kernel.org/doc/html/latest/filesystems/proc.html)
- [ELF specification — magic number and header format](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [Android ART JIT compiler documentation](https://source.android.com/docs/core/runtime/jit-compiler)
- [memfd_create(2) — Linux manual page](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [prctl(2) — PR_SET_VMA_ANON_NAME](https://man7.org/linux/man-pages/man2/prctl.2.html)
