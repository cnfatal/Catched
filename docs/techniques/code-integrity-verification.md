# Code Integrity Verification

> Compares `.text` section bytes on disk (ELF file) with in-memory content to detect runtime code patching by inline hook frameworks.

---

## Overview

Code Integrity Verification exploits a fundamental invariant of the ELF loading process: the `.text` section of a shared library, once memory-mapped by the dynamic linker, should remain byte-for-byte identical to its on-disk counterpart. Unlike `.got`, `.data.rel.ro`, or other writable sections that are patched during relocation, `.text` is mapped read-only/executable and is never modified by the linker. Inline hook frameworks (Dobby, ShadowHook, android-inline-hook) break this invariant by overwriting function prologues in memory with branch instructions to detour trampolines.

From a defender's perspective, this technique provides ground-truth evidence of code tampering. Because the comparison operates on raw bytes — disk via direct SVC `openat`/`read` and memory via pointer dereference — it is resistant to most userspace hooking evasion. It is particularly effective for protecting critical native functions in the app's own SOs and key system libraries.

---

## Injection Side

### How Attackers Use This Technique

1. **Identify target function** — The attacker selects a native function to hook (e.g., `open`, `strcmp`, or an app-specific JNI method) and resolves its in-memory address.
2. **Overwrite function prologue** — The hook framework makes the `.text` page writable via `mprotect`, writes a branch instruction (typically 4–16 bytes on ARM64) at the function entry, then restores the page to `r-xp`.
3. **Install trampoline** — The original prologue bytes are saved to a trampoline buffer (usually in anonymous memory), allowing the hook to call through to the original function.
4. **Memory diverges from disk** — The on-disk ELF file retains the original function bytes while memory now contains the branch instruction. This creates a detectable delta between disk and memory content.

### Artifacts

| Artifact           | Location          | Indicator                                                     |
| ------------------ | ----------------- | ------------------------------------------------------------- |
| Byte mismatch      | `.text` section   | Memory bytes ≠ disk bytes at function entries                 |
| Page-level delta   | Code pages        | CRC32/SHA256 of memory page ≠ disk page                       |
| Patch footprint    | Prologue bytes    | Exactly 4–20 bytes differ at function boundary                |
| Branch instruction | Function entry    | `B`/`BL`/`BR` opcode where original instruction was different |
| Writable .text     | `/proc/self/maps` | Transient `rwxp` permission on code page during patching      |

### Injection PoC _(optional)_

```pseudocode
// Inline hook overwrites function prologue in memory
target_addr = dlsym(handle, "target_function")
mprotect(PAGE_ALIGN(target_addr), PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC)
// Save original bytes to trampoline
memcpy(trampoline, target_addr, PATCH_SIZE)   // typically 4-16 bytes
// Write branch to detour
write_branch_instruction(target_addr, detour_function)
mprotect(PAGE_ALIGN(target_addr), PAGE_SIZE, PROT_READ | PROT_EXEC)
// Disk file is unchanged — memory now differs from disk
```

### Evasion Techniques

| Evasion                  | Description                                                                                                                                                  | Bypass Difficulty |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------- |
| SO packing/encryption    | Packed SOs have encrypted `.text` on disk; runtime decrypted content never matches disk — makes comparison impossible for packed SOs                         | ★★★★              |
| Patching the detection   | Hook the detection function itself to return "clean" results before it can compare bytes                                                                     | ★★★               |
| Disk file replacement    | Replace disk ELF after patching to match memory content (requires write access to app's data directory or `/system`)                                         | ★★                |
| Pre-reserved .text slots | Trampoline slots compiled into `.text` with NOP fill — disk already contains the slot space, only the NOP→branch delta is visible                            | ★★★★              |
| Self-modifying packed SO | Attacker's own SO uses packing; its `.text` is legitimately different from disk, creating noise that masks detection of patched functions in other libraries | ★★★★              |

---

## Detection Side

### Mechanism

ELF shared libraries loaded via `dlopen()` or the dynamic linker are memory-mapped from the filesystem. In a clean environment, the `.text` section bytes in memory must be byte-for-byte identical to the `.text` section on disk. This holds because `.text` sections use `REL`/`RELA` relocations that are resolved in `.got`/`.data.rel.ro`, **not** by patching `.text` itself. Therefore, after loading, `.text` should be pristine.

Any divergence in `.text` bytes indicates runtime code modification — the signature of inline hooking.

### Anti-Evasion Properties

| Property                    | Explanation                                                                                                                                                      |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Resistant to libc hooks     | Disk reads via SVC `openat`/`read`; memory reads via direct pointer dereference                                                                                  |
| Resistant to GOT/PLT hijack | Comparison logic uses no library calls — inline SVC instructions and pointer arithmetic only                                                                     |
| SVC bypass benefit          | File I/O bypasses any userspace hook on `open`/`read`/`fstat`                                                                                                    |
| Remaining bypass surface    | Cannot verify packed/encrypted SOs where disk≠memory is normal; attacker may redirect `openat` to modified file copy via mount namespace or symlink manipulation |

### Detection Strategy

1. **Enumerate loaded SOs** — Parse `/proc/self/maps` to find `.text` segments of interest (lines with `r-xp` permission and a file path).
2. **Extract file offset** — Note the file offset from the maps entry (5th column) and the memory base address.
3. **Open disk file via SVC** — Use SVC `openat` directly (ARM64: `svc #0` with `x8=56`) to open the SO file on disk, bypassing any libc hooks.
4. **Read disk bytes** — Use SVC `read` to load the corresponding bytes from disk at the noted file offset.
5. **Compare memory vs. disk** — Read memory content via direct pointer dereference and compare byte-by-byte with disk content.
6. **Identify patch sites** — Any mismatch in the first 4–20 bytes of a function boundary indicates inline hook patching; decode the mismatched bytes to confirm a branch instruction.
7. **Prioritize critical functions** — For efficiency, focus on known critical functions (e.g., `open`, `read`, `__system_property_get`, app-specific JNI methods) rather than full-section comparison.
8. **Coarse-then-fine detection** — Compute page-level CRC32 for fast coarse-grained detection, then perform byte-level diff only on pages with CRC mismatches.

### Detection PoC _(optional)_

```pseudocode
// Code Integrity Verification: compare .text on disk vs. in memory

maps = svc_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY)
for each line in read_lines(maps):
    if line.permissions == "r-xp" and line.filepath in MONITORED_LIBS:
        mem_base   = line.start_addr
        mem_size   = line.end_addr - line.start_addr
        file_off   = line.offset

        fd = svc_openat(AT_FDCWD, line.filepath, O_RDONLY)
        disk_buf = svc_read(fd, file_off, mem_size)
        svc_close(fd)

        // Coarse check: page-level CRC32
        for page_idx in range(0, mem_size, PAGE_SIZE):
            mem_crc  = crc32(mem_base + page_idx, PAGE_SIZE)
            disk_crc = crc32(disk_buf + page_idx, PAGE_SIZE)
            if mem_crc != disk_crc:
                // Fine check: byte-level diff
                for i in range(page_idx, page_idx + PAGE_SIZE):
                    if mem_base[i] != disk_buf[i]:
                        report_tamper(line.filepath, file_off + i,
                                      expected=disk_buf[i], found=mem_base[i])
                return DETECTED

return CLEAN
```

### False Positive Risks

| Scenario                           | Mitigation                                                                                                                |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| SO packing (Bangcle, iJiami, 360)  | Skip integrity check for SOs with encrypted `.text`; identify packed SOs by checking for decryption stub in `.init_array` |
| ART JIT compiled code              | JIT output is in anonymous memory (`/memfd:jit-cache`), not file-backed — never compare JIT pages                         |
| ART AOT compiled code (.odex/.oat) | AOT code **can** be verified against `.odex` on disk; useful for detecting Java method code patching                      |
| Linker IFUNC resolution            | Some functions resolved at load time — rare in `.text`, mostly in `.got`; verify IFUNC applicability before flagging      |
| Text relocations (legacy)          | Very old SOs with `TEXTREL` flag may have legitimate `.text` modifications; check `DT_TEXTREL` flag and skip if set       |

---

## References

- ELF specification — <https://refspecs.linuxfoundation.org/elf/elf.pdf>
- Android linker relocation types — `.got`/`.data.rel.ro` patching vs. `.text` invariance
- "Android Packing Detection and Unpacking" — packed SO identification techniques
- Dobby inline hook framework — <https://github.com/jmpews/Dobby>
- ShadowHook (ByteDance) — <https://github.com/bytedance/android-inline-hook>
