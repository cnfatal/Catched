# GOT/PLT Hook Detection

> Verifies the integrity of Global Offset Table and Procedure Linkage Table entries in loaded shared libraries to detect function pointer hijacking and inline code patching.

---

## Overview

The Global Offset Table (GOT) and Procedure Linkage Table (PLT) are core mechanisms of the ELF dynamic linking model. When a shared library calls an external function (e.g., libc's `openat`), the call passes through a PLT stub that reads a function pointer from the corresponding GOT entry. On first call, the dynamic linker resolves the symbol and writes the resolved address into the GOT; subsequent calls jump directly to the resolved address. GOT/PLT hooking exploits this by overwriting GOT entries with pointers to attacker-controlled functions, silently redirecting all calls through the PLT to the hook handler. Inline hooking takes a more direct approach: overwriting the first instructions of the target function with a branch to the hook, intercepting even direct calls that bypass the PLT.

From a defender's perspective, GOT/PLT hook detection is critical because these hooks are the primary mechanism used by injection frameworks to intercept libc and system library calls. By validating that resolved function pointers point to their expected library and that function prologues have not been patched, defenders can detect active hooking regardless of how the hook was installed.

---

## Injection Side

### How Attackers Use This Technique

1. **Identify target function** — The attacker determines which libc or system library function to intercept (e.g., `openat`, `read`, `stat`, `access`, `fopen`).
2. **Locate GOT entry** — Using `dlopen` with `RTLD_NOLOAD` and parsing ELF section headers, the attacker finds the GOT entry for the target function in the hooking library or the target library.
3. **Overwrite GOT entry** — The attacker changes the memory protection of the GOT page to writable (`mprotect` with `PROT_WRITE`), writes the address of the hook handler function, then optionally restores the original protection.
4. **Alternatively, install inline hook** — Instead of modifying the GOT, the attacker patches the first instructions of the target function directly. On ARM64, this typically involves writing an `LDR X16, #8; BR X16; <64-bit address>` sequence (12 bytes) or a direct `B` instruction. On ARM32, an `LDR PC, [PC, #-4]; <32-bit address>` pattern is used.
5. **Hook handler filters results** — The hook function calls the original function (via saved pointer or trampoline), inspects the result, and modifies it before returning to the caller. For example, filtering lines from `/proc/self/maps` that contain injected library names.

### Artifacts

| Artifact                          | Location                                      | Indicator                                                                                                                |
| --------------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Modified GOT entry                | `.got` / `.got.plt` section of hooked library | Function pointer does not resolve to the expected library's `.text` segment                                              |
| Writable GOT pages                | `/proc/self/maps`                             | GOT pages changed from `r--p` to `rw-p` (or remain `rw-p` after modification)                                            |
| Inline hook trampoline            | Target function prologue in libc `.text`      | First bytes replaced with branch/load instruction sequence                                                               |
| Modified `.text` page permissions | `/proc/self/maps`                             | libc `.text` pages changed from `r-xp` to `rwxp` (write needed for inline patching)                                      |
| Hook handler library              | `/proc/self/maps`                             | Additional shared library containing the hook handler code, mapped with execute permission                               |
| Trampoline island / code page     | `/proc/self/maps`                             | `r-xp` anonymous memory page near the hooked library — Dobby/ShadowHook allocate nearby pages for trampoline trampolines |

### Injection PoC _(optional)_

```pseudocode
// GOT hooking example: redirect openat to a hook function
target_lib = dlopen("libtarget.so", RTLD_NOLOAD)
got_entry_addr = find_got_entry(target_lib, "openat")
original_openat = *got_entry_addr

// Make GOT page writable
page_addr = got_entry_addr & ~0xFFF
mprotect(page_addr, PAGE_SIZE, PROT_READ | PROT_WRITE)

// Overwrite GOT entry
*got_entry_addr = &hook_openat

function hook_openat(dirfd, path, flags, mode):
    fd = original_openat(dirfd, path, flags, mode)
    if path contains "/proc/self/maps":
        return create_filtered_fd(fd)
    return fd
```

### Evasion Techniques

| Evasion                                | Description                                                                                                                                                      |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hook handler within libc address range | Allocate the hook handler code inside a memory region that falls within libc's mapped range (e.g., via code cave injection), so address range validation passes  |
| Trampoline patching                    | Use a longer instruction sequence for the inline hook that mimics legitimate compiler-generated code patterns                                                    |
| Restore-on-check                       | Detect when GOT integrity checks run and temporarily restore original pointers, re-applying hooks afterward                                                      |
| Symbol interposition                   | Use `LD_PRELOAD` or linker namespace tricks to provide a replacement library that legitimately resolves the symbol, so the GOT entry points to a "valid" library |
| PLT-only hooking                       | Modify the PLT stub code instead of the GOT data, which some detection methods do not check                                                                      |
| Prologue mimicry                       | Replace the original prologue instructions in the trampoline so the first bytes still resemble a valid function prologue, making pattern matching harder         |
| Dynamic trampoline code                | Generate unique trampoline instruction sequences per hook to avoid fixed byte pattern matching                                                                   |

---

## Detection Side

### Mechanism

The invariant is that a resolved function pointer obtained via `dlsym` for a function declared in a specific shared library (e.g., `openat` in libc) must point to an address within that library's executable memory segments. Additionally, the first instructions of the function at that address must be the original compiler-generated prologue, not a hook trampoline. If the resolved address falls outside the library's mapped range, or if the function prologue matches known hook trampoline patterns, the function has been hooked.

### Anti-Evasion Properties

| Property                     | Explanation                                                                                                                                                                                                                              |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Address range validation     | Comparing resolved addresses against mapped library ranges from `/proc/self/maps` detects any hook that redirects outside the target library                                                                                             |
| Instruction pattern analysis | Checking function prologues for trampoline patterns (LDR+BR, direct B) detects inline hooks even when GOT entries are intact                                                                                                             |
| SVC bypass benefit           | Using SVC `openat`/`read` to parse `/proc/self/maps` prevents hooked libc from returning forged memory range information                                                                                                                 |
| Multi-function coverage      | Checking multiple commonly-hooked functions (openat, read, stat, access, fopen) makes selective evasion harder                                                                                                                           |
| Remaining bypass surface     | Code cave injection within the target library's address range defeats address range checks; sophisticated inline hooks that replicate legitimate prologues may evade pattern matching; kernel-level hooks bypass all userspace detection |

### Detection Strategy

1. **Resolve function address via dlsym** — Use `dlopen("libc.so", RTLD_NOLOAD)` to get a handle to the already-loaded libc without triggering a new load. Use `dlsym(handle, "openat")` to obtain the resolved address of the target function. Repeat for other commonly hooked functions: `read`, `write`, `stat`, `access`, `fopen`, `__openat`.
2. **Determine library address range** — Parse `/proc/self/maps` (via SVC) to find all executable (`r-xp`) segments belonging to libc.so (match by pathname). Record the base and end addresses of these segments.
3. **Validate address range** — Check if the resolved function address from step 1 falls within any of the executable segments identified in step 2. If it falls outside, the GOT has been tampered with — the function resolves to code in a different library.
4. **Check for inline hook trampolines** — Read the first 12–16 bytes at the resolved function address. On ARM64, check for:
   - **Dobby / substrate** — `LDR X17, #8; BR X17` pattern (bytes: `51 00 00 58 20 02 1F D6`) followed by an 8-byte absolute address
   - **ShadowHook** — `STP X16, X17, [SP, #-0x10]!; LDR X17, #8; BR X17` pattern (bytes: `F1 4F 1F A9 51 00 00 58 20 02 1F D6`) — 12 bytes before the target address
   - **android-inline-hook** — `LDR X16, #8; BR X16` pattern (bytes: `50 00 00 58 00 02 1F D6`) followed by an 8-byte absolute address
   - **Generic** — Direct `B` instruction (opcode `0x14xxxxxx` or `0x17xxxxxx`) branching outside the function's library range
   - **ADRP+ADD+BR** — `ADRP Xn, #page; ADD Xn, Xn, #off; BR Xn` — a 3-instruction sequence commonly used by hook frameworks when the target is within ±4GB
     On ARM32, check for:
   - `LDR PC, [PC, #-4]` pattern (bytes: `04 F0 1F E5`) followed by a 4-byte absolute address (Dobby, ShadowHook)
   - **android-inline-hook** — `LDR PC, [PC, #0]` pattern (bytes: `00 F0 9F E5`) followed by a 4-byte absolute address
   - **Thumb mode** — `LDR.W PC, [PC, #0]` (bytes: `DF F8 00 F0`) followed by a 4-byte absolute address — hooks on Thumb2 functions
     Note: Framework-specific patterns can overlap; the key invariant is that the first few instructions should match the compiler-generated prologue (e.g., `STP X29, X30, [SP, #-N]!` on ARM64), not a load-branch sequence.
5. **Cross-validate with multiple methods** — If both the GOT range check and inline hook check pass, the function is likely clean. If either fails, report the hook with detailed information about which function, which library, and which check failed.

### Detection PoC _(optional)_

```pseudocode
// Step 1: Resolve function addresses
libc_handle = dlopen("libc.so", RTLD_NOLOAD)
functions_to_check = ["openat", "read", "write", "stat", "access", "fopen"]
resolved = {}
for func_name in functions_to_check:
    resolved[func_name] = dlsym(libc_handle, func_name)

// Step 2: Parse /proc/self/maps to find libc executable ranges
fd = svc_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0)
maps = svc_read(fd, buffer, MAX_SIZE)
svc_close(fd)

libc_ranges = []
for line in parse_lines(maps):
    (base, end, perms, offset, dev, inode, path) = parse_map_entry(line)
    if "libc.so" in path and perms == "r-xp":
        libc_ranges.append((base, end))

// Step 3: Validate resolved addresses against library ranges
for func_name, addr in resolved:
    in_range = any(base <= addr < end for (base, end) in libc_ranges)
    if not in_range:
        report("GOT hook detected", func_name, addr)

// Step 4: Check for inline hook trampolines (ARM64)
for func_name, addr in resolved:
    prologue = read_memory(addr, 16)
    // Check for LDR X16, #8; BR X16 pattern
    if prologue[0:8] == [0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1F, 0xD6]:
        hook_target = read_u64(addr + 8)
        report("inline hook trampoline detected", func_name, hook_target)
    // Check for direct B instruction branching outside range
    if (prologue[3] & 0xFC) == 0x14:  // B opcode
        branch_offset = decode_b_offset(prologue[0:4])
        branch_target = addr + branch_offset
        if not any(base <= branch_target < end for (base, end) in libc_ranges):
            report("suspicious branch at function entry", func_name, branch_target)
```

### False Positive Risks

| Scenario                                                 | Mitigation                                                                                                                                                               |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| IFUNC resolvers redirecting to optimized implementations | IFUNC-resolved addresses may point to a different segment within the same library; ensure range check includes all segments of the library, not just the primary `.text` |
| Linker trampolines for cross-library calls               | On some Android versions, the linker inserts PLT trampolines that technically reside outside the target library; include linker memory ranges as valid                   |
| Debugger breakpoints (software breakpoints)              | Debuggers insert `BRK` instructions at breakpoint addresses; distinguish `BRK` (debugging) from `LDR+BR` or `B` (hooking) patterns                                       |
| ART runtime method stubs                                 | Some ART-generated stubs may have branch instructions that resemble hook trampolines; exclude known ART trampoline address ranges                                        |

---

## References

- [ELF specification — Global Offset Table and Procedure Linkage Table](https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.dynamic.html)
- [ARM64 instruction set — LDR, BR, B instructions](https://developer.arm.com/documentation/ddi0487/latest)
- [ARM32 instruction set — LDR PC](https://developer.arm.com/documentation/ddi0406/latest)
- [dlopen(3) / dlsym(3) — Linux manual pages](https://man7.org/linux/man-pages/man3/dlopen.3.html)
- [Android dynamic linker (linker64) source](https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/)
