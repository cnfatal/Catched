# Inline Code Patching Detection

> Detects direct modification of machine code instructions at function entry points (prologues) used by inline hooking frameworks such as Dobby, ShadowHook, android-inline-hook, and Substrate.

---

## Overview

Inline code patching overwrites the first few bytes of a target function's machine code with a branch or jump instruction that redirects execution to attacker-controlled trampoline code. Unlike GOT/PLT hooking, which modifies function pointers in linkage tables, inline patching alters the actual executable bytes in `.text` sections. This technique is the backbone of popular native hook engines — Dobby, ShadowHook (ByteDance android-inline-hook), and Substrate — each of which emits distinct trampoline patterns at the function prologue. Detection relies on comparing in-memory code bytes against known-good ELF representations and scanning for instruction patterns that standard compilers never emit at function entry.

---

## Injection Side

### How Attackers Use This Technique

1. **Resolve target address** — Attacker identifies the target function address via `dlsym()`, ELF symbol table parsing, or ART method `entry_point_` introspection.
2. **Save original prologue** — Copy the first 4–20 bytes (architecture and tool dependent) of the target function for later restoration or relocation.
3. **Make code page writable** — Call `mprotect()` on the code page to add write permission (RWX, or RW then back to RX).
4. **Overwrite prologue** — Write a branch/jump instruction at the function entry that redirects to a trampoline.
5. **Trampoline execution** — The trampoline saves CPU context (registers, flags), invokes the attacker's handler function, and optionally calls the relocated original prologue (the "backup") to preserve original behavior.
6. **Flush instruction cache** — Call `__builtin___clear_cache()` (or equivalent) to ensure the CPU fetches the patched instructions.
7. **Restore page permissions** — `mprotect()` the code page back to RX to reduce forensic footprint.

### Artifacts

| Artifact                | Location                    | Indicator                                                  |
| ----------------------- | --------------------------- | ---------------------------------------------------------- |
| Modified prologue       | Target function `.text`     | First 4–20 bytes differ from original ELF on disk          |
| Trampoline code         | Anonymous `mmap` or ELF gap | Branch target resides in non-standard memory region        |
| Relocated prologue      | Near trampoline             | Original instructions with fixed-up PC-relative references |
| RWX memory (transient)  | `/proc/self/maps`           | `mprotect` to RWX during patching window                   |
| Instruction cache flush | Syscall trace               | `__builtin___clear_cache()` or equivalent syscall          |
| mprotect pattern        | Syscall trace               | `mprotect(RW) → memcpy → mprotect(RX)` sequence            |

### Architecture-Specific Trampoline Patterns

**ARM64 patterns:**

| Tool                  | Pattern                                     | Size | Encoding                                                                    |
| --------------------- | ------------------------------------------- | ---- | --------------------------------------------------------------------------- |
| Dobby (near)          | `ADRP Xn, #page; ADD Xn, Xn, #off; BR Xn`   | 12B  | `0x90000000` class + `0x91000000` class + `0xD61F0000` class                |
| Dobby (far)           | `LDR Xn, #8; BR Xn; .quad target`           | 16B  | `0x58000040; 0xD61F0000; <8-byte addr>`                                     |
| ShadowHook            | `B #imm26` (±128 MB)                        | 4B   | `(insn & 0xFC000000) == 0x14000000`                                         |
| ShadowHook (non-func) | `STP X16, X17, [SP, #-0x10]!; ...`          | 8B+  | Push regs then branch                                                       |
| ShadowHook (BTI)      | `RET Xn` instead of `BR Xn`                 | 4B   | `(insn & 0xFFFFFC1F) == 0xD65F0000` — bypasses Branch Target Identification |
| Substrate             | `LDR PC, [PC, #off]` (A32) or Thumb variant | 8B   | ARM32 specific                                                              |
| android-inline-hook   | `LDR X17, #8; BR X17; .quad target`         | 16B  | Uses X17 specifically                                                       |

**ARM32 patterns:**

| Tool       | Pattern                           | Size | Encoding                            |
| ---------- | --------------------------------- | ---- | ----------------------------------- |
| Dobby      | `LDR PC, [PC, #-4]; .word target` | 8B   | `(insn & 0x0F7F0000) == 0x051F0000` |
| Substrate  | `LDR PC, [PC]; .word target`      | 8B   | Similar LDR PC encoding             |
| ShadowHook | `B #imm24` (±32 MB)               | 4B   | `(insn & 0x0F000000) == 0x0A000000` |

**x86_64 patterns:**

| Tool      | Pattern                     | Size | Encoding                          |
| --------- | --------------------------- | ---- | --------------------------------- |
| Dobby     | `JMP [RIP+0]; .quad target` | 14B  | `FF 25 00 00 00 00` + 8-byte addr |
| Substrate | `JMP rel32`                 | 5B   | `E9` + 4-byte offset              |

### Injection PoC _(optional)_

```c
// Pseudo-code: inline hook installation (ARM64, far branch)
void install_inline_hook(void *target, void *handler, void **orig_out) {
    // 1. Save original prologue
    uint8_t backup[16];
    memcpy(backup, target, 16);

    // 2. Build relocated prologue (fix up PC-relative instructions)
    void *trampoline = mmap(NULL, PAGE_SIZE, PROT_RWX, MAP_ANON | MAP_PRIVATE, -1, 0);
    relocate_instructions(backup, 16, trampoline);
    // Append branch back to target+16
    emit_ldr_br(trampoline + relocated_size, (uint64_t)target + 16);
    *orig_out = trampoline;

    // 3. Patch target prologue
    uintptr_t page = (uintptr_t)target & ~(PAGE_SIZE - 1);
    mprotect((void *)page, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);

    // ARM64 far branch: LDR X17, #8; BR X17; .quad handler
    uint32_t *code = (uint32_t *)target;
    code[0] = 0x58000051;  // LDR X17, #8
    code[1] = 0xD61F0220;  // BR X17
    *(uint64_t *)&code[2] = (uint64_t)handler;

    __builtin___clear_cache(target, (char *)target + 16);
    mprotect((void *)page, PAGE_SIZE, PROT_READ | PROT_EXEC);
}
```

### Evasion Techniques

| Evasion                      | Description                                                                             | Bypass Difficulty |
| ---------------------------- | --------------------------------------------------------------------------------------- | ----------------- |
| Pre-reserved `.text` slots   | Compile trampoline slots into injected SO's `.text` section — no anonymous pages needed | ★★★★              |
| ELF gap injection            | Write trampoline to LOAD segment padding — no new memory mappings                       | ★★★★              |
| JIT Code Cache injection     | Write trampoline into ART JIT Code Cache free space — blends with legitimate JIT output | ★★★★★             |
| Static linking               | Link hook engine into main SO — no library name signatures to detect                    | ★★★               |
| Immediate permission restore | `mprotect` back to RX immediately after write — RWX window is μs                        | ★★                |
| BTI bypass                   | Use `RET Xn` instead of `BR Xn` to pass hardware Branch Target Identification checks    | ★★★               |

---

## Detection Side

### Mechanism

Function prologues in loaded shared libraries and ART compiled code should match their on-disk ELF representation. Any deviation in the first N bytes of a function indicates patching. Additionally, certain instruction patterns — such as an unconditional branch as the very first instruction, or `LDR` + `BR` pairs loading absolute addresses — are never emitted by standard compilers at function entry points. By reading code bytes directly via pointer dereference (no library calls), detection is resistant to libc-level hook interception.

### Anti-Evasion Properties

| Property                    | Explanation                                                                                                              |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Resistant to libc hooks     | Function bytes are read directly from memory via pointer dereference — no `read()` or `fopen()` calls to intercept       |
| Resistant to GOT/PLT hijack | No library calls needed to read code bytes; detection logic uses only inline memory access                               |
| SVC bypass benefit          | Not applicable — reading own process memory requires no syscall, just pointer dereference                                |
| Remaining bypass surface    | Attacker can hook the detection function itself; mitigate with self-integrity checks and multiple redundant check points |

### Detection Strategy

1. **Enumerate critical functions** — Build a list of security-relevant functions to monitor (e.g., `open`, `read`, `mmap`, `ptrace`, `getenv`, ART internals).
2. **Resolve function addresses** — Read function addresses via `dlsym()` or ART method `entry_point_` field.
3. **Read prologue bytes** — Read the first 4–20 bytes at each function address via direct pointer dereference.
4. **Check for known trampoline patterns:**
   - ARM64: `B #imm26` as first instruction — `(insn & 0xFC000000) == 0x14000000`
   - ARM64: `LDR Xn, #literal; BR Xn` pair — `(insn & 0xFF000000) == 0x58000000` followed by `(insn & 0xFFFFFC1F) == 0xD61F0000`
   - ARM64: `ADRP; ADD; BR` three-instruction sequence
   - ARM64: `RET Xn` where Xn ≠ X30 used as branch — `(insn & 0xFFFFFC1F) == 0xD65F0000` and Rn ≠ 30
   - ARM32: `LDR PC, [PC, #off]` — `(insn & 0x0F7F0000) == 0x051F0000`
   - x86_64: `FF 25` (`JMP [RIP+disp32]`) or `E9` (`JMP rel32`)
5. **Cross-reference with on-disk ELF** — For deeper validation, compare in-memory bytes against the `.text` section of the original ELF file (see code-integrity-verification technique).
6. **Validate branch targets** — Check where the branch instruction jumps to; if the target falls outside any known `.text` segment in `/proc/self/maps`, flag as suspicious.
7. **Scan for framework signatures** — Look for `STP X16, X17, [SP, #-0x10]!` pattern at function entries (ShadowHook non-function hook signature).

### Detection PoC _(optional)_

```c
// Pseudo-code: inline hook detection (ARM64)
#include <stdint.h>
#include <dlfcn.h>

typedef enum { CLEAN, HOOKED_BRANCH, HOOKED_LDR_BR, HOOKED_ADRP } hook_status_t;

hook_status_t check_function_prologue(const char *lib, const char *sym) {
    void *handle = dlopen(lib, RTLD_NOW);
    void *func   = dlsym(handle, sym);
    if (!func) return CLEAN;

    uint32_t *code = (uint32_t *)func;
    uint32_t insn0 = code[0];
    uint32_t insn1 = code[1];

    // Pattern 1: B #imm26 (ShadowHook near branch)
    if ((insn0 & 0xFC000000) == 0x14000000) {
        return HOOKED_BRANCH;
    }

    // Pattern 2: LDR Xn, #8; BR Xn (Dobby/android-inline-hook far branch)
    if ((insn0 & 0xFF000000) == 0x58000000 &&
        (insn1 & 0xFFFFFC1F) == 0xD61F0000) {
        return HOOKED_LDR_BR;
    }

    // Pattern 3: ADRP Xn, #page (Dobby near branch)
    if ((insn0 & 0x9F000000) == 0x90000000) {
        uint32_t insn2 = code[2];
        if ((insn1 & 0xFFC00000) == 0x91000000 &&
            (insn2 & 0xFFFFFC1F) == 0xD61F0000) {
            return HOOKED_ADRP;
        }
    }

    // Pattern 4: RET Xn where Xn != X30 (ShadowHook BTI bypass)
    if ((insn0 & 0xFFFFFC1F) == 0xD65F0000) {
        uint32_t rn = (insn0 >> 5) & 0x1F;
        if (rn != 30) return HOOKED_BRANCH;
    }

    return CLEAN;
}
```

### False Positive Risks

| Scenario                                 | Mitigation                                                                                    |
| ---------------------------------------- | --------------------------------------------------------------------------------------------- |
| ART compiled code with unusual prologues | Only check known library functions and native methods, not JIT output                         |
| PLT stubs (normal indirect calls)        | PLT entries are expected to contain branches — exclude PLT sections from scanning             |
| Compiler-generated tail calls            | `B` instructions for tail call optimization — verify target is within same function or module |
| Android linker relocations               | Some relocations modify code at load time — perform checks after relocation completes         |

---

## References

- [Dobby — A lightweight, multi-platform hook framework](https://github.com/jmpews/Dobby)
- [ShadowHook (android-inline-hook) — ByteDance inline hook library](https://github.com/bytedance/android-inline-hook)
- ARM Architecture Reference Manual — Branch instructions encoding (A64/A32/T32)
- "A Survey of Android Hooking Techniques" — inline hook section
