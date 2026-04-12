# Return Address Validation

> Validates that function return addresses (LR/X30 register on ARM64) point within expected module .text segments, detecting execution flow through injected trampolines.

---

## Overview

When an inline hook redirects a function call through a trampoline, the return address (Link Register on ARM64, LR on ARM32, stack on x86_64) will point to the trampoline's return stub rather than the original caller. If the trampoline resides in anonymous executable memory or an unexpected memory region, the return address falls outside any known module's `.text` segment. By reading the LR register within critical functions and validating it against `/proc/self/maps`, defenders can detect that execution passed through injected code. This technique is complementary to code integrity verification and executable page scanning, providing a runtime call-chain perspective rather than a static memory layout perspective.

---

## Injection Side

### How Attackers Use This Technique

1. **Inline hook patches target function** — The attacker overwrites the first few instructions of a target function with a branch (`B` / `BL`) to a trampoline allocated in anonymous memory or an ELF mapping gap.
2. **Trampoline calls attacker handler** — The trampoline executes `BL handler`, which sets the Link Register (X30) to the trampoline's return stub address.
3. **Handler processes arguments** — The attacker's handler reads/modifies arguments, optionally calls the backup (original function bytes relocated to a separate stub).
4. **Handler returns to trampoline** — Upon `RET`, execution returns to the trampoline via the LR value set in step 2.
5. **Trampoline returns to original caller** — The trampoline restores the original LR and returns to the legitimate caller.
6. **Detection window** — During steps 2–3, if a detection check runs (or if the handler itself calls a detection function), the LR register points to the trampoline address — a non-standard memory region.

### Artifacts

| Artifact               | Location     | Indicator                                                                       |
| ---------------------- | ------------ | ------------------------------------------------------------------------------- |
| LR in anonymous memory | X30 register | Return address in `rwxp` / `r-xp` anonymous mapping                             |
| LR in ELF gap          | X30 register | Return address past `.text` actual end, before page boundary                    |
| Stack return addresses | Thread stack | Backtrace frames in non-module addresses                                        |
| LR in wrong module     | X30 register | Return address in unexpected SO (e.g., `libdobby.so` rather than caller module) |

### Evasion Techniques

| Evasion                         | Description                                                                                         | Bypass Difficulty |
| ------------------------------- | --------------------------------------------------------------------------------------------------- | ----------------- |
| Pre-reserved `.text` trampoline | Place trampoline in injected SO's `.text` section — LR falls within a legitimate file-backed module | ★★★★              |
| ELF gap trampoline              | LR falls within a system SO's mapping range — passes basic range check                              | ★★★★              |
| JIT cache trampoline            | LR falls within JIT code cache — appears as legitimate JIT code                                     | ★★★★★             |
| LR fixup in handler             | Manually set LR to point to legitimate code before detection functions run                          | ★★★               |
| Tail call style                 | Use `B` instead of `BL` — LR retains original caller address                                        | ★★★★              |

---

## Detection Side

### Mechanism

In normal execution, the return address (LR/X30 on ARM64) of any function always points into a known file-backed `.text` segment — either the calling function's module or a system library. Trampolines in anonymous memory make LR point to addresses not covered by any file-backed executable mapping in `/proc/self/maps`. Even trampolines in ELF gaps can be detected by verifying LR falls within the actual `.text` section (between `base + p_offset` and `base + p_offset + p_filesz`), not just within the page-aligned mapping.

### Anti-Evasion Properties

| Property                    | Explanation                                                                                                         |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Resistant to libc hooks     | LR is a CPU register — cannot be hooked                                                                             |
| Resistant to GOT/PLT hijack | Register read is inline; maps read via SVC                                                                          |
| SVC bypass benefit          | Maps parsing bypasses userspace hooks                                                                               |
| Remaining bypass surface    | Attacker with trampoline in file-backed `.text` segment passes this check; combine with code-integrity-verification |

### Detection Strategy

1. **Read LR register** — In critical detection functions, read the return address: ARM64 `__builtin_return_address(0)` or inline asm `mov x0, x30`.
2. **Parse `/proc/self/maps` via SVC** — Use `openat` + `read` syscalls directly (ARM64: SVC #0) to build a list of file-backed executable segments with precise start/end addresses.
3. **Match LR against file-backed segments** — Check if LR falls within any file-backed `r-xp` segment.
4. **Detect anonymous trampoline** — If LR is in anonymous memory or no matching segment → **trampoline detected**.
5. **Deep `.text` validation** — For deeper check: verify LR is within the actual `.text` section (not padding gap) by parsing ELF program headers (`p_offset` + `p_filesz`).
6. **Stack unwinding** — Perform stack unwinding (`_Unwind_Backtrace` or manual frame walk) and validate all return addresses in the call chain.
7. **Flag anomalous frames** — Flag any frame in anonymous memory, unnamed mapping, or outside known modules.

### Detection PoC

```c
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uintptr_t start;
    uintptr_t end;
    char perms[5];
    char path[256];
} MapSegment;

typedef struct {
    MapSegment entries[512];
    int count;
} MapsInfo;

// Parse /proc/self/maps via direct SVC (see svc_openat/svc_read patterns)
extern MapsInfo *parse_maps_svc(void);

int check_return_address(void) {
    void *lr = __builtin_return_address(0);

    // Parse /proc/self/maps for file-backed r-xp segments
    MapsInfo *segments = parse_maps_svc();
    if (!segments) return -1;

    bool found = false;
    for (int i = 0; i < segments->count; i++) {
        if ((uintptr_t)lr >= segments->entries[i].start &&
            (uintptr_t)lr <  segments->entries[i].end &&
            segments->entries[i].path[0] == '/') {
            found = true;
            break;
        }
    }

    if (!found) {
        // LR points to anonymous/unnamed memory — trampoline detected
        return DETECTED;
    }

    return CLEAN;
}
```

### False Positive Risks

| Scenario                                    | Mitigation                                                                                                  |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| JIT-compiled code calling detection         | JIT code is in `jit-cache` (anonymous but legitimate) — whitelist `jit-cache` and `jit-zygote-cache` ranges |
| Dynamically loaded plugins (DexClassLoader) | Plugin SO modules are file-backed — should pass validation                                                  |
| Signal handler context                      | Return address in signal trampoline — whitelist `[vdso]` and signal return stubs                            |
| Tail call optimization                      | Compiler may use `B` instead of `BL` — LR retains grandparent's address; may appear as unexpected module    |

---

## References

- ARM Architecture Reference Manual — Link Register and procedure call standard
- Android AAPCS64 calling convention
- Stack unwinding: `_Unwind_Backtrace` documentation
