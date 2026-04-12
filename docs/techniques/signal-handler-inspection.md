# Signal Handler Inspection

> Detects non-default signal handlers (SIGSYS, SIGSEGV, SIGBUS) registered by injection frameworks for syscall interception and safe memory probing.

---

## Overview

Multiple injection techniques rely on custom signal handlers to intercept or recover from specific CPU/kernel events. Seccomp-bpf uses `SECCOMP_RET_TRAP` which delivers SIGSYS to the offending thread — the attacker must register a SIGSYS handler via `sigaction()` to intercept the signal, inspect `ucontext_t`, and redirect or modify syscall arguments. ShadowHook registers SIGSEGV/SIGBUS handlers for safe memory probing during hook installation, catching faults when reading potentially unmapped or guard-paged pages. Frida-gadget may register signal handlers for crash recovery, preventing agent faults from terminating the host process. Detecting these non-default handlers — especially SIGSYS with disposition other than `SIG_DFL` — reveals active injection frameworks with high confidence.

---

## Injection Side

### How Attackers Use This Technique

1. **Seccomp-bpf + SIGSYS** — Install a `SECCOMP_RET_TRAP` BPF filter via `prctl(PR_SET_SECCOMP)` or `seccomp(SECCOMP_SET_MODE_FILTER)`, then register a SIGSYS handler via `sigaction()`. When the filter traps a syscall, the kernel delivers SIGSYS to the thread. The handler inspects `siginfo_t->si_syscall` and `ucontext_t` to read/modify syscall arguments and redirect file paths (e.g., rewriting `/proc/self/maps` opens to a sanitized copy).
2. **ShadowHook safe mode** — Register a SIGSEGV handler before probing memory that may be unmapped or protected. Attempt read/write operations on target pages; if the page is not mapped, the handler catches the fault and resumes execution at a safe recovery point, avoiding a process crash.
3. **Frida crash guard** — Register SIGSEGV/SIGBUS handlers to prevent faults during JavaScript agent execution from terminating the host process. The handler records the fault context and safely unwinds the Frida agent stack.
4. **Substrate safe mode** — Similar SIGSEGV handler pattern for safe memory probing during hook trampoline installation, catching faults on guard pages or partially mapped regions.

### Artifacts

| Artifact          | Location                            | Indicator                                                                                      |
| ----------------- | ----------------------------------- | ---------------------------------------------------------------------------------------------- |
| SIGSYS handler    | `rt_sigaction(SIGSYS)` disposition  | Non-`SIG_DFL`/`SIG_IGN` handler function pointer                                               |
| SIGSEGV handler   | `rt_sigaction(SIGSEGV)` disposition | Custom handler outside expected range (not in `libart.so`, `libsigchain.so`)                   |
| SIGBUS handler    | `rt_sigaction(SIGBUS)` disposition  | Custom handler with `SA_SIGINFO` flag                                                          |
| Handler address   | Signal disposition function pointer | Points to injected SO or anonymous memory region                                               |
| `SA_SIGINFO` flag | `sigaction` flags field             | Indicates handler uses `siginfo_t` + `ucontext_t` (required for syscall argument interception) |

### Evasion Techniques

| Evasion                             | Description                                                                                                                                     | Bypass Difficulty |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| Handler chaining                    | Save the previous handler via `sigaction()` and chain to it after processing — appears as a transparent wrapper that passes signals through     | ★★★               |
| Handler in `.text` of legitimate SO | Place handler code in a reserved section of a legitimate-looking shared library to appear as a normal library function                          | ★★★★              |
| Temporary handler                   | Register handler only during critical operations (e.g., seccomp filter setup), restore `SIG_DFL` immediately after — minimizes detection window | ★★★               |
| `sigprocmask` blocking              | Block signals during handler swap using `sigprocmask()` to prevent race-condition-based detection that samples handler state asynchronously     | ★★                |

---

## Detection Side

### Mechanism

In a clean Android process, SIGSYS has disposition `SIG_DFL` (which terminates the process on delivery). SIGSEGV is handled by ART's signal chain (`libsigchain.so` → `libart.so`) for null pointer exceptions, stack overflow detection, and implicit suspend checks. Any SIGSYS handler other than `SIG_DFL` strongly indicates seccomp-bpf syscall interception — there is no legitimate Android framework reason to handle SIGSYS. A SIGSEGV handler whose function pointer falls outside the `libart.so` / `libsigchain.so` address range indicates that an external injection framework has registered its own handler.

### Anti-Evasion Properties

| Property                    | Explanation                                                                                                                                                         |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Resistant to libc hooks     | `rt_sigaction` invoked via `SVC #0` directly, bypassing any libc wrapper hook                                                                                       |
| Resistant to GOT/PLT hijack | No library calls needed — detection logic uses inline assembly SVC and pointer arithmetic only                                                                      |
| SVC bypass benefit          | Attacker cannot hook the `sigaction` query itself without kernel-level control (seccomp cannot filter `rt_sigaction` without breaking its own handler registration) |
| Remaining bypass surface    | Attacker can chain handler through `libsigchain` API; detecting chained handlers requires deeper analysis of the signal chain linked list                           |

### Detection Strategy

1. **Query SIGSYS disposition** — Call `rt_sigaction(SIGSYS, NULL, &old_action, sizeof(sigset_t))` via SVC directly (syscall number: ARM64=134, ARM32=174) to retrieve the current SIGSYS handler without triggering any libc hook.
2. **Evaluate SIGSYS handler** — If `old_action.sa_handler != SIG_DFL && old_action.sa_handler != SIG_IGN`, a SIGSYS handler is registered. This is a **strong indicator of seccomp-bpf syscall interception**.
3. **Query SIGSEGV disposition** — Call `rt_sigaction(SIGSEGV, NULL, &old_action, ...)` via SVC to retrieve the current SIGSEGV handler.
4. **Resolve legitimate handler ranges** — Parse `/proc/self/maps` to find the memory address ranges of `libart.so` and `libsigchain.so`.
5. **Validate SIGSEGV handler origin** — Check if `old_action.sa_sigaction` (function pointer) falls within the `libart.so` or `libsigchain.so` address range. If not, an external framework registered it.
6. **Inspect handler flags** — Check `old_action.sa_flags` for `SA_SIGINFO` — this flag indicates the handler receives `siginfo_t` and `ucontext_t`, which is required for syscall argument manipulation.
7. **Repeat for SIGBUS** — Apply the same disposition query and address-range validation for SIGBUS.
8. **Cross-validate with seccomp status** — Read `/proc/self/status` and check the `Seccomp:` field. A combination of SIGSYS handler present + `Seccomp: 2` (filter mode) confirms active syscall interception.

### Detection PoC

```c
// Signal Handler Inspection: detect non-default SIGSYS/SIGSEGV/SIGBUS handlers via SVC

#include <signal.h>
#include <linux/seccomp.h>

#define SYS_rt_sigaction_ARM64  134
#define SYS_rt_sigaction_ARM32  174

struct kernel_sigaction old_action;

// Step 1: Query SIGSYS handler via direct SVC (ARM64 example)
static long svc_rt_sigaction(int signum, const struct kernel_sigaction *act,
                             struct kernel_sigaction *oldact, size_t sigsetsize) {
    register long x8 __asm__("x8") = SYS_rt_sigaction_ARM64;
    register long x0 __asm__("x0") = signum;
    register long x1 __asm__("x1") = (long)act;
    register long x2 __asm__("x2") = (long)oldact;
    register long x3 __asm__("x3") = sigsetsize;
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3));
    return x0;
}

int check_signal_handlers(void) {
    int result = 0;

    // Check SIGSYS — any non-default handler is suspicious
    svc_rt_sigaction(SIGSYS, NULL, &old_action, sizeof(sigset_t));
    if (old_action.sa_handler != SIG_DFL && old_action.sa_handler != SIG_IGN) {
        // SIGSYS handler registered — strong seccomp interception indicator
        result |= FLAG_SIGSYS_HANDLER;
    }

    // Check SIGSEGV — validate handler is within ART signal chain
    svc_rt_sigaction(SIGSEGV, NULL, &old_action, sizeof(sigset_t));
    if (old_action.sa_handler != SIG_DFL && old_action.sa_handler != SIG_IGN) {
        uintptr_t handler_addr = (uintptr_t)old_action.sa_sigaction;
        if (!addr_in_range(handler_addr, libart_base, libart_end) &&
            !addr_in_range(handler_addr, libsigchain_base, libsigchain_end)) {
            // SIGSEGV handler outside ART — injection framework suspected
            result |= FLAG_SIGSEGV_EXTERNAL;
        }
    }

    // Check SA_SIGINFO flag — needed for ucontext_t syscall arg access
    if (old_action.sa_flags & SA_SIGINFO) {
        result |= FLAG_SIGINFO_ENABLED;
    }

    // Cross-validate: read /proc/self/status Seccomp field
    int seccomp_mode = read_proc_seccomp_status();  // via SVC openat/read
    if ((result & FLAG_SIGSYS_HANDLER) && seccomp_mode == 2) {
        result |= FLAG_SECCOMP_INTERCEPTION_CONFIRMED;
    }

    return result;
}
```

### False Positive Risks

| Scenario                                | Mitigation                                                                                                                                                             |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ART signal chain (SIGSEGV)              | ART legitimately handles SIGSEGV for null checks and stack overflow — verify handler address falls within `libart.so` / `libsigchain.so` address range before flagging |
| Crashlytics / Bugly crash reporters     | Third-party crash reporting SDKs register SIGSEGV handlers — check if handler address resolves to a known crash SDK SO (e.g., `libcrashlytics.so`, `libBugly.so`)      |
| App using SIGSEGV for memory protection | Rare but possible in apps using `mprotect`-based guard pages — whitelist known legitimate handler addresses from the app's own SOs                                     |
| Android debugger (SIGTRAP)              | Debugger uses SIGTRAP, not SIGSYS — irrelevant to this check and should not be confused with injection indicators                                                      |

---

## References

- Linux `rt_sigaction(2)` man page — <https://man7.org/linux/man-pages/man2/rt_sigaction.2.html>
- Android signal chain (`libsigchain.so`) — <https://android.googlesource.com/platform/art/+/refs/heads/main/sigchainlib/>
- ShadowHook signal handling source — <https://github.com/bytedance/android-inline-hook>
- Linux seccomp(2) — `SECCOMP_RET_TRAP` and SIGSYS delivery — <https://man7.org/linux/man-pages/man2/seccomp.2.html>
