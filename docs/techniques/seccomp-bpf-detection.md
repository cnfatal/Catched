# Seccomp-BPF Filter Detection

> Detect attacker-installed seccomp-BPF filters that intercept SVC direct syscalls via SIGSYS signal handlers — the only userspace mechanism capable of bypassing Catched's SVC-based anti-evasion strategy.

---

## Overview

Seccomp-BPF (Secure Computing with Berkeley Packet Filter) allows a process to install kernel-level filters that inspect every syscall before execution. When an attacker installs a BPF program that returns `SECCOMP_RET_TRAP` for targeted syscalls (e.g., `openat`), the kernel delivers a SIGSYS signal instead of executing the syscall. A custom SIGSYS handler can then inspect and modify syscall arguments — including file path redirection — before re-executing the syscall with altered parameters. This is critical because seccomp-BPF + SIGSYS is the **only** userspace mechanism that can intercept SVC (`#0`) direct syscalls, which form the foundation of Catched's detection strategy. Seccomp filters are one-directional (can only be tightened, never loosened), meaning once installed they persist for the lifetime of the process.

---

## Injection Side

### How Attackers Use This Technique

1. **Early initialization** — Install the BPF filter in `.init_array` or `JNI_OnLoad`, ensuring it is active before any defender code runs.
2. **Compile BPF bytecode** — Write a BPF program that matches specific syscall numbers (e.g., `openat` = 56 on ARM64, 322 on ARM32) and returns `SECCOMP_RET_TRAP`.
3. **Install filter** — Call `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)` to load the BPF program into the kernel seccomp subsystem.
4. **Register SIGSYS handler** — Install a custom signal handler for `SIGSYS` via `sigaction()`.
5. **Intercept and redirect** — When the defender executes a filtered SVC syscall, the kernel delivers SIGSYS. The handler inspects `ucontext_t`, reads syscall arguments (`x0`–`x5` on ARM64), and can:
   - Modify the pathname argument (`x1`) to redirect file reads (e.g., `base.apk` → `original_base.apk`)
   - Modify the PC register (`+4` to skip the SVC instruction)
   - Execute a replacement syscall from within the handler
6. **Resume execution** — The handler returns, and the process continues with the attacker-controlled syscall result.

### Artifacts

| Artifact          | Location                        | Indicator                                   |
| ----------------- | ------------------------------- | ------------------------------------------- |
| Seccomp status    | `/proc/self/status`             | `Seccomp: 2` (filter mode active)           |
| SIGSYS handler    | Signal disposition              | Non-default SIGSYS handler registered       |
| Original APK copy | `/data/local/tmp/` or cache dir | Unmodified APK stored as redirect target    |
| BPF program       | Kernel seccomp state            | Custom filter rules beyond Android default  |
| Timing anomaly    | Syscall latency                 | 2–5μs additional delay per filtered syscall |

### Injection PoC _(optional)_

```c
// Pseudo-code: seccomp-BPF syscall interception (ARM64)

// 1. Build BPF filter targeting openat (NR=56)
struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),   // trigger SIGSYS
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),   // allow everything else
};
struct sock_fprog prog = { .len = 4, .filter = filter };

// 2. Register SIGSYS handler
struct sigaction sa = { .sa_sigaction = sigsys_handler, .sa_flags = SA_SIGINFO };
sigaction(SIGSYS, &sa, NULL);

// 3. Install seccomp filter
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);

// 4. SIGSYS handler: redirect file path
void sigsys_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *uc = (ucontext_t *)ctx;
    const char *path = (const char *)uc->uc_mcontext.regs[1];  // x1 = pathname
    if (strstr(path, "base.apk")) {
        uc->uc_mcontext.regs[1] = (uint64_t)"/data/local/tmp/original_base.apk";
    }
    // re-execute syscall with modified args
    uc->uc_mcontext.regs[0] = syscall(uc->uc_mcontext.regs[8],
        uc->uc_mcontext.regs[0], uc->uc_mcontext.regs[1],
        uc->uc_mcontext.regs[2], uc->uc_mcontext.regs[3]);
    uc->uc_mcontext.pc += 4;  // skip original SVC instruction
}
```

### Evasion Techniques

| Evasion             | Description                                                                                       | Bypass Difficulty |
| ------------------- | ------------------------------------------------------------------------------------------------- | ----------------- |
| Early installation  | Install filter in `.init_array` before any detection code executes                                | ★★★★              |
| Minimal filtering   | Only filter specific syscall numbers to reduce timing overhead                                    | ★★★               |
| Handler obfuscation | Use indirect jumps and encrypted function pointers in SIGSYS handler to frustrate static analysis | ★★★               |
| Zygote piggyback    | Blend custom filter rules with existing Zygote seccomp policy to appear as default configuration  | ★★★★              |

---

## Detection Side

### Mechanism

A clean Android process has seccomp status `0` (disabled) or `1` (strict mode, rare). Zygote forks with a default seccomp filter (status `2`), but this filter does **not** trap `openat` or `read` — it only restricts dangerous syscalls. If seccomp status is `2` **and** a custom SIGSYS handler is registered **and** `openat` syscalls show timing anomalies, an attacker has installed interception filters. Since `/proc/self/status` is a kernel-provided virtual file and `prctl()` is a direct syscall, these checks cannot be intercepted by userspace hooks — only by the very seccomp filter we are trying to detect, which creates a detectable failure mode.

### Anti-Evasion Properties

| Property                    | Explanation                                                                                                                                                              |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Resistant to libc hooks     | `/proc/self/status` read via SVC bypasses all userspace hooks (LD_PRELOAD, libc interposition)                                                                           |
| Resistant to GOT/PLT hijack | `prctl()` called via `SVC #0` directly, never resolving through the GOT/PLT                                                                                              |
| SVC bypass benefit          | Ironically, SVC is what the attacker is trying to intercept — but reading `/proc/self/status` itself is not typically filtered since blocking it would break the process |
| Remaining bypass surface    | Attacker could filter the detection's own `openat` of `/proc/self/status` — but this creates a detectable failure (read returns -1 or wrong content)                     |

### Detection Strategy

1. **Read seccomp status via SVC** — Open and read `/proc/self/status` using raw `SVC #0` for `openat` and `read`. Parse the `Seccomp:` field — value `2` indicates filter mode is active.
2. **Query seccomp mode via prctl** — Call `prctl(PR_GET_SECCOMP)` via SVC — returns `0` (disabled), `1` (strict), or `2` (filter). Cross-validate with `/proc/self/status`.
3. **Count installed filters** — Read the `Seccomp_filters:` field from `/proc/self/status` (Linux 5.10+). Compare the count against the expected Zygote baseline (typically 1). Extra filters indicate attacker activity.
4. **Check SIGSYS handler disposition** — Call `rt_sigaction(SIGSYS, NULL, &old_action)` via SVC. If `sa_handler` is not `SIG_DFL`, a custom SIGSYS handler has been registered.
5. **Timing side-channel** — Measure SVC `openat` latency on a known-good path (e.g., `/dev/null`). Latency >5μs suggests filter + handler overhead is present.
6. **Attempt own seccomp installation** — Try to install a minimal seccomp filter. If it fails with `EACCES`, another filter with `SECCOMP_FILTER_FLAG_TSYNC` may have locked new filter installation.
7. **Cross-validate** — If `Seccomp: 2` but the Zygote default does not filter `openat`, something extra was installed. Combine all signals for a high-confidence detection.

### Detection PoC _(optional)_

```c
// Pseudo-code: seccomp-BPF filter detection (ARM64)

// Step 1: Read /proc/self/status via raw SVC
int fd = svc_openat(AT_FDCWD, "/proc/self/status", O_RDONLY, 0);
char buf[4096];
svc_read(fd, buf, sizeof(buf));
svc_close(fd);
int seccomp_mode = parse_field(buf, "Seccomp:");
int filter_count = parse_field(buf, "Seccomp_filters:");

// Step 2: Verify via prctl SVC
int prctl_mode = svc_prctl(PR_GET_SECCOMP, 0, 0, 0, 0);

// Step 3: Check SIGSYS handler
struct sigaction old_sa;
svc_rt_sigaction(SIGSYS, NULL, &old_sa, sizeof(sigset_t));
bool custom_sigsys = (old_sa.sa_handler != SIG_DFL);

// Step 4: Timing check
uint64_t t0 = clock_gettime_monotonic_ns();
int tmp_fd = svc_openat(AT_FDCWD, "/dev/null", O_RDONLY, 0);
uint64_t t1 = clock_gettime_monotonic_ns();
svc_close(tmp_fd);
bool timing_anomaly = (t1 - t0) > 5000;  // >5μs

// Step 5: Decision
if (seccomp_mode == 2 && filter_count > 1) return DETECTED;  // extra filters
if (seccomp_mode == 2 && custom_sigsys)    return DETECTED;  // SIGSYS interception
if (seccomp_mode == 2 && timing_anomaly)   return SUSPICIOUS; // needs more evidence
return CLEAN;
```

### False Positive Risks

| Scenario                         | Mitigation                                                                                                                                               |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Android Zygote default seccomp   | Baseline `Seccomp: 2` is normal on modern Android; check `Seccomp_filters` count and validate that `openat` is not trapped by testing a benign open      |
| App using seccomp for sandboxing | Legitimate apps rarely use seccomp directly; flag but verify with SIGSYS handler check — sandbox filters use `SECCOMP_RET_ERRNO`, not `SECCOMP_RET_TRAP` |
| Chrome/WebView seccomp           | Renderer processes use seccomp; only flag if SIGSYS handler targets file I/O syscalls rather than the standard Chrome sandbox policy                     |

---

## References

- [Linux kernel seccomp filter documentation](https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt)
- [Android seccomp policy (Bionic)](https://android.googlesource.com/platform/bionic/+/refs/heads/main/libc/seccomp/)
- NPatch v0.8 Level 3 signature bypass implementation
