# SVC Direct Syscall

> Bypasses all userspace function hooks by invoking Linux kernel syscalls directly through the ARM SVC instruction, eliminating reliance on libc wrappers.

---

## Overview

The SVC (Supervisor Call) instruction triggers a synchronous exception that transitions execution from EL0 (userspace) to EL1 (kernel), allowing direct invocation of kernel syscalls without passing through any libc wrapper functions. On ARM64, the instruction is `SVC #0` with the syscall number in register `x8`; on ARM32, it is `SVC #0` with the syscall number in register `r7`. This technique is the anti-evasion foundation for all other detection strategies: since attackers primarily hook userspace functions (e.g., `open()`, `read()`, `stat()`) via GOT/PLT patching, LD_PRELOAD injection, or inline hooking, any detection code that calls libc is vulnerable to being silently filtered. By emitting SVC instructions via inline assembly, detection code communicates directly with the kernel, rendering all userspace interception mechanisms ineffective.

From a defender's perspective, SVC-based system calls are critical because they restore ground truth. The kernel does not lie about file existence, memory mappings, or process state — only userspace wrappers can be manipulated to hide this information. Every other detection technique (procfs scanning, filesystem path checks, etc.) gains its reliability from being built on top of SVC calls.

---

## Injection Side

### How Attackers Use This Technique

1. **Identify target libc functions** — Attackers determine which libc functions (e.g., `open()`, `read()`, `access()`, `stat()`) are called by security detection code.
2. **Install userspace hooks** — Using GOT/PLT hijacking, LD_PRELOAD, or inline patching, attackers replace the libc function pointers with custom trampolines.
3. **Filter sensitive results** — The hooked functions intercept calls and modify return values to hide artifacts. For example, a hooked `open("/proc/self/maps")` might return a filtered file descriptor that omits lines containing injected library names.
4. **Rely on detection code calling libc** — The entire evasion strategy depends on detection code using standard libc wrappers rather than direct syscalls.

### Artifacts

| Artifact                        | Location                                      | Indicator                                                                           |
| ------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------- |
| GOT/PLT entry modification      | Process memory (`.got` / `.got.plt` sections) | Function pointer no longer points into libc `.text` segment                         |
| LD_PRELOAD environment variable | `/proc/self/environ`                          | Contains path to attacker-controlled shared library                                 |
| Inline hook trampoline          | libc `.text` memory pages                     | First bytes of function replaced with branch instruction to hook handler            |
| Injected shared library         | `/proc/self/maps`                             | Additional `.so` file mapped with execute permission                                |
| Modified page permissions       | `/proc/self/maps`                             | libc `.text` pages changed from `r-xp` to `rwxp` (write needed for inline patching) |

### Injection PoC _(optional)_

```pseudocode
// Attacker hooks libc open() to hide /proc/self/maps content
original_open = GOT["open"]
GOT["open"] = hook_open

function hook_open(path, flags):
    fd = original_open(path, flags)
    if path == "/proc/self/maps":
        return create_filtered_fd(fd)  // removes lines with injected SO names
    return fd
```

### Evasion Techniques

| Evasion              | Description                                                                                                |
| -------------------- | ---------------------------------------------------------------------------------------------------------- |
| GOT/PLT hijacking    | Overwrite Global Offset Table entries so libc calls redirect to attacker-controlled functions              |
| LD_PRELOAD injection | Load a shared library before libc that exports identically-named functions, shadowing the originals        |
| Inline hooking       | Patch the first instructions of a libc function to jump to a hook handler, then optionally trampoline back |
| Namespace isolation  | Use `dlopen` with custom linker namespaces to load a modified libc that intercepts calls                   |

---

## Detection Side

### Mechanism

The invariant is that the Linux kernel syscall interface is immutable from userspace. No matter how many layers of hooking exist in libc, the dynamic linker, or injected shared libraries, an `SVC #0` instruction with the correct syscall number and register arguments will always reach the kernel directly. The kernel returns ground-truth results for file operations, memory queries, and process state — results that userspace hooks cannot intercept or modify without kernel-level access (which requires a custom kernel module or hypervisor).

### Anti-Evasion Properties

| Property                    | Explanation                                                                                                                           |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Resistant to libc hooks     | SVC does not call any libc function; the instruction transfers control directly to the kernel exception vector                        |
| Resistant to GOT/PLT hijack | No PLT stub or GOT indirection is involved; the syscall is emitted as inline assembly                                                 |
| Resistant to LD_PRELOAD     | LD_PRELOAD only affects dynamic symbol resolution; inline assembly is resolved at compile time                                        |
| Resistant to inline hooking | The SVC instruction is embedded in the caller's `.text` section, not in libc; patching the caller requires knowing its exact location |
| Remaining bypass surface    | Kernel-level interception (LKM, KernelSU hooks) can still modify syscall results; seccomp-bpf filters can block specific syscalls     |

### Detection Strategy

1. **Define SVC wrapper functions** — For each required syscall, write an inline assembly function that loads the syscall number into the appropriate register (`x8` on ARM64, `r7` on ARM32), places arguments in `x0`–`x5` (or `r0`–`r5`), executes `SVC #0`, and returns the result from `x0` (or `r0`).
2. **Map syscall numbers per architecture** — Use the correct syscall numbers for each ABI:
   - ARM64: `openat`=56, `read`=63, `close`=57, `write`=64, `faccessat`=48, `newfstatat`=79, `mmap`=222, `munmap`=215, `getdents64`=61, `socket`=198, `connect`=203
   - ARM32: `openat`=322, `read`=3, `close`=6, `write`=4, `faccessat`=334, `fstatat64`=327, `mmap2`=192, `munmap`=91
3. **Replace all libc calls in detection code** — Every file open, read, stat, and access operation in the detection engine must use the SVC wrapper instead of the corresponding libc function.
4. **Validate SVC integrity** — Optionally, verify that the SVC instruction bytes in the compiled binary have not been patched at runtime by checksumming the detection code's own `.text` pages.

### Detection PoC _(optional)_

```pseudocode
// ARM64 SVC wrapper for openat syscall
function svc_openat(dirfd, pathname, flags, mode):
    register x8 = 56          // __NR_openat on ARM64
    register x0 = dirfd
    register x1 = pathname
    register x2 = flags
    register x3 = mode
    execute "SVC #0"
    return x0                  // fd or negative errno

// Usage: open /proc/self/maps bypassing any libc hooks
fd = svc_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0)
if fd >= 0:
    buffer = svc_read(fd, buf, sizeof(buf))
    svc_close(fd)
    // parse buffer for injected library indicators
```

### False Positive Risks

| Scenario                                               | Mitigation                                                                                                          |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| Syscall number mismatch across ABI versions            | Use compile-time architecture detection (`#ifdef __aarch64__`) to select correct syscall numbers                    |
| seccomp-bpf blocking SVC calls                         | Detect seccomp filters via `/proc/self/status` Seccomp field; if active, fall back to alternative detection methods |
| Compiler reordering or optimizing away inline assembly | Use `volatile` and memory clobber constraints to prevent compiler from removing or reordering SVC instructions      |

---

## References

- [Linux syscall table for ARM64 (kernel source)](https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/unistd.h)
- [Linux syscall table for ARM32 (kernel source)](https://github.com/torvalds/linux/blob/master/arch/arm/tools/syscall.tbl)
- [ARM Architecture Reference Manual — SVC instruction](https://developer.arm.com/documentation/ddi0487/latest)
- [Android NDK inline assembly guide](https://developer.android.com/ndk/guides/cpu-arm-neon)
