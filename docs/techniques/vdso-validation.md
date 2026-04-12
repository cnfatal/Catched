# VDSO Validation

> Validates the virtual dynamic shared object (vdso) mapping integrity by cross-checking its address from `getauxval(AT_SYSINFO_EHDR)` against `/proc/self/maps` to detect fake vdso regions hiding injected code.

---

## Overview

The vDSO (virtual dynamic shared object) is a small kernel-mapped shared library that provides fast userspace implementations of certain syscalls (`clock_gettime`, `gettimeofday`). It appears in `/proc/self/maps` as `[vdso]` with execute permission. Since it is a legitimate anonymous executable region, attackers can create fake vdso-like mappings to hide injected code — bypassing anonymous executable page detection that whitelists `[vdso]`. However, the real vdso address is available via `getauxval(AT_SYSINFO_EHDR)` from the kernel auxiliary vector, providing a ground truth that cannot be spoofed from userspace. Comparing this kernel-provided address against `/proc/self/maps` entries reliably detects fabricated vdso regions.

---

## Injection Side

### How Attackers Use This Technique

1. **Allocate anonymous executable memory** — Call `mmap(NULL, size, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)` to create a new executable region.
2. **Name the region** — Use `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, size, "[vdso]")` to label the mapping as `[vdso]` in `/proc/self/maps`.
3. **Place hook engine code** — Copy trampoline or hook dispatch logic into the fake vdso region.
4. **Patch target functions** — Overwrite target function entry points to branch into the fake vdso region.
5. **Result** — The injected code resides in a region labeled `[vdso]`, passing naive anonymous-executable-page scanners that whitelist vdso.

**Alternative (shadow vdso):**

1. **Map near real vdso** — Allocate a region adjacent to or near the real vdso address.
2. **Copy legitimate content** — Copy the real vdso ELF content into the new region.
3. **Append injected code** — Place additional trampoline or dispatcher code after the copied vdso content.
4. **Result** — Two `[vdso]` entries appear in maps; manual inspection may miss the duplicate.

### Artifacts

| Artifact                  | Location                             | Indicator                                                        |
| ------------------------- | ------------------------------------ | ---------------------------------------------------------------- |
| Multiple `[vdso]` entries | `/proc/self/maps`                    | More than 1 `[vdso]` mapping                                     |
| vdso address mismatch     | `getauxval(AT_SYSINFO_EHDR)` vs maps | Address from auxval does not match `[vdso]` in maps              |
| Oversized vdso            | `/proc/self/maps`                    | Real vdso is typically 1 page (4KB); larger is suspicious        |
| Named anonymous region    | `/proc/self/maps`                    | `[anon:vdso]` or similar naming pattern                          |
| Writable vdso             | `/proc/self/maps`                    | Real vdso has `r-xp`; writable vdso (`rw-p` / `rwxp`) is anomaly |

### Evasion Techniques

| Evasion                  | Description                                                 | Bypass Difficulty |
| ------------------------ | ----------------------------------------------------------- | ----------------- |
| Avoid vdso impersonation | Use other hiding techniques instead (ELF gap, JIT cache)    | N/A               |
| Patch maps output        | Hook `/proc/self/maps` reading to filter extra vdso entries | ★★                |
| Kernel module            | Modify actual vdso mapping or auxiliary vector via LKM      | ★★★★★             |

---

## Detection Side

### Mechanism

The kernel auxiliary vector entry `AT_SYSINFO_EHDR` provides the exact address where the kernel mapped the real vdso. This value is set at process creation time and stored in the process auxiliary vector — a read-only kernel data structure that cannot be modified from userspace. By comparing this address against all `[vdso]` entries in `/proc/self/maps`, the detector can:

1. Ensure exactly 1 `[vdso]` entry exists.
2. Verify the entry's start address matches the `getauxval` result.
3. Verify the mapping size is reasonable (typically 1 page = 4096 bytes).
4. Verify the permissions are `r-xp` (read + execute, not writable).

Any violation indicates a fabricated vdso mapping used to hide injected code.

### Anti-Evasion Properties

| Property                    | Explanation                                                                                                 |
| --------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Resistant to libc hooks     | `getauxval` reads from the process auxiliary vector (read-only kernel data); maps read via SVC directly     |
| Resistant to GOT/PLT hijack | `getauxval()` can be implemented inline by reading `AT_SYSINFO_EHDR` from the auxiliary vector on the stack |
| SVC bypass benefit          | `/proc/self/maps` content comes from the kernel — accurate regardless of userspace hooks                    |
| Remaining bypass surface    | Only kernel-level attacks (LKM) can modify the real auxiliary vector or kernel vdso mapping                 |

### Detection Strategy

1. **Get real vdso address** — Call `getauxval(AT_SYSINFO_EHDR)` to obtain the kernel-provided real vdso base address.
2. **Read `/proc/self/maps` via SVC** — Use `openat` + `read` syscalls directly (ARM64: SVC #0) to obtain the memory map without libc hooks.
3. **Count `[vdso]` entries** — Parse all lines with `[vdso]` in the path column; there must be exactly 1.
4. **Verify address match** — The single `[vdso]` entry's start address must equal the `getauxval` result.
5. **Verify mapping size** — The vdso mapping size must be ≤ 2 pages (8192 bytes); the real vdso is small.
6. **Verify permissions** — The vdso mapping must have `r-xp` permissions (not writable).
7. **Scan for fake named regions** — Check for any `[anon:vdso]` or `[anon:*vdso*]` named regions; these are fabricated.
8. **Optional: ELF symbol validation** — Parse the vdso ELF header at the real address and verify it contains only expected symbols (`__kernel_clock_gettime`, `__kernel_gettimeofday`, `__kernel_clock_getres`, `__kernel_rt_sigreturn`).

### Detection PoC

```c
// VDSO Validation
// Detect fake vdso regions by cross-checking getauxval(AT_SYSINFO_EHDR) against /proc/self/maps

#include <sys/auxv.h>
#include <linux/fcntl.h>

#define SYS_openat_ARM64  56
#define SYS_read_ARM64    63
#define SYS_close_ARM64   57

#define FLAG_VDSO_MULTIPLE    (1 << 0)  // More than 1 [vdso] entry
#define FLAG_VDSO_MISSING     (1 << 1)  // No [vdso] entry found
#define FLAG_VDSO_ADDR_MISMATCH (1 << 2)  // Address does not match auxval
#define FLAG_VDSO_OVERSIZED   (1 << 3)  // Mapping > 8192 bytes
#define FLAG_VDSO_WRITABLE    (1 << 4)  // Writable permission on vdso
#define FLAG_VDSO_FAKE_NAMED  (1 << 5)  // [anon:vdso] or similar region

// SVC wrappers (ARM64)
static long svc_openat(int dirfd, const char *path, int flags) {
    register long x8 __asm__("x8") = SYS_openat_ARM64;
    register long x0 __asm__("x0") = dirfd;
    register long x1 __asm__("x1") = (long)path;
    register long x2 __asm__("x2") = flags;
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8), "r"(x0), "r"(x1), "r"(x2));
    return x0;
}

static long svc_read(int fd, void *buf, unsigned long count) {
    register long x8 __asm__("x8") = SYS_read_ARM64;
    register long x0 __asm__("x0") = fd;
    register long x1 __asm__("x1") = (long)buf;
    register long x2 __asm__("x2") = count;
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8), "r"(x0), "r"(x1), "r"(x2));
    return x0;
}

static long svc_close(int fd) {
    register long x8 __asm__("x8") = SYS_close_ARM64;
    register long x0 __asm__("x0") = fd;
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8), "r"(x0));
    return x0;
}

typedef struct {
    unsigned long start;
    unsigned long end;
    char perms[5];
    char name[256];
} MapEntry;

int validate_vdso(void) {
    int result = 0;

    // Step 1: Get kernel-provided real vdso address
    uintptr_t real_vdso = getauxval(AT_SYSINFO_EHDR);

    // Step 2: Read /proc/self/maps via SVC
    int fd = svc_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY);
    if (fd < 0) return -1;

    char buf[65536];
    long total = 0, n;
    while ((n = svc_read(fd, buf + total, sizeof(buf) - total - 1)) > 0)
        total += n;
    buf[total] = '\0';
    svc_close(fd);

    // Step 3: Parse and validate [vdso] entries
    int vdso_count = 0;
    uintptr_t found_addr = 0;
    size_t found_size = 0;
    char found_perms[5] = {0};

    // ... parse each line of buf ...
    // For each line containing "[vdso]":
    //   parse start, end, perms
    //   vdso_count++
    //   found_addr = start; found_size = end - start;
    //   memcpy(found_perms, perms, 4);

    if (vdso_count == 0) {
        // Some architectures may not have vdso — not necessarily an anomaly
        // Only flag if real_vdso != 0 (kernel says vdso exists but maps has none)
        if (real_vdso != 0)
            result |= FLAG_VDSO_MISSING;
        return result;
    }

    if (vdso_count > 1) {
        result |= FLAG_VDSO_MULTIPLE;  // Multiple [vdso] entries — injection
    }

    // Step 4: Verify address matches kernel auxval
    if (found_addr != real_vdso) {
        result |= FLAG_VDSO_ADDR_MISMATCH;
    }

    // Step 5: Verify size is reasonable (≤ 2 pages)
    if (found_size > 8192) {
        result |= FLAG_VDSO_OVERSIZED;
    }

    // Step 6: Verify permissions are r-xp (not writable)
    if (found_perms[1] == 'w') {
        result |= FLAG_VDSO_WRITABLE;
    }

    // Step 7: Scan for fake named vdso regions — [anon:vdso] or similar
    // ... scan buf for lines containing "anon:vdso" or "anon:*vdso*" ...
    // if found: result |= FLAG_VDSO_FAKE_NAMED;

    return result;
}
```

### False Positive Risks

| Scenario                      | Mitigation                                                                                                      |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------- |
| No vdso on some architectures | Some Android devices or architectures may not have vdso; treat `vdso_count == 0` with `real_vdso == 0` as clean |
| `[vvar]` mapping              | `[vvar]` is a separate kernel mapping for vdso data variables — do not confuse with `[vdso]`                    |
| AArch32 compatibility mode    | 32-bit processes may have a different vdso size; adjust the size threshold accordingly                          |
| Custom ROM kernels            | Some custom kernels may have a larger vdso with additional symbols; use a generous size threshold (≤ 2 pages)   |

---

## References

- Linux vDSO documentation: https://man7.org/linux/man-pages/man7/vdso.7.html
- `getauxval(3)`: https://man7.org/linux/man-pages/man3/getauxval.3.html
- "用户态注入已死" — vdso validation section
