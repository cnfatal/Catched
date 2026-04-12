# ELF Segment Gap Analysis

> Detects trampoline code injected into unused padding between ELF LOAD segments or within dead code regions of loaded shared libraries.

---

## Overview

When the Android dynamic linker loads an ELF shared object, LOAD segments are mapped at page-aligned boundaries, creating padding gaps between the end of actual segment content and the next page boundary. Frameworks like ShadowHook exploit these gaps to place trampoline code without allocating new anonymous executable memory — making the injection invisible to anonymous-page-based detection. Additionally, unused symbol code (functions present in the ELF but never called at runtime) can be silently overwritten. Because the trampoline resides inside a legitimate SO's mapped region, `/proc/self/maps` reports it as part of the original library. Detecting these injections requires byte-level comparison of in-memory segment content against the on-disk ELF file.

---

## Injection Side

### How Attackers Use This Technique

1. **Parse `/proc/self/maps`** — Locate loaded shared objects (e.g., `libart.so`, `libc.so`) and their LOAD segment boundaries.
2. **Calculate gap size** — `page_aligned_end - actual_segment_end` typically yields tens to thousands of bytes per segment. For example, if `.text` ends at `0x7f12345abc` and the page boundary is `0x7f12346000`, the gap is ~1.3 KB.
3. **Make gap writable** — Call `mprotect(addr, len, PROT_READ | PROT_WRITE)` on the page containing the gap.
4. **Write trampoline** — `memcpy()` the trampoline shellcode (e.g., `LDR X16, #literal; BR X16`) into the gap region.
5. **Restore permissions** — Call `mprotect(addr, len, PROT_READ | PROT_EXEC)` to make the gap executable again.
6. **Patch target function** — Overwrite the first instruction(s) of the target function with a branch into the gap trampoline.
7. **Result** — The trampoline lives inside `libart.so` or `libc.so`'s own mapped region. `/proc/self/maps` shows it as part of the legitimate SO — no anonymous executable pages are created.

**Alternative (dead code overwrite):**

1. **Identify unused symbols** — Scan the ELF `.symtab` / `.dynsym` for functions that are never called at runtime (e.g., `__linker_init` remnants, deprecated internal helpers).
2. **Overwrite function body** — Replace the original instructions of the dead function with trampoline code.
3. **Patch target** — Branch from the hooked function into the overwritten dead code region.

### Artifacts

| Artifact                  | Location                                         | Indicator                                                                                  |
| ------------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| Non-zero bytes in padding | Between segment `p_filesz` end and page boundary | On-disk these bytes are zero; in memory they contain executable code                       |
| Modified dead code        | Unused function bodies within `.text`            | Original function bytes replaced with trampoline instructions                              |
| Transient `mprotect`      | Syscall trace                                    | `mprotect` on system library `.text` pages — should never happen during normal execution   |
| Branch target in gap      | Hooked function entry point                      | Branch destination falls within gap region (past actual `.text` end, before page boundary) |

### Evasion Techniques

| Evasion                   | Description                                                                                 | Bypass Difficulty |
| ------------------------- | ------------------------------------------------------------------------------------------- | ----------------- |
| Use smallest gap possible | Minimize footprint to 4–8 bytes — hard to distinguish from alignment padding                | ★★★★              |
| Encrypt trampoline        | XOR-encrypt trampoline bytes and decrypt only immediately before use; re-encrypt after      | ★★★               |
| Multiple small injections | Spread trampoline fragments across many gaps — no single large anomaly                      | ★★★★              |
| Use system SO gaps only   | Inject into `libc.so` / `libart.so` gaps — defender must verify all system SOs exhaustively | ★★★               |

---

## Detection Side

### Mechanism

ELF segment padding between actual content end (`p_filesz`) and the page-aligned boundary should be zero-filled. The dynamic linker maps the file content and the kernel zero-fills the remainder of the last page. If non-zero executable instructions appear in these padding regions at runtime, something wrote them after loading — indicating code injection.

### Anti-Evasion Properties

| Property                    | Explanation                                                                                                                              |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Resistant to libc hooks     | File reads via SVC (`openat` + `read`); memory reads via direct pointer dereference                                                      |
| Resistant to GOT/PLT hijack | Custom ELF parser with no `dlsym` / `dlopen` calls                                                                                       |
| SVC bypass benefit          | On-disk file content read via kernel syscall is trustworthy even when libc is hooked                                                     |
| Remaining bypass surface    | Attacker could redirect `openat` to a modified file — cross-validate with multiple file access methods (e.g., `pread`, `/proc/self/fd/`) |

### Detection Strategy

1. **Read `/proc/self/maps` via SVC** — Use `openat` + `read` syscalls directly (ARM64: SVC #0) to obtain all file-backed executable (`r-xp`) segment entries.
2. **Parse ELF headers from disk** — For each mapped SO, open the file via SVC `openat` and parse the ELF program headers to extract each LOAD segment's `p_offset`, `p_filesz`, and `p_memsz`.
3. **Calculate gap region** — The gap spans from `(load_base + p_offset + p_filesz)` to `page_align_up(load_base + p_offset + p_memsz)`.
4. **Read memory content** — Dereference the gap address range directly (no syscall needed — it is in-process memory).
5. **Read disk content** — Read the corresponding file offset range via SVC `openat` + `pread`.
6. **Compare** — If memory contains non-zero bytes where disk has zeros, flag as injection.
7. **Instruction pattern scan** — Additionally scan for known trampoline patterns (`B imm`, `LDR Xn, #literal; BR Xn`, `ADRP + ADD + BR`) in the gap region.
8. **Dead code validation** — For selected symbols (known unused or rarely-used functions), compare in-memory function body against on-disk content. Any mismatch indicates overwrite.

### Detection PoC

```c
// ELF Segment Gap Analysis
// Detect trampoline code injected into padding between LOAD segments

#include <elf.h>
#include <linux/fcntl.h>

#define SYS_openat  56
#define SYS_read    63
#define SYS_pread64 67
#define SYS_close   57

// SVC wrappers (ARM64)
static long svc_openat(int dirfd, const char *path, int flags) {
    register long x8 __asm__("x8") = SYS_openat;
    register long x0 __asm__("x0") = dirfd;
    register long x1 __asm__("x1") = (long)path;
    register long x2 __asm__("x2") = flags;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}

static long svc_pread64(int fd, void *buf, unsigned long count, long offset) {
    register long x8 __asm__("x8") = SYS_pread64;
    register long x0 __asm__("x0") = fd;
    register long x1 __asm__("x1") = (long)buf;
    register long x2 __asm__("x2") = count;
    register long x3 __asm__("x3") = offset;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    return x0;
}

static long svc_close(int fd) {
    register long x8 __asm__("x8") = SYS_close;
    register long x0 __asm__("x0") = fd;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}

#define PAGE_SIZE 4096
#define PAGE_ALIGN_UP(x) (((x) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

typedef struct {
    unsigned long base;      // mapping base address
    const char  *path;       // SO file path
} MappedSo;

int check_segment_gap(MappedSo *so) {
    int result = 0;

    // Step 1: Open the on-disk ELF file via SVC
    int fd = svc_openat(AT_FDCWD, so->path, O_RDONLY);
    if (fd < 0) return -1;

    // Step 2: Read ELF header
    Elf64_Ehdr ehdr;
    svc_pread64(fd, &ehdr, sizeof(ehdr), 0);

    // Step 3: Iterate LOAD segments
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        svc_pread64(fd, &phdr, sizeof(phdr),
                    ehdr.e_phoff + i * ehdr.e_phentsize);

        if (phdr.p_type != PT_LOAD) continue;
        if (!(phdr.p_flags & PF_X))  continue;  // only check executable segments

        // Step 4: Calculate gap region
        unsigned long content_end = so->base + phdr.p_offset + phdr.p_filesz;
        unsigned long page_end    = PAGE_ALIGN_UP(so->base + phdr.p_offset + phdr.p_memsz);
        unsigned long gap_size    = page_end - content_end;

        if (gap_size == 0) continue;

        // Step 5: Read on-disk bytes at the gap offset
        unsigned char disk_buf[PAGE_SIZE];
        unsigned long read_len = gap_size < PAGE_SIZE ? gap_size : PAGE_SIZE;
        svc_pread64(fd, disk_buf, read_len, phdr.p_offset + phdr.p_filesz);

        // Step 6: Compare memory vs disk
        unsigned char *mem_ptr = (unsigned char *)content_end;
        for (unsigned long j = 0; j < read_len; j++) {
            if (mem_ptr[j] != 0 && disk_buf[j] == 0) {
                // Non-zero byte in memory where disk has zero — injection detected
                result |= 1;
                break;
            }
        }

        // Step 7: Scan for trampoline instruction patterns (ARM64)
        for (unsigned long j = 0; j + 3 < read_len; j += 4) {
            unsigned int insn = *(unsigned int *)(mem_ptr + j);
            // Check for B (unconditional branch): opcode 000101xx
            if ((insn & 0xFC000000) == 0x14000000) {
                result |= 2;  // branch instruction in gap
                break;
            }
            // Check for BR Xn: 1101011_0000_11111_000000_Xn_00000
            if ((insn & 0xFFFFFC1F) == 0xD61F0000) {
                result |= 2;  // BR instruction in gap
                break;
            }
        }
    }

    svc_close(fd);
    return result;
}
```

### False Positive Risks

| Scenario                                   | Mitigation                                                                                                |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| SO packing modifying `.text`               | Skip packed SOs — detect via `DT_TEXTREL` flag or encrypted section markers in the dynamic section        |
| Linker text relocations                    | Legacy SOs with `TEXTREL` flag may legitimately modify `.text` at load time — check `DT_TEXTREL` and skip |
| Memory-mapped file modifications by kernel | Extremely rare — cross-validate with multiple reads at different times                                    |
| AOT-compiled code in `.odex`               | `.odex` / `.oat` files follow a different layout — verify separately with OAT-specific parsing            |

---

## References

- [ELF Specification — LOAD segment alignment and page padding](https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html)
- [ShadowHook source — ELF gap discovery and trampoline placement](https://github.com/niclas-egli/shadowhook)
- [Android dynamic linker (`linker64`) source — segment mapping logic](https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/)
