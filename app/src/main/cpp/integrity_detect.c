#include "integrity_detect.h"
#include "syscall_wrapper.h"
#include "maps_scanner.h"
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <elf.h>
#include <sys/auxv.h>
#include <android/log.h>

#define TAG "Catched"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

// ============================================================
// 辅助: 从 maps 中提取库的内存范围
// ============================================================

typedef struct
{
    unsigned long start;
    unsigned long end;
    char perms[5];
    unsigned long offset;
    char path[256];
} MapEntry;

static int parse_maps_entries(MapEntry *entries, int max_entries)
{
    char *buf = (char *)sg_mmap(NULL, 131072, 3, 0x22, -1, 0);
    if (buf == (char *)-1)
        return 0;

    ssize_t len = sg_read_file("/proc/self/maps", buf, 131072);
    if (len <= 0)
    {
        sg_munmap(buf, 131072);
        return 0;
    }

    int count = 0;
    char *line = buf;
    while (*line && count < max_entries)
    {
        char *next = line;
        while (*next && *next != '\n')
            next++;
        char saved = *next;
        *next = '\0';

        MapEntry *e = &entries[count];
        memset(e, 0, sizeof(MapEntry));

        // 解析 start
        const char *p = line;
        e->start = 0;
        while (*p && *p != '-')
        {
            unsigned long c = 0;
            if (*p >= '0' && *p <= '9')
                c = *p - '0';
            else if (*p >= 'a' && *p <= 'f')
                c = *p - 'a' + 10;
            else if (*p >= 'A' && *p <= 'F')
                c = *p - 'A' + 10;
            e->start = (e->start << 4) | c;
            p++;
        }
        if (*p == '-')
            p++;

        // 解析 end
        e->end = 0;
        while (*p && *p != ' ')
        {
            unsigned long c = 0;
            if (*p >= '0' && *p <= '9')
                c = *p - '0';
            else if (*p >= 'a' && *p <= 'f')
                c = *p - 'a' + 10;
            else if (*p >= 'A' && *p <= 'F')
                c = *p - 'A' + 10;
            e->end = (e->end << 4) | c;
            p++;
        }
        if (*p == ' ')
            p++;

        // 解析 perms
        for (int i = 0; i < 4 && *p && *p != ' '; i++)
            e->perms[i] = *p++;
        e->perms[4] = '\0';
        if (*p == ' ')
            p++;

        // 解析 offset
        e->offset = 0;
        while (*p && *p != ' ')
        {
            unsigned long c = 0;
            if (*p >= '0' && *p <= '9')
                c = *p - '0';
            else if (*p >= 'a' && *p <= 'f')
                c = *p - 'a' + 10;
            else if (*p >= 'A' && *p <= 'F')
                c = *p - 'A' + 10;
            e->offset = (e->offset << 4) | c;
            p++;
        }

        // 跳过 dev inode 到路径
        int spaces = 0;
        while (*p && spaces < 2)
        {
            if (*p == ' ')
                spaces++;
            p++;
        }
        while (*p == ' ')
            p++;

        // 复制路径
        size_t pi = 0;
        while (*p && *p != '\n' && pi < sizeof(e->path) - 1)
            e->path[pi++] = *p++;
        e->path[pi] = '\0';

        count++;
        *next = saved;
        if (*next)
            next++;
        line = next;
    }

    sg_munmap(buf, 131072);
    return count;
}

// ============================================================
// .text 段内存 vs 磁盘比对
// ============================================================

int detect_text_integrity(const char *so_path)
{
    if (!so_path)
        return 0;

    // 1. 打开 SO 文件读取 ELF header 和 program headers
    int fd = sg_open(so_path, O_RDONLY);
    if (fd < 0)
        return 0;

    // 读取 ELF header
#if defined(__aarch64__)
    Elf64_Ehdr ehdr;
#else
    Elf32_Ehdr ehdr;
#endif
    ssize_t n = sg_read(fd, &ehdr, sizeof(ehdr));
    if (n != sizeof(ehdr) || memcmp(ehdr.e_ident, "\x7f"
                                                  "ELF",
                                    4) != 0)
    {
        sg_close(fd);
        return 0;
    }

    // 2. 找到 SO 在内存中的基地址 (通过 maps)
    MapEntry entries[512];
    int entry_count = parse_maps_entries(entries, 512);
    unsigned long base_addr = 0;
    for (int i = 0; i < entry_count; i++)
    {
        if (entries[i].offset == 0 && strstr(entries[i].path, so_path) != NULL)
        {
            base_addr = entries[i].start;
            break;
        }
    }
    if (base_addr == 0)
    {
        sg_close(fd);
        return 0;
    }

    // 3. 读取 program headers 找 PT_LOAD with execute
#if defined(__aarch64__)
    Elf64_Phdr phdrs[32];
    int phdr_size = sizeof(Elf64_Phdr);
#else
    Elf32_Phdr phdrs[32];
    int phdr_size = sizeof(Elf32_Phdr);
#endif
    int phnum = ehdr.e_phnum > 32 ? 32 : ehdr.e_phnum;

    // 去到 program header table 位置
    // 用 lseek 不安全（可能被 hook），但我们用 read 从头开始
    // 重新打开并跳过到 phoff
    sg_close(fd);
    fd = sg_open(so_path, O_RDONLY);
    if (fd < 0)
        return 0;

    // 读取到 phoff 处
    char skip_buf[4096];
    size_t to_skip = (size_t)ehdr.e_phoff;
    while (to_skip > 0)
    {
        size_t chunk = to_skip > sizeof(skip_buf) ? sizeof(skip_buf) : to_skip;
        ssize_t rd = sg_read(fd, skip_buf, chunk);
        if (rd <= 0)
        {
            sg_close(fd);
            return 0;
        }
        to_skip -= rd;
    }

    n = sg_read(fd, phdrs, phnum * phdr_size);
    sg_close(fd);
    if (n < phnum * phdr_size)
        return 0;

    // 4. 找到可执行 LOAD 段 (PF_X)
    int diff_count = 0;
    for (int i = 0; i < phnum; i++)
    {
        if (phdrs[i].p_type != 1 /* PT_LOAD */)
            continue;
        if (!(phdrs[i].p_flags & 1 /* PF_X */))
            continue;

        // 这是 .text 所在的 LOAD 段
        unsigned long mem_addr = base_addr + phdrs[i].p_vaddr;
        size_t seg_size = phdrs[i].p_filesz;
        size_t file_offset = phdrs[i].p_offset;

        if (seg_size == 0 || seg_size > 16 * 1024 * 1024)
            continue;

        // 5. 从磁盘读取该段内容
        char *disk_buf = (char *)sg_mmap(NULL, seg_size, 3, 0x22, -1, 0);
        if (disk_buf == (char *)-1)
            continue;

        fd = sg_open(so_path, O_RDONLY);
        if (fd < 0)
        {
            sg_munmap(disk_buf, seg_size);
            continue;
        }

        to_skip = file_offset;
        while (to_skip > 0)
        {
            size_t chunk = to_skip > sizeof(skip_buf) ? sizeof(skip_buf) : to_skip;
            ssize_t rd = sg_read(fd, skip_buf, chunk);
            if (rd <= 0)
                break;
            to_skip -= rd;
        }

        ssize_t read_len = 0;
        while ((size_t)read_len < seg_size)
        {
            ssize_t rd = sg_read(fd, disk_buf + read_len, seg_size - read_len);
            if (rd <= 0)
                break;
            read_len += rd;
        }
        sg_close(fd);

        if ((size_t)read_len < seg_size)
        {
            sg_munmap(disk_buf, seg_size);
            continue;
        }

        // 6. 比较内存和磁盘内容
        const uint8_t *mem_ptr = (const uint8_t *)mem_addr;
        const uint8_t *disk_ptr = (const uint8_t *)disk_buf;
        for (size_t j = 0; j < seg_size; j++)
        {
            if (mem_ptr[j] != disk_ptr[j])
            {
                diff_count++;
                if (diff_count <= 3)
                {
                    LOGD("Text integrity: diff at offset 0x%zx (mem=0x%02x disk=0x%02x) in %s",
                         j, mem_ptr[j], disk_ptr[j], so_path);
                }
            }
        }

        sg_munmap(disk_buf, seg_size);
        break; // 只检查第一个可执行 LOAD 段
    }

    if (diff_count > 0)
    {
        LOGD("Text integrity: %d bytes differ in %s", diff_count, so_path);
    }
    return diff_count;
}

// ============================================================
// ELF LOAD 段间隙检测
// ============================================================

int detect_elf_segment_gap(void)
{
    MapEntry entries[512];
    int count = parse_maps_entries(entries, 512);
    int detected = 0;

    for (int i = 1; i < count; i++)
    {
        // 查找连续的、属于同一库的映射之间的匿名可执行间隙
        // 模式: [lib.so r-xp] [<anon> r-xp] [lib.so r--p]
        if (entries[i].perms[2] == 'x' && entries[i].path[0] == '\0')
        {
            // 匿名可执行页
            int prev_is_lib = (i > 0 && entries[i - 1].path[0] == '/' &&
                               entries[i - 1].perms[2] == 'x');
            int next_is_same_lib = (i + 1 < count && entries[i + 1].path[0] == '/' &&
                                    i > 0 && strcmp(entries[i - 1].path, entries[i + 1].path) == 0);

            if (prev_is_lib && next_is_same_lib)
            {
                LOGD("ELF segment gap: anon r-xp at 0x%lx-0x%lx between %s segments",
                     entries[i].start, entries[i].end, entries[i - 1].path);
                detected = 1;
            }
        }
    }
    return detected;
}

// ============================================================
// vDSO 完整性验证
// ============================================================

int detect_vdso_anomaly(void)
{
    // 1. 通过 getauxval 获取内核提供的 vDSO 地址
    unsigned long vdso_auxval = getauxval(AT_SYSINFO_EHDR);
    if (vdso_auxval == 0)
        return 0; // 平台不提供 vDSO

    // 2. 从 maps 中找 [vdso] 条目
    MapEntry entries[512];
    int count = parse_maps_entries(entries, 512);

    unsigned long vdso_maps_start = 0;
    for (int i = 0; i < count; i++)
    {
        if (strcmp(entries[i].path, "[vdso]") == 0)
        {
            vdso_maps_start = entries[i].start;
            break;
        }
    }

    // 3. 交叉验证
    if (vdso_maps_start == 0)
    {
        LOGD("vDSO: [vdso] not found in maps but auxval=0x%lx", vdso_auxval);
        return 1; // maps 被篡改，过滤掉了 vdso
    }

    if (vdso_auxval != vdso_maps_start)
    {
        LOGD("vDSO: address mismatch auxval=0x%lx maps=0x%lx", vdso_auxval, vdso_maps_start);
        return 1; // 地址不一致
    }

    // 4. 验证 vDSO 内容是 ELF
    uint32_t magic = *(uint32_t *)vdso_auxval;
    if (magic != 0x464C457F)
    { // \x7fELF
        LOGD("vDSO: invalid ELF magic at 0x%lx", vdso_auxval);
        return 1;
    }

    return 0;
}

// ============================================================
// Trampoline island 检测
// ============================================================

int detect_trampoline_islands(void)
{
    MapEntry entries[512];
    int count = parse_maps_entries(entries, 512);
    int detected = 0;

    for (int i = 0; i < count; i++)
    {
        // 匿名可执行段
        if (entries[i].perms[2] != 'x' || entries[i].path[0] != '\0')
            continue;
        // 跳过 [vdso] 和已知的 jit-cache
        if (strcmp(entries[i].path, "[vdso]") == 0)
            continue;

        unsigned long size = entries[i].end - entries[i].start;
        // Trampoline island 通常是 1-2 页 (4KB-8KB)
        if (size > 65536)
            continue;

        // 检查是否靠近某个已知库 (< 4GB，在 ADRP 范围内)
        int near_library = 0;
        for (int j = 0; j < count; j++)
        {
            if (j == i)
                continue;
            if (entries[j].path[0] != '/')
                continue;
            long long dist = (long long)entries[i].start - (long long)entries[j].start;
            if (dist < 0)
                dist = -dist;
            if (dist < (long long)4 * 1024 * 1024 * 1024LL)
            { // 4GB
                near_library = 1;
                break;
            }
        }

        if (!near_library)
            continue;

        // 读取内容检查跳转指令模式
        const uint8_t *code = (const uint8_t *)entries[i].start;

#if defined(__aarch64__)
        // 检查 Dobby 模式: LDR X17, #8; BR X17 (51 00 00 58 20 02 1F D6)
        // 检查 ShadowHook 模式: STP X16,X17,...; LDR X17; BR X17
        // 检查 android-inline-hook: LDR X16, #8; BR X16 (50 00 00 58 00 02 1F D6)
        int trampoline_count = 0;
        for (unsigned long off = 0; off + 16 <= size; off += 4)
        {
            // Dobby: 51 00 00 58 20 02 1F D6
            if (code[off] == 0x51 && code[off + 1] == 0x00 &&
                code[off + 2] == 0x00 && code[off + 3] == 0x58 &&
                code[off + 4] == 0x20 && code[off + 5] == 0x02 &&
                code[off + 6] == 0x1F && code[off + 7] == 0xD6)
            {
                trampoline_count++;
            }
            // android-inline-hook: 50 00 00 58 00 02 1F D6
            if (code[off] == 0x50 && code[off + 1] == 0x00 &&
                code[off + 2] == 0x00 && code[off + 3] == 0x58 &&
                code[off + 4] == 0x00 && code[off + 5] == 0x02 &&
                code[off + 6] == 0x1F && code[off + 7] == 0xD6)
            {
                trampoline_count++;
            }
        }
        if (trampoline_count >= 2)
        {
            LOGD("Trampoline island: %d trampolines in anon r-xp at 0x%lx-0x%lx",
                 trampoline_count, entries[i].start, entries[i].end);
            detected = 1;
        }
#elif defined(__arm__)
        int trampoline_count = 0;
        for (unsigned long off = 0; off + 8 <= size; off += 4)
        {
            // LDR PC, [PC, #-4]: 04 F0 1F E5
            if (code[off] == 0x04 && code[off + 1] == 0xF0 &&
                code[off + 2] == 0x1F && code[off + 3] == 0xE5)
            {
                trampoline_count++;
            }
            // Thumb: LDR.W PC, [PC, #0]: DF F8 00 F0
            if (code[off] == 0xDF && code[off + 1] == 0xF8 &&
                code[off + 2] == 0x00 && code[off + 3] == 0xF0)
            {
                trampoline_count++;
            }
        }
        if (trampoline_count >= 2)
        {
            LOGD("Trampoline island: %d trampolines in anon r-xp at 0x%lx-0x%lx",
                 trampoline_count, entries[i].start, entries[i].end);
            detected = 1;
        }
#endif
    }
    return detected;
}

// ============================================================
// libart.so 内部函数 Hook 检测
// ============================================================

int detect_libart_internal_hooks(void)
{
    void *handle = dlopen("libart.so", RTLD_NOLOAD);
    if (!handle)
        return 0;

    int detected = 0;

    // 检查几个关键函数的函数头是否被修改
    static const char *const symbols[] = {
        "_ZN3art11ClassLinker14RegisterNativeEPNS_6ThreadEPNS_9ArtMethodEPKv",
        "_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc",
    };
    int symbol_count = sizeof(symbols) / sizeof(symbols[0]);

    for (int i = 0; i < symbol_count; i++)
    {
        void *sym = dlsym(handle, symbols[i]);
        if (!sym)
            continue;

#if defined(__aarch64__)
        uint32_t *code = (uint32_t *)sym;
        uint32_t insn = code[0];

        // 检查 LDR Xn, =addr 模式
        if ((insn & 0xFF000000) == 0x58000000)
        {
            uint32_t next = code[1];
            if ((next & 0xFFFFFC1F) == 0xD61F0000)
            { // BR Xn
                LOGD("libart internal hook: trampoline at %s (%p)", symbols[i], sym);
                detected = 1;
            }
        }
        // 检查 B #imm 模式
        if ((insn & 0xFC000000) == 0x14000000)
        {
            LOGD("libart internal hook: B instruction at %s (%p)", symbols[i], sym);
            detected = 1;
        }
#elif defined(__arm__)
        uint32_t *code = (uint32_t *)((uintptr_t)sym & ~1);
        uint32_t insn = code[0];
        if ((insn & 0x0F7F0000) == 0x051F0000)
        {
            LOGD("libart internal hook: LDR PC at %s (%p)", symbols[i], sym);
            detected = 1;
        }
#endif
    }

    dlclose(handle);
    return detected;
}

// ============================================================
// 返回地址验证
// ============================================================

int detect_return_address_anomaly(void)
{
#if defined(__aarch64__)
    // 获取当前 LR (X30) 的值
    void *lr;
    __asm__ volatile("mov %0, x30" : "=r"(lr));
#elif defined(__arm__)
    void *lr;
    __asm__ volatile("mov %0, lr" : "=r"(lr));
#else
    return 0;
#endif

    unsigned long lr_addr = (unsigned long)lr;

    // 在 maps 中验证 LR 是否在合法库范围内
    MapEntry entries[512];
    int count = parse_maps_entries(entries, 512);

    for (int i = 0; i < count; i++)
    {
        if (entries[i].perms[2] != 'x')
            continue;
        if (lr_addr >= entries[i].start && lr_addr < entries[i].end)
        {
            // LR 在某个可执行段内
            if (entries[i].path[0] == '/')
            {
                // 在已知库中 — 正常
                return 0;
            }
            if (strcmp(entries[i].path, "[vdso]") == 0)
            {
                return 0;
            }
            // 在匿名可执行段中 — 可能是 trampoline
            LOGD("Return address 0x%lx in anonymous executable region 0x%lx-0x%lx",
                 lr_addr, entries[i].start, entries[i].end);
            return 1;
        }
    }

    // LR 不在任何可执行段中 — 异常
    LOGD("Return address 0x%lx not in any executable region", lr_addr);
    return 1;
}
