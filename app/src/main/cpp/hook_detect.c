#include "hook_detect.h"
#include "syscall_wrapper.h"
#include "maps_scanner.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <android/log.h>

#define TAG "Catched"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

// Xposed/LSPosed 相关 SO 黑名单
static const char *xposed_so_blacklist[] = {
    "libsandhook",
    "libmemtrack",
    "arthook_native",
    "riru",
    "libva",
    "XposedBridge.jar",
    "libAndroidCydia",
    "libvirtualcamera",
    "libAndroidBootstrap0",
    "libsubstrate",
    "libDalvikLoader",
    "libAndroidLoader",
    "libsubstrate-dvm",
    "libriruloader",
    "liblspd",
    "libnpatch",
    "liblsplant",
    "lspatch",
    "edxposed",
};
static const int xposed_blacklist_count = sizeof(xposed_so_blacklist) / sizeof(xposed_so_blacklist[0]);

// 简易 GOT/PLT 检查: 验证 libc 函数地址是否在预期范围内
int check_got_hook(const char *so_name) {
    if (!so_name) return 0;

    // 通过 dl_iterate_phdr 获取 SO 的加载信息
    // 然后检查 GOT 条目是否指向 SO 自身的 .text 段之外
    // 简化实现: 检查 openat 的 GOT 是否被修改

    void *handle = dlopen(so_name, RTLD_NOLOAD);
    if (!handle) return 0;

    // 获取 openat 的地址
    void *openat_addr = dlsym(handle, "openat");
    if (!openat_addr) {
        dlclose(handle);
        return 0;
    }

    // 读取 maps 确认 openat 地址是否在 libc 范围内
    char maps_buf[32768];
    ssize_t maps_len = sg_read_maps(maps_buf, sizeof(maps_buf));
    if (maps_len <= 0) {
        dlclose(handle);
        return 0;
    }

    // 检查 openat 地址是否在 libc.so 的可执行段内
    unsigned long addr = (unsigned long)openat_addr;
    int in_libc = 0;
    char *line = maps_buf;
    while (*line) {
        char *next = line;
        while (*next && *next != '\n') next++;

        char saved = *next;
        *next = '\0';

        if (strstr(line, "libc.so") != NULL && line[strlen(line) > 20 ? 20 : 0] != '\0') {
            // 解析地址范围
            unsigned long start = 0, end = 0;
            const char *p = line;
            while (*p && *p != '-') {
                unsigned long c = 0;
                if (*p >= '0' && *p <= '9') c = *p - '0';
                else if (*p >= 'a' && *p <= 'f') c = *p - 'a' + 10;
                start = (start << 4) | c;
                p++;
            }
            if (*p == '-') p++;
            while (*p && *p != ' ') {
                unsigned long c = 0;
                if (*p >= '0' && *p <= '9') c = *p - '0';
                else if (*p >= 'a' && *p <= 'f') c = *p - 'a' + 10;
                end = (end << 4) | c;
                p++;
            }

            if (addr >= start && addr < end) {
                in_libc = 1;
            }
        }

        *next = saved;
        if (*next) next++;
        line = next;
    }

    dlclose(handle);

    if (!in_libc && openat_addr != NULL) {
        LOGD("GOT Hook: openat address 0x%lx not in libc range", addr);
        return 1;
    }
    return 0;
}

// 简易 inline hook 检测: 检查函数开头是否有跳转指令
int check_inline_hook(void *func_addr) {
    if (!func_addr) return 0;

#if defined(__aarch64__)
    // ARM64: 检查开头是否是 BR/BLR/B (跳转指令)
    uint32_t *code = (uint32_t *)func_addr;
    uint32_t insn = code[0];

    // LDR Xn, [PC, #imm] 然后 BR Xn 模式 (常见 hook trampoline)
    if ((insn & 0xFF000000) == 0x58000000) { // LDR Xn, =addr
        uint32_t next = code[1];
        if ((next & 0xFFFFFC1F) == 0xD61F0000) { // BR Xn
            LOGD("Inline hook detected: LDR+BR pattern at %p", func_addr);
            return 1;
        }
    }

    // B #imm26 (直接跳转到远处)
    if ((insn & 0xFC000000) == 0x14000000) {
        LOGD("Inline hook detected: B instruction at %p", func_addr);
        return 1;
    }
#elif defined(__arm__)
    // ARM32: 检查 LDR PC, [PC, #-4] 模式
    uint32_t *code = (uint32_t *)((uintptr_t)func_addr & ~1); // 清除 Thumb 位
    uint32_t insn = code[0];

    // LDR PC, [PC, #offset]
    if ((insn & 0x0F7F0000) == 0x051F0000) {
        LOGD("Inline hook detected: LDR PC pattern at %p", func_addr);
        return 1;
    }
#endif

    return 0;
}

// 检查 openat 是否被 hook
int check_openat_hook(void) {
    void *libc_handle = dlopen("libc.so", RTLD_NOLOAD);
    if (!libc_handle) return 0;

    void *openat_func = dlsym(libc_handle, "openat");
    dlclose(libc_handle);

    if (openat_func) {
        return check_inline_hook(openat_func);
    }
    return 0;
}

// X9: 扫描 /proc/self/maps 中的 Xposed 相关 SO
int detect_xposed_maps(void) {
    SgMapScanResult result;
    int count = sg_scan_maps(xposed_so_blacklist, xposed_blacklist_count, &result);
    if (count > 0) {
        for (int i = 0; i < result.count; i++) {
            LOGD("X9: Suspicious SO in maps: %s (0x%lx-0x%lx)",
                 result.matches[i].library,
                 result.matches[i].start,
                 result.matches[i].end);
        }
    }
    return count;
}

// X10: 扫描 libart.so 中的 xposed 字符串
int detect_xposed_libart(void) {
    // 在 maps 中查找 libart.so 的路径
    char maps_buf[32768];
    ssize_t len = sg_read_maps(maps_buf, sizeof(maps_buf));
    if (len <= 0) return 0;

    // 找到 libart.so 的完整路径
    char libart_path[256] = {0};
    char *line = maps_buf;
    while (*line) {
        char *next = line;
        while (*next && *next != '\n') next++;

        char saved = *next;
        *next = '\0';

        char *libart = strstr(line, "libart.so");
        if (libart) {
            // 从行中提取路径
            char *path_start = strrchr(line, ' ');
            if (path_start && path_start[1] == '/') {
                strncpy(libart_path, path_start + 1, sizeof(libart_path) - 1);
            }
        }

        *next = saved;
        if (*next) next++;
        line = next;
        if (libart_path[0]) break;
    }

    if (libart_path[0] == '\0') return 0;

    // 读取 libart.so 前 64KB 搜索 xposed 字符串
    char *art_buf = (char *)sg_mmap(NULL, 65536, 3, 0x22, -1, 0);
    if (art_buf == (char *)-1) return 0;

    int fd = sg_open(libart_path, O_RDONLY);
    if (fd < 0) {
        sg_munmap(art_buf, 65536);
        return 0;
    }

    ssize_t art_len = sg_read(fd, art_buf, 65536);
    sg_close(fd);

    int detected = 0;
    if (art_len > 0) {
        // 在二进制数据中搜索字符串
        for (ssize_t i = 0; i < art_len - 6; i++) {
            if (art_buf[i] == 'x' && art_buf[i+1] == 'p' &&
                art_buf[i+2] == 'o' && art_buf[i+3] == 's' &&
                art_buf[i+4] == 'e' && art_buf[i+5] == 'd') {
                LOGD("X10: 'xposed' string found in libart.so at offset %zd", i);
                detected = 1;
                break;
            }
        }
    }

    sg_munmap(art_buf, 65536);
    return detected;
}

// X11: 检查 app_process.orig 是否存在
int detect_xposed_app_process(void) {
    const char *paths[] = {
        "/system/bin/app_process.orig",
        "/system/bin/app_process32.orig",
        "/system/bin/app_process64.orig",
        "/system/bin/app_process_xposed",
    };

    for (int i = 0; i < 4; i++) {
        if (sg_access(paths[i], 0) == 0) {
            LOGD("X11: app_process backup found: %s", paths[i]);
            return 1;
        }
    }
    return 0;
}

// 聚合检测
int detect_hook_native(JNIEnv *env) {
    (void)env;
    int total = 0;
    total += detect_xposed_maps() > 0 ? 1 : 0;
    total += detect_xposed_libart();
    total += detect_xposed_app_process();
    total += check_openat_hook();
    return total;
}
