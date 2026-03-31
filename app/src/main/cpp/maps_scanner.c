#include "maps_scanner.h"
#include "syscall_wrapper.h"
#include <fcntl.h>
#include <string.h>
#include <android/log.h>

#define TAG "Catched"

// 自实现 strstr 避免 libc hook
static const char *sg_local_strstr(const char *haystack, const char *needle) {
    if (!needle || !*needle) return haystack;
    for (; *haystack; haystack++) {
        const char *h = haystack;
        const char *n = needle;
        while (*h && *n && *h == *n) {
            h++;
            n++;
        }
        if (!*n) return haystack;
    }
    return NULL;
}

// 从一行中提取路径部分 (maps 格式: addr perms offset dev inode pathname)
static int extract_path(const char *line, char *path, size_t path_size) {
    // 跳过前 5 个字段
    int spaces = 0;
    const char *p = line;
    while (*p && spaces < 5) {
        if (*p == ' ') {
            spaces++;
            while (*(p + 1) == ' ') p++; // skip consecutive spaces
        }
        p++;
    }
    // 跳过前导空格
    while (*p == ' ') p++;

    if (*p == '\0' || *p == '\n') return 0;

    size_t i = 0;
    while (*p && *p != '\n' && i < path_size - 1) {
        path[i++] = *p++;
    }
    path[i] = '\0';
    return (int)i;
}

// 从一行中提取地址范围和权限
static void parse_maps_line_meta(const char *line, unsigned long *start,
                                  unsigned long *end, char *perms) {
    // 格式: start-end perms ...
    *start = 0;
    *end = 0;
    const char *p = line;

    // 解析 start
    while (*p && *p != '-') {
        unsigned long c = 0;
        if (*p >= '0' && *p <= '9') c = *p - '0';
        else if (*p >= 'a' && *p <= 'f') c = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') c = *p - 'A' + 10;
        *start = (*start << 4) | c;
        p++;
    }
    if (*p == '-') p++;

    // 解析 end
    while (*p && *p != ' ') {
        unsigned long c = 0;
        if (*p >= '0' && *p <= '9') c = *p - '0';
        else if (*p >= 'a' && *p <= 'f') c = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') c = *p - 'A' + 10;
        *end = (*end << 4) | c;
        p++;
    }
    if (*p == ' ') p++;

    // 解析 perms
    for (int i = 0; i < 4 && *p && *p != ' '; i++) {
        perms[i] = *p++;
    }
    perms[4] = '\0';
}

ssize_t sg_read_maps(char *buf, size_t buf_size) {
    return sg_read_file("/proc/self/maps", buf, buf_size);
}

int sg_scan_maps(const char **blacklist, int blacklist_len, SgMapScanResult *result) {
    if (!result) return 0;
    result->count = 0;

    // 使用较大缓冲区读取 maps 内容
    // /proc/self/maps 通常在 4-32KB 之间
    char *buf = (char *)sg_mmap(NULL, 65536, 3 /* PROT_READ|PROT_WRITE */,
                                 0x22 /* MAP_PRIVATE|MAP_ANON */, -1, 0);
    if (buf == (char *)-1) return 0;

    ssize_t len = sg_read_maps(buf, 65536);
    if (len <= 0) {
        sg_munmap(buf, 65536);
        return 0;
    }

    // 逐行分析
    char *line_start = buf;
    char *line_end;

    while (line_start < buf + len && result->count < 32) {
        line_end = line_start;
        while (line_end < buf + len && *line_end != '\n') line_end++;

        // 临时终止该行
        char saved = *line_end;
        *line_end = '\0';

        // 在该行中搜索黑名单关键字
        for (int i = 0; i < blacklist_len && result->count < 32; i++) {
            if (sg_local_strstr(line_start, blacklist[i]) != NULL) {
                SgMapMatch *match = &result->matches[result->count];

                parse_maps_line_meta(line_start, &match->start, &match->end, match->perms);
                extract_path(line_start, match->library, sizeof(match->library));

                // 如果路径为空则填入匹配的关键字
                if (match->library[0] == '\0') {
                    strncpy(match->library, blacklist[i], sizeof(match->library) - 1);
                }

                result->count++;
                break; // 同一行只匹配一次
            }
        }

        *line_end = saved;
        line_start = line_end + 1;
    }

    sg_munmap(buf, 65536);
    return result->count;
}
