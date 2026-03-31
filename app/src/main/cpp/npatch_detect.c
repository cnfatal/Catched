#include "npatch_detect.h"
#include "syscall_wrapper.h"
#include "maps_scanner.h"
#include "hook_detect.h"
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <android/log.h>

#define TAG "Catched"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

// NPatch/LSPatch 相关关键字
static const char *npatch_so_blacklist[] = {
    "libnpatch.so",
    "liblspatch.so",
    "liblsplant.so",
    "npatch",
    "lspatch",
};
static const int npatch_blacklist_count = sizeof(npatch_so_blacklist) / sizeof(npatch_so_blacklist[0]);

// N3: 检查 /proc/self/maps 中是否加载了 npatch/lspatch SO
int detect_npatch_so_maps(void) {
    SgMapScanResult result;
    int count = sg_scan_maps(npatch_so_blacklist, npatch_blacklist_count, &result);
    if (count > 0) {
        for (int i = 0; i < result.count; i++) {
            LOGD("N3: NPatch SO in maps: %s (0x%lx-0x%lx)",
                 result.matches[i].library,
                 result.matches[i].start,
                 result.matches[i].end);
        }
    }
    return count > 0 ? 1 : 0;
}

// N4: 检查 openat 是否被 Hook (NPatch 会 Hook openat 来重定向 APK 读取)
int detect_npatch_openat_hook(void) {
    return check_openat_hook();
}

// N6: 检查 cache/npatch/ 特征目录
int detect_npatch_cache_dir(JNIEnv *env, const char *data_dir) {
    (void)env;
    if (!data_dir) return 0;

    char path[256];

    // 检查 cache/npatch/ 目录
    snprintf(path, sizeof(path), "%s/cache/npatch", data_dir);
    if (sg_access(path, 0) == 0) {
        LOGD("N6: NPatch cache directory found: %s", path);
        return 1;
    }

    // 检查 cache/lspatch/ 目录
    snprintf(path, sizeof(path), "%s/cache/lspatch", data_dir);
    if (sg_access(path, 0) == 0) {
        LOGD("N6: LSPatch cache directory found: %s", path);
        return 1;
    }

    // 检查 cache/npatch_origin/ 目录
    snprintf(path, sizeof(path), "%s/cache/npatch_origin", data_dir);
    if (sg_access(path, 0) == 0) {
        LOGD("N6: NPatch origin cache found: %s", path);
        return 1;
    }

    return 0;
}

// N8: 检查 profile 文件权限异常 (NPatch 会将 profile 设置为只读)
int detect_npatch_profile(JNIEnv *env, const char *data_dir) {
    (void)env;
    if (!data_dir) return 0;

    char path[256];
    struct stat st;

    // 检查 cur/0/primary.prof
    snprintf(path, sizeof(path),
             "/data/misc/profiles/cur/0/%s/primary.prof",
             strrchr(data_dir, '/') ? strrchr(data_dir, '/') + 1 : data_dir);

    if (sg_stat(path, &st) == 0) {
        // 正常情况下 profile 文件应该是 rw
        // NPatch 会设为只读 (0444 / 0440)
        if ((st.st_mode & 0200) == 0) { // 所有者没有写权限
            LOGD("N8: Profile file is read-only (suspicious): %s mode=0%o",
                 path, st.st_mode & 0777);
            return 1;
        }
    }

    return 0;
}

// 聚合检测
int detect_npatch_native(JNIEnv *env, const char *data_dir) {
    int total = 0;
    total += detect_npatch_so_maps();
    total += detect_npatch_openat_hook();
    total += detect_npatch_cache_dir(env, data_dir);
    total += detect_npatch_profile(env, data_dir);
    return total;
}
