#include "root_detect.h"
#include "npatch_detect.h"
#include "syscall_wrapper.h"
#include "maps_scanner.h"
#include "hook_detect.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/system_properties.h>
#include <android/log.h>

#define TAG "Catched"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

// su 路径列表
static const char *su_paths[] = {
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/data/local/bin/su",
    "/data/local/su",
    "/data/local/xbin/su",
    "/system/sd/xbin/su",
    "/system/bin/failsafe/su",
    "/su/bin/su",
    "/system/app/Superuser.apk",
    "/system/app/longeneroot.apk",
    "/cache/su",
    "/data/su",
    "/dev/su",
};
static const int su_paths_count = sizeof(su_paths) / sizeof(su_paths[0]);

// R1: 使用 SVC 直接系统调用检查 su 路径
int detect_su_paths_svc(void) {
    for (int i = 0; i < su_paths_count; i++) {
        if (sg_access(su_paths[i], 0 /* F_OK */) == 0) {
            LOGD("R1: su found via SVC access: %s", su_paths[i]);
            return 1;
        }
    }
    return 0;
}

// R5: 使用 SVC stat 检查 su 文件属性
int detect_su_stat_native(void) {
    struct stat st;
    for (int i = 0; i < su_paths_count; i++) {
        if (sg_stat(su_paths[i], &st) == 0) {
            // 进一步检查是否设置了 SUID 位
            if (st.st_mode & 04000) {
                LOGD("R5: su found with SUID bit: %s", su_paths[i]);
            } else {
                LOGD("R5: su found via stat: %s", su_paths[i]);
            }
            return 1;
        }
    }
    return 0;
}

// R6: 检查 /proc/mounts 中的 Magisk 特征
int detect_magisk_mount(void) {
    const char *keywords[] = {
        "magisk", "core/mirror", "core/img",
        "/sbin/.magisk", "/dev/magisk"
    };
    int count = sg_search_file("/proc/mounts", keywords, 5);
    if (count > 0) {
        LOGD("R6: Magisk mount point detected (%d matches)", count);
    }
    return count > 0 ? 1 : 0;
}

// R7: 分析 /proc/self/mountinfo
int detect_mountinfo(void) {
    const char *keywords[] = {
        "magisk", "tmpfs /system",
        "tmpfs /vendor", "tmpfs /product"
    };
    int count = sg_search_file("/proc/self/mountinfo", keywords, 4);
    if (count > 0) {
        LOGD("R7: Suspicious mountinfo detected (%d matches)", count);
    }
    return count > 0 ? 1 : 0;
}

// R9: 检查 SELinux 上下文中的 magisk_file 标签
int detect_selinux_context(void) {
    char buf[512];
    // 读取 /dev/pts 或其他路径的 SELinux 上下文
    ssize_t len = sg_read_file("/proc/self/attr/current", buf, sizeof(buf));
    if (len > 0) {
        // 查找 magisk 相关 SELinux 上下文
        if (strstr(buf, "magisk") != NULL) {
            LOGD("R9: Magisk SELinux context detected in current attr");
            return 1;
        }
    }

    // 尝试枚举 /sys/fs/selinux/class 或类似路径搜索 magisk_file
    const char *selinux_paths[] = {
        "/sys/fs/selinux/class/magisk_file",
        "/sys/fs/selinux/class/zygote_magisk"
    };
    for (int i = 0; i < 2; i++) {
        if (sg_access(selinux_paths[i], 0) == 0) {
            LOGD("R9: Magisk SELinux class found: %s", selinux_paths[i]);
            return 1;
        }
    }
    return 0;
}

// R10: 检查 /proc/self/attr/prev
int detect_selinux_prev(void) {
    char buf[256];
    ssize_t len = sg_read_file("/proc/self/attr/prev", buf, sizeof(buf));
    if (len > 0) {
        if (strstr(buf, "magisk") != NULL ||
            strstr(buf, "zygisk") != NULL ||
            strstr(buf, "u:r:magisk:") != NULL) {
            LOGD("R10: Magisk detected in SELinux prev context: %s", buf);
            return 1;
        }
    }
    return 0;
}

// R11: 尝试连接 Magisk local socket
int detect_magisk_socket(void) {
    int fd = sg_socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    // Magisk 使用抽象 socket namespace
    // socket 名称通常基于随机 32 位值
    // 但我们可以尝试扫描 /proc/net/unix 查找特征
    sg_close(fd);

    // 扫描 /proc/net/unix 查找 Magisk socket
    char buf[8192];
    ssize_t len = sg_read_file("/proc/net/unix", buf, sizeof(buf));
    if (len > 0) {
        if (strstr(buf, "magisk") != NULL ||
            strstr(buf, "MAGISK") != NULL) {
            LOGD("R11: Magisk socket found in /proc/net/unix");
            return 1;
        }
    }
    return 0;
}

// R12: 检查系统属性
int detect_system_properties(void) {
    char value[92];
    int detected = 0;

    // 检查 ro.debuggable
    if (__system_property_get("ro.debuggable", value) > 0) {
        if (strcmp(value, "1") == 0) {
            LOGD("R12: ro.debuggable=1 (debuggable build)");
            detected++;
        }
    }

    // 检查 ro.secure
    if (__system_property_get("ro.secure", value) > 0) {
        if (strcmp(value, "0") == 0) {
            LOGD("R12: ro.secure=0 (insecure build)");
            detected++;
        }
    }

    // 检查 ro.build.tags
    if (__system_property_get("ro.build.tags", value) > 0) {
        if (strstr(value, "test-keys") != NULL) {
            LOGD("R12: ro.build.tags contains test-keys");
            detected++;
        }
    }

    // 检查 Magisk 相关属性
    const char *magisk_props[] = {
        "init.svc.magisk_daemon",
        "init.svc.magisk_service",
        "persist.magisk.hide"
    };
    for (int i = 0; i < 3; i++) {
        if (__system_property_get(magisk_props[i], value) > 0 && value[0] != '\0') {
            LOGD("R12: Magisk property found: %s=%s", magisk_props[i], value);
            detected++;
        }
    }

    return detected > 0 ? 1 : 0;
}

// JNI 聚合检测
int detect_root_native(JNIEnv *env, jobjectArray results) {
    (void)env;
    (void)results;

    int total = 0;
    total += detect_su_paths_svc();
    total += detect_su_stat_native();
    total += detect_magisk_mount();
    total += detect_mountinfo();
    total += detect_selinux_context();
    total += detect_selinux_prev();
    total += detect_magisk_socket();
    total += detect_system_properties();
    return total;
}
