#include "frida_detect.h"
#include "syscall_wrapper.h"
#include "maps_scanner.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <dirent.h>
#include <android/log.h>

#define TAG "Catched"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

// Frida 相关 SO 黑名单
static const char *frida_so_blacklist[] = {
    "frida-agent",
    "frida-loader",
    "frida-gadget",
    "LIBFRIDA",
    "libfrida",
    "frida_agent",
};
static const int frida_blacklist_count = sizeof(frida_so_blacklist) / sizeof(frida_so_blacklist[0]);

// F1: 扫描 /proc/self/maps 中的 Frida SO
int detect_frida_maps(void) {
    SgMapScanResult result;
    int count = sg_scan_maps(frida_so_blacklist, frida_blacklist_count, &result);
    if (count > 0) {
        for (int i = 0; i < result.count; i++) {
            LOGD("F1: Frida SO in maps: %s (0x%lx-0x%lx)",
                 result.matches[i].library,
                 result.matches[i].start,
                 result.matches[i].end);
        }
    }
    return count > 0 ? 1 : 0;
}

// F2: 尝试连接 Frida 默认端口 27042
int detect_frida_port(void) {
    int sock = sg_socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(27042);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    // 设置非阻塞连接 (使用简单超时逻辑)
    int ret = sg_connect(sock, &addr, sizeof(addr));
    sg_close(sock);

    if (ret == 0) {
        LOGD("F2: Frida default port 27042 is open");
        return 1;
    }

    // 也检查 27043
    sock = sg_socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;

    addr.sin_port = htons(27043);
    ret = sg_connect(sock, &addr, sizeof(addr));
    sg_close(sock);

    if (ret == 0) {
        LOGD("F2: Frida port 27043 is open");
        return 1;
    }

    return 0;
}

// F3: 扫描 /proc/net/tcp 查找 Frida 端口
int detect_frida_proc_tcp(void) {
    char buf[8192];
    ssize_t len = sg_read_file("/proc/net/tcp", buf, sizeof(buf));
    if (len <= 0) return 0;

    // 27042 = 0x69A2, 27043 = 0x69A3
    const char *frida_ports[] = {
        ":69A2", ":69A3",  // 大写
        ":69a2", ":69a3",  // 小写
    };

    for (int i = 0; i < 4; i++) {
        if (strstr(buf, frida_ports[i]) != NULL) {
            LOGD("F3: Frida port found in /proc/net/tcp: %s", frida_ports[i]);
            return 1;
        }
    }
    return 0;
}

// F4: 检查 frida-server 文件
int detect_frida_server_file(void) {
    const char *paths[] = {
        "/data/local/tmp/frida-server",
        "/data/local/tmp/frida-server-arm",
        "/data/local/tmp/frida-server-arm64",
        "/data/local/tmp/re.frida.server",
        "/data/local/tmp/frida",
        "/system/bin/frida-server",
        "/system/xbin/frida-server",
    };

    for (int i = 0; i < 7; i++) {
        if (sg_access(paths[i], 0) == 0) {
            LOGD("F4: frida-server file found: %s", paths[i]);
            return 1;
        }
    }
    return 0;
}

// F5: 扫描 /proc/self/fd/ 查找 Frida named pipe
int detect_frida_named_pipe(void) {
    char fd_dir[] = "/proc/self/fd";
    int dir_fd = sg_open(fd_dir, O_RDONLY | O_DIRECTORY);
    if (dir_fd < 0) return 0;

    struct linux_dirent64 {
        uint64_t d_ino;
        int64_t d_off;
        unsigned short d_reclen;
        unsigned char d_type;
        char d_name[];
    };

    char buf[4096];
    int detected = 0;

    int nread = sg_getdents64(dir_fd, buf, sizeof(buf));
    while (nread > 0) {
        int pos = 0;
        while (pos < nread) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + pos);

            // 读取 fd 的链接目标
            char link_path[128];
            char link_target[256];
            snprintf(link_path, sizeof(link_path), "/proc/self/fd/%s", d->d_name);

            // 使用 readlink (通过 read_file 模拟)
            // 直接读取 link 内容
            ssize_t link_len = readlink(link_path, link_target, sizeof(link_target) - 1);
            if (link_len > 0) {
                link_target[link_len] = '\0';
                if (strstr(link_target, "frida") != NULL ||
                    strstr(link_target, "linjector") != NULL) {
                    LOGD("F5: Frida pipe found: fd=%s -> %s", d->d_name, link_target);
                    detected = 1;
                    break;
                }
            }

            pos += d->d_reclen;
        }
        if (detected) break;
        nread = sg_getdents64(dir_fd, buf, sizeof(buf));
    }

    sg_close(dir_fd);
    return detected;
}

// F6: D-Bus 协议探测
int detect_frida_dbus(void) {
    // 向常见端口发送 D-Bus AUTH 消息并检查响应
    int ports[] = {27042, 27043};

    for (int p = 0; p < 2; p++) {
        int sock = sg_socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ports[p]);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (sg_connect(sock, &addr, sizeof(addr)) == 0) {
            // 发送 D-Bus AUTH 握手
            const char *dbus_auth = "\x00AUTH\r\n";
            sg_write(sock, dbus_auth, 7);

            // 等待响应
            char response[256];
            ssize_t n = sg_read(sock, response, sizeof(response) - 1);
            if (n > 0) {
                response[n] = '\0';
                if (strstr(response, "REJECTED") != NULL ||
                    strstr(response, "OK") != NULL) {
                    LOGD("F6: D-Bus response on port %d: %.32s", ports[p], response);
                    sg_close(sock);
                    return 1;
                }
            }
        }
        sg_close(sock);
    }

    return 0;
}

// F7: 内存特征扫描
int detect_frida_memory(void) {
    // 读取 /proc/self/maps 然后扫描可读内存区域
    char maps_buf[32768];
    ssize_t maps_len = sg_read_maps(maps_buf, sizeof(maps_buf));
    if (maps_len <= 0) return 0;

    const char *signatures[] = {
        "LIBFRIDA", "frida:rpc", "frida-agent",
        "gum-js-loop", "gmain"
    };
    int sig_count = 5;
    int detected = 0;

    char *line = maps_buf;
    while (*line && !detected) {
        char *next = line;
        while (*next && *next != '\n') next++;

        char saved = *next;
        *next = '\0';

        // 只扫描可读的匿名映射 (rw-p ... 00000000 00:00 0)
        if (strlen(line) > 20 && line[0] != '\0') {
            // 检查是否包含 00000000 00:00 0 (匿名映射)
            if (strstr(line, "00000000 00:00 0") != NULL &&
                line[18] == 'r') { // 可读

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

                size_t region_size = end - start;
                if (region_size > 0 && region_size <= 4 * 1024 * 1024) {
                    // 扫描此区域
                    char *region = (char *)start;
                    for (size_t i = 0; i < region_size - 8 && !detected; i++) {
                        for (int s = 0; s < sig_count; s++) {
                            size_t sig_len = strlen(signatures[s]);
                            if (i + sig_len <= region_size &&
                                memcmp(region + i, signatures[s], sig_len) == 0) {
                                LOGD("F7: Frida signature '%s' found at 0x%lx+%zu",
                                     signatures[s], start, i);
                                detected = 1;
                                break;
                            }
                        }
                    }
                }
            }
        }

        *next = saved;
        if (*next) next++;
        line = next;
    }

    return detected;
}

// F8: 扫描线程名
int detect_frida_thread(void) {
    char task_dir[] = "/proc/self/task";
    int dir_fd = sg_open(task_dir, O_RDONLY | O_DIRECTORY);
    if (dir_fd < 0) return 0;

    struct linux_dirent64 {
        uint64_t d_ino;
        int64_t d_off;
        unsigned short d_reclen;
        unsigned char d_type;
        char d_name[];
    };

    char buf[4096];
    int detected = 0;

    int nread = sg_getdents64(dir_fd, buf, sizeof(buf));
    while (nread > 0) {
        int pos = 0;
        while (pos < nread) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + pos);

            if (d->d_name[0] != '.') {
                char comm_path[128];
                snprintf(comm_path, sizeof(comm_path),
                         "/proc/self/task/%s/comm", d->d_name);

                char comm[64];
                ssize_t comm_len = sg_read_file(comm_path, comm, sizeof(comm));
                if (comm_len > 0) {
                    // 移除末尾换行
                    if (comm[comm_len - 1] == '\n') comm[comm_len - 1] = '\0';

                    if (strstr(comm, "frida") != NULL ||
                        strstr(comm, "gmain") != NULL ||
                        strstr(comm, "gum-js-loop") != NULL ||
                        strstr(comm, "linjector") != NULL) {
                        LOGD("F8: Frida thread: tid=%s comm=%s", d->d_name, comm);
                        detected = 1;
                        break;
                    }
                }
            }

            pos += d->d_reclen;
        }
        if (detected) break;
        nread = sg_getdents64(dir_fd, buf, sizeof(buf));
    }

    sg_close(dir_fd);
    return detected;
}

// 聚合检测
int detect_frida_native(JNIEnv *env) {
    (void)env;
    int total = 0;
    total += detect_frida_maps();
    total += detect_frida_port();
    total += detect_frida_proc_tcp();
    total += detect_frida_server_file();
    total += detect_frida_named_pipe();
    total += detect_frida_dbus();
    total += detect_frida_memory();
    total += detect_frida_thread();
    return total;
}
