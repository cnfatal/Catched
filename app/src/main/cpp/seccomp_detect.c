#include "seccomp_detect.h"
#include "syscall_wrapper.h"
#include <string.h>
#include <android/log.h>

#define TAG "Catched"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

// 从 /proc/self/status 中提取指定字段的整数值
// 返回字段值，未找到返回 -1
static long parse_status_field(const char *buf, const char *field_name)
{
    const char *pos = buf;
    size_t field_len = strlen(field_name);

    while (*pos)
    {
        if (strncmp(pos, field_name, field_len) == 0)
        {
            pos += field_len;
            // 跳过空白字符
            while (*pos == ' ' || *pos == '\t')
                pos++;
            // 解析数值
            long val = 0;
            int found_digit = 0;
            while (*pos >= '0' && *pos <= '9')
            {
                val = val * 10 + (*pos - '0');
                found_digit = 1;
                pos++;
            }
            if (found_digit)
                return val;
            return -1;
        }
        // 跳到下一行
        while (*pos && *pos != '\n')
            pos++;
        if (*pos == '\n')
            pos++;
    }
    return -1;
}

// 从 /proc/self/status 中提取十六进制字段值 (用于 Cap* 字段)
static unsigned long long parse_status_hex_field(const char *buf, const char *field_name)
{
    const char *pos = buf;
    size_t field_len = strlen(field_name);

    while (*pos)
    {
        if (strncmp(pos, field_name, field_len) == 0)
        {
            pos += field_len;
            while (*pos == ' ' || *pos == '\t')
                pos++;
            unsigned long long val = 0;
            while ((*pos >= '0' && *pos <= '9') ||
                   (*pos >= 'a' && *pos <= 'f') ||
                   (*pos >= 'A' && *pos <= 'F'))
            {
                unsigned long long c = 0;
                if (*pos >= '0' && *pos <= '9')
                    c = *pos - '0';
                else if (*pos >= 'a' && *pos <= 'f')
                    c = *pos - 'a' + 10;
                else if (*pos >= 'A' && *pos <= 'F')
                    c = *pos - 'A' + 10;
                val = (val << 4) | c;
                pos++;
            }
            return val;
        }
        while (*pos && *pos != '\n')
            pos++;
        if (*pos == '\n')
            pos++;
    }
    return 0;
}

int detect_seccomp_status(void)
{
    char buf[4096];
    ssize_t len = sg_read_file("/proc/self/status", buf, sizeof(buf));
    if (len <= 0)
        return 0;

    long seccomp = parse_status_field(buf, "Seccomp:");
    if (seccomp < 0)
    {
        // 字段不存在，内核可能不支持
        return 0;
    }

    /*
     * Seccomp 值含义:
     * 0 = SECCOMP_MODE_DISABLED
     * 1 = SECCOMP_MODE_STRICT
     * 2 = SECCOMP_MODE_FILTER (BPF)
     *
     * Android 从 O (8.0) 开始在 Zygote fork 时安装系统 seccomp 过滤器，
     * 所以正常 app 的 Seccomp 值为 2。
     * 这里返回原始值供上层判断，关键是检查 filter 数量。
     */
    LOGD("Seccomp status: %ld", seccomp);
    return (int)seccomp;
}

int detect_seccomp_filter_count(void)
{
    char buf[4096];
    ssize_t len = sg_read_file("/proc/self/status", buf, sizeof(buf));
    if (len <= 0)
        return -1;

    long count = parse_status_field(buf, "Seccomp_filters:");
    if (count < 0)
    {
        // Linux 5.10 以下不支持此字段
        return -1;
    }

    /*
     * 正常 Android 进程（Zygote fork）应有 1 个系统 seccomp 过滤器。
     * 如果 count > 1（或攻击者自定义的阈值），说明有额外的 BPF 过滤器被安装，
     * 可能是注入框架用于拦截 SVC 调用。
     */
    if (count > 1)
    {
        LOGD("Seccomp: %ld filters detected (expected 1)", count);
    }
    return (int)count;
}

int detect_capability_anomaly(void)
{
    char buf[4096];
    ssize_t len = sg_read_file("/proc/self/status", buf, sizeof(buf));
    if (len <= 0)
        return 0;

    unsigned long long cap_eff = parse_status_hex_field(buf, "CapEff:");
    unsigned long long cap_prm = parse_status_hex_field(buf, "CapPrm:");

    /*
     * 正常 app 进程的 CapEff 和 CapPrm 应为全 0。
     * 非零值表示进程获得了额外权限，可能是通过 root 或 capability 注入。
     */
    if (cap_eff != 0 || cap_prm != 0)
    {
        LOGD("Capability anomaly: CapEff=0x%llx CapPrm=0x%llx", cap_eff, cap_prm);
        return 1;
    }
    return 0;
}
