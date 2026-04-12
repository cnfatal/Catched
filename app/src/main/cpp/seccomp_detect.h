#ifndef CATCHED_SECCOMP_DETECT_H
#define CATCHED_SECCOMP_DETECT_H

/**
 * Seccomp-BPF 过滤器检测
 *
 * 检测攻击者是否安装了 seccomp-bpf 过滤器来拦截 SVC 系统调用。
 * Seccomp-BPF 是唯一能从用户态拦截 SVC 直接系统调用的机制。
 */

// 检查 /proc/self/status 中 Seccomp 字段 (0=disabled, 1=strict, 2=filter)
int detect_seccomp_status(void);

// 检查 Seccomp_filters 数量 (Linux 5.10+ / Android 12+)
// 返回过滤器数量，-1 表示字段不存在
int detect_seccomp_filter_count(void);

// 检查 /proc/self/status 中 CapEff/CapPrm 是否异常
// 正常 app 进程的 effective/permitted capabilities 应为 0
int detect_capability_anomaly(void);

#endif // CATCHED_SECCOMP_DETECT_H
