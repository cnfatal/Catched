#ifndef CATCHED_SIGNAL_DETECT_H
#define CATCHED_SIGNAL_DETECT_H

/**
 * 信号处理器检测
 *
 * 通过 SVC rt_sigaction 检查 SIGSYS/SIGSEGV/SIGBUS 的信号处理器。
 * 攻击者安装 seccomp-bpf 后需注册 SIGSYS handler 来拦截被过滤的系统调用。
 */

// 检查 SIGSYS handler 是否被设置 (非 SIG_DFL/SIG_IGN)
// 返回 1 表示检测到自定义 handler
int detect_sigsys_handler(void);

// 检查 SIGSEGV handler (某些 hook 框架用于处理代码补丁产生的段错误)
int detect_sigsegv_handler(void);

// 检查 SIGBUS handler
int detect_sigbus_handler(void);

#endif // CATCHED_SIGNAL_DETECT_H
