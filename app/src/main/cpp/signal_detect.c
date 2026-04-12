#include "signal_detect.h"
#include "syscall_wrapper.h"
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <android/log.h>

#define TAG "Catched"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

/*
 * 内核级 sigaction 结构体 (与 libc 的 struct sigaction 不同)
 * kernel 使用固定布局，sa_handler/sa_sigaction 在偏移 0
 */
struct kernel_sigaction
{
    union
    {
        void (*sa_handler)(int);
        void (*sa_sigaction)(int, void *, void *);
    };
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    unsigned long sa_mask[2]; // 64 位系统上 128 位 sigset
};

// SIGSYS = 31 (ARM64/ARM32 Linux)
#ifndef SIGSYS
#define SIGSYS 31
#endif

// 检查指定信号的 handler
static int check_signal_handler(int signum, const char *sig_name)
{
    struct kernel_sigaction old_act;
    memset(&old_act, 0, sizeof(old_act));

    /*
     * 使用 SVC rt_sigaction 获取当前信号的处理器设置。
     * 参数: signum, new_act (NULL = 只查询), old_act, sigsetsize
     *
     * 这里不修改 handler，只读取当前设置。
     */
    int ret = sg_rt_sigaction(signum, NULL, &old_act, sizeof(unsigned long) * 2);
    if (ret < 0)
    {
        LOGD("rt_sigaction failed for %s: ret=%d", sig_name, ret);
        return 0;
    }

    void *handler = (void *)old_act.sa_handler;

    /*
     * SIG_DFL = (void *)0    — 默认处理
     * SIG_IGN = (void *)1    — 忽略
     * 其他值                  — 自定义处理器
     *
     * 对于 SIGSYS:
     *   正常 app 的 SIGSYS 处理器应为 SIG_DFL（因为正常运行时不会触发 SIGSYS）。
     *   如果存在自定义 handler，说明有代码安装了 seccomp-bpf 过滤器
     *   并用 SIGSYS handler 来拦截和修改被过滤的系统调用。
     */
    if (handler != (void *)0 && handler != (void *)1)
    {
        LOGD("Custom %s handler detected at %p (flags=0x%lx)",
             sig_name, handler, old_act.sa_flags);
        return 1;
    }

    return 0;
}

int detect_sigsys_handler(void)
{
    return check_signal_handler(SIGSYS, "SIGSYS");
}

int detect_sigsegv_handler(void)
{
    return check_signal_handler(SIGSEGV, "SIGSEGV");
}

int detect_sigbus_handler(void)
{
    return check_signal_handler(SIGBUS, "SIGBUS");
}
