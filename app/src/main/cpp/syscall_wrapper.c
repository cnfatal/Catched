#include "syscall_wrapper.h"
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

/*
 * SVC 直接系统调用实现
 *
 * 采用内联汇编直接执行 SVC 指令，完全绕过 libc 层。
 * - ARM64: 系统调用号放在 x8，参数在 x0-x5，SVC #0
 * - ARM32: 系统调用号放在 r7，参数在 r0-r5，SVC #0
 *
 * 参考: Linux kernel syscall table
 *   ARM64: include/uapi/asm-generic/unistd.h
 *   ARM32: arch/arm/tools/syscall.tbl
 */

// ============================================================
// ARM64 (aarch64) 实现
// ============================================================
#if defined(__aarch64__)

__attribute__((naked)) int sg_openat(int dirfd, const char *path, int flags)
{
    __asm__ volatile(
        "mov x8, #56\n" // __NR_openat = 56
        "svc #0\n"
        "ret\n");
}

__attribute__((naked))
ssize_t
sg_read(int fd, void *buf, size_t count)
{
    __asm__ volatile(
        "mov x8, #63\n" // __NR_read = 63
        "svc #0\n"
        "ret\n");
}

__attribute__((naked)) int sg_close(int fd)
{
    __asm__ volatile(
        "mov x8, #57\n" // __NR_close = 57
        "svc #0\n"
        "ret\n");
}

__attribute__((naked))
ssize_t
sg_write(int fd, const void *buf, size_t count)
{
    __asm__ volatile(
        "mov x8, #64\n" // __NR_write = 64
        "svc #0\n"
        "ret\n");
}

__attribute__((naked)) int sg_faccessat(int dirfd, const char *path, int mode)
{
    __asm__ volatile(
        "mov x8, #48\n" // __NR_faccessat = 48
        "svc #0\n"
        "ret\n");
}

__attribute__((naked)) int sg_fstatat(int dirfd, const char *path, struct stat *buf, int flags)
{
    __asm__ volatile(
        "mov x8, #79\n" // __NR_fstatat = 79 (newfstatat)
        "svc #0\n"
        "ret\n");
}

__attribute__((naked)) off_t sg_lseek(int fd, off_t offset, int whence)
{
    __asm__ volatile(
        "mov x8, #62\n" // __NR_lseek = 62
        "svc #0\n"
        "ret\n");
}

__attribute__((naked)) void *sg_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    __asm__ volatile(
        "mov x8, #222\n" // __NR_mmap = 222
        "svc #0\n"
        "ret\n");
}

__attribute__((naked)) int sg_munmap(void *addr, size_t length)
{
    __asm__ volatile(
        "mov x8, #215\n" // __NR_munmap = 215
        "svc #0\n"
        "ret\n");
}

__attribute__((naked)) int sg_getdents64(int fd, void *dirp, size_t count)
{
    __asm__ volatile(
        "mov x8, #61\n" // __NR_getdents64 = 61
        "svc #0\n"
        "ret\n");
}

__attribute__((naked)) int sg_socket(int domain, int type, int protocol)
{
    __asm__ volatile(
        "mov x8, #198\n" // __NR_socket = 198
        "svc #0\n"
        "ret\n");
}

__attribute__((naked)) int sg_connect(int sockfd, const void *addr, int addrlen)
{
    __asm__ volatile(
        "mov x8, #203\n" // __NR_connect = 203
        "svc #0\n"
        "ret\n");
}

__attribute__((naked)) int sg_rt_sigaction(int signum, const void *act, void *oldact, size_t sigsetsize)
{
    __asm__ volatile(
        "mov x8, #134\n" // __NR_rt_sigaction = 134
        "svc #0\n"
        "ret\n");
}

__attribute__((naked))
ssize_t
sg_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz)
{
    __asm__ volatile(
        "mov x8, #78\n" // __NR_readlinkat = 78
        "svc #0\n"
        "ret\n");
}

__attribute__((naked)) int sg_prctl(int option, unsigned long arg2, unsigned long arg3,
                                    unsigned long arg4, unsigned long arg5)
{
    __asm__ volatile(
        "mov x8, #167\n" // __NR_prctl = 167
        "svc #0\n"
        "ret\n");
}

// ============================================================
// ARM32 (armeabi-v7a) 实现
// ============================================================
#elif defined(__arm__)

__attribute__((naked)) int sg_openat(int dirfd, const char *path, int flags)
{
    __asm__ volatile(
        "mov r7, #322\n" // __NR_openat = 322
        "svc #0\n"
        "bx lr\n");
}

__attribute__((naked))
ssize_t
sg_read(int fd, void *buf, size_t count)
{
    __asm__ volatile(
        "mov r7, #3\n" // __NR_read = 3
        "svc #0\n"
        "bx lr\n");
}

__attribute__((naked)) int sg_close(int fd)
{
    __asm__ volatile(
        "mov r7, #6\n" // __NR_close = 6
        "svc #0\n"
        "bx lr\n");
}

__attribute__((naked))
ssize_t
sg_write(int fd, const void *buf, size_t count)
{
    __asm__ volatile(
        "mov r7, #4\n" // __NR_write = 4
        "svc #0\n"
        "bx lr\n");
}

__attribute__((naked)) int sg_faccessat(int dirfd, const char *path, int mode)
{
    __asm__ volatile(
        "mov r7, #334\n" // __NR_faccessat = 334
        "svc #0\n"
        "bx lr\n");
}

__attribute__((naked)) int sg_fstatat(int dirfd, const char *path, struct stat *buf, int flags)
{
    __asm__ volatile(
        "mov r7, #327\n" // __NR_fstatat64 = 327
        "svc #0\n"
        "bx lr\n");
}

__attribute__((naked)) off_t sg_lseek(int fd, off_t offset, int whence)
{
    __asm__ volatile(
        "mov r7, #19\n" // __NR_lseek = 19
        "svc #0\n"
        "bx lr\n");
}

__attribute__((naked)) void *sg_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    __asm__ volatile(
        "mov r7, #192\n" // __NR_mmap2 = 192
        "svc #0\n"
        "bx lr\n");
}

__attribute__((naked)) int sg_munmap(void *addr, size_t length)
{
    __asm__ volatile(
        "mov r7, #91\n" // __NR_munmap = 91
        "svc #0\n"
        "bx lr\n");
}

__attribute__((naked)) int sg_getdents64(int fd, void *dirp, size_t count)
{
    __asm__ volatile(
        "mov r7, #217\n" // __NR_getdents64 = 217
        "svc #0\n"
        "bx lr\n");
}

__attribute__((naked)) int sg_socket(int domain, int type, int protocol)
{
    __asm__ volatile(
        "mov r7, #281\n" // __NR_socket = 281
        "svc #0\n"
        "bx lr\n");
}

__attribute__((naked)) int sg_connect(int sockfd, const void *addr, int addrlen)
{
    __asm__ volatile(
        "mov r7, #283\n" // __NR_connect = 283
        "svc #0\n"
        "bx lr\n");
}

__attribute__((naked)) int sg_rt_sigaction(int signum, const void *act, void *oldact, size_t sigsetsize)
{
    __asm__ volatile(
        "mov r7, #174\n" // __NR_rt_sigaction = 174
        "svc #0\n"
        "bx lr\n");
}

__attribute__((naked))
ssize_t
sg_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz)
{
    __asm__ volatile(
        "mov r7, #332\n" // __NR_readlinkat = 332
        "svc #0\n"
        "bx lr\n");
}

__attribute__((naked)) int sg_prctl(int option, unsigned long arg2, unsigned long arg3,
                                    unsigned long arg4, unsigned long arg5)
{
    __asm__ volatile(
        "mov r7, #172\n" // __NR_prctl = 172
        "svc #0\n"
        "bx lr\n");
}

#else
#error "Unsupported architecture: only ARM64 and ARM32 are supported"
#endif

// ============================================================
// 便捷包装函数 (架构无关)
// ============================================================

int sg_open(const char *path, int flags)
{
    return sg_openat(-100 /* AT_FDCWD */, path, flags);
}

int sg_access(const char *path, int mode)
{
    return sg_faccessat(-100 /* AT_FDCWD */, path, mode);
}

int sg_stat(const char *path, struct stat *buf)
{
    return sg_fstatat(-100 /* AT_FDCWD */, path, buf, 0);
}

ssize_t sg_read_file(const char *path, char *buf, size_t buf_size)
{
    if (!path || !buf || buf_size == 0)
        return -1;

    int fd = sg_open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    ssize_t total = 0;
    ssize_t n;

    while ((size_t)total < buf_size - 1)
    {
        n = sg_read(fd, buf + total, buf_size - 1 - total);
        if (n <= 0)
            break;
        total += n;
    }

    buf[total] = '\0';
    sg_close(fd);
    return total;
}

// 在字符串中搜索子串 (不依赖 libc strstr 以防 hook)
static const char *sg_strstr(const char *haystack, const char *needle)
{
    if (!*needle)
        return haystack;
    size_t needle_len = 0;
    const char *p = needle;
    while (*p++)
        needle_len++;

    for (; *haystack; haystack++)
    {
        const char *h = haystack;
        const char *n = needle;
        size_t i = 0;
        while (i < needle_len && *h && *h == *n)
        {
            h++;
            n++;
            i++;
        }
        if (i == needle_len)
            return haystack;
    }
    return NULL;
}

int sg_search_file(const char *path, const char **keywords, int keyword_count)
{
    char buf[8192];
    ssize_t len = sg_read_file(path, buf, sizeof(buf));
    if (len <= 0)
        return 0;

    int matches = 0;
    for (int i = 0; i < keyword_count; i++)
    {
        if (sg_strstr(buf, keywords[i]) != NULL)
        {
            matches++;
        }
    }
    return matches;
}
