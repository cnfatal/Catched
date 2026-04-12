#ifndef CATCHED_SYSCALL_WRAPPER_H
#define CATCHED_SYSCALL_WRAPPER_H

#include <sys/types.h>
#include <sys/stat.h>

/**
 * SVC 直接系统调用包装器
 *
 * 绕过 libc 函数 Hook，直接通过 SVC 指令调用 Linux 内核。
 * 攻击者使用 Frida Hook libc 的 open/read/fgets 等函数时，
 * 这些 SVC 调用不会经过 libc，因此无法被截获。
 *
 * 支持架构: ARM64 (aarch64) / ARM32 (arm)
 */

// 文件操作
int sg_openat(int dirfd, const char *path, int flags);
int sg_open(const char *path, int flags);
ssize_t sg_read(int fd, void *buf, size_t count);
int sg_close(int fd);
ssize_t sg_write(int fd, const void *buf, size_t count);

// 文件属性检查
int sg_faccessat(int dirfd, const char *path, int mode);
int sg_access(const char *path, int mode);
int sg_fstatat(int dirfd, const char *path, struct stat *buf, int flags);
int sg_stat(const char *path, struct stat *buf);

// 文件定位
off_t sg_lseek(int fd, off_t offset, int whence);

// 内存映射
void *sg_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int sg_munmap(void *addr, size_t length);

// 目录操作
int sg_getdents64(int fd, void *dirp, size_t count);

// Socket 操作
int sg_socket(int domain, int type, int protocol);
int sg_connect(int sockfd, const void *addr, int addrlen);

// 信号操作
int sg_rt_sigaction(int signum, const void *act, void *oldact, size_t sigsetsize);

// 链接与进程信息
ssize_t sg_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz);
int sg_prctl(int option, unsigned long arg2, unsigned long arg3,
             unsigned long arg4, unsigned long arg5);

// 读取完整文件到缓冲区 (使用 SVC 调用)
// 返回读取字节数，失败返回 -1
ssize_t sg_read_file(const char *path, char *buf, size_t buf_size);

// 逐行搜索文件内容中的关键字
// 返回匹配次数
int sg_search_file(const char *path, const char **keywords, int keyword_count);

#endif // CATCHED_SYSCALL_WRAPPER_H
