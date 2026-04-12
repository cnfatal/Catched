#ifndef CATCHED_MAPS_SCANNER_H
#define CATCHED_MAPS_SCANNER_H

#include <stddef.h>
#include <sys/types.h>

/**
 * /proc/self/maps 扫描器
 *
 * 使用 SVC 直接系统调用读取 /proc/self/maps，
 * 搜索可疑 so 库和路径特征。
 */

// 单条 maps 扫描结果
typedef struct
{
    char library[256];   // 匹配到的库名/路径
    unsigned long start; // 映射起始地址
    unsigned long end;   // 映射结束地址
    char perms[5];       // 权限 (rwxp)
} SgMapMatch;

// 扫描结果集
typedef struct
{
    SgMapMatch matches[32]; // 最多 32 条匹配
    int count;              // 实际匹配数
} SgMapScanResult;

/**
 * 扫描 /proc/self/maps 中是否包含黑名单中的关键字
 *
 * @param blacklist     关键字数组
 * @param blacklist_len 关键字数量
 * @param result        输出结果
 * @return 匹配数量
 */
int sg_scan_maps(const char **blacklist, int blacklist_len, SgMapScanResult *result);

/**
 * 扫描 /proc/self/maps 的完整内容到缓冲区
 * 返回读取字节数
 */
ssize_t sg_read_maps(char *buf, size_t buf_size);

/**
 * 扫描 /proc/self/maps 中异常的可执行内存段（如虚假 jit-cache 或匿名可执行段）
 */
int sg_detect_suspicious_executable_maps(void);

/**
 * 扫描 /proc/self/maps 的匿名读写内存段（r--p/rw-p）内是否存在被去除了执行权限伪装的 ELF
 */
int sg_detect_hidden_elf_maps(void);

/**
 * 验证 /proc/self/maps 中文件映射的 inode 是否与实际文件一致
 * 检测 maps 篡改（通过 overlay/bind mount 替换库文件）
 * @return 不一致的映射数量
 */
int sg_validate_maps_inode(void);

#endif // CATCHED_MAPS_SCANNER_H
