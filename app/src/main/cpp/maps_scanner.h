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
typedef struct {
    char library[256];       // 匹配到的库名/路径
    unsigned long start;     // 映射起始地址
    unsigned long end;       // 映射结束地址
    char perms[5];           // 权限 (rwxp)
} SgMapMatch;

// 扫描结果集
typedef struct {
    SgMapMatch matches[32];  // 最多 32 条匹配
    int count;               // 实际匹配数
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

#endif // CATCHED_MAPS_SCANNER_H
