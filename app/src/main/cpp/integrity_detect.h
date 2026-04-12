#ifndef CATCHED_INTEGRITY_DETECT_H
#define CATCHED_INTEGRITY_DETECT_H

#include <jni.h>

/**
 * 代码完整性与高级 Hook 检测
 *
 * 包含:
 * - .text 段内存 vs 磁盘比对
 * - ELF LOAD 段间隙注入检测
 * - vDSO 完整性验证
 * - 返回地址 (LR/X30) 验证
 * - Trampoline island 检测 (匿名 r-xp 页)
 * - libart.so 内部函数 Hook 检测
 */

// .text 段磁盘 vs 内存比对 (检测 inline hook 补丁)
// 对指定 SO 文件比较其 .text 段在磁盘文件和进程内存中的内容
// 返回差异字节数 (0 = 完整)
int detect_text_integrity(const char *so_path);

// ELF LOAD 段间隙检测
// 检查 maps 中库的 LOAD 段之间是否有异常的可执行匿名页
int detect_elf_segment_gap(void);

// vDSO 完整性验证
// 通过 getauxval(AT_SYSINFO_EHDR) 获取 vDSO 地址，
// 与 /proc/self/maps 中 [vdso] 的地址交叉验证
int detect_vdso_anomaly(void);

// 匿名可执行内存 (trampoline island) 检测
// 扫描 maps 中靠近已知库的匿名 r-xp 页，检查是否包含跳转指令模式
int detect_trampoline_islands(void);

// libart.so 内部函数 inline hook 检测
// 检查 libart.so 中已知被 hook 框架劫持的内部函数的函数头
int detect_libart_internal_hooks(void);

// 返回地址验证 (检查调用链是否经过非法内存区域)
// 在 JNI 层获取当前 LR 并验证是否在合法库范围内
int detect_return_address_anomaly(void);

#endif // CATCHED_INTEGRITY_DETECT_H
