#ifndef CATCHED_ART_METHOD_H
#define CATCHED_ART_METHOD_H

#include <jni.h>

/**
 * ArtMethod 结构体分析
 *
 * X12: 读取 ArtMethod 内部结构体检测 Hook
 *
 * ArtMethod 是 ART 虚拟机中表示 Java 方法的核心结构体。
 * Xposed/LSPosed Hook 方法时会修改 ArtMethod 的 entry_point 和 access_flags。
 */

// 检查方法是否被 hook (比较 ArtMethod size 和 access_flags)
int check_art_method_hooked(JNIEnv *env, jobject method);

// 比较两个方法的 ArtMethod 大小
int compare_art_method_size(JNIEnv *env, jobject method1, jobject method2);

// 检查 access_flags 异常
int check_access_flags_anomaly(JNIEnv *env, jobject method, int sdk_version);

// 获取 ArtMethod 大小 (通过两个相邻方法的地址差)
int get_art_method_size(JNIEnv *env);

#endif // CATCHED_ART_METHOD_H
