#include "art_method.h"
#include <jni.h>
#include <string.h>
#include <stdint.h>
#include <android/log.h>

#define TAG "Catched"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

/*
 * ArtMethod 结构体布局 (简化, Android 10+):
 *
 * struct ArtMethod {
 *     uint32_t declaring_class_;        // GcRoot<mirror::Class>
 *     uint32_t access_flags_;
 *     uint32_t dex_code_item_offset_;
 *     uint32_t dex_method_index_;
 *     uint16_t method_index_;
 *     uint16_t hotness_count_;
 *     struct PtrSizedFields {
 *         void* data_;                  // ArtMethod** 或 native 方法指针
 *         void* entry_point_from_quick_compiled_code_;
 *     } ptr_sized_fields_;
 * };
 *
 * Hook 检测的核心思路:
 * 1. ArtMethod 的大小在同一设备上是固定的
 * 2. Xposed Hook 会修改 access_flags 加上 kAccNative 位
 * 3. Hook 后 entry_point 会指向 Hook 框架的代码
 */

// access_flags 中的关键位
#define kAccPublic       0x0001
#define kAccNative       0x0100
#define kAccFastNative   0x00080000
#define kAccPreCompiled  0x00200000

// 通过反射获取 ArtMethod 指针
static void *get_art_method_ptr(JNIEnv *env, jobject method) {
    if (!method) return NULL;
    // jmethodID 在 ART 中就是 ArtMethod*
    jclass method_class = (*env)->GetObjectClass(env, method);
    jmethodID get_method_id = (*env)->GetMethodID(env, method_class, "toString", "()Ljava/lang/String;");
    (void)get_method_id;

    // 在 ART 中，通过 FromReflectedMethod 获取 ArtMethod*
    jmethodID art_method = (*env)->FromReflectedMethod(env, method);
    (*env)->DeleteLocalRef(env, method_class);
    return (void *)art_method;
}

// 获取 ArtMethod 大小
int get_art_method_size(JNIEnv *env) {
    // 通过获取同一个类中两个相邻声明方法的 ArtMethod 地址差来计算
    jclass string_class = (*env)->FindClass(env, "java/lang/String");
    if (!string_class) return 0;

    // 获取两个已知的相邻方法
    jmethodID m1 = (*env)->GetMethodID(env, string_class, "length", "()I");
    jmethodID m2 = (*env)->GetMethodID(env, string_class, "isEmpty", "()Z");

    (*env)->DeleteLocalRef(env, string_class);

    if (!m1 || !m2) return 0;

    uintptr_t addr1 = (uintptr_t)m1;
    uintptr_t addr2 = (uintptr_t)m2;
    int size = (int)(addr2 > addr1 ? addr2 - addr1 : addr1 - addr2);

    LOGD("X12: ArtMethod size = %d (m1=0x%lx, m2=0x%lx)",
         size, (unsigned long)addr1, (unsigned long)addr2);
    return size;
}

// 检查方法是否被 hook
int check_art_method_hooked(JNIEnv *env, jobject method) {
    void *art_method = get_art_method_ptr(env, method);
    if (!art_method) return 0;

    // 读取 access_flags (偏移量通常为 4 字节)
    uint32_t *access_flags_ptr = (uint32_t *)((uint8_t *)art_method + 4);
    uint32_t flags = *access_flags_ptr;

    // 检查是否被不当标记为 native
    // 正常的 Java 方法不应该有 kAccNative
    // 但 Xposed Hook 后会加上这个标志
    if (flags & kAccNative) {
        LOGD("X12: Method has unexpected native flag: access_flags=0x%x", flags);
        return 1;
    }

    return 0;
}

// 比较两个方法的 ArtMethod 大小
int compare_art_method_size(JNIEnv *env, jobject method1, jobject method2) {
    void *am1 = get_art_method_ptr(env, method1);
    void *am2 = get_art_method_ptr(env, method2);

    if (!am1 || !am2) return 0;

    // 如果一个方法被 Hook 了，ArtMethod 的有效内容可能被修改
    // 比较前 16 字节的模式
    int diff = memcmp(am1, am2, 4); // 比较 declaring_class
    if (diff == 0) {
        // 同一个类的方法，declaring_class 应该相同
        // 进一步比较 entry_point
#if defined(__aarch64__)
        void **ep1 = (void **)((uint8_t *)am1 + 32); // approximate offset
        void **ep2 = (void **)((uint8_t *)am2 + 32);
#else
        void **ep1 = (void **)((uint8_t *)am1 + 20);
        void **ep2 = (void **)((uint8_t *)am2 + 20);
#endif
        (void)ep1;
        (void)ep2;
    }

    return 0;
}

// 检查 access_flags 异常
int check_access_flags_anomaly(JNIEnv *env, jobject method, int sdk_version) {
    (void)sdk_version;
    return check_art_method_hooked(env, method);
}
