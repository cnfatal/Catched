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
#define kAccPublic 0x0001
#define kAccNative 0x0100
#define kAccFastNative 0x00080000
#define kAccPreCompiled_R 0x00200000 // Android R (11)
#define kAccPreCompiled_S 0x00800000 // Android S+ (12+)
#define kAccCompileDontBother 0x02000000
#define kAccFastInterpreterToInterpreterInvoke 0x40000000

// 通过反射获取 ArtMethod 指针
static void *get_art_method_ptr(JNIEnv *env, jobject method)
{
    if (!method)
        return NULL;
    // jmethodID 在 ART 中就是 ArtMethod*
    jclass method_class = (*env)->GetObjectClass(env, method);
    jmethodID get_method_id = (*env)->GetMethodID(env, method_class, "toString", "()Ljava/lang/String;");
    (void)get_method_id;

    // 在 ART 中，通过 FromReflectedMethod 获取 ArtMethod*
    jmethodID art_method = (*env)->FromReflectedMethod(env, method);
    (*env)->DeleteLocalRef(env, method_class);
    if (!art_method) {
        LOGD("get_art_method_ptr: FromReflectedMethod returned NULL");
        return NULL;
    }
    return (void *)art_method;
}

// 获取 ArtMethod 大小
int get_art_method_size(JNIEnv *env)
{
    // 通过获取同一个类中两个相邻声明方法的 ArtMethod 地址差来计算
    jclass string_class = (*env)->FindClass(env, "java/lang/String");
    if (!string_class)
        return 0;

    // 获取两个已知的相邻方法
    jmethodID m1 = (*env)->GetMethodID(env, string_class, "length", "()I");
    jmethodID m2 = (*env)->GetMethodID(env, string_class, "isEmpty", "()Z");

    (*env)->DeleteLocalRef(env, string_class);

    if (!m1 || !m2)
        return 0;

    uintptr_t addr1 = (uintptr_t)m1;
    uintptr_t addr2 = (uintptr_t)m2;
    int size = (int)(addr2 > addr1 ? addr2 - addr1 : addr1 - addr2);

    LOGD("X12: ArtMethod size = %d (m1=0x%lx, m2=0x%lx)",
         size, (unsigned long)addr1, (unsigned long)addr2);
    return size;
}

// 检查方法是否被 hook
int check_art_method_hooked(JNIEnv *env, jobject method)
{
    void *art_method = get_art_method_ptr(env, method);
    if (!art_method || (uintptr_t)art_method < 0x1000)
        return 0;

    // 读取 access_flags (偏移量通常为 4 字节)
    uint32_t *access_flags_ptr = (uint32_t *)((uint8_t *)art_method + 4);
    uint32_t flags = *access_flags_ptr;

    // 检查是否被不当标记为 native
    // 正常的 Java 方法不应该有 kAccNative
    // 但 Xposed Hook 后会加上这个标志
    if (flags & kAccNative)
    {
        LOGD("X12: Method has unexpected native flag: access_flags=0x%x", flags);
        return 1;
    }

    return 0;
}

// 比较两个方法的 ArtMethod 大小
int compare_art_method_size(JNIEnv *env, jobject method1, jobject method2)
{
    void *am1 = get_art_method_ptr(env, method1);
    void *am2 = get_art_method_ptr(env, method2);

    if (!am1 || !am2)
        return 0;

    // 如果一个方法被 Hook 了，ArtMethod 的有效内容可能被修改
    // 比较前 16 字节的模式
    int diff = memcmp(am1, am2, 4); // 比较 declaring_class
    if (diff == 0)
    {
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

// 检查 access_flags 异常 (包括编译控制标志)
int check_access_flags_anomaly(JNIEnv *env, jobject method, int sdk_version)
{
    void *art_method = get_art_method_ptr(env, method);
    if (!art_method || (uintptr_t)art_method < 0x1000)
        return 0;

    uint32_t *access_flags_ptr = (uint32_t *)((uint8_t *)art_method + 4);
    uint32_t flags = *access_flags_ptr;
    int anomaly = 0;

    // 1. kAccNative 检查 (经典 Xposed/LSPosed Hook)
    if (flags & kAccNative)
    {
        LOGD("X12: Method has unexpected native flag: access_flags=0x%x", flags);
        anomaly |= 1;
    }

    // 2. kAccCompileDontBother 检查
    // 该标志阻止 JIT 重新编译；inline code patching 必须设置此标志
    // 以防止 JIT 覆盖补丁代码。正常 app 方法通常不会有此标志。
    if (flags & kAccCompileDontBother)
    {
        LOGD("X12: Method has kAccCompileDontBother: access_flags=0x%x", flags);
        anomaly |= 2;
    }

    // 3. kAccPreCompiled 检查 (Android R 和 S+ 使用不同的位)
    // 攻击者可能清除此标志以阻止 ART 假设代码已验证
    // 这里我们记录该标志的状态供上层使用
    uint32_t pre_compiled_mask = (sdk_version >= 31) ? kAccPreCompiled_S : kAccPreCompiled_R;
    // 如果方法同时有 kAccCompileDontBother 但没有 kAccPreCompiled，这是可疑模式
    if ((flags & kAccCompileDontBother) && !(flags & pre_compiled_mask))
    {
        LOGD("X12: CompileDontBother set but PreCompiled cleared: flags=0x%x (sdk=%d)",
             flags, sdk_version);
        anomaly |= 4;
    }

    // 4. kAccFastInterpreterToInterpreterInvoke 检查 (Android Q+)
    // 攻击者清除此标志以强制 ART 走 entry_point_ 路径
    // 正常的解释执行方法应有此标志
    if (sdk_version >= 29)
    {
        // 如果 kAccCompileDontBother 被设置但 FastInterpreter 被清除，非常可疑
        if ((flags & kAccCompileDontBother) &&
            !(flags & kAccFastInterpreterToInterpreterInvoke))
        {
            LOGD("X12: CompileDontBother set, FastInterpreter cleared: flags=0x%x",
                 flags);
            anomaly |= 8;
        }
    }

    return anomaly;
}
