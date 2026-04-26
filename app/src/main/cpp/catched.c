#include <jni.h>
#include <string.h>
#include <android/log.h>

#include "root_detect.h"
#include "hook_detect.h"
#include "frida_detect.h"
#include "art_method.h"
#include "npatch_detect.h"
#include "maps_scanner.h"
#include "seccomp_detect.h"
#include "signal_detect.h"
#include "integrity_detect.h"
#include "apk_signature.h"
#include "ssl_detect.h"

#define TAG "Catched"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

// ============================================================
// JNI 函数声明
// ============================================================

// --- Root/Magisk 检测 ---
static jboolean native_detectSuPathsSvc(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_su_paths_svc() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectSuStatNative(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_su_stat_native() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectMagiskMount(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_magisk_mount() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectMountinfo(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_mountinfo() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectSelinuxContext(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_selinux_context() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectSelinuxPrev(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_selinux_prev() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectMagiskSocket(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_magisk_socket() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectSystemProperties(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_system_properties() ? JNI_TRUE : JNI_FALSE;
}

// --- Xposed/LSPosed 检测 (Native 层) ---
static jboolean native_detectSuspiciousExecutableMaps(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return sg_detect_suspicious_executable_maps() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectHiddenElfMaps(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return sg_detect_hidden_elf_maps() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectXposedMaps(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_xposed_maps() > 0 ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectXposedLibart(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_xposed_libart() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectXposedAppProcess(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_xposed_app_process() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_checkOpenatHook(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return check_openat_hook() ? JNI_TRUE : JNI_FALSE;
}

static jint native_getArtMethodSize(JNIEnv *env, jclass clazz)
{
    (void)clazz;
    return get_art_method_size(env);
}

static jboolean native_checkArtMethodHooked(JNIEnv *env, jclass clazz, jobject method)
{
    (void)clazz;
    return check_art_method_hooked(env, method) ? JNI_TRUE : JNI_FALSE;
}

// --- Frida 检测 ---
static jboolean native_detectFridaMaps(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_frida_maps() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectFridaPort(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_frida_port() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectFridaProcTcp(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_frida_proc_tcp() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectFridaServerFile(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_frida_server_file() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectFridaNamedPipe(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_frida_named_pipe() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectFridaDbus(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_frida_dbus() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectFridaMemory(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_frida_memory() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectFridaThread(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_frida_thread() ? JNI_TRUE : JNI_FALSE;
}

// --- NPatch/LSPatch 检测 ---
static jboolean native_detectNPatchSoMaps(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_npatch_so_maps() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectNPatchOpenatHook(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_npatch_openat_hook() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectNPatchCacheDir(JNIEnv *env, jclass clazz, jstring dataDir)
{
    (void)clazz;
    const char *dir = (*env)->GetStringUTFChars(env, dataDir, NULL);
    int result = detect_npatch_cache_dir(env, dir);
    (*env)->ReleaseStringUTFChars(env, dataDir, dir);
    return result ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectNPatchProfile(JNIEnv *env, jclass clazz, jstring dataDir)
{
    (void)clazz;
    const char *dir = (*env)->GetStringUTFChars(env, dataDir, NULL);
    int result = detect_npatch_profile(env, dir);
    (*env)->ReleaseStringUTFChars(env, dataDir, dir);
    return result ? JNI_TRUE : JNI_FALSE;
}

// --- Seccomp-BPF 检测 ---
static jint native_detectSeccompStatus(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_seccomp_status();
}

static jint native_detectSeccompFilterCount(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_seccomp_filter_count();
}

static jboolean native_detectCapabilityAnomaly(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_capability_anomaly() ? JNI_TRUE : JNI_FALSE;
}

// --- 信号处理器检测 ---
static jboolean native_detectSigsysHandler(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_sigsys_handler() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectSigsegvHandler(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_sigsegv_handler() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectSigbusHandler(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_sigbus_handler() ? JNI_TRUE : JNI_FALSE;
}

// --- 代码完整性检测 ---
static jint native_detectTextIntegrity(JNIEnv *env, jclass clazz, jstring soPath)
{
    (void)clazz;
    const char *path = (*env)->GetStringUTFChars(env, soPath, NULL);
    int result = detect_text_integrity(path);
    (*env)->ReleaseStringUTFChars(env, soPath, path);
    return result;
}

static jboolean native_detectElfSegmentGap(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_elf_segment_gap() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectVdsoAnomaly(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_vdso_anomaly() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectTrampolineIslands(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_trampoline_islands() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectLibartInternalHooks(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_libart_internal_hooks() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectReturnAddressAnomaly(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_return_address_anomaly() ? JNI_TRUE : JNI_FALSE;
}

// --- 扩展 Hook 检测 ---
static jint native_checkAccessFlagsAnomaly(JNIEnv *env, jclass clazz, jobject method, jint sdkVersion)
{
    (void)clazz;
    return check_access_flags_anomaly(env, method, sdkVersion);
}

static jint native_checkCriticalFunctionsHook(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return check_critical_functions_hook();
}

static jint native_validateMapsInode(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return sg_validate_maps_inode();
}

// --- SSL Pinning ---
static jboolean native_detectSslFuncHook(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_ssl_func_hook() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectLibsslPathAnomaly(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_libssl_path_anomaly() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectMultipleLibssl(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_multiple_libssl() ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_detectSslBypassLibs(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return detect_ssl_bypass_libs() ? JNI_TRUE : JNI_FALSE;
}

// --- APK 签名直接解析 ---
static jstring native_extractApkCertSha256(JNIEnv *env, jclass clazz, jstring apkPath)
{
    (void)clazz;
    const char *path = (*env)->GetStringUTFChars(env, apkPath, NULL);
    unsigned char hash[32];
    int ret = apk_extract_cert_sha256(path, hash);
    (*env)->ReleaseStringUTFChars(env, apkPath, path);

    if (ret != 0)
        return NULL;

    // 转换为十六进制字符串
    char hex[65];
    static const char hexchars[] = "0123456789ABCDEF";
    for (int i = 0; i < 32; i++)
    {
        hex[i * 2] = hexchars[(hash[i] >> 4) & 0xF];
        hex[i * 2 + 1] = hexchars[hash[i] & 0xF];
    }
    hex[64] = '\0';
    return (*env)->NewStringUTF(env, hex);
}

// ============================================================
// JNI 动态注册
// ============================================================

static const char *NATIVE_BRIDGE_CLASS = "cn/fatalc/catched/native/NativeBridge";

static JNINativeMethod methods[] = {
    // Root/Magisk
    {"nDetectSuPathsSvc", "()Z", (void *)native_detectSuPathsSvc},
    {"nDetectSuStatNative", "()Z", (void *)native_detectSuStatNative},
    {"nDetectMagiskMount", "()Z", (void *)native_detectMagiskMount},
    {"nDetectMountinfo", "()Z", (void *)native_detectMountinfo},
    {"nDetectSelinuxContext", "()Z", (void *)native_detectSelinuxContext},
    {"nDetectSelinuxPrev", "()Z", (void *)native_detectSelinuxPrev},
    {"nDetectMagiskSocket", "()Z", (void *)native_detectMagiskSocket},
    {"nDetectSystemProperties", "()Z", (void *)native_detectSystemProperties},

    // Xposed/LSPosed (Native)
    {"nDetectSuspiciousExecutableMaps", "()Z", (void *)native_detectSuspiciousExecutableMaps},
    {"nDetectHiddenElfMaps", "()Z", (void *)native_detectHiddenElfMaps},
    {"nDetectXposedMaps", "()Z", (void *)native_detectXposedMaps},
    {"nDetectXposedLibart", "()Z", (void *)native_detectXposedLibart},
    {"nDetectXposedAppProcess", "()Z", (void *)native_detectXposedAppProcess},
    {"nCheckOpenatHook", "()Z", (void *)native_checkOpenatHook},
    {"nGetArtMethodSize", "()I", (void *)native_getArtMethodSize},
    {"nCheckArtMethodHooked", "(Ljava/lang/reflect/Method;)Z", (void *)native_checkArtMethodHooked},

    // Frida
    {"nDetectFridaMaps", "()Z", (void *)native_detectFridaMaps},
    {"nDetectFridaPort", "()Z", (void *)native_detectFridaPort},
    {"nDetectFridaProcTcp", "()Z", (void *)native_detectFridaProcTcp},
    {"nDetectFridaServerFile", "()Z", (void *)native_detectFridaServerFile},
    {"nDetectFridaNamedPipe", "()Z", (void *)native_detectFridaNamedPipe},
    {"nDetectFridaDbus", "()Z", (void *)native_detectFridaDbus},
    {"nDetectFridaMemory", "()Z", (void *)native_detectFridaMemory},
    {"nDetectFridaThread", "()Z", (void *)native_detectFridaThread},

    // NPatch/LSPatch
    {"nDetectNPatchSoMaps", "()Z", (void *)native_detectNPatchSoMaps},
    {"nDetectNPatchOpenatHook", "()Z", (void *)native_detectNPatchOpenatHook},
    {"nDetectNPatchCacheDir", "(Ljava/lang/String;)Z", (void *)native_detectNPatchCacheDir},
    {"nDetectNPatchProfile", "(Ljava/lang/String;)Z", (void *)native_detectNPatchProfile},

    // Seccomp-BPF
    {"nDetectSeccompStatus", "()I", (void *)native_detectSeccompStatus},
    {"nDetectSeccompFilterCount", "()I", (void *)native_detectSeccompFilterCount},
    {"nDetectCapabilityAnomaly", "()Z", (void *)native_detectCapabilityAnomaly},

    // Signal handler
    {"nDetectSigsysHandler", "()Z", (void *)native_detectSigsysHandler},
    {"nDetectSigsegvHandler", "()Z", (void *)native_detectSigsegvHandler},
    {"nDetectSigbusHandler", "()Z", (void *)native_detectSigbusHandler},

    // Code integrity
    {"nDetectTextIntegrity", "(Ljava/lang/String;)I", (void *)native_detectTextIntegrity},
    {"nDetectElfSegmentGap", "()Z", (void *)native_detectElfSegmentGap},
    {"nDetectVdsoAnomaly", "()Z", (void *)native_detectVdsoAnomaly},
    {"nDetectTrampolineIslands", "()Z", (void *)native_detectTrampolineIslands},
    {"nDetectLibartInternalHooks", "()Z", (void *)native_detectLibartInternalHooks},
    {"nDetectReturnAddressAnomaly", "()Z", (void *)native_detectReturnAddressAnomaly},

    // Extended hook detection
    {"nCheckAccessFlagsAnomaly", "(Ljava/lang/reflect/Method;I)I", (void *)native_checkAccessFlagsAnomaly},
    {"nCheckCriticalFunctionsHook", "()I", (void *)native_checkCriticalFunctionsHook},
    {"nValidateMapsInode", "()I", (void *)native_validateMapsInode},

    // APK signature
    {"nExtractApkCertSha256", "(Ljava/lang/String;)Ljava/lang/String;", (void *)native_extractApkCertSha256},

    // SSL pinning
    {"nDetectSslFuncHook", "()Z", (void *)native_detectSslFuncHook},
    {"nDetectLibsslPathAnomaly", "()Z", (void *)native_detectLibsslPathAnomaly},
    {"nDetectMultipleLibssl", "()Z", (void *)native_detectMultipleLibssl},
    {"nDetectSslBypassLibs", "()Z", (void *)native_detectSslBypassLibs},
};

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)reserved;
    JNIEnv *env;

    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK)
    {
        return JNI_ERR;
    }

    jclass clazz = (*env)->FindClass(env, NATIVE_BRIDGE_CLASS);
    if (!clazz)
    {
        LOGD("Failed to find NativeBridge class");
        return JNI_ERR;
    }

    int method_count = sizeof(methods) / sizeof(methods[0]);
    if ((*env)->RegisterNatives(env, clazz, methods, method_count) < 0)
    {
        LOGD("Failed to register native methods");
        return JNI_ERR;
    }

    LOGD("Catched native library loaded, %d methods registered", method_count);
    return JNI_VERSION_1_6;
}
