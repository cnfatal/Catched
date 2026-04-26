package cn.fatalc.catched.native

import java.lang.reflect.Method

object NativeBridge {

    init { System.loadLibrary("catched") }

    // Root/Magisk
    @JvmStatic external fun nDetectSuPathsSvc(): Boolean
    @JvmStatic external fun nDetectSuStatNative(): Boolean
    @JvmStatic external fun nDetectMagiskMount(): Boolean
    @JvmStatic external fun nDetectMountinfo(): Boolean
    @JvmStatic external fun nDetectSelinuxContext(): Boolean
    @JvmStatic external fun nDetectSelinuxPrev(): Boolean
    @JvmStatic external fun nDetectMagiskSocket(): Boolean
    @JvmStatic external fun nDetectSystemProperties(): Boolean

    // Xposed/LSPosed
    @JvmStatic external fun nDetectSuspiciousExecutableMaps(): Boolean
    @JvmStatic external fun nDetectHiddenElfMaps(): Boolean
    @JvmStatic external fun nDetectXposedMaps(): Boolean
    @JvmStatic external fun nDetectXposedLibart(): Boolean
    @JvmStatic external fun nDetectXposedAppProcess(): Boolean
    @JvmStatic external fun nCheckOpenatHook(): Boolean
    @JvmStatic external fun nGetArtMethodSize(): Int
    @JvmStatic external fun nCheckArtMethodHooked(method: Method): Boolean

    // Frida
    @JvmStatic external fun nDetectFridaMaps(): Boolean
    @JvmStatic external fun nDetectFridaPort(): Boolean
    @JvmStatic external fun nDetectFridaProcTcp(): Boolean
    @JvmStatic external fun nDetectFridaServerFile(): Boolean
    @JvmStatic external fun nDetectFridaNamedPipe(): Boolean
    @JvmStatic external fun nDetectFridaDbus(): Boolean
    @JvmStatic external fun nDetectFridaMemory(): Boolean
    @JvmStatic external fun nDetectFridaThread(): Boolean

    // NPatch/LSPatch
    @JvmStatic external fun nDetectNPatchSoMaps(): Boolean
    @JvmStatic external fun nDetectNPatchOpenatHook(): Boolean
    @JvmStatic external fun nDetectNPatchCacheDir(dataDir: String): Boolean
    @JvmStatic external fun nDetectNPatchProfile(dataDir: String): Boolean

    // Seccomp-BPF
    @JvmStatic external fun nDetectSeccompStatus(): Int
    @JvmStatic external fun nDetectSeccompFilterCount(): Int
    @JvmStatic external fun nDetectCapabilityAnomaly(): Boolean

    // Signal handler
    @JvmStatic external fun nDetectSigsysHandler(): Boolean
    @JvmStatic external fun nDetectSigsegvHandler(): Boolean
    @JvmStatic external fun nDetectSigbusHandler(): Boolean

    // Code integrity
    @JvmStatic external fun nDetectTextIntegrity(soPath: String): Int
    @JvmStatic external fun nDetectElfSegmentGap(): Boolean
    @JvmStatic external fun nDetectVdsoAnomaly(): Boolean
    @JvmStatic external fun nDetectTrampolineIslands(): Boolean
    @JvmStatic external fun nDetectLibartInternalHooks(): Boolean
    @JvmStatic external fun nDetectReturnAddressAnomaly(): Boolean

    // Extended hook detection
    @JvmStatic external fun nCheckAccessFlagsAnomaly(method: Method, sdkVersion: Int): Int
    @JvmStatic external fun nCheckCriticalFunctionsHook(): Int
    @JvmStatic external fun nValidateMapsInode(): Int

    // APK signature
    @JvmStatic external fun nExtractApkCertSha256(apkPath: String): String?

    // SSL pinning
    @JvmStatic external fun nDetectSslFuncHook(): Boolean
    @JvmStatic external fun nDetectLibsslPathAnomaly(): Boolean
    @JvmStatic external fun nDetectMultipleLibssl(): Boolean
    @JvmStatic external fun nDetectSslBypassLibs(): Boolean
}
