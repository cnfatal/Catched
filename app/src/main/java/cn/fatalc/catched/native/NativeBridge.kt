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
}
