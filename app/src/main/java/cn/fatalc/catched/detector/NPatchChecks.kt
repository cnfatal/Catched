package cn.fatalc.catched.detector

import android.content.Context
import android.content.pm.ApplicationInfo
import cn.fatalc.catched.model.Check
import cn.fatalc.catched.model.CheckResult
import cn.fatalc.catched.native.NativeBridge

private const val G = "NPatch/LSPatch"

private val stubs = listOf(
    "org.lsposed.lspatch.loader.LSPAppComponentFactoryStub",
    "org.lsposed.lspatch.appstub.LSPAppComponentFactoryStub",
    "org.lsposed.npatch.loader.NpatchAppComponentFactoryStub"
)

fun npatchChecks(context: Context): List<Check> = listOf(
    Check("np.acf", G, "appComponentFactory 篡改",
        "反射读取 ApplicationInfo.appComponentFactory 字段值，LSPatch/NPatch 会将其替换为自定义的 LSPAppComponentFactoryStub 以实现无 Root 注入",
        setOf("java", "reflection")
    ) {
        val acf = runCatching {
            ApplicationInfo::class.java
                .getDeclaredField("appComponentFactory").apply { isAccessible = true }
                .get(context.applicationInfo) as? String
        }.getOrNull()
        val detected = acf?.contains("lsp", true) == true || acf?.contains("npatch", true) == true
        CheckResult(detected, if (detected) "appComponentFactory: $acf" else "appComponentFactory: ${acf ?: "null"}")
    },

    Check("np.stub", G, "LSPatch Stub 类",
        "尝试通过当前 ClassLoader 加载 LSPAppComponentFactoryStub / NpatchAppComponentFactoryStub 等 Stub 类，加载成功说明 APK 已被 LSPatch/NPatch 重打包",
        setOf("java", "classloader")
    ) {
        val found = stubs.firstOrNull { cls ->
            runCatching { context.classLoader.loadClass(cls); true }.getOrDefault(false)
        }
        CheckResult(found != null, if (found != null) "loaded: $found" else null)
    },

    Check("np.so", G, "npatch SO 加载",
        "通过 SVC 读取 /proc/self/maps 搜索 libnpatch.so、liblspatch.so、liblspd.so 等 NPatch/LSPatch 注入的动态库映射记录",
        setOf("native", "svc", "procfs")
    ) {
        CheckResult(NativeBridge.nDetectNPatchSoMaps())
    },

    Check("np.openat", G, "openat Hook",
        "比对 libc.so 中 openat 函数的 GOT/PLT 条目地址与实际函数地址，不一致说明 openat 被 Hook（NPatch 用此拦截文件访问实现路径重定向）",
        setOf("native", "hook")
    ) {
        CheckResult(NativeBridge.nDetectNPatchOpenatHook())
    },

    Check("np.apk_path", G, "APK 路径异常",
        "检查 ApplicationInfo.sourceDir 是否指向 /data/data/包名/cache/ 等异常路径。NPatch 会将修改后的 APK 释放到 cache 目录并从该路径加载",
        setOf("java", "filesystem")
    ) {
        val src = context.applicationInfo.sourceDir ?: ""
        val data = context.applicationInfo.dataDir ?: ""
        val d = src.contains("/cache/") || src.contains("/npatch/") || src.contains("/lspatch/") ||
                (src.startsWith(data) && src.contains("cache"))
        CheckResult(d, "sourceDir: $src")
    },

    Check("np.cache", G, "cache/npatch/ 目录",
        "通过 SVC 检查应用 dataDir 下 cache/npatch/、cache/lspatch/ 目录是否存在。NPatch 重打包后会在这些目录存放配置和模块文件",
        setOf("native", "svc", "filesystem")
    ) {
        val dir = context.applicationInfo.dataDir ?: ""
        val d = if (dir.isNotEmpty()) NativeBridge.nDetectNPatchCacheDir(dir) else false
        CheckResult(d, if (d) "found in: $dir/cache/npatch/ or lspatch/" else null)
    },

    Check("np.meta", G, "metadata npatch 键",
        "反射读取 ApplicationInfo.metaData Bundle，检查是否包含 npatch、lspatch 等键名。NPatch 重打包时会在 AndroidManifest.xml 中注入这些 metadata",
        setOf("java", "reflection")
    ) {
        val meta = context.applicationInfo.metaData
        val keys = runCatching {
            meta?.keySet()?.filter {
                it.contains("npatch", true) || it.contains("lspatch", true)
            }
        }.getOrNull()
        val d = keys?.isNotEmpty() == true
        CheckResult(d, keys?.joinToString("\n") { "meta-key: $it" }?.ifEmpty { null })
    },

    Check("np.profile", G, "profile 文件异常",
        "通过 SVC 检查应用 dataDir 下 code_cache/profile 文件权限，NPatch 会将 profile 文件设为只读（0444）以防止系统覆盖其修改",
        setOf("native", "svc", "filesystem")
    ) {
        val dir = context.applicationInfo.dataDir ?: ""
        val d = if (dir.isNotEmpty()) NativeBridge.nDetectNPatchProfile(dir) else false
        CheckResult(d, if (d) "profile file is read-only in $dir" else null)
    },

    Check("np.assets", G, "assets/npatch/ 扫描",
        "检查当前 APK 的 assets 目录中是否存在 npatch/、lspatch/ 子目录或 config.json 配置文件。NPatch 重打包时会将模块配置打包到 assets 中",
        setOf("java", "filesystem")
    ) {
        val found = runCatching {
            val assets = context.assets
            val paths = listOf("npatch", "lspatch", "npatch/config.json", "lspatch/config.json")
            paths.filter { path ->
                runCatching { assets.open(path).close(); true }.getOrDefault(false) ||
                runCatching { assets.list(path)?.isNotEmpty() == true }.getOrDefault(false)
            }
        }.getOrDefault(emptyList())
        CheckResult(found.isNotEmpty(), found.joinToString("\n") { "assets/$it" }.ifEmpty { null })
    },
)
