package cn.fatalc.catched.detector

import android.content.Context
import android.content.pm.PackageManager
import cn.fatalc.catched.model.Check
import cn.fatalc.catched.model.CheckResult
import cn.fatalc.catched.native.NativeBridge
import dalvik.system.BaseDexClassLoader
import java.lang.reflect.Modifier

private const val G = "Xposed/LSPosed"

private val xposedPackages = listOf(
    "de.robv.android.xposed.installer", "org.meowcat.edxposed.manager",
    "org.lsposed.manager", "org.lsposed.npatch", "org.lsposed.lspatch"
)

@Suppress("PrivateApi")
fun xposedChecks(context: Context): List<Check> = listOf(
    Check("xp.classloader", G, "ClassLoader 加载",
        "通过系统 ClassLoader 尝试加载 de.robv.android.xposed.XposedBridge 类，加载成功说明 Xposed 框架已注入到当前运行时",
        setOf("java", "classloader")
    ) {
        val d = runCatching {
            ClassLoader.getSystemClassLoader().loadClass("de.robv.android.xposed.XposedBridge"); true
        }.getOrDefault(false)
        CheckResult(d, if (d) "XposedBridge class found in system classloader" else null)
    },

    Check("xp.vmdebug", G, "VMDebug 实例扫描",
        "调用隐藏 API dalvik.system.VMDebug.getInstancesOfClasses 获取运行时所有 BaseDexClassLoader 实例，检查是否存在包含 xposed/lsposed 关键字的异常类加载器",
        setOf("java", "reflection")
    ) {
        val d = runCatching {
            val vmDebug = Class.forName("dalvik.system.VMDebug")
            val method = vmDebug.getDeclaredMethod(
                "getInstancesOfClasses", arrayOf<Class<*>>()::class.java, Boolean::class.javaPrimitiveType
            )
            method.isAccessible = true
            @Suppress("UNCHECKED_CAST")
            val instances = method.invoke(null, arrayOf(BaseDexClassLoader::class.java), false) as? Array<Array<Any>>
            val suspicious = instances?.firstOrNull()?.filter { cl ->
                val n = cl.javaClass.name
                n.contains("xposed", true) || n.contains("lsposed", true)
            }
            if (suspicious?.isNotEmpty() == true) suspicious.joinToString("\n") { it.javaClass.name } else null
        }.getOrNull()
        CheckResult(d != null, d)
    },

    Check("xp.dexpath", G, "DexPathList 扫描",
        "反射读取当前 ClassLoader 的 BaseDexClassLoader.pathList.dexElements 数组，遍历所有已加载的 DEX 文件名，搜索包含 XposedBridge 或 lsposed 的条目",
        setOf("java", "reflection")
    ) {
        val evidence = runCatching {
            val cl = context.classLoader
            if (cl is BaseDexClassLoader) {
                val plf = BaseDexClassLoader::class.java.getDeclaredField("pathList").apply { isAccessible = true }
                val pl = plf.get(cl)
                val def = pl!!.javaClass.getDeclaredField("dexElements").apply { isAccessible = true }
                val elements = def.get(pl) as? Array<*>
                val found = elements?.mapNotNull { e ->
                    val df = e?.javaClass?.getDeclaredField("dexFile")?.apply { isAccessible = true }?.get(e)
                    val fn = df?.javaClass?.getDeclaredMethod("getName")?.invoke(df) as? String
                    if (fn?.contains("XposedBridge", true) == true || fn?.contains("lsposed", true) == true) fn else null
                }
                found?.joinToString("\n")?.ifEmpty { null }
            } else null
        }.getOrNull()
        CheckResult(evidence != null, evidence)
    },

    Check("xp.stack", G, "堆栈特征分析",
        "获取当前线程完整调用堆栈，逐帧检查类名是否包含 xposed、de.robv.android.xposed、com.saurik.substrate、lsposed 等框架特征字符串",
        setOf("java", "stacktrace")
    ) {
        val frames = Thread.currentThread().stackTrace.filter {
            it.className.contains("xposed", true) || it.className.contains("saurik") || it.className.contains("lsposed", true)
        }
        CheckResult(
            frames.isNotEmpty(),
            frames.joinToString("\n") { "${it.className}.${it.methodName}(${it.fileName}:${it.lineNumber})" }.ifEmpty { null }
        )
    },

    Check("xp.pkg", G, "安装包 metadata",
        "通过 PackageManager 查询已知 Xposed/LSPosed/EdXposed 管理器包名，并遍历所有已安装应用的 metaData 检查 xposedmodule/xposeddescription 标记",
        setOf("java", "pm")
    ) {
        val pm = context.packageManager
        val found = mutableListOf<String>()
        xposedPackages.forEach { pkg -> if (runCatching { pm.getPackageInfo(pkg, 0) }.isSuccess) found.add("pkg: $pkg") }
        runCatching {
            @Suppress("QueryPermissionsNeeded")
            pm.getInstalledApplications(PackageManager.GET_META_DATA).forEach { app ->
                if (app.metaData?.containsKey("xposedmodule") == true) found.add("module: ${app.packageName}")
            }
        }
        CheckResult(found.isNotEmpty(), found.joinToString("\n").ifEmpty { null })
    },

    Check("xp.cache", G, "XposedHelpers 缓存",
        "反射加载 de.robv.android.xposed.XposedHelpers 类并读取其静态字段 methodCache，非空缓存表明 Xposed 框架已初始化并缓存了 Hook 相关的方法引用",
        setOf("java", "reflection")
    ) {
        val evidence = runCatching {
            val xh = Class.forName("de.robv.android.xposed.XposedHelpers")
            val f = xh.getDeclaredField("methodCache").apply { isAccessible = true }
            val c = f.get(null) as? Map<*, *>
            if (c != null && c.isNotEmpty()) "methodCache entries: ${c.size}" else null
        }.getOrNull()
        CheckResult(evidence != null, evidence)
    },

    Check("xp.hooks", G, "sHookedMethodCallbacks",
        "反射加载 XposedBridge 类并读取 sHookedMethodCallbacks 静态字段，该 Map 记录了所有已被 Hook 的方法及其回调链，非空说明存在活跃 Hook",
        setOf("java", "reflection")
    ) {
        val evidence = runCatching {
            val xb = Class.forName("de.robv.android.xposed.XposedBridge")
            val f = xb.getDeclaredField("sHookedMethodCallbacks").apply { isAccessible = true }
            val c = f.get(null) as? Map<*, *>
            if (c != null && c.isNotEmpty()) "hooked methods: ${c.size}" else null
        }.getOrNull()
        CheckResult(evidence != null, evidence)
    },

    Check("xp.native_flag", G, "方法 native 标志",
        "检查 Runtime.exec() 和 ClassLoader.loadClass() 等系统方法是否被异常标记为 native，Xposed/Frida 的 ART Hook 可能修改方法的 access flags",
        setOf("java", "reflection")
    ) {
        val targets = listOf(Runtime::class.java to "exec", ClassLoader::class.java to "loadClass")
        val anomalies = targets.flatMap { (clz, m) ->
            runCatching {
                clz.declaredMethods.filter { it.name == m && Modifier.isNative(it.modifiers) }
                    .map { "${clz.simpleName}.${it.name}(${it.parameterTypes.joinToString { p -> p.simpleName }})" }
            }.getOrDefault(emptyList())
        }
        CheckResult(anomalies.isNotEmpty(), anomalies.joinToString("\n").ifEmpty { null })
    },

    Check("xp.maps", G, "maps SO 扫描",
        "通过 SVC 直接读取 /proc/self/maps，搜索 libxposed、liblspd、libedxposed、XposedBridge 等 Xposed 框架相关的动态库映射",
        setOf("native", "svc", "procfs")
    ) {
        CheckResult(NativeBridge.nDetectXposedMaps())
    },

    Check("xp.libart", G, "libart.so 扫描",
        "通过 SVC 读取已加载的 libart.so 内存区域，在其 .rodata/.data 段中搜索 \"xposed\"、\"XposedBridge\" 等特征字符串，可检测修改版 ART",
        setOf("native", "svc", "memory")
    ) {
        CheckResult(NativeBridge.nDetectXposedLibart())
    },

    Check("xp.app_process", G, "app_process.orig",
        "通过 SVC 检查 /system/bin/app_process.orig、/system/bin/app_process32.orig 等备份文件是否存在，Xposed 安装时会重命名原始 app_process",
        setOf("native", "svc", "filesystem")
    ) {
        CheckResult(NativeBridge.nDetectXposedAppProcess())
    },

    Check("xp.artmethod", G, "ArtMethod 分析",
        "通过 JNI 获取 ArtMethod 结构体的内存大小，正常 ARM64 上为 32-64 字节。异常大小可能表明 ART 被修补或 ArtMethod 结构被 Xposed/LSPosed 扩展",
        setOf("native", "memory")
    ) {
        val size = NativeBridge.nGetArtMethodSize()
        val anomaly = size < 16 || size > 128
        CheckResult(anomaly, "ArtMethod size: $size bytes" + if (anomaly) " (expected 32-64)" else "")
    },
)
