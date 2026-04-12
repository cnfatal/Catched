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
    Check("xp.classloader", G, "ClassLoader 异常与多实例检测",
        "不仅通过系统 ClassLoader，还通过 VMDebug 获取运行时所有 BaseDexClassLoader 实例，同时检查 ClassLoader 继承链中是否存在非 Android 官方自带的异常加载器，并在多实例中广泛搜寻风险类",
        setOf("java", "classloader", "reflection")
    ) {
        val contextCl = context.classLoader
        val foundClasses = mutableListOf<String>()
        val suspiciousLoaders = mutableListOf<String>()

        // 1. 检查类加载器链中是否有非自带的 ClassLoader
        var currentCl: ClassLoader? = contextCl
        while (currentCl != null) {
            val clName = currentCl.javaClass.name
            // 筛选出非官方包名的自定义 ClassLoader，正常基本都是 dalvik.system. 或 java.lang.
            if (!clName.startsWith("dalvik.system.") && !clName.startsWith("java.") && !clName.startsWith("android.")) {
                suspiciousLoaders.add("Chain: $clName")
            }
            currentCl = currentCl.parent
        }

        // 2. 覆盖多个 ClassLoader 搜寻风险类
        val allLoaders = runCatching {
            val vmDebug = Class.forName("dalvik.system.VMDebug")
            val method = vmDebug.getDeclaredMethod(
                "getInstancesOfClasses", Class.forName("[Ljava.lang.Class;"), Boolean::class.javaPrimitiveType
            )
            method.isAccessible = true
            val bdcClass = Class.forName("dalvik.system.BaseDexClassLoader")
            val classArray = java.lang.reflect.Array.newInstance(Class::class.java, 1)
            java.lang.reflect.Array.set(classArray, 0, bdcClass)
            @Suppress("UNCHECKED_CAST")
            val instances = method.invoke(null, classArray, false) as? Array<Array<Any>>
            instances?.firstOrNull()?.filterIsInstance<ClassLoader>()
        }.getOrNull() ?: listOf(context.classLoader, ClassLoader.getSystemClassLoader())

        // 移除固定的业务包名，仅保留框架核心注入特征，因为外挂包名可随机生成
        val threats = listOf(
            "de.robv.android.xposed.XposedBridge"
        )

        allLoaders.forEach { cl ->
            val clName = cl.javaClass.name
            // 记录非常规包名的外部类加载器实例
            if (!clName.startsWith("dalvik.system.") && !clName.startsWith("java.") && !clName.startsWith("android.")) {
                suspiciousLoaders.add("Instance: $clName")
            }
            if (clName.contains("xposed", true) || clName.contains("lsposed", true)) {
                suspiciousLoaders.add("RiskName: $clName")
            }

            // 在所有获取到的 ClassLoader 中尝试加载风险类
            threats.forEach { threat ->
                if (runCatching { cl.loadClass(threat); true }.getOrDefault(false)) {
                    foundClasses.add("$threat (in $clName)")
                }
            }
        }

        val res = mutableListOf<String>()
        if (suspiciousLoaders.isNotEmpty()) {
            res.add("Suspicious Loaders:\n" + suspiciousLoaders.distinct().joinToString("\n"))
        }
        if (foundClasses.isNotEmpty()) {
            res.add("Found Classes:\n" + foundClasses.distinct().joinToString("\n"))
        }

        CheckResult(res.isNotEmpty(), res.joinToString("\n\n").ifEmpty { null })
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

    Check("xp.dexpath", G, "DexPathList 路径扫描",
        "反射读取当前 ClassLoader 的 BaseDexClassLoader.pathList.dexElements 数组，除搜寻特定框架外，主动发现任何外部注入的、非系统自带且非本应用的随机名 APK/JAR 模块",
        setOf("java", "reflection")
    ) {
        val evidence = runCatching {
            val cl = context.classLoader
            if (cl is BaseDexClassLoader) {
                val plf = BaseDexClassLoader::class.java.getDeclaredField("pathList").apply { isAccessible = true }
                val pl = plf.get(cl)
                val def = pl!!.javaClass.getDeclaredField("dexElements").apply { isAccessible = true }
                val elements = def.get(pl) as? Array<*>
                val myApk = context.applicationInfo.sourceDir
                val myData = context.applicationInfo.dataDir ?: ""
                val found = elements?.mapNotNull { e ->
                    val df = e?.javaClass?.getDeclaredField("dexFile")?.apply { isAccessible = true }?.get(e)
                    val fn = df?.javaClass?.getDeclaredMethod("getName")?.invoke(df) as? String
                    if (fn != null) {
                        val isSystem = fn.startsWith("/system/") || fn.startsWith("/apex/") || fn.startsWith("/vendor/")
                        val isSelf = fn == myApk || (myData.isNotEmpty() && fn.startsWith(myData))
                        if (!isSystem && !isSelf && (fn.endsWith(".apk") || fn.endsWith(".jar") || fn.endsWith(".dex"))) {
                            "External Injected Module: $fn"
                        } else if (fn.contains("XposedBridge", true) || fn.contains("lsposed", true)) {
                            "Framework: $fn"
                        } else null
                    } else null
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
            !it.className.startsWith(context.packageName) &&
            (it.className.contains("xposed", true) || it.className.contains("saurik") || it.className.contains("lsposed", true))
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

    Check("xp.anon_exe", G, "匿名执行段扫描",
        "扫描 /proc/self/maps 识别非法的匿名可执行内存或伪造的 jit-cache 分段，此举可识别 Zygisk/Riru 内存隐藏技术",
        setOf("native", "svc", "memory")
    ) {
        CheckResult(NativeBridge.nDetectSuspiciousExecutableMaps())
    },

    Check("xp.hidden_elf", G, "被伪装的 ELF 隐敲扫描",
        "针对内核层通过修改权限将 mmap 的可执行文件强行标记为无执行权限 (-)、并抹除路径信息的隐蔽手段（常见于某些修改 ROM 或内核的黑产设备），扫描可读权限下匿名段数据头部是否掩盖了一个可执行的 ELF 库。",
        setOf("native", "svc", "memory")
    ) {
        CheckResult(NativeBridge.nDetectHiddenElfMaps())
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

    Check("xp.compilation_flags", G, "ArtMethod 编译控制标志",
        "检查 ArtMethod access_flags 中的 kAccCompileDontBother/kAccPreCompiled/kAccFastInterpreterToInterpreterInvoke 标志组合，" +
        "Xposed/LSPosed hook 方法时必须设置 kAccCompileDontBother 阻止 JIT 重编译，同时清除 PreCompiled 和 FastInterpreter 标志",
        setOf("native", "memory", "art")
    ) {
        val evidence = mutableListOf<String>()
        val sdkVersion = android.os.Build.VERSION.SDK_INT

        // 选取几个常见的被 hook 目标方法来检查
        val targetMethods = listOf(
            "android.app.Activity" to "onCreate",
            "android.app.Application" to "attach",
            "android.content.ContextWrapper" to "attachBaseContext",
        )

        targetMethods.forEach { (className, methodName) ->
            runCatching {
                val clazz = Class.forName(className)
                val methods = clazz.declaredMethods.filter { it.name == methodName }
                methods.forEach { method ->
                    val anomaly = NativeBridge.nCheckAccessFlagsAnomaly(method, sdkVersion)
                    if (anomaly != 0) {
                        val flags = mutableListOf<String>()
                        if (anomaly and 1 != 0) flags.add("kAccNative")
                        if (anomaly and 2 != 0) flags.add("kAccCompileDontBother")
                        if (anomaly and 4 != 0) flags.add("PreCompiled cleared")
                        if (anomaly and 8 != 0) flags.add("FastInterpreter cleared")
                        evidence.add("$className.$methodName: ${flags.joinToString(", ")}")
                    }
                }
            }
        }

        CheckResult(evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null })
    },

    Check("xp.signal_handler", G, "信号处理器异常",
        "通过 SVC rt_sigaction 检查 SIGSEGV 和 SIGBUS 的信号处理器，Xposed/LSPosed 在进行不安全内存操作时会注册自定义的崩溃恢复处理器",
        setOf("native", "svc", "signal")
    ) {
        val sigsegv = NativeBridge.nDetectSigsegvHandler()
        val sigbus = NativeBridge.nDetectSigbusHandler()
        val detected = sigsegv || sigbus
        val detail = buildString {
            if (sigsegv) append("SIGSEGV: 自定义处理器\n")
            if (sigbus) append("SIGBUS: 自定义处理器")
        }.trim()
        CheckResult(detected, detail.ifEmpty { null })
    },
)
