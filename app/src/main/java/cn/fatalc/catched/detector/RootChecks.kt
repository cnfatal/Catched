package cn.fatalc.catched.detector

import android.content.Context
import cn.fatalc.catched.model.Check
import cn.fatalc.catched.model.CheckResult
import cn.fatalc.catched.native.NativeBridge

private const val G = "Root/Magisk"

private val rootPackages = listOf(
    "eu.chainfire.supersu", "com.koushikdutta.superuser",
    "com.topjohnwu.magisk", "io.github.vvb2060.magisk", "com.fox2code.mmm"
)

fun rootChecks(context: Context): List<Check> = listOf(
    Check("rt.su_svc", G, "su 路径 SVC",
        "通过 SVC 直接系统调用（绕过 libc）检查 /system/bin/su, /system/xbin/su, /sbin/su 等 14 条常见 su 二进制路径是否存在，避免被 libc hook 欺骗",
        setOf("native", "svc", "filesystem")
    ) {
        CheckResult(NativeBridge.nDetectSuPathsSvc())
    },

    Check("rt.pkg", G, "Root 管理器包名",
        "通过 PackageManager 查询 SuperSU、Magisk、KernelSU 等已知 Root 管理器应用的包名是否已安装",
        setOf("java", "pm")
    ) {
        val found = rootPackages.filter { pkg ->
            runCatching { context.packageManager.getPackageInfo(pkg, 0) }.isSuccess
        }
        CheckResult(found.isNotEmpty(), found.joinToString("\n").ifEmpty { null })
    },

    Check("rt.which", G, "which su",
        "执行 which su 命令检查系统 PATH 中是否存在可执行的 su 二进制文件",
        setOf("java", "shell")
    ) {
        val result = runCatching {
            val p = Runtime.getRuntime().exec(arrayOf("which", "su"))
            val output = p.inputStream.bufferedReader().readText().trim()
            p.waitFor()
            output
        }.getOrDefault("")
        CheckResult(result.isNotEmpty(), if (result.isNotEmpty()) "path: $result" else null)
    },

    Check("rt.path", G, "PATH 环境变量",
        "遍历系统 PATH 环境变量中的所有目录，通过 File.exists() 检查每个目录下是否存在名为 su 的文件",
        setOf("java", "filesystem")
    ) {
        val path = System.getenv("PATH") ?: ""
        val found = path.split(":").filter { java.io.File("$it/su").exists() }
        CheckResult(found.isNotEmpty(), found.joinToString("\n") { "$it/su" }.ifEmpty { null })
    },

    Check("rt.stat", G, "Native su stat",
        "通过 SVC 直接调用 fstatat 系统调用检测 su 文件属性，包括检查 SUID 位是否被设置（权限 04755），可绕过 stat() 函数级别的 hook",
        setOf("native", "svc", "filesystem")
    ) {
        CheckResult(NativeBridge.nDetectSuStatNative())
    },

    Check("rt.mount", G, "Magisk 挂载点",
        "通过 SVC 读取 /proc/mounts 内容，搜索 magisk、magisktmp、tmpfs 挂载到 /sbin 等 Magisk 特征挂载点",
        setOf("native", "svc", "procfs")
    ) {
        CheckResult(NativeBridge.nDetectMagiskMount())
    },

    Check("rt.mountinfo", G, "mountinfo 分析",
        "通过 SVC 读取 /proc/self/mountinfo，分析可疑的 bind mount 和 overlay mount，检测 Magisk 的 Magic Mount 机制",
        setOf("native", "svc", "procfs")
    ) {
        CheckResult(NativeBridge.nDetectMountinfo())
    },

    Check("rt.overlay", G, "OverlayFS workdir",
        "执行 mount 命令解析输出中的 workdir 参数和挂载信息，搜索 magisk、/adb/ 等关键字以检测 Magisk 的 OverlayFS 模块挂载",
        setOf("java", "shell")
    ) {
        val output = runCatching {
            val p = Runtime.getRuntime().exec("mount")
            val o = p.inputStream.bufferedReader().readText()
            p.waitFor()
            o
        }.getOrDefault("")
        val suspicious = output.lines().filter {
            it.contains("magisk") || (it.contains("workdir=") && it.contains("/adb/"))
        }
        CheckResult(suspicious.isNotEmpty(), suspicious.joinToString("\n").ifEmpty { null })
    },

    Check("rt.selinux", G, "SELinux 上下文",
        "通过 SVC 读取文件的 SELinux 安全标签，检查是否包含 u:object_r:magisk_file:s0 等 Magisk 注入的自定义标签",
        setOf("native", "svc", "selinux")
    ) {
        CheckResult(NativeBridge.nDetectSelinuxContext())
    },

    Check("rt.seprev", G, "SELinux prev",
        "通过 SVC 读取 /proc/self/attr/prev 获取进程上一个 SELinux 上下文，检查是否包含 magisk、zygisk 等特征字符串",
        setOf("native", "svc", "selinux")
    ) {
        CheckResult(NativeBridge.nDetectSelinuxPrev())
    },

    Check("rt.socket", G, "Magisk Socket",
        "通过 SVC 读取 /proc/net/unix 扫描所有 Unix Domain Socket，搜索包含 magisk、.magisk 的 socket 名称",
        setOf("native", "procfs")
    ) {
        CheckResult(NativeBridge.nDetectMagiskSocket())
    },

    Check("rt.prop", G, "系统属性",
        "检查 ro.debuggable=1、ro.secure=0、ro.build.tags 包含 test-keys 等表明设备已解锁或处于调试状态的系统属性",
        setOf("java", "property")
    ) {
        val props = mapOf(
            "ro.debuggable" to "0",
            "ro.secure" to "1",
            "ro.build.type" to null,
            "ro.build.tags" to null,
            "ro.build.selinux" to null
        )
        val anomalies = mutableListOf<String>()
        val getProp = { key: String ->
            runCatching {
                @Suppress("PrivateApi")
                val sp = Class.forName("android.os.SystemProperties")
                sp.getDeclaredMethod("get", String::class.java).invoke(null, key) as? String ?: ""
            }.getOrDefault("")
        }
        props.forEach { (key, expected) ->
            val value = getProp(key)
            when {
                key == "ro.debuggable" && value == "1" -> anomalies.add("$key=$value (expected 0)")
                key == "ro.secure" && value == "0" -> anomalies.add("$key=$value (expected 1)")
                key == "ro.build.type" && (value == "eng" || value == "userdebug") -> anomalies.add("$key=$value")
                key == "ro.build.tags" && value.contains("test-keys") -> anomalies.add("$key=$value")
                key == "ro.build.selinux" && value == "0" -> anomalies.add("$key=$value (SELinux disabled)")
                expected == null && value.isNotEmpty() -> {} // just record, no anomaly
            }
        }
        CheckResult(anomalies.isNotEmpty(), anomalies.joinToString("\n").ifEmpty { null })
    },
)
