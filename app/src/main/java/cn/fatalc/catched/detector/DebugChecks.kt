package cn.fatalc.catched.detector

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Debug
import android.provider.Settings
import cn.fatalc.catched.model.Check
import cn.fatalc.catched.model.CheckResult

private const val G = "Debug/DevOps"

fun debugChecks(context: Context): List<Check> = listOf(
    Check("db.usb", G, "USB 调试",
        "检查 Settings.Global.ADB_ENABLED 是否为 1，开启 USB 调试允许通过 ADB 连接设备执行任意命令",
        setOf("java", "settings")
    ) {
        val enabled = Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0)
        CheckResult(enabled == 1, "adb_enabled=$enabled")
    },

    Check("db.wifi_adb", G, "无线调试",
        "检查 Settings.Global 的 adb_wifi_enabled 是否为 1，无线调试允许通过 Wi-Fi 远程连接设备",
        setOf("java", "settings")
    ) {
        val enabled = runCatching {
            Settings.Global.getInt(context.contentResolver, "adb_wifi_enabled", 0)
        }.getOrDefault(0)
        CheckResult(enabled == 1, "adb_wifi_enabled=$enabled")
    },

    Check("db.devopt", G, "开发者选项",
        "检查 Settings.Global.DEVELOPMENT_SETTINGS_ENABLED 是否为 1，开发者选项包含多个潜在安全风险设置",
        setOf("java", "settings")
    ) {
        val enabled = Settings.Global.getInt(
            context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
        )
        CheckResult(enabled == 1, "development_settings_enabled=$enabled")
    },

    Check("db.debugger", G, "调试器附加",
        "调用 Debug.isDebuggerConnected() 检查当前进程是否有 JDWP 调试器附加，调试器可读写进程内存和执行任意代码",
        setOf("java", "debug")
    ) {
        val connected = Debug.isDebuggerConnected()
        CheckResult(connected, if (connected) "JDWP debugger attached" else null)
    },

    Check("db.tracerpid", G, "TracerPid",
        "读取 /proc/self/status 中的 TracerPid 字段，非零值表示当前进程正被 ptrace 跟踪（如 strace/ltrace/调试器）",
        setOf("java", "procfs")
    ) {
        val tracerPid = runCatching {
            java.io.File("/proc/self/status").readLines()
                .firstOrNull { it.startsWith("TracerPid:") }
                ?.substringAfter(":")?.trim()?.toIntOrNull() ?: 0
        }.getOrDefault(0)
        CheckResult(tracerPid != 0, if (tracerPid != 0) "TracerPid=$tracerPid" else null)
    },

    Check("db.debuggable", G, "debuggable 标志",
        "检查 ApplicationInfo.FLAG_DEBUGGABLE 标志位，debuggable=true 的应用可被任意调试器附加，正式发布应关闭此标志",
        setOf("java", "build")
    ) {
        val debuggable = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        CheckResult(debuggable, if (debuggable) "FLAG_DEBUGGABLE=true" else null)
    },
)
