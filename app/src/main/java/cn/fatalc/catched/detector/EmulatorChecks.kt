package cn.fatalc.catched.detector

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.BatteryManager
import android.os.Build
import android.telephony.TelephonyManager
import cn.fatalc.catched.model.Check
import cn.fatalc.catched.model.CheckResult

private const val G = "Emulator"

private fun getProp(key: String): String = runCatching {
    @Suppress("PrivateApi")
    val sp = Class.forName("android.os.SystemProperties")
    sp.getDeclaredMethod("get", String::class.java).invoke(null, key) as? String ?: ""
}.getOrDefault("")

fun emulatorChecks(context: Context): List<Check> = listOf(
    Check("em.qemu", G, "QEMU 属性",
        "检查 ro.kernel.qemu、ro.hardware.chipname 等属性是否包含 QEMU/Goldfish/Ranchu 等模拟器虚拟化标识",
        setOf("java", "property")
    ) {
        val checks = mapOf(
            "ro.kernel.qemu" to "1",
            "ro.hardware" to null,
            "ro.hardware.chipname" to null,
            "ro.boot.qemu" to "1"
        )
        val anomalies = mutableListOf<String>()
        checks.forEach { (key, expected) ->
            val value = getProp(key)
            if (expected != null && value == expected) {
                anomalies.add("$key=$value")
            } else if (expected == null && value.isNotEmpty()) {
                val emuNames = listOf("goldfish", "ranchu", "vbox86", "nox", "ttvm", "memu")
                if (emuNames.any { value.contains(it, true) }) {
                    anomalies.add("$key=$value")
                }
            }
        }
        CheckResult(anomalies.isNotEmpty(), anomalies.joinToString("\n").ifEmpty { null })
    },

    Check("em.build", G, "Build 信息",
        "检查 Build.MODEL/BRAND/DEVICE/PRODUCT/MANUFACTURER 是否包含 sdk/google_sdk/Emulator/Genymotion 等模拟器默认值",
        setOf("java", "build")
    ) {
        val fields = mapOf(
            "MODEL" to (Build.MODEL ?: ""),
            "BRAND" to (Build.BRAND ?: ""),
            "DEVICE" to (Build.DEVICE ?: ""),
            "PRODUCT" to (Build.PRODUCT ?: ""),
            "MANUFACTURER" to (Build.MANUFACTURER ?: ""),
            "HARDWARE" to (Build.HARDWARE ?: ""),
            "BOARD" to (Build.BOARD ?: "")
        )
        val emuKeywords = listOf(
            "sdk", "google_sdk", "emulator", "android sdk", "genymotion",
            "nox", "bluestacks", "memu", "tiantian", "goldfish", "ranchu", "vbox86"
        )
        val matched = fields.entries.filter { (_, v) ->
            emuKeywords.any { v.contains(it, true) }
        }.map { "${it.key}=${it.value}" }
        CheckResult(matched.isNotEmpty(), matched.joinToString("\n").ifEmpty { null })
    },

    Check("em.files", G, "虚拟化文件",
        "检查 /dev/qemu_pipe, /dev/socket/qemud, /dev/vboxguest, /system/lib/libnox*.so 等模拟器特征文件或设备节点是否存在",
        setOf("java", "filesystem")
    ) {
        val emuFiles = listOf(
            "/dev/qemu_pipe", "/dev/socket/qemud", "/dev/qemu_trace",
            "/dev/vboxguest", "/dev/vboxuser",
            "/system/lib/libnox.so", "/system/lib/libnoxd.so", "/system/lib/libnoxspeedup.so",
            "/system/bin/nox-prop", "/system/bin/ttVM-prop",
            "/system/bin/microvirt-prop", "/system/bin/androVM-prop",
            "/init.goldfish.rc", "/init.ranchu.rc",
            "/fstab.goldfish", "/fstab.ranchu"
        )
        val found = emuFiles.filter { java.io.File(it).exists() }
        CheckResult(found.isNotEmpty(), found.joinToString("\n").ifEmpty { null })
    },

    Check("em.sensor", G, "传感器缺失",
        "通过 SensorManager 查询设备传感器列表，物理设备通常有加速度计和陀螺仪，模拟器通常缺少或传感器数量极少",
        setOf("java", "hardware")
    ) {
        val sm = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
        val accel = sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
        val gyro = sm.getDefaultSensor(Sensor.TYPE_GYROSCOPE)
        val mag = sm.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD)
        val total = sm.getSensorList(Sensor.TYPE_ALL).size
        val missing = mutableListOf<String>()
        if (accel == null) missing.add("accelerometer")
        if (gyro == null) missing.add("gyroscope")
        if (mag == null) missing.add("magnetometer")
        val detected = missing.size >= 2 || total < 3
        CheckResult(detected, "sensors=$total, missing: ${missing.joinToString(", ").ifEmpty { "none" }}")
    },

    Check("em.telephony", G, "电话信息异常",
        "检查 TelephonyManager 返回的设备信息，模拟器通常网络运营商为 Android/空，设备 ID 为全零或 000000000000000",
        setOf("java", "telephony")
    ) {
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        val anomalies = mutableListOf<String>()
        val operator = tm.networkOperatorName ?: ""
        if (operator.equals("android", true) || operator.isEmpty()) {
            anomalies.add("operator=$operator")
        }
        val simOp = tm.simOperatorName ?: ""
        if (simOp.equals("android", true)) {
            anomalies.add("simOperator=$simOp")
        }
        val phoneType = tm.phoneType
        if (phoneType == TelephonyManager.PHONE_TYPE_NONE) {
            anomalies.add("phoneType=NONE")
        }
        CheckResult(anomalies.isNotEmpty(), anomalies.joinToString("\n").ifEmpty { null })
    },

    Check("em.battery", G, "电池状态",
        "通过 BatteryManager 检查电池信息，模拟器通常电量固定 50%、始终充电、电池温度恒定 25.0°C",
        setOf("java", "hardware")
    ) {
        val bm = context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
        val level = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
        val status = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_STATUS)
        val present = runCatching {
            val intent = context.registerReceiver(null,
                android.content.IntentFilter(android.content.Intent.ACTION_BATTERY_CHANGED))
            intent?.getBooleanExtra(BatteryManager.EXTRA_PRESENT, true) ?: true
        }.getOrDefault(true)
        val temp = runCatching {
            val intent = context.registerReceiver(null,
                android.content.IntentFilter(android.content.Intent.ACTION_BATTERY_CHANGED))
            (intent?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1) ?: -1) / 10.0
        }.getOrDefault(-1.0)
        val anomalies = mutableListOf<String>()
        if (!present) anomalies.add("battery not present")
        if (level == 50 && status == BatteryManager.BATTERY_STATUS_CHARGING) {
            anomalies.add("level=50% + always charging (emulator pattern)")
        }
        if (temp == 25.0) anomalies.add("temperature=25.0°C (constant)")
        CheckResult(anomalies.isNotEmpty(), anomalies.joinToString("\n").ifEmpty { null })
    },

    Check("em.cpu", G, "CPU 架构",
        "检查 Build.SUPPORTED_ABIS 是否仅包含 x86/x86_64 而无 ARM，大多数 Android 物理设备为 ARM 架构，纯 x86 通常是模拟器",
        setOf("java", "build")
    ) {
        val abis = Build.SUPPORTED_ABIS?.toList() ?: emptyList()
        val hasArm = abis.any { it.startsWith("arm") }
        val hasX86 = abis.any { it.startsWith("x86") }
        val detected = hasX86 && !hasArm
        CheckResult(detected, "SUPPORTED_ABIS=${abis.joinToString(", ")}")
    },

    Check("em.host", G, "Build Host",
        "检查 Build.HOST 是否包含 Genymotion/BuildBot 等已知模拟器构建服务器主机名特征",
        setOf("java", "build")
    ) {
        val host = Build.HOST ?: ""
        val emuHosts = listOf("genymotion", "buildbot", "nox", "memu", "tiantian")
        val matched = emuHosts.filter { host.contains(it, true) }
        CheckResult(matched.isNotEmpty(), "Build.HOST=$host")
    },
)
