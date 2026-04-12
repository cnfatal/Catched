package cn.fatalc.catched.detector

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import cn.fatalc.catched.model.Check
import cn.fatalc.catched.model.CheckResult
import cn.fatalc.catched.native.NativeBridge
import java.security.MessageDigest

private const val G = "Device Integrity"

private const val EXPECTED_CERT_SHA256 = "41E8A70D1FCC232344E820CB1C08BC2D42E4B2F268CB8E75F07748880A26CF08"

private fun getProp(key: String): String = runCatching {
    @Suppress("PrivateApi")
    val sp = Class.forName("android.os.SystemProperties")
    sp.getDeclaredMethod("get", String::class.java).invoke(null, key) as? String ?: ""
}.getOrDefault("")

fun deviceIntegrityChecks(context: Context): List<Check> = listOf(
    Check("di.apksig", G, "APK 签名校验",
        "提取当前 APK 的签名证书 SHA-256 指纹，与仓库内预置 release.jks 的证书指纹对比，不一致说明 APK 被重签名或重打包",
        setOf("java", "signature"),
        expected = EXPECTED_CERT_SHA256
    ) {
        val currentHash = runCatching {
            @Suppress("DEPRECATION", "PackageManagerGetSignatures")
            val sigs = context.packageManager
                .getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
                .signatures
            if (sigs.isNullOrEmpty()) return@runCatching null
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(sigs[0].toByteArray())
            hash.joinToString("") { "%02X".format(it) }
        }.getOrNull()
        val matched = currentHash.equals(EXPECTED_CERT_SHA256, ignoreCase = true)
        CheckResult(!matched, actual = currentHash)
    },

    Check("di.apksig_native", G, "APK 签名直接解析 (SVC)",
        "通过 SVC openat 直接读取 APK 文件，独立解析 APK Signing Block (v2/v3) 提取证书 SHA-256 指纹，完全绕过 PackageManager Java API，防止 PM hook 伪造证书返回值",
        setOf("native", "svc", "signature"),
        expected = EXPECTED_CERT_SHA256
    ) {
        val apkPath = context.applicationInfo.sourceDir ?: ""
        val nativeHash = if (apkPath.isNotEmpty()) NativeBridge.nExtractApkCertSha256(apkPath) else null
        val matched = nativeHash.equals(EXPECTED_CERT_SHA256, ignoreCase = true)
        CheckResult(!matched, actual = nativeHash ?: "parse failed")
    },

    Check("di.apksig_cross", G, "APK 签名交叉验证",
        "将 PackageManager 返回的签名证书指纹与 SVC 直接从 APK 文件解析的证书指纹进行交叉比对，二者不一致说明 PackageManager API 被 Hook 返回了伪造的证书",
        setOf("java", "native", "signature")
    ) {
        val pmHash = runCatching {
            @Suppress("DEPRECATION", "PackageManagerGetSignatures")
            val sigs = context.packageManager
                .getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
                .signatures
            if (sigs.isNullOrEmpty()) return@runCatching null
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(sigs[0].toByteArray())
            hash.joinToString("") { "%02X".format(it) }
        }.getOrNull()

        val apkPath = context.applicationInfo.sourceDir ?: ""
        val nativeHash = if (apkPath.isNotEmpty()) NativeBridge.nExtractApkCertSha256(apkPath) else null

        val mismatch = pmHash != null && nativeHash != null &&
                !pmHash.equals(nativeHash, ignoreCase = true)
        val detail = if (mismatch) "PM=$pmHash\nAPK=$nativeHash" else null
        CheckResult(mismatch, detail)
    },

    @Suppress("DEPRECATION")
    Check("di.apksig_lineage", G, "签名密钥轮换检测 (v3 lineage)",
        "使用 API 28+ 的 GET_SIGNING_CERTIFICATES 获取 SigningInfo，检查是否存在密钥轮换历史 (lineage)，以及当前签名是否与预期一致，支持 APK Signature Scheme v3 的密钥轮换场景",
        setOf("java", "signature"),
        expected = EXPECTED_CERT_SHA256
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = runCatching {
                context.packageManager
                    .getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                    .signingInfo
            }.getOrNull()

            if (signingInfo == null) {
                CheckResult(true, "无法获取 SigningInfo")
            } else {
                val evidence = mutableListOf<String>()

                // 检查是否有多个签名者 (不应有)
                if (signingInfo.hasMultipleSigners()) {
                    val sigs = signingInfo.apkContentsSigners
                    evidence.add("多签名者: ${sigs.size}")
                }

                // 检查密钥轮换历史
                if (signingInfo.hasPastSigningCertificates()) {
                    val history = signingInfo.signingCertificateHistory
                    evidence.add("密钥轮换历史: ${history.size} 个证书")
                    history.forEachIndexed { i, sig ->
                        val digest = MessageDigest.getInstance("SHA-256")
                        val hash = digest.digest(sig.toByteArray())
                        val hex = hash.joinToString("") { "%02X".format(it) }
                        evidence.add("  lineage[$i]: $hex")
                    }
                }

                // 当前签名指纹
                val currentSigs = if (signingInfo.hasMultipleSigners())
                    signingInfo.apkContentsSigners else signingInfo.signingCertificateHistory
                        ?: arrayOf(signingInfo.apkContentsSigners?.firstOrNull()).filterNotNull().toTypedArray()

                val currentHash = currentSigs.firstOrNull()?.let { sig ->
                    val digest = MessageDigest.getInstance("SHA-256")
                    val hash = digest.digest(sig.toByteArray())
                    hash.joinToString("") { "%02X".format(it) }
                }
                val matched = currentHash.equals(EXPECTED_CERT_SHA256, ignoreCase = true)
                if (!matched) evidence.add("当前证书: $currentHash")

                CheckResult(!matched || evidence.isNotEmpty(),
                    evidence.joinToString("\n").ifEmpty { null }, actual = currentHash)
            }
        } else {
            // API < 28, 回退到 GET_SIGNATURES
            CheckResult(false, "API ${Build.VERSION.SDK_INT} < 28, 使用 di.apksig 检查")
        }
    },

    Check("di.bootloader", G, "Bootloader 状态",
        "读取 ro.boot.flash.locked 和 sys.oem_unlock_allowed 属性判断 Bootloader 是否已解锁",
        setOf("java", "property"),
        expected = "locked"
    ) {
        val locked = getProp("ro.boot.flash.locked")
        val oemUnlock = getProp("sys.oem_unlock_allowed")
        val secureboot = getProp("ro.boot.secureboot")
        val anomalies = mutableListOf<String>()
        if (locked == "0") anomalies.add("ro.boot.flash.locked=0")
        if (oemUnlock == "1") anomalies.add("sys.oem_unlock_allowed=1")
        if (secureboot == "0") anomalies.add("ro.boot.secureboot=0")
        val actual = if (anomalies.isEmpty()) "locked" else "unlocked"
        CheckResult(anomalies.isNotEmpty(), anomalies.joinToString("\n").ifEmpty { null }, actual = actual)
    },

    Check("di.verifiedboot", G, "Verified Boot",
        "读取 ro.boot.verifiedbootstate 属性检查 AVB 状态：green=完整, yellow=自签名, orange=解锁, red=校验失败",
        setOf("java", "property"),
        expected = "green"
    ) {
        val state = getProp("ro.boot.verifiedbootstate").ifEmpty { "unknown" }
        val detected = state != "green"
        CheckResult(detected, actual = state)
    },

    Check("di.buildtags", G, "Build 签名",
        "检查 Build.TAGS 是否为 release-keys，test-keys 表示使用了测试密钥或自编译系统",
        setOf("java", "build"),
        expected = "release-keys"
    ) {
        val tags = Build.TAGS ?: ""
        CheckResult(tags.contains("test-keys"), actual = tags)
    },

    Check("di.buildtype", G, "Build 类型",
        "检查 Build.TYPE 是否为 user 类型，eng/userdebug 包含额外调试能力",
        setOf("java", "build"),
        expected = "user"
    ) {
        val type = Build.TYPE ?: ""
        CheckResult(type != "user", actual = type)
    },

    Check("di.fingerprint", G, "设备指纹",
        "检查 Build.FINGERPRINT 是否包含 generic/unknown/test 等模拟器或测试设备特征",
        setOf("java", "build")
    ) {
        val fp = Build.FINGERPRINT ?: ""
        val suspects = listOf("generic", "unknown", "test", "robolectric", "sdk_gphone")
        val matched = suspects.filter { fp.contains(it, true) }
        CheckResult(matched.isNotEmpty(), actual = fp)
    },

    Check("di.customrom", G, "自定义 ROM",
        "检查 ro.modversion、ro.lineage.version 等第三方 ROM 特征属性是否存在",
        setOf("java", "property")
    ) {
        val romProps = mapOf(
            "ro.modversion" to "CM/Lineage mod",
            "ro.lineage.version" to "LineageOS",
            "ro.lineage.build.version" to "LineageOS",
            "ro.pixelexperience.version" to "PixelExperience",
            "ro.carbon.version" to "CarbonROM",
            "ro.crdroid.version" to "crDroid",
            "ro.evolution.version" to "EvolutionX",
            "ro.potato.version" to "PotatoProject"
        )
        val found = romProps.entries.filter { getProp(it.key).isNotEmpty() }
            .map { "${it.value}: ${it.key}=${getProp(it.key)}" }
        CheckResult(found.isNotEmpty(), found.joinToString("\n").ifEmpty { null })
    },

    Check("di.selinux_enforce", G, "SELinux 模式",
        "检查 SELinux 是否处于 Enforcing 模式，Permissive 模式下安全策略不强制执行",
        setOf("java", "filesystem"),
        expected = "Enforcing"
    ) {
        val enforce = runCatching {
            java.io.File("/sys/fs/selinux/enforce").readText().trim()
        }.getOrDefault("")
        val actual = when (enforce) {
            "0" -> "Permissive"
            "1" -> "Enforcing"
            else -> "unknown"
        }
        CheckResult(enforce == "0", actual = actual)
    },
)
