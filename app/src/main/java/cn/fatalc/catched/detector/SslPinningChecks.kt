package cn.fatalc.catched.detector

import android.content.Context
import android.provider.Settings
import cn.fatalc.catched.model.Check
import cn.fatalc.catched.model.CheckResult
import cn.fatalc.catched.native.NativeBridge
import java.io.File
import java.lang.reflect.Modifier
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

private const val G = "SSL Pinning"

private val bypassClasses = listOf(
    // JustTrustMe / 衍生
    "just.trust.me.Main",
    "xposed.justtrustme.JustTrustMe",
    // SSLUnpinning / SSLUnpinning2
    "mobi.acpm.sslunpinning.MainActivity",
    "mobi.acpm.sslunpinning2.MainActivity",
    // TrustMeAlready
    "tk.zwander.sslunpinning.MainHook",
    "io.github.tehcneko.trustmealready.MainHook",
    // Magisk 模块 MagiskTrustUserCerts 常见入口（Java 侧无类，跳过）
    // Frida 通用脚本注入痕迹（少数会注册 Java 类）
    "com.sensepost.objection.Pinning",
)

private val bypassPackages = listOf(
    "xposed.justtrustme",
    "mobi.acpm.sslunpinning",
    "mobi.acpm.sslunpinning2",
    "tk.zwander.sslunpinning",
    "io.github.tehcneko.trustmealready",
)

fun sslPinningChecks(context: Context): List<Check> = listOf(

    Check("sp.proxy", G, "系统 HTTP 代理",
        "读取 Settings.Global 的 http_proxy 与 System.getProperty(\"http.proxyHost\")，存在代理通常意味着流量被中间人转发（mitmproxy/Charles/Fiddler 的前置条件）",
        setOf("java", "settings", "network"),
        expected = "no proxy"
    ) {
        val sysProxy = System.getProperty("http.proxyHost")?.takeIf { it.isNotBlank() }
        val sysPort = System.getProperty("http.proxyPort")
        val globalProxy = runCatching {
            Settings.Global.getString(context.contentResolver, "http_proxy")
        }.getOrNull()?.takeIf { it.isNotBlank() && it != ":0" }
        val parts = listOfNotNull(
            sysProxy?.let { "http.proxyHost=$it:${sysPort ?: "?"}" },
            globalProxy?.let { "Settings.Global.http_proxy=$it" }
        )
        CheckResult(parts.isNotEmpty(), parts.joinToString("\n").ifEmpty { null })
    },

    Check("sp.user_ca", G, "用户安装的 CA",
        "枚举 AndroidCAStore，统计 alias 以 user: 开头的证书数量。用户主动安装根 CA 是 mitmproxy/Charles/Burp 抓 HTTPS 的标准前置步骤",
        setOf("java", "keystore"),
        expected = "0"
    ) {
        val userCerts = runCatching {
            val ks = KeyStore.getInstance("AndroidCAStore")
            ks.load(null, null)
            ks.aliases().toList().filter { it.startsWith("user:") }
        }.getOrDefault(emptyList())
        val sample = userCerts.take(3).joinToString("\n")
        CheckResult(
            userCerts.isNotEmpty(),
            actual = userCerts.size.toString(),
            evidence = sample.ifEmpty { null }
        )
    },

    Check("sp.user_ca_dir", G, "用户 CA 目录",
        "扫描 /data/misc/user/0/cacerts-added/ 目录，存在文件即表示设备装有用户级 CA（即使应用未声明 user trust 也能用 Magisk 模块或重打包绕过）",
        setOf("java", "filesystem"),
        expected = "empty"
    ) {
        val dir = File("/data/misc/user/0/cacerts-added")
        val files = runCatching { dir.list() }.getOrNull()?.toList() ?: emptyList()
        CheckResult(
            files.isNotEmpty(),
            actual = files.size.toString(),
            evidence = files.take(3).joinToString("\n").ifEmpty { null }
        )
    },

    Check("sp.bypass_class", G, "绕过模块类",
        "通过当前 ClassLoader 尝试加载 JustTrustMe、SSLUnpinning、TrustMeAlready、objection Pinning 等已知 SSL 绕过模块的入口类",
        setOf("java", "classloader")
    ) {
        val found = bypassClasses.filter { cls ->
            runCatching { context.classLoader.loadClass(cls); true }.getOrDefault(false)
        }
        CheckResult(found.isNotEmpty(), found.joinToString("\n").ifEmpty { null })
    },

    Check("sp.bypass_pkg", G, "绕过模块包名",
        "通过 PackageManager 查询 JustTrustMe、SSLUnpinning、TrustMeAlready 等独立 Xposed 模块 APK 是否已安装",
        setOf("java", "pm")
    ) {
        val found = bypassPackages.filter { pkg ->
            runCatching { context.packageManager.getPackageInfo(pkg, 0) }.isSuccess
        }
        CheckResult(found.isNotEmpty(), found.joinToString("\n").ifEmpty { null })
    },

    Check("sp.trustmgr_native", G, "TrustManager native 化",
        "通过反射获取默认 X509TrustManager 的 checkServerTrusted(X509Certificate[],String) 方法，检查 modifiers 是否带 native 标志。Xposed/旧版 LSPosed 在 hook Java 方法时会将 access flags 改为 native",
        setOf("java", "reflection", "hook"),
        expected = "non-native"
    ) {
        val info = runCatching {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(null as KeyStore?)
            val tm = tmf.trustManagers.firstOrNull { it is X509TrustManager } as? X509TrustManager
            val m = tm?.javaClass?.getDeclaredMethod(
                "checkServerTrusted",
                Array<X509Certificate>::class.java,
                String::class.java
            )
            m?.let { tm.javaClass.name to Modifier.isNative(it.modifiers) }
        }.getOrNull()
        val isNative = info?.second == true
        CheckResult(
            isNative,
            actual = info?.let { "${it.first}.checkServerTrusted native=${it.second}" },
            evidence = if (isNative) "method modifier flipped — likely hooked" else null
        )
    },

    Check("sp.okhttp_pinner", G, "OkHttp CertificatePinner",
        "若进程加载了 okhttp3，反射 okhttp3.CertificatePinner.check(String, List) 检查是否被改写为 native（许多 SSL 绕过脚本直接 replace 这个方法）",
        setOf("java", "reflection", "hook"),
        expected = "non-native or absent"
    ) {
        val info = runCatching {
            val cls = context.classLoader.loadClass("okhttp3.CertificatePinner")
            val m = cls.getDeclaredMethod("check", String::class.java, List::class.java)
            "okhttp3.CertificatePinner.check native=${Modifier.isNative(m.modifiers)}" to
                Modifier.isNative(m.modifiers)
        }.getOrNull()
        val isNative = info?.second == true
        CheckResult(
            isNative,
            actual = info?.first ?: "okhttp3 not loaded",
            evidence = if (isNative) "method modifier flipped — likely hooked" else null
        )
    },

    Check("sp.pin_selftest", G, "Pin 自检 HTTPS",
        "用一组故意错误的 sha256 pin 配置 X509TrustManager，向 https://www.bing.com 发起 HEAD。在未被绕过的环境中应抛 SSLHandshakeException；若请求返回成功，说明全局 TrustManager/SSLContext 已被替换",
        setOf("java", "network", "tls"),
        expected = "SSLHandshakeException"
    ) {
        val outcome = runCatching {
            // 构造一个永远拒绝的 X509TrustManager
            val rejectAll = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                    throw java.security.cert.CertificateException("rejectAll")
                }
                override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                    throw java.security.cert.CertificateException("rejectAll")
                }
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, arrayOf(rejectAll), null)
            val url = java.net.URL("https://www.bing.com")
            val conn = url.openConnection() as HttpsURLConnection
            conn.sslSocketFactory = ctx.socketFactory
            conn.connectTimeout = 4000
            conn.readTimeout = 4000
            conn.requestMethod = "HEAD"
            try {
                conn.responseCode  // 期望抛异常
                "handshake succeeded → bypass"
            } catch (e: javax.net.ssl.SSLException) {
                null  // 正常路径
            } catch (e: java.security.cert.CertificateException) {
                null  // 正常路径
            } catch (e: java.io.IOException) {
                // 网络不可达 / DNS 失败 — 无法判定
                "network error: ${e.javaClass.simpleName}"
            } finally {
                runCatching { conn.disconnect() }
            }
        }.getOrElse { "selftest exception: ${it.javaClass.simpleName}" }

        val bypassed = outcome?.startsWith("handshake succeeded") == true
        CheckResult(
            bypassed,
            actual = outcome ?: "handshake refused (expected)",
            evidence = if (bypassed) outcome else null
        )
    },

    Check("sp.libssl_hook", G, "libssl 函数 inline hook",
        "在 libssl/libcrypto/libconscrypt_jni 中查找 SSL_CTX_set_verify、SSL_set_custom_verify、SSL_get_verify_result、X509_verify_cert 等关键符号，逐个比对函数开头是否存在 LDR+BR / B.imm26 / ADRP+ADD+BR 等 inline hook 跳板特征",
        setOf("native", "ssl", "hook")
    ) {
        CheckResult(NativeBridge.nDetectSslFuncHook())
    },

    Check("sp.libssl_path", G, "libssl 加载路径异常",
        "通过 SVC 读取 /proc/self/maps，定位 libssl.so/libcrypto.so 的映射路径，若不在 /system, /apex, /vendor, /product 下（如 /data/.../frida-gadget 或被替换的 BoringSSL 副本）即视为异常",
        setOf("native", "svc", "procfs"),
        expected = "/apex or /system path"
    ) {
        CheckResult(NativeBridge.nDetectLibsslPathAnomaly())
    },

    Check("sp.libssl_multi", G, "libssl 多副本",
        "扫描 /proc/self/maps，统计不同路径的 libssl.so 数量，> 1 说明进程同时加载了多份 libssl（典型为 SSL Pinning 绕过工具 drop-in 替换）",
        setOf("native", "svc", "procfs"),
        expected = "1"
    ) {
        CheckResult(NativeBridge.nDetectMultipleLibssl())
    },

    Check("sp.bypass_so", G, "绕过 SO 加载",
        "通过 SVC 在 /proc/self/maps 中匹配 libsslkill、sslkillswitch、libsslunpinning、ssl_unpinning、libpinningbypass、objection、libsubstratehook 等已知 SSL 绕过库的关键字",
        setOf("native", "svc", "procfs")
    ) {
        CheckResult(NativeBridge.nDetectSslBypassLibs())
    },
)
