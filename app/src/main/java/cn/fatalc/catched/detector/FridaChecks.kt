package cn.fatalc.catched.detector

import cn.fatalc.catched.model.Check
import cn.fatalc.catched.model.CheckResult
import cn.fatalc.catched.native.NativeBridge

private const val G = "Frida"

fun fridaChecks(): List<Check> = listOf(
    Check("fr.maps", G, "maps SO 扫描",
        "通过 SVC 直接读取 /proc/self/maps，逐行搜索 frida-agent、frida-loader、frida-gadget 等动态库的映射记录，可绕过 libc read hook",
        setOf("native", "svc", "procfs")
    ) {
        CheckResult(NativeBridge.nDetectFridaMaps())
    },

    Check("fr.port", G, "TCP 默认端口",
        "尝试建立到 127.0.0.1:27042（frida-server 默认端口）和 27043 的 TCP 连接，连接成功则表明本地存在 frida-server 监听",
        setOf("native", "network")
    ) {
        CheckResult(NativeBridge.nDetectFridaPort())
    },

    Check("fr.tcp", G, "/proc/net/tcp 扫描",
        "通过 SVC 读取 /proc/net/tcp 文件，解析十六进制端口号搜索 0x69A2(27042) 和 0x69A3(27043)，可发现非默认绑定地址的 frida-server",
        setOf("native", "svc", "procfs")
    ) {
        CheckResult(NativeBridge.nDetectFridaProcTcp())
    },

    Check("fr.server", G, "frida-server 文件",
        "通过 SVC 检查 /data/local/tmp/frida-server、/data/local/tmp/re.frida.server 等常见部署路径是否存在 frida-server 二进制文件",
        setOf("native", "svc", "filesystem")
    ) {
        CheckResult(NativeBridge.nDetectFridaServerFile())
    },

    Check("fr.pipe", G, "Named Pipe",
        "通过 SVC 遍历 /proc/self/fd/ 下的所有文件描述符，readlink 解析实际路径，搜索 linjector、frida 相关的命名管道",
        setOf("native", "svc", "procfs")
    ) {
        CheckResult(NativeBridge.nDetectFridaNamedPipe())
    },

    Check("fr.dbus", G, "D-Bus 探测",
        "向本地各可疑端口发送 D-Bus AUTH 握手消息（\\x00 + AUTH\\r\\n），若收到 REJECTED 响应则确认目标为 frida-server 的 D-Bus 通道",
        setOf("native", "network")
    ) {
        CheckResult(NativeBridge.nDetectFridaDbus())
    },

    Check("fr.mem", G, "内存特征扫描",
        "扫描进程所有匿名可读内存映射区域，搜索 \"LIBFRIDA\"、\"frida:rpc\"、\"frida-agent\" 等特征字节串，可检测已注入但未映射文件的 Frida gadget",
        setOf("native", "memory")
    ) {
        CheckResult(NativeBridge.nDetectFridaMemory())
    },

    Check("fr.thread", G, "线程名检测",
        "通过 SVC 遍历 /proc/self/task/*/comm 读取所有线程名，搜索 gmain、gdbus、gum-js-loop、frida-* 等 Frida 注入后创建的特征线程",
        setOf("native", "svc", "procfs")
    ) {
        CheckResult(NativeBridge.nDetectFridaThread())
    },
)
