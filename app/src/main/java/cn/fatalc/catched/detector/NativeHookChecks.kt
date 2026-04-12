package cn.fatalc.catched.detector

import cn.fatalc.catched.model.Check
import cn.fatalc.catched.model.CheckResult
import cn.fatalc.catched.native.NativeBridge

private const val G = "Native Hook"

fun nativeHookChecks(): List<Check> = listOf(
    Check("nh.trampoline_islands", G, "Trampoline Island 检测",
        "扫描匿名可执行内存段中的跳板指令模式 (Dobby: LDR X17+BR X17, ShadowHook: STP+LDR+BR, android-inline-hook: LDR X16+BR X16)，检测是否存在 hook 框架注入的跳板代码岛",
        setOf("native", "memory", "inline-hook")
    ) {
        val detected = NativeBridge.nDetectTrampolineIslands()
        CheckResult(detected, if (detected) "发现匿名可执行段中的跳板指令" else null)
    },

    Check("nh.text_integrity_libc", G, "libc.so .text 段完整性",
        "将 libc.so 的可执行 LOAD 段内存内容与磁盘原始文件逐字节比对，检测 inline hook 导致的代码篡改",
        setOf("native", "integrity", "inline-hook")
    ) {
        val diffCount = NativeBridge.nDetectTextIntegrity("/system/lib64/libc.so")
        val diffCount32 = if (diffCount == 0) NativeBridge.nDetectTextIntegrity("/system/lib/libc.so") else diffCount
        val total = if (diffCount > 0) diffCount else diffCount32
        CheckResult(total > 0, if (total > 0) "libc.so .text 段有 $total 字节被修改" else null)
    },

    Check("nh.text_integrity_libart", G, "libart.so .text 段完整性",
        "将 libart.so 的可执行 LOAD 段内存内容与磁盘原始文件逐字节比对，检测 ART 内部函数被 inline hook 篡改",
        setOf("native", "integrity", "inline-hook")
    ) {
        val diffCount = NativeBridge.nDetectTextIntegrity("/system/lib64/libart.so")
        val diffCount32 = if (diffCount == 0) NativeBridge.nDetectTextIntegrity("/system/lib/libart.so") else diffCount
        val total = if (diffCount > 0) diffCount else diffCount32
        CheckResult(total > 0, if (total > 0) "libart.so .text 段有 $total 字节被修改" else null)
    },

    Check("nh.critical_functions", G, "关键 libc 函数 Hook 检测",
        "检查 openat/read/write/stat/access/fopen/mmap/ptrace 等关键 libc 函数入口是否被 inline hook 修改",
        setOf("native", "inline-hook", "libc")
    ) {
        val hooked = NativeBridge.nCheckCriticalFunctionsHook()
        CheckResult(hooked > 0, if (hooked > 0) "$hooked 个关键函数被 hook" else null)
    },

    Check("nh.libart_internal", G, "libart.so 内部函数 Hook",
        "通过 dlsym 定位 libart.so 的 ClassLinker::RegisterNative 和 ArtMethod::Invoke 等内部符号，检查函数序言是否被替换为跳转指令",
        setOf("native", "inline-hook", "libart")
    ) {
        val detected = NativeBridge.nDetectLibartInternalHooks()
        CheckResult(detected, if (detected) "libart.so 内部函数被 hook" else null)
    },

    Check("nh.elf_segment_gap", G, "ELF LOAD 段间隙检测",
        "扫描 /proc/self/maps，检查同一 SO 库的两个 LOAD 段之间是否被插入了匿名可执行页 (r-xp)，这是部分 hook 框架的代码注入特征",
        setOf("native", "memory", "maps")
    ) {
        val detected = NativeBridge.nDetectElfSegmentGap()
        CheckResult(detected, if (detected) "检测到 ELF LOAD 段间隙中的匿名可执行页" else null)
    },

    Check("nh.return_address", G, "返回地址验证",
        "读取当前函数的返回地址 (LR/X30 寄存器)，验证其是否位于合法的已知库映射范围内，检测从匿名可执行段 (trampoline) 发起的调用",
        setOf("native", "register", "stack")
    ) {
        val detected = NativeBridge.nDetectReturnAddressAnomaly()
        CheckResult(detected, if (detected) "返回地址指向匿名可执行区域" else null)
    },

    Check("nh.vdso", G, "vDSO 完整性验证",
        "交叉验证 getauxval(AT_SYSINFO_EHDR) 返回的 vDSO 地址与 /proc/self/maps 中 [vdso] 条目的一致性，检测 maps 伪造或 vDSO 劫持",
        setOf("native", "vdso", "integrity")
    ) {
        val detected = NativeBridge.nDetectVdsoAnomaly()
        CheckResult(detected, if (detected) "vDSO 地址不一致或内容异常" else null)
    },

    Check("nh.maps_inode", G, "Maps Inode 一致性验证",
        "将 /proc/self/maps 中文件映射记录的 inode 与通过 SVC fstatat 获取的实际文件 inode 比对，检测通过 overlay/bind mount 替换库文件的攻击",
        setOf("native", "maps", "integrity")
    ) {
        val mismatch = NativeBridge.nValidateMapsInode()
        CheckResult(mismatch > 0, if (mismatch > 0) "$mismatch 个映射的 inode 不一致" else null)
    },
)
