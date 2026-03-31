# Catched - Android 蓝队安全检测 App

> 基于大圣-众包 APK 逆向分析中发现的真实攻击手法，构建针对性防御检测工具

## 一、项目定位

**独立安全检测 App**，安装后一键扫描设备环境，检测以下高优先级威胁：

| 优先级 | 威胁类别 | 检测目标 | 来源分析 |
|--------|----------|----------|----------|
| P0 | NPatch/LSPatch 重打包 | 检测 App 是否被 NPatch/LSPatch 注入框架篡改 | ANALYSIS_NPATCH.md §十 |
| P0 | Xposed/LSPosed Hook | 检测 Xposed 框架及模块的存在和活动 | ANALYSIS_HOOK.md §八 |
| P0 | Frida 注入 | 检测 Frida 动态注入工具 | ANALYSIS_HOOK.md §8.2 |
| P0 | Root/Magisk | 检测设备 Root 状态和 Magisk 隐藏 | ANALYSIS_HOOK.md §8.3 |

---

## 二、技术架构

```
┌─────────────────────────────────────────────────────┐
│                    Catched App                    │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ┌── Kotlin UI Layer (Jetpack Compose) ───────────┐  │
│  │  MainActivity → ScanScreen → ReportScreen       │  │
│  │  ├── 一键扫描按钮                                │  │
│  │  ├── 实时扫描进度                                │  │
│  │  ├── 威胁等级仪表盘                              │  │
│  │  └── 详细检测报告                                │  │
│  └─────────────────────────────────────────────────┘  │
│                         │                             │
│  ┌── Detection Engine (Kotlin + JNI) ─────────────┐  │
│  │                                                  │  │
│  │  ┌─ Java Layer Detectors ───────────────────┐   │  │
│  │  │  RootDetector.kt                          │   │  │
│  │  │  XposedDetector.kt                        │   │  │
│  │  │  FridaDetector.kt                         │   │  │
│  │  │  NPatchDetector.kt                        │   │  │
│  │  └───────────────────────────────────────────┘   │  │
│  │                                                  │  │
│  │  ┌─ Native Layer (C/NDK) ───────────────────┐   │  │
│  │  │  libcatched.so                        │   │  │
│  │  │  ├── syscall_wrapper.c  (SVC 直接调用)    │   │  │
│  │  │  ├── root_detect.c                        │   │  │
│  │  │  ├── hook_detect.c     (GOT/PLT/inline)  │   │  │
│  │  │  ├── frida_detect.c                       │   │  │
│  │  │  ├── maps_scanner.c    (/proc/self/maps)  │   │  │
│  │  │  ├── art_method.c      (ArtMethod 分析)   │   │  │
│  │  │  └── npatch_detect.c   (NPatch 特征)      │   │  │
│  │  └───────────────────────────────────────────┘   │  │
│  │                                                  │  │
│  │  ┌─ Result Aggregator ──────────────────────┐   │  │
│  │  │  ThreatReport.kt                          │   │  │
│  │  │  ├── 威胁评分 (0-100)                     │   │  │
│  │  │  ├── 按模块分类结果                       │   │  │
│  │  │  └── 详细证据链                           │   │  │
│  │  └───────────────────────────────────────────┘   │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## 三、检测模块详细设计

### 3.1 模块 1: Root/Magisk 检测 (12 项检查)

基于 ANALYSIS_HOOK.md §8.3 中识别的 12 种检测手段：

| # | 检测项 | 实现层 | 技术方案 | 绕过难度 |
|---|--------|--------|----------|----------|
| R1 | su 文件路径扫描 | **Native (SVC)** | `sg_access()` 直接系统调用检查 14 条路径 | ★★★★ |
| R2 | Root 管理器包名 | Java | PackageManager 查询 16+ 个已知包名 | ★★ |
| R3 | `which su` 命令 | Java | Runtime.exec + ProcessBuilder | ★★ |
| R4 | PATH 环境变量 | Java | 遍历 PATH 路径检查 su 可执行文件 | ★★ |
| R5 | Native su 路径 | **Native (SVC)** | `sg_stat()` + `sg_access()` 检测文件属性 | ★★★★ |
| R6 | Magisk 挂载点 | **Native (SVC)** | `sg_open()` 读取 `/proc/mounts` 搜索 magisk 特征 | ★★★★ |
| R7 | mountinfo 分析 | **Native (SVC)** | `sg_open()` 读取 `/proc/self/mountinfo` | ★★★★ |
| R8 | OverlayFS workdir | Java | 执行 `mount` 命令解析 workdir= 参数 | ★★★★ |
| R9 | SELinux 上下文 | **Native (SVC)** | 读取 `/dev/pts` SELinux 标签 `magisk_file` | ★★★★ |
| R10 | SELinux prev 属性 | **Native (SVC)** | 读取 `/proc/self/attr/prev` | ★★★★ |
| R11 | Magisk Socket | **Native** | 尝试连接 Magisk 本地 socket 接口 | ★★★★★ |
| R12 | 系统属性检查 | **Native** | `__system_property_get()` 检查 `ro.debuggable`, `ro.secure` | ★★★ |

**su 路径检测列表：**
```
/system/bin/su, /system/xbin/su, /sbin/su, /data/local/bin/su,
/data/local/su, /data/local/xbin/su, /system/sd/xbin/su,
/system/bin/failsafe/su, /su/bin/, /sbin/su,
/system/app/Superuser.apk, /system/app/longeneroot.apk,
/cache/, /data/, /dev/
```

**Root 管理器包名列表：**
```
eu.chainfire.supersu, com.koushikdutta.superuser, com.thirdparty.superuser,
com.yellowes.su, com.qihoo.permmgr, com.wmshua.wmroot, com.baidu.easyroot,
com.baiyi_mobile.easyroot, com.mgyun.shua.su, com.z4mod.z4root,
com.shuame.rootgenius, com.zhiqupk.root, com.kingroot.kinguser,
com.apkol.root, com.corner23.android.universalandroot, com.roothelper,
com.topjohnwu.magisk, io.github.vvb2060.magisk, com.fox2code.mmm
```

### 3.2 模块 2: Xposed/LSPosed 检测 (12 项检查)

基于 ANALYSIS_HOOK.md §8.1 中识别的 11 种检测手段 + 扩展：

| # | 检测项 | 实现层 | 技术方案 | 绕过难度 |
|---|--------|--------|----------|----------|
| X1 | ClassLoader 加载检测 | Java | `ClassLoader.loadClass("de.robv.android.xposed.XposedBridge")` | ★★ |
| X2 | VMDebug 实例扫描 | Java | `VMDebug.getInstancesOfClasses()` 扫描全部 BaseDexClassLoader | ★★★★★ |
| X3 | DexPathList 扫描 | Java | 反射读取 `DexPathList.dexElements` 搜索 XposedBridge | ★★★ |
| X4 | 堆栈特征分析 | Java | `new Exception().getStackTrace()` 检查 Xposed/Substrate 特征 | ★★★ |
| X5 | 安装包 metadata | Java | 遍历已安装应用 metaData 查找 `xposedmodule` 标记 | ★★ |
| X6 | XposedHelpers 缓存扫描 | Java | 反射读取 `XposedHelpers.methodCache` 内存数据 | ★★★★★ |
| X7 | sHookedMethodCallbacks | Java | 反射读取 `XposedBridge.sHookedMethodCallbacks` | ★★★★★ |
| X8 | 方法 native 标志异常 | Java | `Modifier.isNative()` 检查系统方法是否被篡改 | ★★★ |
| X9 | /proc/self/maps 磁盘扫描 | **Native (SVC)** | `sg_open()` 读取 maps 搜索 XposedBridge.jar | ★★★★ |
| X10 | libart.so 字符串扫描 | **Native (SVC)** | `sg_open()` 读取 `/system/lib/libart.so` 搜索 "xposed" | ★★★★ |
| X11 | app_process.orig 检测 | **Native (SVC)** | `sg_access()` 检查 `/system/bin/app_process.orig` | ★★★★ |
| X12 | ArtMethod 结构体分析 | **Native** | 读取 ArtMethod.access_flags/size 比对检测 Hook | ★★★★★ |

**SO 黑名单（/proc/self/maps 扫描）：**
```
libsandhook, libmemtrack, arthook_native, riru, libva,
XposedBridge.jar, libAndroidCydia.cy.so, libvirtualcamera.so,
libAndroidBootstrap0.so, libsubstrate.so, libDalvikLoader.cy.so,
libAndroidLoader.so, libsubstrate-dvm.so, libriruloader.so,
liblspd.so, libnpatch.so, liblsplant.so
```

**Xposed 相关包名：**
```
de.robv.android.xposed.installer, org.meowcat.edxposed.manager,
io.va.exposed, org.lsposed.manager, org.lsposed.npatch,
com.solohsu.android.edxp.manager, com.tsng.hidemyapplist,
org.lsposed.lspatch
```

### 3.3 模块 3: Frida 检测 (8 项检查)

基于 ANALYSIS_HOOK.md §8.2 的 6 种手段 + 扩展：

| # | 检测项 | 实现层 | 技术方案 | 绕过难度 |
|---|--------|--------|----------|----------|
| F1 | /proc/self/maps SO 扫描 | **Native (SVC)** | `sg_open()` 搜索 frida-agent, frida-loader, LIBFRIDA | ★★★★ |
| F2 | TCP 默认端口检测 | **Native** | connect() 尝试 127.0.0.1:27042 | ★★ |
| F3 | /proc/net/tcp 端口扫描 | **Native (SVC)** | `sg_open()` 读取 tcp 表扫描可疑端口 | ★★★★ |
| F4 | frida-server 文件检测 | **Native (SVC)** | `sg_access()` 检查 `/data/local/tmp/frida-server*` | ★★★ |
| F5 | Named Pipe 检测 | **Native (SVC)** | 扫描 `/proc/self/fd/` 查找 frida pipe | ★★★★ |
| F6 | D-Bus 协议探测 | **Native** | 向可疑端口发送 D-Bus 握手消息检测响应 | ★★★★★ |
| F7 | 内存特征扫描 | **Native** | `sg_mmap()` 扫描内存中 "LIBFRIDA" / "frida:rpc" 特征 | ★★★★ |
| F8 | 线程名检测 | **Native (SVC)** | 扫描 `/proc/self/task/*/comm` 搜索 frida 相关线程 | ★★★★ |

### 3.4 模块 4: NPatch/LSPatch 重打包检测 (9 项检查)

基于 ANALYSIS_NPATCH.md §十 的检测点 + apk-re SKILL：

| # | 检测项 | 实现层 | 技术方案 | 绕过难度 |
|---|--------|--------|----------|----------|
| N1 | appComponentFactory 篡改 | Java | 反射读取 ApplicationInfo.appComponentFactory 比对 | ★★★ |
| N2 | LSPAppComponentFactoryStub 类 | Java | ClassLoader 尝试加载该类 | ★★★ |
| N3 | libnpatch.so 加载检测 | **Native (SVC)** | /proc/self/maps 搜索 libnpatch/liblspatch | ★★★★ |
| N4 | openat Hook 检测 | **Native** | 比对 libc __openat GOT/PLT 条目完整性 | ★★★★★ |
| N5 | APK 路径异常 | Java | ApplicationInfo.sourceDir 是否指向 cache 目录 | ★★★ |
| N6 | cache/npatch/ 目录 | **Native (SVC)** | `sg_access()` 检查特征目录 | ★★★★ |
| N7 | metadata "npatch" 键 | Java | 反射检查 ApplicationInfo.metaData | ★★★ |
| N8 | profile 文件异常 | **Native (SVC)** | 检查 profile 文件权限是否被设为只读 | ★★★ |
| N9 | assets/npatch/ 目录扫描 | Java | 检查 APK 内是否有 npatch/lspatch assets | ★★★ |

---

## 四、核心 Native 层设计

### 4.1 SVC 直接系统调用包装器 (anti-hook 核心)

```c
// syscall_wrapper.h - 绕过 libc 函数 Hook 的直接系统调用
// 参考 libAntiCheat.so 的 rc_* 实现

// 直接通过 SVC 指令调用内核，不经过 libc
int sg_open(const char *path, int flags);
int sg_read(int fd, void *buf, size_t count);
int sg_close(int fd);
int sg_access(const char *path, int mode);
int sg_stat(const char *path, struct stat *buf);
void* sg_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);

// AArch64 SVC 实现:
// __attribute__((naked))
// int sg_open(const char *path, int flags) {
//     asm volatile(
//         "mov x8, #56\n"    // __NR_openat
//         "mov x0, #-100\n"  // AT_FDCWD
//         "svc #0\n"
//         "ret\n"
//     );
// }
```

### 4.2 /proc/self/maps 扫描器

```c
// maps_scanner.c
// 使用 SVC 直接读取 /proc/self/maps，避免被 fopen/fgets Hook

typedef struct {
    char path[256];
    char perms[5];
    unsigned long start;
    unsigned long end;
} MapEntry;

int scan_maps_for_threats(const char **blacklist, int count,
                          char *results, int max_results);
```

### 4.3 ArtMethod 结构体分析

```c
// art_method.c
// 读取 ArtMethod 内部结构体检测 Hook

int check_art_method_hooked(JNIEnv *env, jobject method);
int compare_art_method_size(JNIEnv *env, jobject method1, jobject method2);
int check_access_flags_anomaly(JNIEnv *env, jobject method, int sdk_version);
```

### 4.4 GOT/PLT 完整性检查

```c
// hook_detect.c
int check_got_hook(const char *so_name);
int check_inline_hook(void *func_addr);
int check_openat_hook();
```

---

## 五、项目结构

```
blue-team-app/
├── app/
│   ├── src/main/
│   │   ├── java/cn/fatalc/catched/
│   │   │   ├── MainActivity.kt
│   │   │   ├── ui/
│   │   │   │   ├── ScanScreen.kt
│   │   │   │   ├── ReportScreen.kt
│   │   │   │   ├── theme/
│   │   │   │   └── components/
│   │   │   ├── detector/
│   │   │   │   ├── DetectorEngine.kt
│   │   │   │   ├── BaseDetector.kt
│   │   │   │   ├── RootDetector.kt
│   │   │   │   ├── XposedDetector.kt
│   │   │   │   ├── FridaDetector.kt
│   │   │   │   └── NPatchDetector.kt
│   │   │   ├── model/
│   │   │   │   ├── ThreatReport.kt
│   │   │   │   ├── DetectionResult.kt
│   │   │   │   └── ThreatLevel.kt
│   │   │   └── native/
│   │   │       └── NativeBridge.kt
│   │   ├── cpp/
│   │   │   ├── CMakeLists.txt
│   │   │   ├── catched.c
│   │   │   ├── syscall_wrapper.h / .c
│   │   │   ├── root_detect.h / .c
│   │   │   ├── hook_detect.h / .c
│   │   │   ├── frida_detect.h / .c
│   │   │   ├── maps_scanner.h / .c
│   │   │   ├── art_method.h / .c
│   │   │   └── npatch_detect.h / .c
│   │   ├── res/
│   │   └── AndroidManifest.xml
│   └── build.gradle.kts
├── build.gradle.kts
├── settings.gradle.kts
└── PLAN.md
```

---

## 六、实施阶段

### Phase 1: 项目脚手架 + Native 基础

- [ ] Android 项目初始化 (Kotlin + NDK + Compose)
- [ ] CMake 构建配置
- [ ] SVC 直接系统调用包装器 (`syscall_wrapper.c`)
- [ ] JNI 桥接层 (`NativeBridge.kt` ↔ `catched.c`)
- [ ] /proc/self/maps 扫描器基础 (`maps_scanner.c`)

### Phase 2: Root/Magisk 检测模块

- [ ] Java 层: 包名检测、PATH 检测、命令执行
- [ ] Native 层: su 路径 SVC 扫描、Magisk 挂载点、Socket、SELinux
- [ ] RootDetector.kt 整合

### Phase 3: Xposed/LSPosed 检测模块

- [ ] Java 层: ClassLoader、VMDebug、堆栈分析、metadata
- [ ] Java 层 (高级): XposedHelpers 缓存、sHookedMethodCallbacks
- [ ] Native 层: maps 扫描、libart 字符串、ArtMethod 分析
- [ ] XposedDetector.kt 整合

### Phase 4: Frida 检测模块

- [ ] Native 层: maps SO 扫描、端口检测、/proc/net/tcp
- [ ] Native 层: Named Pipe、D-Bus 探测、内存特征、线程名
- [ ] FridaDetector.kt 整合

### Phase 5: NPatch/LSPatch 检测模块

- [ ] Java 层: appComponentFactory、APK 路径、metadata
- [ ] Native 层: libnpatch SO、openat GOT 检查、cache 目录
- [ ] NPatchDetector.kt 整合

### Phase 6: UI + 报告

- [ ] Compose UI: 扫描界面、动画、进度
- [ ] 报告页面: 威胁评分、详细结果、证据链
- [ ] 导出报告功能

---

## 七、威胁评分算法

```kotlin
data class ThreatScore(
    val total: Int,          // 0-100
    val rootScore: Int,      // 0-25
    val xposedScore: Int,    // 0-25  
    val fridaScore: Int,     // 0-25
    val npatchScore: Int,    // 0-25
    val level: ThreatLevel   // SAFE / LOW / MEDIUM / HIGH / CRITICAL
)

enum class ThreatLevel {
    SAFE,      // 0-10: 未发现威胁
    LOW,       // 11-30: 发现轻微异常
    MEDIUM,    // 31-50: 发现可疑迹象
    HIGH,      // 51-75: 确认存在安全威胁
    CRITICAL   // 76-100: 发现严重攻击活动
}
```

每个检测项根据「绕过难度」给予不同权重：
- ★★ (容易绕过): 1 分
- ★★★: 2 分
- ★★★★: 3 分
- ★★★★★ (极难绕过): 5 分

---

## 八、关键设计决策

### 8.1 为什么使用 SVC 直接系统调用？

> 参考 libAntiCheat.so 的 rc_* 实现 (ANALYSIS_HOOK.md §4.4)

标准 Frida/Xposed 可以 Hook libc 的 `open`/`fopen`/`fgets` 等函数，使检测代码读取到被篡改的文件内容。SVC 直接系统调用绕过整个 libc 层，直接与 Linux 内核通信，攻击者必须在内核层拦截才能绕过。

### 8.2 为什么 Java 层和 Native 层都要做检测？

- **Java 层**：可以访问 Android Framework API (PackageManager, ClassLoader, VMDebug)
- **Native 层**：可以直接操作文件系统和内存，绕过 Java 层 Hook

两者互补，单独绕过一层不足以逃避检测。

### 8.3 为什么检测 XposedHelpers.methodCache？

> 参考 ANALYSIS_HOOK.md §3.2.2 (f0.java)

这是目前**最强的 Xposed 检测手段**。只要攻击者使用了 `XposedHelpers.findAndHookMethod()`（几乎所有 Xposed 模块都会使用），被 Hook 的方法信息就会缓存在 `methodCache` 中。通过反射读取这个 Map，可以精确知道**哪些方法被 Hook 了**。

### 8.4 与现有开源项目的差异

| 特性 | RootBeer | Free-RASP | securevale | **Catched** |
|------|----------|-----------|------------|-----------------|
| NPatch/LSPatch 检测 | ❌ | ❌ | ❌ | ✅ (9项) |
| Xposed 缓存扫描 | ❌ | ❌ | ❌ | ✅ |
| ArtMethod 结构体分析 | ❌ | ❌ | ❌ | ✅ |
| SVC 直接系统调用 | ❌ | 部分 | ❌ | ✅ 全面 |
| Frida D-Bus 探测 | ❌ | ❌ | ❌ | ✅ |
| Magisk Socket 检测 | ❌ | ❌ | ❌ | ✅ |
| openat Hook 检测 | ❌ | ❌ | ❌ | ✅ |
| 独立 App (非 SDK) | RootBeer有 | ❌ | 有 | ✅ |
| 开源 | ✅ | 部分 | ✅ | ✅ |
