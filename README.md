# Catched

An Android security detection toolkit that identifies Root, Xposed, Frida, and LSPatch/NPatch environments through multi-layered analysis combining Java reflection and raw SVC syscalls.

## Features

- **41 detection checks** across 4 categories
- **SVC direct syscalls** bypass libc hooks for tamper-resistant detection
- **Registration-based architecture** — each check is self-contained with metadata + execution logic
- **Real-time UI** — results stream in per-check as scanning progresses
- **Tag system** — checks are tagged by layer (`native`, `svc`, `java`, `reflection`, etc.) for filtering

## Detection Groups

### Root/Magisk (12 checks)

| ID | Check | Layer |
|---|---|---|
| `rt.su_svc` | SVC access to 14 su binary paths | native/svc |
| `rt.pkg` | Known root manager package names | java/pm |
| `rt.which` | `which su` shell execution | java/shell |
| `rt.path` | PATH env traversal for su | java/filesystem |
| `rt.stat` | SVC fstatat with SUID bit check | native/svc |
| `rt.mount` | `/proc/mounts` magisk keyword scan | native/svc |
| `rt.mountinfo` | `/proc/self/mountinfo` analysis | native/svc |
| `rt.overlay` | OverlayFS workdir detection | java/shell |
| `rt.selinux` | SELinux magisk_file label check | native/svc |
| `rt.seprev` | `/proc/self/attr/prev` context | native/svc |
| `rt.socket` | `/proc/net/unix` magisk socket scan | native/procfs |
| `rt.prop` | System property anomaly check | java/property |

### Xposed/LSPosed (12 checks)

| ID | Check | Layer |
|---|---|---|
| `xp.classloader` | XposedBridge class loading | java/classloader |
| `xp.vmdebug` | VMDebug BaseDexClassLoader instance scan | java/reflection |
| `xp.dexpath` | DexPathList.dexElements traversal | java/reflection |
| `xp.stack` | Stack trace Xposed/Substrate pattern match | java/stacktrace |
| `xp.pkg` | Xposed module metadata scan | java/pm |
| `xp.cache` | XposedHelpers.methodCache inspection | java/reflection |
| `xp.hooks` | sHookedMethodCallbacks field read | java/reflection |
| `xp.native_flag` | Anomalous native method flag detection | java/reflection |
| `xp.maps` | `/proc/self/maps` Xposed SO scan | native/svc |
| `xp.libart` | libart.so xposed string search | native/svc |
| `xp.app_process` | app_process.orig backup detection | native/svc |
| `xp.artmethod` | ArtMethod struct size anomaly | native/memory |

### Frida (8 checks)

| ID | Check | Layer |
|---|---|---|
| `fr.maps` | `/proc/self/maps` frida-agent scan | native/svc |
| `fr.port` | TCP connect to 27042/27043 | native/network |
| `fr.tcp` | `/proc/net/tcp` port hex scan | native/svc |
| `fr.server` | frida-server file existence | native/svc |
| `fr.pipe` | `/proc/self/fd` named pipe scan | native/svc |
| `fr.dbus` | D-Bus AUTH handshake probe | native/network |
| `fr.mem` | Anonymous memory LIBFRIDA/frida:rpc scan | native/memory |
| `fr.thread` | `/proc/self/task/*/comm` thread name scan | native/svc |

### NPatch/LSPatch (9 checks)

| ID | Check | Layer |
|---|---|---|
| `np.acf` | appComponentFactory tampering | java/reflection |
| `np.stub` | LSPatch/NPatch stub class loading | java/classloader |
| `np.so` | `/proc/self/maps` libnpatch SO scan | native/svc |
| `np.openat` | openat GOT/PLT integrity check | native/hook |
| `np.apk_path` | sourceDir cache path anomaly | java/filesystem |
| `np.cache` | cache/npatch/ directory existence | native/svc |
| `np.meta` | ApplicationInfo metadata key scan | java/reflection |
| `np.profile` | Profile file read-only permission | native/svc |
| `np.assets` | APK assets npatch directory scan | java/filesystem |

## Architecture

```
cn.fatalc.catched/
├── model/
│   └── Check.kt              # Check (id, group, name, desc, tags, run) + CheckResult
├── engine/
│   └── DetectorEngine.kt     # Registry + scheduler, per-check callback
├── detector/
│   ├── RootChecks.kt          # fun rootChecks(ctx): List<Check>
│   ├── XposedChecks.kt        # fun xposedChecks(ctx): List<Check>
│   ├── FridaChecks.kt         # fun fridaChecks(): List<Check>
│   └── NPatchChecks.kt        # fun npatchChecks(ctx): List<Check>
├── native/
│   └── NativeBridge.kt        # JNI declarations
└── cpp/
    ├── catched.c              # JNI dynamic registration
    ├── root_detect.c/h        # Root/Magisk native detection
    ├── frida_detect.c/h       # Frida native detection
    ├── hook_detect.c/h        # Xposed/Hook native detection
    ├── npatch_detect.c/h      # NPatch native detection
    ├── maps_scanner.c/h       # /proc/self/maps parser
    ├── syscall_wrapper.c/h    # SVC direct syscall wrappers
    └── art_method.c/h         # ArtMethod struct analysis
```

### Design Principles

**Registration-first** — Each check is a self-contained `Check` object with metadata and a `run` lambda. The engine collects them and schedules execution. Adding a new check = one function call.

```kotlin
Check("fr.maps", "Frida", "maps SO scan", "...", setOf("native", "svc")) {
    CheckResult(NativeBridge.nDetectFridaMaps())
}
```

**Groups are labels, not executors** — Groups exist only for UI categorization. The engine runs checks individually.

**Tag-based filtering** — Each check carries semantic tags (`native`, `svc`, `java`, `reflection`, `procfs`, etc.). Supports scanning by specific check IDs.

**SVC syscall bypass** — Native checks use inline assembly SVC instructions instead of libc wrappers, making them resistant to LD_PRELOAD / GOT hooking.

## Build

```bash
# Debug build
./gradlew assembleDebug

# Install to connected device
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

**Requirements:**
- Android Studio with NDK installed
- Min SDK 26 (Android 8.0)
- Target SDK 36
- ABI: arm64-v8a, armeabi-v7a

## License

MIT
