# Xposed / LSPosed

> Xposed is the original Java-level hooking framework for Android, and LSPosed is its modern successor that runs via Zygisk to intercept and modify any Java method at runtime.

---

## Overview

The Xposed framework allows modules to hook any Java or Kotlin method in any Android app without modifying the APK. It works by injecting `XposedBridge.jar` into the Zygote process so that every forked app inherits the hooking environment. LSPosed, the current-generation implementation, runs as a Zygisk module and supports selective per-app injection, making it harder to detect from non-targeted apps. Both require root access. The framework targets the ART runtime, modifying method entry points and access flags to redirect execution flow.

---

## How It Works

1. **Zygote injection** — At boot, the Xposed/LSPosed module injects `XposedBridge.jar` (or equivalent loader) into the Zygote process via Riru or Zygisk. This ensures the bridge is present before any app process is created.
2. **App fork inheritance** — When Android forks a new app process from Zygote, the injected bridge is inherited. LSPosed selectively activates only for apps in its scope list.
3. **Module loading** — The bridge loads Xposed modules (APKs with `xposed_init` metadata) using custom `ClassLoader` instances. Each module's entry class is instantiated and its `handleLoadPackage()` callback is invoked.
4. **Method hooking** — Modules call `XposedHelpers.findAndHookMethod()` which modifies the target `ArtMethod` struct in memory: the `access_flags` field gains `kAccNative`, and the `entry_point_from_quick_compiled_code` is redirected to the Xposed trampoline.
5. **Callback execution** — When the hooked method is called, the trampoline dispatches to registered `beforeHookedMethod` / `afterHookedMethod` callbacks, giving modules full control over arguments, return values, and execution flow.

---

## Variants

| Variant                 | Description                                                      | Root Required |
| ----------------------- | ---------------------------------------------------------------- | :-----------: |
| Xposed (rovo89)         | Original framework, requires system partition modification       |      Yes      |
| EdXposed                | Riru-based implementation, native injection                      |      Yes      |
| LSPosed                 | Zygisk-based modern implementation, selective per-app hooking    |      Yes      |
| LSPosed (parasite mode) | Embedded directly into a target APK, no root needed              |      No       |
| TaiChi                  | Xposed-compatible framework, supports partial rootless operation |      No       |

---

## Artifacts

Persistent evidence this framework leaves that cannot be fully erased:

| Artifact                      | Location                              | Indicator                                                           |
| ----------------------------- | ------------------------------------- | ------------------------------------------------------------------- |
| ClassLoader instances         | Runtime heap                          | `BaseDexClassLoader` with "xposed" or "lsposed" in class/path names |
| DexPathList dexElements       | Runtime heap                          | Entries containing `XposedBridge.jar` or LSPosed module JARs        |
| Memory maps                   | `/proc/self/maps`                     | `libxposed*`, `liblsp*`, `libgadget*` mapped libraries              |
| Anonymous executable segments | `/proc/self/maps`                     | Executable anonymous mappings from injected code                    |
| Hidden ELF                    | `/proc/self/maps`                     | ELF headers found in anonymous readable memory regions              |
| Method cache                  | `XposedHelpers.methodCache`           | Non-empty cache indicating reflection-based method lookup occurred  |
| Hook callbacks                | `XposedBridge.sHookedMethodCallbacks` | Non-empty callback list proving methods have been hooked            |
| ArtMethod flags               | ART runtime memory                    | Methods with `kAccNative` flag that are not declared as native      |
| Stack trace frames            | Runtime call stack                    | `de.robv.android.xposed.*` classes appearing in stack traces        |
| app_process backup            | `/system/bin/app_process.orig`        | Backup of original app_process binary                               |
| Package                       | Package manager                       | `org.lsposed.manager`, `de.robv.android.xposed.installer`           |

---

## Evasion Capabilities

Known anti-detection techniques supported by this framework:

| Technique                 | Description                                                                                 |
| ------------------------- | ------------------------------------------------------------------------------------------- |
| Obfuscated class names    | Renames injected classes to avoid string-based detection of Xposed/LSPosed identifiers      |
| ArtMethod flag cleanup    | Restores `access_flags` after hook installation to remove the `kAccNative` indicator        |
| Stack trace frame removal | Strips Xposed-related frames from exception stack traces before they reach the target app   |
| XposedBridge unloading    | Unloads the bridge JAR from memory after all hooks are installed to reduce artifact surface |

---

## Techniques Used

| Technique               | Doc                                                                    | Role in This Framework                                                     |
| ----------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| ClassLoader analysis    | [classloader-analysis.md](../techniques/classloader-analysis.md)       | Detect injected ClassLoaders carrying Xposed/LSPosed module JARs           |
| Java reflection         | [java-reflection.md](../techniques/java-reflection.md)                 | Access XposedBridge internal fields like methodCache and callback lists    |
| ArtMethod introspection | [artmethod-introspection.md](../techniques/artmethod-introspection.md) | Detect tampered access_flags and redirected entry points on hooked methods |
| procfs scanning         | [procfs-scanning.md](../techniques/procfs-scanning.md)                 | Scan `/proc/self/maps` for injected libraries and anonymous executables    |
| Memory pattern scan     | [memory-pattern-scan.md](../techniques/memory-pattern-scan.md)         | Search anonymous memory regions for hidden ELF headers and Xposed strings  |
| Stack trace analysis    | [stack-trace-analysis.md](../techniques/stack-trace-analysis.md)       | Inspect call stacks for `de.robv.android.xposed` class frames              |
| Filesystem path check   | [filesystem-path-check.md](../techniques/filesystem-path-check.md)     | Check for `app_process.orig` and other Xposed filesystem artifacts         |
| Package manager scan    | [package-manager-scan.md](../techniques/package-manager-scan.md)       | Detect LSPosed manager or Xposed installer packages                        |
