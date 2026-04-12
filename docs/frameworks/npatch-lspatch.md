# NPatch / LSPatch

> NPatch and LSPatch are APK repackaging tools that embed Xposed-compatible hook modules directly into the target APK, enabling runtime method hooking without root access.

---

## Overview

NPatch (and its predecessor LSPatch) provides a rootless alternative to LSPosed by modifying the target APK at install time rather than injecting at runtime via Zygote. The tool replaces the app's `appComponentFactory` with a custom stub, bundles hook modules and loader libraries as APK assets, and re-signs the package. At launch, the stub bootstraps a full Xposed-compatible environment before the original application code runs. Because the modified APK carries a different signature, this approach is detectable through certificate comparison but requires no privileged access on the device.

---

## How It Works

1. **APK extraction** — NPatch/LSPatch takes the original target APK and unpacks its contents for modification.
2. **Dex patching** — The tool replaces the `appComponentFactory` declaration in the manifest (and corresponding dex code) with its own stub class that will execute first during app initialization.
3. **Asset injection** — The loader library, Xposed-compatible bridge, and selected hook modules are added as assets (under `assets/npatch/` or `assets/lspatch/`).
4. **Re-signing** — The modified APK is signed with a new certificate, since the original signing key is unavailable. This invalidates the original signature.
5. **Installation** — The patched APK is installed on the device, replacing (or side-loading alongside) the original app.
6. **Runtime bootstrap** — On app launch, the custom `appComponentFactory` stub runs before `Application.onCreate()`. It loads the embedded loader native library, initializes the Xposed bridge from assets, and installs GOT hooks (e.g., on `openat()`) to redirect APK reads from the original path to the patched version.
7. **Module activation** — Embedded Xposed modules are loaded and their hooks are applied to the running app, providing the same hooking capabilities as a rooted LSPosed installation.

---

## Variants

| Variant                 | Description                                                                                                                  | Root Required |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------- | :-----------: |
| LSPatch                 | Original tool by the LSPosed team, modifies APK offline                                                                      |      No       |
| NPatch                  | Fork/successor of LSPatch with continued development                                                                         |      No       |
| LSPatch (portable mode) | Creates a manager app that performs patching on-device                                                                       |      No       |
| JShook                  | Similar repackaging concept but uses JavaScript-based hooking engine                                                         |      No       |
| NPatch (minimal mode)   | Minimal repackaging — only patches appComponentFactory and injects loader SO; no full DEX patching, smaller artifact surface |      No       |

---

## Artifacts

Persistent evidence this framework leaves that cannot be fully erased:

| Artifact            | Location                                            | Indicator                                                         |
| ------------------- | --------------------------------------------------- | ----------------------------------------------------------------- |
| AppComponentFactory | `applicationInfo.appComponentFactory`               | Contains "lsp", "npatch", or known stub class names               |
| Cache directories   | `$dataDir/cache/npatch/`, `$dataDir/cache/lspatch/` | Characteristic cache directories created by the loader            |
| APK source path     | `applicationInfo.sourceDir`                         | Points to a cache directory instead of `/data/app/`               |
| Asset directories   | APK assets                                          | `assets/npatch/` or `assets/lspatch/` directories present         |
| MetaData entries    | `applicationInfo.metaData`                          | Keys containing "npatch" or "lspatch" identifiers                 |
| Signature mismatch  | APK certificate                                     | APK signed with a different certificate than the original release |
| Profile files       | `$dataDir/`                                         | Profile files marked read-only by NPatch during initialization    |
| GOT hooks           | PLT/GOT section                                     | `openat()` redirected to intercept file read operations           |
| Native libraries    | `/proc/self/maps`                                   | `libnpatch_jni.so` or `liblspatch_jni.so` mapped into the process |

---

## Evasion Capabilities

Known anti-detection techniques supported by this framework:

| Technique                            | Description                                                                                                                                                                                 |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GOT hook on openat()                 | Redirects file read operations on the original APK path to the patched version transparently                                                                                                |
| Obfuscated stub class names          | Renames the appComponentFactory stub class to avoid string-pattern-based detection                                                                                                          |
| Asset directory name changes         | Uses non-standard names for the asset directory to evade known-path checks                                                                                                                  |
| Metadata stripping after init        | Removes identifying metadata keys from ApplicationInfo after initialization completes                                                                                                       |
| Seccomp-BPF syscall interception     | Installs BPF filter via `prctl(PR_SET_SECCOMP)` to intercept `openat` SVC calls; SIGSYS handler redirects `/proc/self/maps` and APK reads to filtered copies, defeating SVC-based detection |
| Inline code patching of Java methods | Patches AOT/JIT compiled code of target methods instead of modifying ArtMethod fields; avoids kAccNative detection while achieving the same hook effect                                     |
| RegisterNatives redirection          | Intercepts `RegisterNatives` JNI call to redirect native method bindings; avoids modifying Java-visible method metadata                                                                     |

---

## Techniques Used

| Technique                   | Doc                                                                            | Role in This Framework                                                    |
| --------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------- |
| Java reflection             | [java-reflection.md](../techniques/java-reflection.md)                         | Inspect appComponentFactory, metaData, and sourceDir via ApplicationInfo  |
| Filesystem path check       | [filesystem-path-check.md](../techniques/filesystem-path-check.md)             | Detect NPatch/LSPatch cache directories and loader files on disk          |
| Signature verification      | [signature-verification.md](../techniques/signature-verification.md)           | Compare APK signing certificate against expected original certificate     |
| GOT/PLT hook detection      | [got-plt-hook.md](../techniques/got-plt-hook.md)                               | Detect redirected openat() entries in the Global Offset Table             |
| procfs scanning             | [procfs-scanning.md](../techniques/procfs-scanning.md)                         | Scan `/proc/self/maps` for libnpatch_jni.so and liblspatch_jni.so         |
| ClassLoader analysis        | [classloader-analysis.md](../techniques/classloader-analysis.md)               | Detect additional ClassLoaders introduced by the embedded Xposed bridge   |
| Seccomp-BPF detection       | [seccomp-bpf-detection.md](../techniques/seccomp-bpf-detection.md)             | Detect BPF filters installed to intercept SVC-based detection syscalls    |
| Signal handler inspection   | [signal-handler-inspection.md](../techniques/signal-handler-inspection.md)     | Detect SIGSYS handler installed by seccomp-based evasion                  |
| Inline code patching        | [inline-code-patching.md](../techniques/inline-code-patching.md)               | Detect patched function prologues in AOT/JIT compiled method code         |
| ArtMethod introspection     | [artmethod-introspection.md](../techniques/artmethod-introspection.md)         | Detect kAccCompileDontBother and other compilation-control flag anomalies |
| ART internal hook detection | [art-internal-hook-detection.md](../techniques/art-internal-hook-detection.md) | Detect hooks on libart.so internal functions used for method resolution   |
| SVC direct syscall          | [svc-direct-syscall.md](../techniques/svc-direct-syscall.md)                   | Use SVC to bypass GOT hooks on openat() installed by NPatch/LSPatch       |
