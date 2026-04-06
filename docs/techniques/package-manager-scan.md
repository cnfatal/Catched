# PackageManager Scan

> Queries the Android PackageManager API to detect installed root managers, hook framework UIs, and Xposed modules by matching known package names and metadata keys.

---

## Overview

Android's `PackageManager` maintains a database of all installed applications, including their package names, signing certificates, and declared metadata. Root managers (SuperSU, Magisk), hook framework managers (Xposed Installer, LSPosed Manager), and Xposed modules must be installed as regular APKs to function, and Xposed modules must declare specific metadata in their `AndroidManifest.xml` for the framework to discover them. PackageManager Scan exploits these requirements by querying for known package names and scanning installed applications for the `xposedmodule` metadata key.

From a defender's perspective, this technique provides broad coverage because it can detect the entire ecosystem of attack tools — not just the active hooking framework, but also the management UI and individual modules. The PackageManager is a system service backed by the `packages.xml` database, making it a reliable data source. However, it is also the most commonly evaded technique, as tools like Magisk support package name randomization and package hiding.

---

## Injection Side

### How Attackers Use This Technique

1. **Install root manager** — The attacker installs a root management app (e.g., Magisk Manager) as a standard APK. This app provides a UI for granting root access to other apps and manages the root environment.
2. **Install hook framework manager** — A framework UI such as LSPosed Manager or EdXposed Manager is installed to configure which modules are loaded and which apps are targeted.
3. **Install hook modules** — Individual Xposed modules are installed as APKs. Each module must declare `<meta-data android:name="xposedmodule" android:value="true" />` in its `AndroidManifest.xml` so the framework can discover and load it.
4. **Module declares additional metadata** — Modules also declare `xposedminversion` (minimum framework API version) and `xposeddescription` (module description) metadata entries, providing further detectable signals.
5. **All packages visible via PackageManager** — Unless explicitly hidden, all installed packages are queryable through `PackageManager.getPackageInfo()` and `PackageManager.getInstalledApplications()`.

### Artifacts

| Artifact                | Location                 | Indicator                                                                                                              |
| ----------------------- | ------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| Root manager package    | PackageManager database  | Package name: `eu.chainfire.supersu`, `com.topjohnwu.magisk`, `io.github.vvb2060.magisk`, `com.koushikdutta.superuser` |
| Magisk module manager   | PackageManager database  | Package name: `com.fox2code.mmm`                                                                                       |
| Xposed manager package  | PackageManager database  | Package name: `de.robv.android.xposed.installer`, `org.meowcat.edxposed.manager`, `org.lsposed.manager`                |
| NPatch/LSPatch manager  | PackageManager database  | Package name: `org.lsposed.npatch`, `org.lsposed.lspatch`                                                              |
| Xposed module metadata  | ApplicationInfo.metaData | Key `xposedmodule` with value `true`                                                                                   |
| Xposed version metadata | ApplicationInfo.metaData | Key `xposedminversion` present                                                                                         |

### Injection PoC _(optional)_

```pseudocode
// AndroidManifest.xml of a typical Xposed module
<application>
    <meta-data android:name="xposedmodule" android:value="true" />
    <meta-data android:name="xposedminversion" android:value="93" />
    <meta-data android:name="xposeddescription" android:value="Hooks target app" />
</application>

// The module is installed as a normal APK and becomes visible via:
//   PackageManager.getPackageInfo("com.attacker.module", 0)  → success
//   ApplicationInfo.metaData.getBoolean("xposedmodule")      → true
```

### Evasion Techniques

| Evasion                        | Description                                                                                                               |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| Package name randomization     | Magisk Manager supports randomizing its package name at install time, making the default package name undetectable ★★     |
| Magisk Hide / DenyList         | Hides specific packages from the target app's view of PackageManager queries by intercepting system calls ★★★             |
| Package visibility filtering   | Android 11+ package visibility restrictions can prevent apps from seeing other packages unless declared in `<queries>` ★★ |
| Metadata stripping             | A modified module build could omit the `xposedmodule` metadata and use an alternative discovery mechanism ★★★★            |
| Hidden system app installation | Installing the tool as a hidden system app that doesn't appear in normal PackageManager queries ★★★                       |

---

## Detection Side

### Mechanism

The invariant is twofold: (1) known attack tool package names should not be installed on a clean device, and (2) no installed application should declare `xposedmodule` metadata unless it is a Xposed module. The first check uses direct package name lookups against a curated list. The second check iterates all installed applications and inspects their `metaData` Bundle for the `xposedmodule` key, which is a mandatory declaration for Xposed module discovery. Both checks leverage the system `PackageManager` service, which maintains the authoritative package database.

### Anti-Evasion Properties

| Property                       | Explanation                                                                                                                                                                                                   |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| System service backing         | PackageManager queries go through the system_server process, providing a reliable data source for installed packages                                                                                          |
| Metadata is framework-required | Xposed modules must declare `xposedmodule` metadata for the framework to discover them — omitting it breaks module loading                                                                                    |
| Broad tool coverage            | Scanning for multiple package names covers root managers, framework UIs, and patch tools in a single pass                                                                                                     |
| Remaining bypass surface       | Package name randomization defeats direct name lookups; Magisk DenyList can hide packages from queries; Android 11+ package visibility restricts what apps can see; custom module loaders could skip metadata |

### Detection Strategy

1. **Query known package names** — For each package name in the known attack tool list (`eu.chainfire.supersu`, `com.topjohnwu.magisk`, `io.github.vvb2060.magisk`, `com.koushikdutta.superuser`, `com.fox2code.mmm`, `de.robv.android.xposed.installer`, `org.meowcat.edxposed.manager`, `org.lsposed.manager`, `org.lsposed.npatch`, `org.lsposed.lspatch`), call `PackageManager.getPackageInfo(packageName, 0)`. If the call succeeds without throwing `NameNotFoundException`, the package is installed.
2. **Scan for Xposed module metadata** — Call `PackageManager.getInstalledApplications(PackageManager.GET_META_DATA)` to retrieve all installed applications with their metadata. For each application, check if `applicationInfo.metaData` is non-null and contains the key `"xposedmodule"`.
3. **Record findings** — For each detected package or module, record the package name, application label, and version code as detection evidence.

### Detection PoC _(optional)_

```pseudocode
// Approach 1: Direct package name lookup
known_packages = [
    "eu.chainfire.supersu", "com.koushikdutta.superuser",
    "com.topjohnwu.magisk", "io.github.vvb2060.magisk",
    "com.fox2code.mmm",
    "de.robv.android.xposed.installer",
    "org.meowcat.edxposed.manager", "org.lsposed.manager",
    "org.lsposed.npatch", "org.lsposed.lspatch"
]

for pkg in known_packages:
    try:
        info = packageManager.getPackageInfo(pkg, 0)
        report("known attack tool installed", pkg, info.versionName)
    catch NameNotFoundException:
        continue  // not installed

// Approach 2: Xposed module metadata scan
all_apps = packageManager.getInstalledApplications(GET_META_DATA)
for app in all_apps:
    if app.metaData != null and app.metaData.containsKey("xposedmodule"):
        report("xposed module detected", app.packageName)
```

### False Positive Risks

| Scenario                                                 | Mitigation                                                                                                                                   |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Legitimate app with coincidentally matching package name | The known package list uses fully-qualified package names specific to attack tools — collisions are extremely unlikely                       |
| Developer testing tools on device                        | Development devices may legitimately have these tools; detection should be informational in debug builds                                     |
| Android 11+ package visibility restrictions              | On API 30+, the app may need `<queries>` declarations in its manifest to see other packages; without them, queries silently return not-found |

---

## References

- [Android PackageManager API](https://developer.android.com/reference/android/content/pm/PackageManager)
- [Android 11 package visibility](https://developer.android.com/training/package-visibility)
- [Xposed module development — metadata requirements](https://api.xposed.info/reference/de/robv/android/xposed/IXposedHookLoadPackage.html)
- [Magisk — package name randomization](https://github.com/topjohnwu/Magisk)
- [LSPosed Manager](https://github.com/LSPosed/LSPosed)
