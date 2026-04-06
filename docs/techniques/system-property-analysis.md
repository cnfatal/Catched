# System Property Analysis

> Reads Android system properties, Build.\* fields, and system settings to detect device compromise, bootloader unlock, custom ROM installation, or emulator environment.

---

## Overview

Android system properties are key-value pairs maintained by the `init` process and exposed via the `property_service` socket. They encode hardware configuration, build parameters, boot state, and security policy settings. The `android.os.Build` class mirrors many of these properties into Java-accessible static fields. Together, these data sources provide a comprehensive fingerprint of the device's integrity state. A production device running stock firmware with a locked bootloader has a specific, predictable set of property values; deviation from these expected values indicates rooting, bootloader unlocking, custom ROM installation, or emulator execution.

From a defender's perspective, system property analysis is a broad-spectrum detection technique. While individual properties can be spoofed by sophisticated attackers, the sheer number of correlated signals — spanning build type, SELinux state, bootloader lock, verified boot status, hardware identifiers, and developer settings — makes it extremely difficult to present a fully consistent clean profile on a compromised device. Cross-correlating multiple properties significantly raises the evasion bar.

---

## Injection Side

### How Attackers Use This Technique

1. **Root the device** — The attacker unlocks the bootloader and installs a root management framework (e.g., Magisk, KernelSU), which modifies boot images and system properties.
2. **Install custom ROM** — The attacker flashes a custom ROM (e.g., LineageOS, PixelExperience), which sets distinctive build properties like `ro.lineage.version` or `ro.modversion`.
3. **Enable developer options** — To use debugging tools, the attacker enables developer settings, USB debugging, and wireless ADB, which set corresponding system settings.
4. **Run on emulator** — For analysis, the attacker runs the app on an emulator (QEMU, Genymotion, Nox, BlueStacks), which has characteristic hardware identifiers and build fingerprints.
5. **Attempt property spoofing** — Advanced attackers use Magisk modules (MagiskHide Props, ResetProp) to override property values, trying to make the device appear stock.

### Artifacts

| Artifact                  | Location                                                            | Indicator                                                 |
| ------------------------- | ------------------------------------------------------------------- | --------------------------------------------------------- |
| Debuggable build          | `ro.debuggable`                                                     | Value is "1" (should be "0" on production)                |
| Insecure build            | `ro.secure`                                                         | Value is "0" (should be "1")                              |
| Test signing keys         | `ro.build.tags`                                                     | Value is "test-keys" (should be "release-keys")           |
| Development build type    | `ro.build.type`                                                     | Value is "eng" or "userdebug" (should be "user")          |
| SELinux disabled          | `ro.build.selinux`                                                  | Value is "0"                                              |
| Magisk properties         | `init.svc.magisk_daemon`, `persist.magisk.hide`                     | Properties exist or have active values                    |
| Unlocked bootloader       | `ro.boot.flash.locked`                                              | Value is "0" (should be "1")                              |
| OEM unlock allowed        | `sys.oem_unlock_allowed`                                            | Value is "1"                                              |
| Compromised verified boot | `ro.boot.verifiedbootstate`                                         | Value is "yellow", "orange", or "red" (should be "green") |
| Custom ROM identifiers    | `ro.modversion`, `ro.lineage.version`, `ro.pixelexperience.version` | Properties exist with version strings                     |
| Emulator QEMU flag        | `ro.kernel.qemu`, `ro.boot.qemu`                                    | Value is "1"                                              |
| Emulator hardware         | `ro.hardware`                                                       | Contains "goldfish", "ranchu", or "vbox86"                |
| SELinux permissive mode   | `/sys/fs/selinux/enforce`                                           | File content is "0"                                       |
| ADB enabled               | `Settings.Global.ADB_ENABLED`                                       | Value is "1" in an environment where it should not be     |
| Developer settings        | `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED`                      | Value is "1"                                              |

### Injection PoC _(optional)_

```pseudocode
// Attacker uses resetprop to spoof system properties
resetprop ro.debuggable 0
resetprop ro.secure 1
resetprop ro.build.tags release-keys
resetprop ro.build.type user
resetprop ro.boot.verifiedbootstate green

// Hide Magisk-specific properties
resetprop --delete persist.magisk.hide
resetprop --delete init.svc.magisk_daemon

// Modify Build.* fields via Xposed/LSPosed module
hook(Build.class, "FINGERPRINT", "google/oriole/oriole:13/...")
hook(Build.class, "MODEL", "Pixel 6")
hook(Build.class, "MANUFACTURER", "Google")
```

### Evasion Techniques

| Evasion                 | Description                                                                                                                 |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Property value spoofing | Use `resetprop` or similar tools to override specific property values at the property service level                         |
| Build field hooking     | Hook `Build.*` static field accesses via Xposed to return spoofed values                                                    |
| Magisk DenyList         | Magisk's DenyList feature unmounts modified partitions and restores original properties in the target app's mount namespace |
| Property deletion       | Remove Magisk-specific properties entirely using `resetprop --delete`                                                       |
| SELinux status spoofing | Hook the file read for `/sys/fs/selinux/enforce` to return "1" even when SELinux is permissive                              |

---

## Detection Side

### Mechanism

The invariant is that a production Android device with stock firmware, a locked bootloader, and no modifications has a specific, internally consistent set of system properties: `ro.debuggable` is "0", `ro.secure` is "1", `ro.build.tags` is "release-keys", `ro.build.type` is "user", `ro.boot.verifiedbootstate` is "green", `ro.boot.flash.locked` is "1", no Magisk-specific properties exist, no custom ROM version properties exist, `Build.*` fields match genuine hardware, and SELinux is in enforcing mode. Deviation from any of these values, or inconsistency between correlated properties (e.g., `ro.build.type` says "user" but `ro.debuggable` says "1"), indicates device compromise.

### Anti-Evasion Properties

| Property                 | Explanation                                                                                                                                                                |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| High signal count        | Dozens of independent properties must all be spoofed consistently; missing even one creates a detectable inconsistency                                                     |
| Cross-correlation        | Checking relationships between properties (e.g., build type vs. debuggable flag) catches partial spoofing attempts                                                         |
| Multiple access paths    | Properties can be read via `SystemProperties.get()` (reflection), `Build.*` fields, native `__system_property_get()`, and direct file reads — hooking all paths is complex |
| Direct file reads        | Reading `/sys/fs/selinux/enforce` and `/proc/self/status` via SVC bypasses userspace hooks on property access APIs                                                         |
| Remaining bypass surface | Kernel-level property service patches, comprehensive Xposed modules that hook all access paths, or custom kernels that forge `/sys/fs/selinux/enforce` content             |

### Detection Strategy

1. **Read system properties via reflection** — Use Java reflection to access the hidden `android.os.SystemProperties.get()` method. Query each security-relevant property: `ro.debuggable`, `ro.secure`, `ro.build.tags`, `ro.build.type`, `ro.build.selinux`, `ro.boot.flash.locked`, `sys.oem_unlock_allowed`, `ro.boot.verifiedbootstate`, `ro.kernel.qemu`, `ro.boot.qemu`, `ro.hardware`. Also query Magisk-specific properties: `init.svc.magisk_daemon`, `persist.magisk.hide`. Query custom ROM properties: `ro.modversion`, `ro.lineage.version`, `ro.pixelexperience.version`.
2. **Check Build.\* fields** — Read `Build.MODEL`, `Build.BRAND`, `Build.DEVICE`, `Build.PRODUCT`, `Build.MANUFACTURER`, `Build.HARDWARE`, `Build.BOARD`, `Build.FINGERPRINT`, `Build.HOST`, `Build.SUPPORTED_ABIS`. Check each against known emulator and test-device patterns:
   - MODEL/BRAND/DEVICE/PRODUCT/MANUFACTURER/HARDWARE/BOARD containing: "sdk", "google_sdk", "emulator", "genymotion", "nox", "bluestacks", "Android SDK built for"
   - FINGERPRINT containing: "generic", "unknown", "test"
   - HOST containing: "genymotion", "buildbot", "nox"
   - SUPPORTED_ABIS containing only x86/x86_64 without ARM ABIs (indicates emulator without ARM translation)
3. **Read SELinux enforcement status** — Open `/sys/fs/selinux/enforce` via SVC and read its content. Value "0" indicates permissive mode (security policy not enforced). Cross-reference with `ro.build.selinux` property.
4. **Check Android settings** — Use `Settings.Global.getInt()` to read `ADB_ENABLED`, `adb_wifi_enabled`, and `DEVELOPMENT_SETTINGS_ENABLED`. While these alone are not conclusive, they contribute to the overall risk score when combined with other signals.
5. **Cross-correlate signals** — Build a composite risk score. A single borderline signal (e.g., developer settings enabled) may be acceptable. Multiple signals (debuggable build + test keys + unlocked bootloader + permissive SELinux) provide high-confidence detection of device compromise.

### Detection PoC _(optional)_

```pseudocode
// Step 1: Read system properties via reflection
sp_class = Class.forName("android.os.SystemProperties")
get_method = sp_class.getMethod("get", String.class, String.class)

risk_signals = []

if get_method.invoke(null, "ro.debuggable", "0") == "1":
    risk_signals.append("debuggable_build")
if get_method.invoke(null, "ro.secure", "1") == "0":
    risk_signals.append("insecure_build")
if get_method.invoke(null, "ro.build.tags", "") == "test-keys":
    risk_signals.append("test_keys")
if get_method.invoke(null, "ro.build.type", "") in ["eng", "userdebug"]:
    risk_signals.append("dev_build_type")
if get_method.invoke(null, "ro.boot.flash.locked", "1") == "0":
    risk_signals.append("unlocked_bootloader")
if get_method.invoke(null, "ro.boot.verifiedbootstate", "green") != "green":
    risk_signals.append("compromised_verified_boot")
if get_method.invoke(null, "ro.kernel.qemu", "0") == "1":
    risk_signals.append("emulator_qemu")

// Check Magisk-specific properties
magisk_props = ["init.svc.magisk_daemon", "persist.magisk.hide"]
for prop in magisk_props:
    if get_method.invoke(null, prop, "") != "":
        risk_signals.append("magisk_property_" + prop)

// Step 2: Check Build.* fields for emulator patterns
emulator_keywords = ["sdk", "google_sdk", "emulator", "genymotion",
                      "nox", "bluestacks", "goldfish", "ranchu", "vbox86"]
build_fields = [Build.MODEL, Build.BRAND, Build.DEVICE, Build.PRODUCT,
                Build.MANUFACTURER, Build.HARDWARE, Build.BOARD]
for field in build_fields:
    for keyword in emulator_keywords:
        if keyword in field.toLowerCase():
            risk_signals.append("emulator_build_field")

if "generic" in Build.FINGERPRINT or "unknown" in Build.FINGERPRINT:
    risk_signals.append("suspicious_fingerprint")

// Check for x86-only ABI (emulator without ARM translation)
abis = Build.SUPPORTED_ABIS
if all("x86" in abi for abi in abis):
    risk_signals.append("x86_only_abi")

// Step 3: Read SELinux enforcement status via SVC
fd = svc_openat(AT_FDCWD, "/sys/fs/selinux/enforce", O_RDONLY, 0)
if fd >= 0:
    content = svc_read(fd, buffer, 1)
    svc_close(fd)
    if content == "0":
        risk_signals.append("selinux_permissive")

// Step 4: Check developer settings
if Settings.Global.getInt(resolver, "adb_enabled", 0) == 1:
    risk_signals.append("adb_enabled")
if Settings.Global.getInt(resolver, "development_settings_enabled", 0) == 1:
    risk_signals.append("dev_settings_enabled")

// Step 5: Return composite result
return risk_signals
```

### False Positive Risks

| Scenario                                                  | Mitigation                                                                                                                                                |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Legitimate developer testing with USB debugging enabled   | Weight ADB/developer settings as low-severity signals; only flag when combined with other indicators                                                      |
| OEM devices with non-standard build properties            | Maintain a database of known OEM-specific property values that deviate from AOSP defaults (e.g., some manufacturers use "userdebug" builds in production) |
| x86 Android devices (Chromebooks, Intel tablets)          | Check for known legitimate x86 device models before flagging x86-only ABI as emulator                                                                     |
| Unlocked bootloader on developer-targeted devices (Pixel) | Combine bootloader status with other signals; an unlocked bootloader alone on a Pixel device is common for developers                                     |
| Custom AOSP builds for enterprise devices                 | Enterprise MDM solutions may set custom properties; check for known enterprise ROM identifiers                                                            |

---

## References

- [Android system properties documentation](https://source.android.com/docs/core/architecture/configuration/add-system-properties)
- [Android Build class — API reference](https://developer.android.com/reference/android/os/Build)
- [Android Verified Boot (AVB) documentation](https://source.android.com/docs/security/features/verifiedboot)
- [SELinux on Android](https://source.android.com/docs/security/features/selinux)
- [Android Settings.Global — API reference](https://developer.android.com/reference/android/provider/Settings.Global)
- [Magisk documentation — MagiskHide and DenyList](https://topjohnwu.github.io/Magisk/)
