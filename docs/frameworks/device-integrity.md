# Device Integrity

> Device integrity encompasses the trustworthiness of the entire Android security chain — from bootloader state and verified boot to SELinux enforcement and APK signing — where any broken link indicates a compromised device.

---

## Overview

Device integrity is not a single attack framework but a collection of security signals that reflect whether the device's trust chain remains intact. A fully trusted device has a locked bootloader, verified boot in "green" state, release-keys build, enforcing SELinux policy, and properly signed applications. Compromises such as bootloader unlocking, custom ROM installation, rooting, or APK repackaging each break one or more links in this chain. Detecting these signals does not require root access — the application inspects publicly readable system properties, its own signing certificate, and SELinux state.

---

## How It Works

1. **Bootloader unlock** — The user enables OEM unlocking in developer settings and unlocks the bootloader via `fastboot oem unlock`, which wipes user data and changes `ro.boot.flash.locked` to `0`.
2. **Custom recovery** — A custom recovery image (TWRP, OrangeFox) is flashed via fastboot, granting full filesystem access in recovery mode.
3. **System modification** — A custom ROM (LineageOS, PixelExperience) replaces the stock system partition, or a root solution (Magisk, KernelSU) is installed on the stock ROM.
4. **SELinux weakening** — Custom ROMs or root tools may set SELinux to Permissive mode for compatibility, disabling mandatory access control enforcement.
5. **Build property changes** — Non-production builds use `test-keys`, `eng`, or `userdebug` build types, and custom ROMs introduce their own version properties.
6. **APK repackaging** — An attacker decompiles the APK, modifies its code, and re-signs it with a different certificate — requiring no device modification at all.

---

## Variants

| Variant                  | Description                                                                   | Root Required |
| ------------------------ | ----------------------------------------------------------------------------- | :-----------: |
| Unlocked bootloader only | Bootloader unlocked but stock ROM and no root — weakest compromise            |      No       |
| Custom ROM               | Full system replacement (LineageOS, PixelExperience, etc.) with optional root |   Optional    |
| Rooted stock ROM         | Stock ROM with root access added via Magisk or KernelSU                       |      Yes      |
| Repackaged APK           | Application decompiled, modified, and re-signed with a different certificate  |      No       |

---

## Artifacts

Persistent evidence this framework leaves that cannot be fully erased:

| Artifact              | Location                  | Indicator                                                           |
| --------------------- | ------------------------- | ------------------------------------------------------------------- |
| Bootloader state      | System properties         | `ro.boot.flash.locked=0`, `sys.oem_unlock_allowed=1`                |
| Verified boot state   | System properties         | `ro.boot.verifiedbootstate` is "yellow", "orange", or "red"         |
| Build tags            | `ro.build.tags`           | Value `test-keys` instead of `release-keys`                         |
| Build type            | `ro.build.type`           | Value `eng` or `userdebug` instead of `user`                        |
| Build fingerprint     | `ro.build.fingerprint`    | Containing "generic", "unknown", or "test"                          |
| Custom ROM properties | System properties         | `ro.modversion`, `ro.lineage.version`, `ro.pixelexperience.version` |
| SELinux enforcement   | `/sys/fs/selinux/enforce` | Value `0` (Permissive) or `getenforce` not returning "Enforcing"    |
| APK signature         | Application certificate   | SHA-256 fingerprint mismatch against known production certificate   |

---

## Evasion Capabilities

Known anti-detection techniques supported by this framework:

| Technique                       | Description                                                                                      |
| ------------------------------- | ------------------------------------------------------------------------------------------------ |
| SafetyNet/Play Integrity bypass | Magisk modules (e.g., MagiskHide Props Config, Play Integrity Fix) spoof device attestation      |
| Property spoofing               | `resetprop` or `init.rc` overrides change build tags, fingerprint, and boot state at runtime     |
| SELinux context manipulation    | Switch SELinux to enforcing selectively or spoof the enforce file while keeping permissive rules |
| Signature spoofing              | Tools that make the system report the original app signature despite repackaging                 |

---

## Techniques Used

| Technique                | Doc                                                                      | Role in This Framework                                                         |
| ------------------------ | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| System property analysis | [system-property-analysis.md](../techniques/system-property-analysis.md) | Read bootloader state, build tags, build type, verified boot, custom ROM props |
| Signature verification   | [signature-verification.md](../techniques/signature-verification.md)     | Compare APK signing certificate against expected production fingerprint        |
| Java reflection          | [java-reflection.md](../techniques/java-reflection.md)                   | Access `Build.*` fields and read SELinux state via runtime APIs                |
