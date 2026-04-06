# Emulator

> Android emulators provide fully virtualized environments that grant attackers easy root access, filesystem manipulation, and debugging capabilities — undermining all device-trust assumptions.

---

## Overview

Android emulators run a complete Android system inside a virtual machine backed by QEMU, VirtualBox, or Hyper-V. They emulate or paravirtualize hardware components including CPU, GPU, sensors, telephony, and storage. Emulators range from developer-focused tools (Android Studio AVD, Genymotion) to consumer gaming platforms (BlueStacks, NoxPlayer, LDPlayer, MEmu). Because emulators provide trivial root access, full filesystem control, and built-in network interception, they allow attackers to bypass virtually all client-side protections without modifying the application itself.

---

## How It Works

1. **Install emulator** — The attacker installs an Android emulator on a desktop operating system (Windows, macOS, Linux).
2. **Configure environment** — The emulator is configured with a target Android version, screen resolution, and hardware profile. Root access is enabled (often by default).
3. **Install target application** — The APK is sideloaded or installed from a cloned Play Store.
4. **Manipulate device state** — The attacker modifies system properties, filesystem contents, network configuration, and sensor data to simulate a legitimate device.
5. **Execute attack** — With root access and full system control, the attacker runs Frida, Xposed, or debuggers inside the emulator, intercepts network traffic, or directly modifies application data files.

---

## Variants

| Variant               | Description                                              | Root Required |
| --------------------- | -------------------------------------------------------- | :-----------: |
| Android Studio AVD    | Official QEMU-based emulator for development and testing | Configurable  |
| Genymotion            | VirtualBox-based emulator for development and QA         |      Yes      |
| BlueStacks            | Consumer gaming emulator with large user base            |      Yes      |
| NoxPlayer             | Gaming-focused emulator with built-in root toggle        |      Yes      |
| LDPlayer              | Gaming emulator optimized for performance                |      Yes      |
| MEmu                  | Gaming emulator with multi-instance support              |      Yes      |
| Tiantian (天天模拟器) | Chinese-market gaming emulator                           |      Yes      |

---

## Artifacts

Persistent evidence this framework leaves that cannot be fully erased:

| Artifact                | Location               | Indicator                                                                        |
| ----------------------- | ---------------------- | -------------------------------------------------------------------------------- |
| QEMU properties         | System properties      | `ro.kernel.qemu=1`, `ro.hardware=goldfish` or `ranchu`                           |
| VirtualBox properties   | System properties      | `ro.hardware=vbox86`, `ro.hardware.chipname=vbox86`                              |
| Build identity          | `Build.*` fields       | BRAND/MODEL/DEVICE/PRODUCT containing "google_sdk", "Emulator", "generic", "sdk" |
| Build.HOST              | `Build.HOST`           | Containing "genymotion", "buildbot", "nox", "memu", "tiantian"                   |
| Build.FINGERPRINT       | `Build.FINGERPRINT`    | Containing "generic", "unknown", "test", "sdk"                                   |
| QEMU device nodes       | `/dev/`                | `/dev/qemu_pipe`, `/dev/socket/qemud`                                            |
| VirtualBox device nodes | `/dev/`                | `/dev/vboxguest`, `/dev/vboxuser`                                                |
| Emulator system files   | `/system/`             | `libc_malloc_debug_qemu.so`, `ueventd.goldfish.rc`, `init.goldfish.rc`           |
| Sensor anomaly          | `SensorManager`        | Missing accelerometer/gyroscope/magnetometer, total sensor count < 3             |
| Telephony anomaly       | `TelephonyManager`     | Network operator "Android", phone type `NONE`, SIM operator "Android"            |
| Battery anomaly         | `BatteryManager`       | Level fixed at 50%, always charging, constant 25°C temperature, "not present"    |
| CPU ABI                 | `Build.SUPPORTED_ABIS` | x86-only with no ARM ABI support                                                 |

---

## Evasion Capabilities

Known anti-detection techniques supported by this framework:

| Technique                 | Description                                                                         |
| ------------------------- | ----------------------------------------------------------------------------------- |
| Property spoofing         | Override `Build.*` fields at runtime using reflection or Xposed hooks               |
| ARM translation layer     | Add ARM ABI support via `libhoudini` or native bridge to hide x86-only architecture |
| Sensor emulation          | Modern emulators inject realistic accelerometer, gyroscope, and magnetometer data   |
| Fingerprint randomization | Tools that randomize IMEI, serial number, model, and other hardware identifiers     |
| Device node hiding        | Mount overlays or hook filesystem calls to hide `/dev/qemu_pipe` and similar nodes  |

---

## Techniques Used

| Technique                | Doc                                                                      | Role in This Framework                                                        |
| ------------------------ | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------- |
| System property analysis | [system-property-analysis.md](../techniques/system-property-analysis.md) | Check `ro.kernel.qemu`, `ro.hardware`, Build.\* fields for emulator markers   |
| Filesystem path check    | [filesystem-path-check.md](../techniques/filesystem-path-check.md)       | Detect QEMU/VirtualBox device nodes and emulator-specific system files        |
| Hardware fingerprint     | [hardware-fingerprint.md](../techniques/hardware-fingerprint.md)         | Identify sensor anomalies, battery anomalies, telephony anomalies, CPU ABI    |
| Java reflection          | [java-reflection.md](../techniques/java-reflection.md)                   | Read `Build.*` fields and query `SensorManager`/`TelephonyManager` at runtime |
