# Hardware Fingerprint Analysis

> Detects emulated environments by probing hardware characteristics — sensors, telephony, battery, CPU architecture, and build metadata — that are difficult for emulators to virtualize accurately.

---

## Overview

Physical Android devices contain real hardware components that produce specific, consistent behaviors: accelerometers report gravity, SIM cards provide carrier information, batteries discharge over time, and ARM CPUs support specific ABIs. Emulators attempt to virtualize these components but frequently fail to replicate them faithfully — sensors are absent or limited, telephony fields return placeholder values, battery metrics are static, and CPU architecture defaults to x86. Hardware Fingerprint Analysis queries multiple hardware-related APIs and cross-correlates their responses to distinguish real devices from emulated environments.

From a defender's perspective, this technique is powerful because it leverages a fundamental asymmetry: perfectly simulating diverse hardware is extremely difficult. Each individual signal may be weak (a device could legitimately lack a gyroscope), but combining multiple signals creates a strong composite indicator. Emulators that pass some checks almost always fail others, making multi-signal cross-correlation an effective detection strategy.

---

## Injection Side

### How Attackers Use This Technique

1. **Set up emulated environment** — The attacker installs an Android emulator (Genymotion, Nox, MEmu, LDPlayer, or the Android SDK emulator) to create a controlled environment where root access and debugging are freely available.
2. **Configure virtual hardware** — The emulator creates virtual hardware devices that mimic physical hardware. Sensors may be partially emulated or absent entirely. Telephony returns default placeholder values. Battery state is typically fixed.
3. **Install target application** — The attacker installs the target APK in the emulator for analysis, reverse engineering, or running modified versions without risk to a physical device.
4. **Leverage emulator capabilities** — The emulator provides easy root access, memory inspection, network interception, and debugging capabilities that would require additional tools on a physical device.
5. **Attempt to mask emulator identity** — Advanced attackers may use emulator detection bypass tools that hook Build fields and hardware APIs to return realistic values, but achieving full coverage across all signals is challenging.

### Artifacts

| Artifact                     | Location                       | Indicator                                                                                    |
| ---------------------------- | ------------------------------ | -------------------------------------------------------------------------------------------- |
| Missing sensors              | SensorManager.getSensorList()  | Fewer than 3 total sensors, or missing accelerometer / gyroscope / magnetometer              |
| Placeholder telephony data   | TelephonyManager               | Network operator = "Android", SIM operator = "Android", phone type = NONE                    |
| Static battery metrics       | BatteryManager sticky intent   | Level fixed at 50%, always charging, temperature constant at 25.0°C, battery present = false |
| x86-only CPU architecture    | Build.SUPPORTED_ABIS           | Contains only `x86` or `x86_64` without any ARM ABI (`armeabi-v7a`, `arm64-v8a`)             |
| Known emulator build host    | Build.HOST                     | Contains `genymotion`, `buildbot`, `nox`, `memu`, `tiantian`                                 |
| Emulator build fingerprints  | Build.FINGERPRINT, Build.MODEL | Contains `generic`, `sdk`, `google_sdk`, `Emulator`, `Android SDK`                           |
| Virtual hardware identifiers | Build.HARDWARE, Build.BOARD    | Values like `goldfish`, `ranchu`, `vbox86`, `nox`                                            |

### Injection PoC _(optional)_

```pseudocode
// Attacker runs app inside an emulator — default hardware values are visible
// to any code querying the standard Android APIs:

Build.SUPPORTED_ABIS     → ["x86_64", "x86"]     // no ARM ABIs
Build.HOST               → "buildbot.nox.com"     // emulator build host
Build.HARDWARE            → "ranchu"               // QEMU virtual hardware
SensorManager.getSensorList(ALL) → [accelerometer] // only 1 sensor
TelephonyManager.getNetworkOperatorName() → "Android"
BatteryManager: level=50, status=CHARGING, temp=250, present=false
```

### Evasion Techniques

| Evasion                  | Description                                                                                     |
| ------------------------ | ----------------------------------------------------------------------------------------------- |
| Build property spoofing  | Hook `Build` field accesses to return realistic device values (e.g., "Pixel 7", "arm64-v8a") ★★ |
| Sensor emulation         | Inject virtual sensor data with realistic noise patterns and gravity vectors ★★★                |
| Telephony data override  | Hook TelephonyManager to return plausible carrier names and SIM data ★★                         |
| Battery state simulation | Hook BatteryManager to return varying battery levels and temperature over time ★★★              |
| ARM translation layers   | Use emulators with ARM translation (e.g., libhoudini) so SUPPORTED_ABIS includes ARM entries ★★ |
| Custom ROM builds        | Build the emulator image with realistic Build fields matching a specific physical device ★★★★   |

---

## Detection Side

### Mechanism

The invariant is that a physical Android device exhibits consistent real-hardware characteristics across multiple independent data sources: diverse sensor hardware, real cellular network data, dynamic battery behavior, ARM CPU architecture, and legitimate build metadata. An emulated environment produces detectable anomalies in one or more of these areas because perfect virtualization of all hardware subsystems simultaneously is impractical. Each data source is queried independently, and results are cross-correlated to produce a composite confidence score.

### Anti-Evasion Properties

| Property                       | Explanation                                                                                                                                                                    |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Multi-signal cross-correlation | Querying 5+ independent hardware subsystems means an attacker must spoof all of them consistently — missing even one exposes the emulator                                      |
| Physical hardware dependency   | Real sensors produce noisy, time-varying data that is difficult to simulate realistically                                                                                      |
| Build metadata breadth         | Many Build fields (HOST, HARDWARE, BOARD, FINGERPRINT, MODEL) must all be consistent — spoofing some but not others creates detectable inconsistencies                         |
| Dynamic behavior checks        | Battery level and temperature that never change over time indicate static emulation rather than real hardware                                                                  |
| Remaining bypass surface       | High-quality emulators with ARM translation, custom ROM images, and comprehensive API hooking can pass most individual checks; sophisticated multi-signal spoofing tools exist |

### Detection Strategy

1. **Probe sensor hardware** — Query `SensorManager.getSensorList(Sensor.TYPE_ALL)` and count total sensors. Check specifically for `TYPE_ACCELEROMETER`, `TYPE_GYROSCOPE`, and `TYPE_MAGNETIC_FIELD`. Flag if total sensor count is below 3 or if 2+ of the three core motion sensors are missing.
2. **Check telephony data** — Query `TelephonyManager.getNetworkOperatorName()` and `getSimOperatorName()`. Flag if either returns `"Android"` or is empty. Check `getPhoneType()` — flag if it returns `PHONE_TYPE_NONE` on a device that claims to have telephony capability.
3. **Inspect battery state** — Register a receiver for `Intent.ACTION_BATTERY_CHANGED` or query the sticky broadcast. Flag if battery level is exactly 50, temperature is exactly 250 (25.0°C), status is always `BATTERY_STATUS_CHARGING`, or `EXTRA_PRESENT` is false.
4. **Verify CPU architecture** — Read `Build.SUPPORTED_ABIS`. Flag if the array contains only x86/x86_64 entries and no ARM entries (`armeabi-v7a`, `arm64-v8a`).
5. **Scan build metadata** — Check `Build.HOST`, `Build.HARDWARE`, `Build.BOARD`, `Build.FINGERPRINT`, and `Build.MODEL` against known emulator patterns (`goldfish`, `ranchu`, `vbox86`, `nox`, `genymotion`, `generic`, `sdk`, `google_sdk`, `memu`, `tiantian`, `buildbot`).
6. **Cross-correlate signals** — Assign each positive signal a weight. Sum the weights to produce a composite score. Above a threshold, classify the environment as emulated.

### Detection PoC _(optional)_

```pseudocode
score = 0

// Check 1: Sensor count
sensors = sensorManager.getSensorList(Sensor.TYPE_ALL)
if sensors.size() < 3:
    score += 2
core_sensors = [TYPE_ACCELEROMETER, TYPE_GYROSCOPE, TYPE_MAGNETIC_FIELD]
missing = count(s for s in core_sensors if sensorManager.getDefaultSensor(s) == null)
if missing >= 2:
    score += 2

// Check 2: Telephony
operator = telephonyManager.getNetworkOperatorName()
sim_operator = telephonyManager.getSimOperatorName()
if operator == "Android" or operator == "":
    score += 2
if sim_operator == "Android":
    score += 1
if telephonyManager.getPhoneType() == PHONE_TYPE_NONE:
    score += 1

// Check 3: Battery
battery_intent = context.registerReceiver(null, IntentFilter(ACTION_BATTERY_CHANGED))
level = battery_intent.getIntExtra(EXTRA_LEVEL, -1)
temp = battery_intent.getIntExtra(EXTRA_TEMPERATURE, -1)
present = battery_intent.getBooleanExtra(EXTRA_PRESENT, true)
if level == 50 and temp == 250:
    score += 2
if not present:
    score += 2

// Check 4: CPU architecture
abis = Build.SUPPORTED_ABIS
has_arm = any(abi.startsWith("arm") for abi in abis)
if not has_arm:
    score += 3

// Check 5: Build metadata
emulator_patterns = ["goldfish", "ranchu", "vbox86", "nox",
                     "genymotion", "generic", "sdk", "memu",
                     "tiantian", "buildbot", "google_sdk"]
build_fields = [Build.HOST, Build.HARDWARE, Build.BOARD,
                Build.FINGERPRINT, Build.MODEL]
for field in build_fields:
    for pattern in emulator_patterns:
        if field.toLowerCase().contains(pattern):
            score += 1

// Cross-correlation decision
if score >= 5:
    report("emulated environment detected", "score", score)
```

### False Positive Risks

| Scenario                                                          | Mitigation                                                                                                                         |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Low-end physical device with few sensors                          | Use a threshold (e.g., <3 sensors) rather than requiring specific sensors; combine with other signals                              |
| Tablet without telephony hardware                                 | Check `PackageManager.hasSystemFeature(FEATURE_TELEPHONY)` before flagging telephony anomalies                                     |
| Device in airplane mode                                           | Telephony fields should still report the carrier name even in airplane mode; only affects active network state                     |
| x86-based physical devices (e.g., some older Intel-based tablets) | These are extremely rare in modern markets; combine with other signals rather than using as sole indicator                         |
| Custom ROM with non-standard Build fields                         | Cross-correlate with other signals — a custom ROM will still have real sensors and battery behavior                                |
| Device plugged in and fully charged                               | Battery charging status alone is not sufficient; require multiple battery anomalies (level=50, temp=25.0°C, present=false) to flag |

---

## References

- [Android SensorManager API](https://developer.android.com/reference/android/hardware/SensorManager)
- [Android TelephonyManager API](https://developer.android.com/reference/android/telephony/TelephonyManager)
- [Android BatteryManager — monitoring battery state](https://developer.android.com/training/monitoring-device-state/battery-monitoring)
- [Android Build class — device metadata](https://developer.android.com/reference/android/os/Build)
- [QEMU — Android emulator backend (goldfish/ranchu)](https://source.android.com/docs/setup/create/avd)
