# Debugger

> Debuggers and tracing tools attach to a running Android process to inspect memory, set breakpoints, modify variables, and step through code — enabling full dynamic analysis of an application.

---

## Overview

Debuggers exploit the standard debugging interfaces built into Android: JDWP (Java Debug Wire Protocol) for Java/Kotlin code and `ptrace` for native code. When an application is marked as `android:debuggable=true` in its manifest, or when the device has developer mode and USB debugging enabled, an attacker can attach a debugger without any device modification. Native debuggers typically require root access to attach via `ptrace` to arbitrary processes. Once attached, the debugger has full control over execution flow, memory, and register state.

---

## How It Works

1. **Enable developer access** — The attacker enables Developer Options and USB Debugging (ADB) on the target device, or sets up ADB over WiFi for remote access.
2. **Identify the target process** — Using `adb shell ps` or `adb jdwp`, the attacker locates the target application's PID or identifies JDWP-enabled processes.
3. **Attach to the process** — For Java-level debugging, a JDWP client (Android Studio, `jdb`) connects through ADB port forwarding. For native debugging, `lldb` or `gdb` attaches via `ptrace` (requires root or a debuggable process).
4. **Intercept execution** — The debugger sets breakpoints at strategic points (e.g., license checks, certificate pinning, authentication routines), halting execution when those points are reached.
5. **Inspect and modify state** — While paused, the debugger reads and modifies local variables, object fields, registers, and memory. The attacker can alter return values, skip function calls, or inject method invocations.
6. **Resume and repeat** — Execution resumes, and the attacker continues stepping through code or running to the next breakpoint until the analysis objective is achieved.

---

## Variants

| Variant                               | Description                                                               | Root Required |
| ------------------------------------- | ------------------------------------------------------------------------- | :-----------: |
| JDWP debugger (Android Studio, jdb)   | Java/Kotlin-level debugging via the JDWP protocol                         |      No       |
| Native debugger (lldb, gdb)           | Native code debugging via ptrace, inspects ARM/x86 instructions directly  |      Yes      |
| ptrace-based tracers (strace, ltrace) | Trace system calls and library calls for behavioral analysis              |      Yes      |
| ADB WiFi debugging                    | Remote debugging over the network without a USB cable                     |      No       |
| Frida (ptrace attach mode)            | Dynamic instrumentation via ptrace, also covered in its own framework doc |      Yes      |

---

## Artifacts

Persistent evidence this framework leaves that cannot be fully erased:

| Artifact                  | Location                | Indicator                                                |
| ------------------------- | ----------------------- | -------------------------------------------------------- |
| TracerPid                 | `/proc/self/status`     | Non-zero `TracerPid` field indicates ptrace attachment   |
| JDWP connection           | Runtime state           | `Debug.isDebuggerConnected()` returns `true`             |
| ADB enabled               | `Settings.Global`       | `ADB_ENABLED = 1`                                        |
| WiFi ADB enabled          | `Settings.Global`       | `adb_wifi_enabled = 1`                                   |
| Developer options enabled | `Settings.Global`       | `DEVELOPMENT_SETTINGS_ENABLED = 1`                       |
| Debuggable flag           | `ApplicationInfo.flags` | `FLAG_DEBUGGABLE` bit set in the application manifest    |
| USB connection            | `UsbManager`            | Attached USB accessories or host devices detected        |
| ro.debuggable             | System properties       | Value `1` indicates system-wide debug capability enabled |

---

## Evasion Capabilities

Known anti-detection techniques supported by this framework:

| Technique              | Description                                                                                       |
| ---------------------- | ------------------------------------------------------------------------------------------------- |
| Immediate detach       | Some tools attach, read state, and detach before periodic anti-debug checks can detect attachment |
| Process spawning       | Launch the app under debugger control before anti-debug initialization code runs                  |
| JDWP via ro.debuggable | Set `ro.debuggable=1` system property (requires root) to debug apps without manifest modification |
| Timing evasion         | Slow-step through anti-debug code to avoid timing-based detection                                 |

---

## Techniques Used

| Technique                | Doc                                                                      | Role in This Framework                                                   |
| ------------------------ | ------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| procfs scanning          | [procfs-scanning.md](../techniques/procfs-scanning.md)                   | Read `/proc/self/status` to detect non-zero TracerPid from ptrace attach |
| Java reflection          | [java-reflection.md](../techniques/java-reflection.md)                   | Call `Debug.isDebuggerConnected()` and check `ApplicationInfo.flags`     |
| System property analysis | [system-property-analysis.md](../techniques/system-property-analysis.md) | Inspect `ro.debuggable`, `ro.secure`, and developer settings values      |
