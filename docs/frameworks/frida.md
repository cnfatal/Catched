# Frida

> Frida is a dynamic instrumentation toolkit that injects a JavaScript runtime into target processes, enabling real-time hooking, tracing, and modification of any native or managed function.

---

## Overview

Frida is a cross-platform dynamic instrumentation framework widely used for reverse engineering, security research, and runtime manipulation of Android applications. In its most common deployment, a `frida-server` daemon runs as root on the device and injects a shared-library agent into target processes via `ptrace`. The agent embeds a JavaScript engine (V8 or Duktape) that exposes a rich API for intercepting function calls, reading/writing memory, and modifying program behavior — all without recompilation or APK modification.

---

## How It Works

1. **Server deployment** — The operator pushes `frida-server` to the device (typically `/data/local/tmp/`) and starts it as root. The server binds to TCP port 27042 on the loopback interface.
2. **Client connection** — A Frida client on the host machine connects to the server over USB (forwarded) or over the network.
3. **Process attachment** — The server attaches to the target process using `ptrace` (or spawns the process and suspends it before execution). For spawn mode, Frida intercepts the process before `onCreate` runs.
4. **Agent injection** — Frida injects `frida-agent.so` (a shared library) into the target process address space. The agent bootstraps a JavaScript engine and establishes a D-Bus IPC channel back to the server.
5. **Script execution** — The client sends JavaScript scripts to the in-process agent. The `Interceptor` API hooks native functions, the `Java.perform` API hooks Java methods, and the `Memory` API reads/writes arbitrary addresses.
6. **Ongoing control** — The client maintains a persistent session, allowing dynamic script loading, REPL interaction, and real-time tracing until the session is detached or the process exits.

---

## Variants

| Variant      | Description                                                         | Root Required |
| ------------ | ------------------------------------------------------------------- | :-----------: |
| frida-server | Standalone daemon running on-device, attaches via ptrace            |      Yes      |
| frida-gadget | Shared library bundled into the target APK, self-loads on startup   |      No       |
| frida-inject | CLI tool that injects the agent into a running process via ptrace   |      Yes      |
| frida-portal | Network-based relay that allows remote Frida access across machines |      Yes      |

---

## Artifacts

Persistent evidence this framework leaves that cannot be fully erased:

| Artifact           | Location                 | Indicator                                                          |
| ------------------ | ------------------------ | ------------------------------------------------------------------ |
| TCP listening port | Network stack            | Ports 27042 and 27043 listening on loopback (0.0.0.0 or 127.0.0.1) |
| Memory maps        | `/proc/self/maps`        | `frida-agent-*.so`, `frida-gadget*.so`, `re.frida.server` entries  |
| Memory strings     | Anonymous memory regions | "LIBFRIDA", "frida:rpc", "frida-agent", "gum-js-loop", "gmain"     |
| Named pipes        | `/proc/self/fd`          | File descriptors linking to `linjector-*` named pipes              |
| Thread names       | `/proc/self/task/*/comm` | Threads named "gmain", "gdbus", "gum-js-loop", "frida-\*"          |
| D-Bus protocol     | Injected agent IPC       | Responds to D-Bus `AUTH` handshake with `REJECTED` or `OK`         |
| Filesystem         | `/data/local/tmp/`       | `frida-server`, `re.frida.server` binaries on disk                 |
| TracerPid          | `/proc/self/status`      | Non-zero `TracerPid` when attached via ptrace                      |

---

## Evasion Capabilities

Known anti-detection techniques supported by this framework:

| Technique                  | Description                                                                                 |
| -------------------------- | ------------------------------------------------------------------------------------------- |
| Custom port binding        | Configuring frida-server to listen on a non-default port instead of 27042                   |
| frida-gadget mode          | Embedding as a shared library removes the need for frida-server and ptrace attachment       |
| Memory string obfuscation  | Compiling Frida from source with modified string constants to avoid pattern-based detection |
| Library name randomization | Renaming `frida-agent.so` and `frida-gadget.so` to arbitrary names before injection         |
| Port rebinding             | Closing and reopening the listening port to evade point-in-time port scans                  |
| Thread name spoofing       | Renaming characteristic thread names ("gmain", "gum-js-loop") to generic names              |

---

## Techniques Used

| Technique             | Doc                                                                | Role in This Framework                                                   |
| --------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| SVC direct syscall    | [svc-direct-syscall.md](../techniques/svc-direct-syscall.md)       | Bypass libc hooks placed by Frida to read `/proc` files directly         |
| procfs scanning       | [procfs-scanning.md](../techniques/procfs-scanning.md)             | Scan maps, status (TracerPid), task/comm, and fd for Frida artifacts     |
| Network probe         | [network-probe.md](../techniques/network-probe.md)                 | Connect to port 27042 and perform D-Bus AUTH handshake detection         |
| Memory pattern scan   | [memory-pattern-scan.md](../techniques/memory-pattern-scan.md)     | Search anonymous memory for "LIBFRIDA", "frida:rpc" and other signatures |
| Filesystem path check | [filesystem-path-check.md](../techniques/filesystem-path-check.md) | Check `/data/local/tmp/` for frida-server binaries                       |
