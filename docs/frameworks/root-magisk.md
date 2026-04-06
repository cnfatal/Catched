# Root / Magisk

> Root access grants unrestricted superuser privileges to any application, and Magisk is the most widely adopted rooting framework that achieves this while attempting to remain undetectable.

---

## Overview

Rooting an Android device means obtaining superuser (UID 0) access, bypassing the normal permission model enforced by the Linux kernel and Android's security sandbox. Magisk is the dominant rooting solution — it patches the boot image to start a daemon early in the boot process, provides a `su` binary for privilege escalation, and uses Magic Mount (bind mounts) to overlay system modifications without touching the `/system` partition. Because root access can disable every security boundary Android enforces, it is the foundational threat that enables most other injection frameworks.

---

## How It Works

1. **Boot image patching** — The user flashes a modified boot image (or uses the Magisk app to patch it in-place). Magisk inserts its init binary into the ramdisk so it starts before Android's own init.
2. **Daemon startup** — During early boot, `magiskd` (the Magisk daemon) starts, sets up its internal tmpfs workspace, and prepares the `su` binary and Zygisk injection points.
3. **Magic Mount** — Magisk uses bind mounts to overlay modified files and directories onto the original filesystem. This allows system-level changes (adding binaries, modifying properties) without altering the `/system` partition, preserving dm-verity and AVB checks.
4. **su grant** — When an app requests root via the `su` binary, `magiskd` intercepts the request, prompts the user for approval (via the Magisk manager app), and spawns a root shell for the calling process.
5. **Module loading** — Magisk modules (zip packages) can inject arbitrary files into the system overlay, run boot scripts, or load Zygisk modules that execute code inside every app process forked from Zygote.

---

## Variants

| Variant             | Description                                                      |    Root Required    |
| ------------------- | ---------------------------------------------------------------- | :-----------------: |
| Magisk (topjohnwu)  | Original and most widely used rooting solution                   | Yes (provides root) |
| Magisk Alpha        | Development/preview variant with experimental features           | Yes (provides root) |
| KernelSU            | Kernel-based su implementation using a loadable kernel module    | Yes (provides root) |
| APatch              | Android kernel patching approach, similar philosophy to KernelSU | Yes (provides root) |
| SuperSU / Superuser | Legacy rooting solutions, largely obsolete                       | Yes (provides root) |

---

## Artifacts

Persistent evidence this framework leaves that cannot be fully erased:

| Artifact          | Location                                                              | Indicator                                                   |
| ----------------- | --------------------------------------------------------------------- | ----------------------------------------------------------- |
| su binary         | `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/data/local/bin/su` | Existence of the `su` executable in common paths            |
| Magisk daemon     | System property `init.svc.magisk_daemon`                              | Service registered in init service list                     |
| Mount points      | `/proc/self/mountinfo`                                                | Overlay, tmpfs, or bind mounts not present on stock devices |
| OverlayFS entries | `/proc/self/mountinfo`                                                | `upperdir` entries indicating filesystem overlays           |
| Unix socket       | `/proc/net/unix`                                                      | Socket paths containing "magisk"                            |
| Package           | Package manager                                                       | `com.topjohnwu.magisk` or randomized package name variants  |
| SELinux context   | `/proc/self/attr/current`, `/proc/self/attr/prev`                     | Context `u:r:magisk:s0` indicating Magisk SELinux domain    |
| System properties | `getprop`                                                             | `ro.secure=0`, `ro.debuggable=1`, `ro.build.tags=test-keys` |

---

## Evasion Capabilities

Known anti-detection techniques supported by this framework:

| Technique                    | Description                                                                                          |
| ---------------------------- | ---------------------------------------------------------------------------------------------------- |
| MagiskHide / Zygisk DenyList | Unmounts Magisk overlays from a specific app's mount namespace, hiding root artifacts from that app  |
| Package name randomization   | Installs the Magisk manager app with a randomly generated package name to avoid package-based checks |
| Shamiko                      | Zygisk module that aggressively hides root traces by intercepting detection syscalls                 |
| Mount namespace isolation    | Creates isolated mount namespaces for target apps so Magisk mounts are invisible                     |

---

## Techniques Used

| Technique                | Doc                                                                      | Role in This Framework                                                  |
| ------------------------ | ------------------------------------------------------------------------ | ----------------------------------------------------------------------- |
| SVC direct syscall       | [svc-direct-syscall.md](../techniques/svc-direct-syscall.md)             | Bypass libc hooks by invoking `stat`, `access` directly to check for su |
| procfs scanning          | [procfs-scanning.md](../techniques/procfs-scanning.md)                   | Read mountinfo, unix sockets, and SELinux context from `/proc`          |
| Filesystem path check    | [filesystem-path-check.md](../techniques/filesystem-path-check.md)       | Probe well-known su binary paths and Magisk directories                 |
| System property analysis | [system-property-analysis.md](../techniques/system-property-analysis.md) | Check for insecure build properties like `ro.secure=0`                  |
| Package manager scan     | [package-manager-scan.md](../techniques/package-manager-scan.md)         | Detect Magisk manager package (including randomized names)              |
