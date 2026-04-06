# Filesystem Path Check

> Detects compromise indicators by probing whether specific files, directories, or device nodes exist on disk that should not be present on a clean device.

---

## Overview

Filesystem path checking is a straightforward but effective detection technique that tests for the existence of known indicator files, directories, device nodes, and APK artifacts on the Android filesystem. Attack tools, root management solutions, hook frameworks, and emulators all leave characteristic filesystem footprints — binary files dropped into system directories, cache directories created for module storage, backup copies of replaced system binaries, and virtual device nodes exposed by hypervisors. These paths are well-documented and relatively stable across versions of attack tools, making filesystem probing a reliable first-pass detection method.

From a defender's perspective, filesystem path checks provide broad coverage with minimal complexity. While sophisticated attackers can hide individual files by hooking `access()` or `stat()`, combining SVC-based file existence checks with multiple path categories (su binaries, agent files, cache directories, device nodes, APK metadata) creates a high-confidence detection signal that is difficult to evade completely.

---

## Injection Side

### How Attackers Use This Technique

1. **Drop privileged binaries** — Root management tools install `su` binaries into well-known system paths (`/system/bin/su`, `/system/xbin/su`, `/sbin/su`, etc.) to provide privilege escalation to apps.
2. **Deploy agent servers** — Debugging agents are placed as server binaries in writable locations like `/data/local/tmp/` or occasionally in system paths.
3. **Create cache directories** — Repackaging tools create directories under the app's data directory (e.g., `cache/npatch/`, `cache/lspatch/`) to store modified dex files, native libraries, and configuration.
4. **Back up replaced binaries** — Injection frameworks that replace `app_process` create backup copies with `.orig` extension (e.g., `/system/bin/app_process.orig`).
5. **Expose virtual device nodes** — Emulators expose hypervisor-specific device nodes (`/dev/qemu_pipe`, `/dev/vboxguest`, etc.) that do not exist on physical hardware.
6. **Relocate APK files** — Repackaging tools copy and modify the APK to a cache directory, causing `ApplicationInfo.sourceDir` to point to an unexpected path.
7. **Inject assets** — Repackaging tools add asset directories (e.g., `assets/npatch/`, `assets/lspatch/`) into the APK.

### Artifacts

| Artifact                     | Location                                                                                                                                                                                                                                                                                 | Indicator                                                                            |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| su binary                    | `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/data/local/bin/su`, `/data/local/xbin/su`, `/system/sd/xbin/su`, `/data/local/su`, `/su/bin/su`, `/data/adb/su`, `/system/app/Superuser.apk`, `/system/etc/.installed_su_daemon`, `/system/usr/we-need-root/`, `/cache/su`, `/dev/su` | File existence                                                                       |
| Agent server binary          | `/data/local/tmp/frida-server*`, `/system/bin/frida-server`                                                                                                                                                                                                                              | File existence with agent name in filename                                           |
| Repackage cache directory    | `$dataDir/cache/npatch/`, `$dataDir/cache/lspatch/`                                                                                                                                                                                                                                      | Directory existence                                                                  |
| Backup app_process           | `/system/bin/app_process.orig`, `/system/bin/app_process32.orig`, `/system/bin/app_process64.orig`                                                                                                                                                                                       | File existence with `.orig` extension                                                |
| Emulator device node         | `/dev/qemu_pipe`, `/dev/socket/qemud`, `/dev/vboxguest`, `/dev/vboxuser`                                                                                                                                                                                                                 | Device node existence                                                                |
| Injected APK assets          | `assets/npatch/`, `assets/lspatch/`                                                                                                                                                                                                                                                      | Asset directory enumerable via AssetManager                                          |
| Relocated APK                | `ApplicationInfo.sourceDir` pointing to cache directory                                                                                                                                                                                                                                  | Path prefix mismatch with expected install location                                  |
| SUID bit on binary           | Any su path                                                                                                                                                                                                                                                                              | `stat()` returns SUID bit set (mode & 04000)                                         |
| Modified profile permissions | App profile file                                                                                                                                                                                                                                                                         | File is read-only when it should be writable (repackaging tool modifies permissions) |

### Injection PoC _(optional)_

```pseudocode
// Root tool installs su binary
step_1: remount /system as read-write
step_2: copy su binary to /system/xbin/su
step_3: chmod 6755 /system/xbin/su  // set SUID + SGID
step_4: remount /system as read-only

// Repackaging tool creates cache directory
step_1: create directory $dataDir/cache/npatch/
step_2: extract modified dex files into cache/npatch/
step_3: modify ApplicationInfo.sourceDir to point to cache/npatch/base.apk
```

### Evasion Techniques

| Evasion                        | Description                                                                            |
| ------------------------------ | -------------------------------------------------------------------------------------- |
| Hook access()/stat()           | Intercept libc file existence checks to return ENOENT for known paths                  |
| Path randomization             | Place binaries in randomized directory names instead of well-known paths               |
| Unmount before check           | Remove bind mounts or overlay entries before detection code runs, remount after        |
| Use app_process without backup | Some injection methods modify `app_process` in-memory without creating `.orig` backups |
| Hide device nodes              | Emulators can configure pass-through to not expose certain `/dev/` entries             |

---

## Detection Side

### Mechanism

The invariant is that clean, unrooted, non-emulated Android devices do not contain `su` binaries in system directories, do not have debugging agent files in `/data/local/tmp/`, do not expose hypervisor device nodes, and do not have repackaging cache directories. The presence of any of these paths indicates that the device or app has been tampered with. Since these are on-disk filesystem objects tracked by the kernel's VFS layer, their existence can be verified via direct kernel syscalls (`faccessat`, `newfstatat`) that bypass userspace hiding mechanisms.

### Anti-Evasion Properties

| Property                    | Explanation                                                                                                                 |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Resistant to libc hooks     | Using SVC-wrapped `faccessat` and `newfstatat` bypasses hooked `access()` and `stat()` functions                            |
| Resistant to GOT/PLT hijack | SVC calls do not use PLT resolution                                                                                         |
| Multi-path redundancy       | Checking 14+ su paths, multiple emulator device nodes, and multiple cache directories means attackers must hide all of them |
| SUID bit detection          | `stat()` returns file mode bits from the kernel inode; SUID detection catches su binaries even if renamed                   |
| Remaining bypass surface    | Kernel-level hooks can fake stat/access results; attackers can use non-standard paths; MagiskHide can unmount before checks |

### Detection Strategy

1. **Enumerate all known indicator paths** — Maintain a list of paths categorized by type: su binaries, agent server files, cache directories, backup binaries, emulator device nodes.
2. **Check existence via SVC faccessat** — For each path, call `svc_faccessat(AT_FDCWD, path, F_OK, 0)`. If the return value is 0, the path exists.
3. **Check SUID bit via SVC newfstatat** — For su binary paths that exist, call `svc_newfstatat()` and inspect the `st_mode` field for the SUID bit (04000). A SUID binary in a system directory is a strong root indicator.
4. **Check APK assets via AssetManager** — Use `AssetManager.list("npatch")` and `AssetManager.list("lspatch")` from Java to detect injected asset directories.
5. **Verify ApplicationInfo.sourceDir** — Read `context.applicationInfo.sourceDir` and verify it matches the expected install path (`/data/app/<package>/base.apk`). If it points to a cache directory, the APK has been relocated by a repackaging tool.
6. **Check profile file permissions** — Stat the app's profile file and verify it is writable. If read-only, a repackaging tool may have modified its permissions.
7. **Cross-reference with other signals** — Combine filesystem path results with procfs scanning and reflection-based checks for higher confidence.

### Detection PoC _(optional)_

```pseudocode
// Check su binary existence via SVC
su_paths = [
    "/system/bin/su", "/system/xbin/su", "/sbin/su",
    "/data/local/bin/su", "/data/local/xbin/su",
    "/system/sd/xbin/su", "/data/local/su", "/su/bin/su",
    "/data/adb/su", "/cache/su", "/dev/su",
    "/system/app/Superuser.apk",
    "/system/etc/.installed_su_daemon",
    "/system/usr/we-need-root/"
]

for path in su_paths:
    result = svc_faccessat(AT_FDCWD, path, F_OK, 0)
    if result == 0:
        flag("su_binary_found", path)
        // Additional SUID check
        stat_buf = svc_newfstatat(AT_FDCWD, path, 0)
        if stat_buf.st_mode & 0o4000:
            flag("suid_su_binary", path)

// Check emulator device nodes
emu_paths = ["/dev/qemu_pipe", "/dev/socket/qemud",
             "/dev/vboxguest", "/dev/vboxuser"]
for path in emu_paths:
    if svc_faccessat(AT_FDCWD, path, F_OK, 0) == 0:
        flag("emulator_device", path)

// Check repackage cache directories
cache_dirs = [dataDir + "/cache/npatch/", dataDir + "/cache/lspatch/"]
for path in cache_dirs:
    if svc_faccessat(AT_FDCWD, path, F_OK, 0) == 0:
        flag("repackage_cache", path)
```

### False Positive Risks

| Scenario                                                    | Mitigation                                                                                                    |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Custom ROMs that ship with su binary pre-installed          | Combine su path detection with process-level checks (is su actually functional?) and mount analysis           |
| Development devices with adb root enabled                   | Check `ro.debuggable` and `ro.secure` properties; suppress warnings in development contexts                   |
| Emulator paths present on some MediaTek devices             | Maintain a device-model whitelist for known false-positive `/dev/` entries                                    |
| AssetManager.list() returning assets from bundled libraries | Verify suspicious asset directories contain specific indicator files, not just the directory name             |
| Cached APK paths during system updates                      | Verify that the sourceDir path prefix matches known repackage cache patterns, not generic system update cache |

---

## References

- [Android filesystem layout](https://source.android.com/docs/core/architecture/partitions)
- [Linux faccessat(2) man page](https://man7.org/linux/man-pages/man2/faccessat.2.html)
- [Linux fstatat(2) man page](https://man7.org/linux/man-pages/man2/fstatat.2.html)
- [Android ApplicationInfo documentation](https://developer.android.com/reference/android/content/pm/ApplicationInfo)
