# [Framework Name] — e.g., Frida

> One-sentence summary of what this framework is and the threat it poses.

---

## Overview

2–4 sentences: what the framework does, whether it requires Root, and what Android subsystems it targets.

---

## How It Works

Step-by-step description of the attack lifecycle — from initial deployment to code execution inside the target process.

1. **Step 1** — ...
2. **Step 2** — ...
3. **Step N** — ...

---

## Variants

| Variant   | Description | Root Required |
| --------- | ----------- | :-----------: |
| Variant A | ...         |   Yes / No    |
| Variant B | ...         |   Yes / No    |

---

## Artifacts

Persistent evidence this framework leaves that cannot be fully erased:

| Artifact        | Location               | Indicator                         |
| --------------- | ---------------------- | --------------------------------- |
| Binary / SO     | `/path/to/file`        | File name or path pattern         |
| Memory mapping  | `/proc/self/maps`      | Library name or anonymous segment |
| Network socket  | TCP port / Unix socket | Port number or socket name        |
| Filesystem path | `/data/...`            | Characteristic directory or file  |

---

## Evasion Capabilities

Known anti-detection techniques supported by this framework:

| Technique | Description |
| --------- | ----------- |
| ...       | ...         |

---

## Techniques Used

| Technique       | Doc                                                    | Role in This Framework                   |
| --------------- | ------------------------------------------------------ | ---------------------------------------- |
| procfs scanning | [procfs-scanning.md](../techniques/procfs-scanning.md) | Detect injected SO via `/proc/self/maps` |
| network probe   | [network-probe.md](../techniques/network-probe.md)     | Detect frida-server TCP port             |
