# [Technique Name]

> One-sentence summary of what this technique is.

---

## Overview

3–5 sentences covering:

- What the technique does at a low level (kernel, ART, dynamic linker, procfs, etc.)
- Why it matters from a defender's perspective

---

## Injection Side

### How Attackers Use This Technique

Step-by-step description of how an attacker employs this technique:

1. **Step 1** — ...
2. **Step 2** — ...

### Artifacts

Forensic evidence this technique leaves that cannot be fully erased:

| Artifact        | Location               | Indicator                         |
| --------------- | ---------------------- | --------------------------------- |
| Binary / SO     | `/path/to/file`        | File name or path pattern         |
| Memory mapping  | `/proc/self/maps`      | Library name or anonymous segment |
| Mount entry     | `/proc/mounts`         | Keyword (e.g., `magisk`)          |
| Socket          | `/proc/net/unix`       | Socket name pattern               |
| Directory       | `/data/data/<pkg>/...` | Characteristic path               |
| System property | `ro.xxx`               | Unexpected value                  |

### Injection PoC _(optional)_

```pseudocode
// Pseudo-code illustrating how an attacker deploys this technique
// (not real exploit code — describe the logic only)

step_1: ...
step_2: ...
```

### Evasion Techniques

| Evasion   | Description |
| --------- | ----------- |
| Evasion A | ...         |
| Evasion B | ...         |

---

## Detection Side

### Mechanism

What observable invariant is checked, and why it holds for clean environments but breaks under this technique.

### Anti-Evasion Properties

| Property                    | Explanation |
| --------------------------- | ----------- |
| Resistant to libc hooks     | ...         |
| Resistant to GOT/PLT hijack | ...         |
| SVC bypass benefit          | ...         |
| Remaining bypass surface    | ...         |

### Detection Strategy

Describe the detection approach (e.g., what data source to read, what pattern to search for, what comparison to perform) without referencing app-specific implementation:

1. **Step 1** — ...
2. **Step 2** — ...

### Detection PoC _(optional)_

```pseudocode
// Pseudo-code illustrating the detection logic
// (language-agnostic; focus on the algorithm, not the implementation)

data_source = read("/proc/self/maps")  // or any relevant source
for each line in data_source:
    if matches(line, SUSPICIOUS_PATTERN):
        return DETECTED
return CLEAN
```

### False Positive Risks

| Scenario | Mitigation |
| -------- | ---------- |
| ...      | ...        |

---

## References

- [External write-up or CVE](#)
