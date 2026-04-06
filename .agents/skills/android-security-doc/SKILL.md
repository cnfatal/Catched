---
name: android-security-doc
description: "Write or update Android security detection documentation for the Catched project. Use when: creating docs for a new injection type (Root, Xposed, Frida, NPatch, Debugger, Emulator); documenting a new detection technique (SVC syscall, procfs scan, reflection, memory scan, network probe, ArtMethod, GOT/PLT); adding entries to docs/; following the project doc template. Triggers on: 'add doc', 'document detection', 'write injection doc', 'detection template', 'docs/'"
---

# Android Security Documentation

## Structure

Two layers under `docs/`:

| Layer               | Path                        | Template                                                |
| ------------------- | --------------------------- | ------------------------------------------------------- |
| Framework overview  | `docs/frameworks/<name>.md` | [framework-template.md](./assets/framework-template.md) |
| Technique deep-dive | `docs/techniques/<name>.md` | [technique-template.md](./assets/technique-template.md) |

Framework docs group techniques by attack framework (Root, Xposed, Frida, NPatch, Debugger, Emulator).  
Technique docs cover **both the injection side and the detection side** for one technique.

## Procedure

1. Choose the correct layer (framework overview vs. technique deep-dive).
2. For a **technique doc**: copy [technique-template.md](./assets/technique-template.md) and fill every section.
3. For a **framework overview**: copy [framework-template.md](./assets/framework-template.md); link to all relevant technique docs.
4. Use bypass-difficulty scale ★ (trivial) → ★★★★★ (very hard) consistently.

## Style Rules

- Language: **English**
- Code blocks: include language tag (`kotlin`, `c`, `bash`)
- Headings: H1 title · H2 sections · H3 subsections
- Prefer tables over bullet lists for structured data
