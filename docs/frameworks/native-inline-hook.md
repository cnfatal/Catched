# Native Inline Hook Frameworks

> Native inline hook frameworks directly patch machine code instructions at function entry points to redirect execution, enabling interception of both native C/C++ functions and ART-compiled Java method code without modifying ART runtime structures.

---

## Overview

Native inline hook frameworks (Dobby, ShadowHook, android-inline-hook) operate at the machine code level, overwriting function prologues with branch instructions that redirect execution to attacker-controlled trampolines. Unlike Xposed/LSPosed which modify ArtMethod structures, these tools patch the actual executable bytes, making them invisible to ArtMethod field inspection. They can hook any native function (libc, libart, app SOs) and, critically, can also hook the compiled output of Java methods (AOT/JIT code) by treating the compiled code as ordinary machine code. They do not require root when injected via APK repackaging.

---

## How It Works

1. **Library injection** — The hook engine SO is loaded into the target process (via repackaging with `System.loadLibrary`, Zygisk module, or ptrace injection).
2. **Symbol resolution** — Target function address is resolved via `dlsym()`, ELF symbol parsing, or for Java methods, reading `ArtMethod.entry_point_from_quick_compiled_code_`.
3. **Prologue backup** — Original instructions at the function entry (4–20 bytes depending on architecture and tool) are copied to a "trampoline island".
4. **PC-relative fixup** — Backed-up instructions containing PC-relative references (`ADRP`, `ADR`, `LDR` literal, `B.cond`, etc.) are patched to account for their new address.
5. **Prologue overwrite** — Entry point is overwritten with a branch to attacker's handler (requires `mprotect` to make page writable).
6. **Cache flush** — `__builtin___clear_cache()` ensures the instruction cache sees the new code.
7. **Handler execution** — When the target function is called, CPU executes the branch to handler. Handler can inspect/modify arguments, call the original via relocated prologue, and modify return values.
8. **For Java methods** — Additional ART preparation: set `kAccCompileDontBother` to prevent JIT recompilation, clear `kAccFastInterpreterToInterpreterInvoke`, ensure method is already compiled (AOT via `cmd package compile -m speed` or trigger JIT).

---

## Variants

| Variant                             | Description                                                                                                                                                                                                             |   Root Required    |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------: |
| **Dobby** (jmpews)                  | Full-featured inline hook supporting ARM64/ARM32/x86_64. Uses 12–16 byte prologue overwrite. Allocates anonymous RWX pages for trampolines. Most widely used.                                                           | No (if repackaged) |
| **ShadowHook** (ByteDance)          | Optimized for Android. Uses single 4-byte `B` instruction (±128MB) when possible. Exploits ELF LOAD segment gaps for trampoline placement (no anonymous pages). Supports shared-mode (multiple hooks on same function). | No (if repackaged) |
| **android-inline-hook** (ByteDance) | Lightweight alternative to ShadowHook. ARM64-focused. Uses X17 register for trampolines.                                                                                                                                | No (if repackaged) |
| **Substrate/MSHookFunction**        | Legacy iOS/Android hooking framework. Uses `LDR PC` patterns on ARM32. Declining usage on Android.                                                                                                                      |   Typically Yes    |
| **Java method code patching**       | Not a framework but a technique: use any of the above to hook the machine code that ART compiled from a Java method. Requires ART-level preparation (`access_flags`, ensure compilation).                               | No (if repackaged) |

---

## Artifacts

Persistent evidence this framework leaves that cannot be fully erased:

| Artifact                | Location                                | Indicator                                                                                            |
| ----------------------- | --------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Modified prologue       | Target function `.text` segment         | First 4–20 bytes differ from on-disk ELF                                                             |
| Trampoline memory       | Anonymous mmap `rwxp`/`r-xp` or ELF gap | Executable code at non-standard addresses                                                            |
| Hook engine SO          | `/proc/self/maps`                       | `libdobby.so`, `libshadowhook.so`, `libandroid-inline-hook.so` (or statically linked — no signature) |
| Relocated original code | Near trampoline                         | Backed-up prologue with PC-relative fixups                                                           |
| access_flags anomaly    | ArtMethod structure                     | `kAccCompileDontBother` (`0x02000000`) set on Java methods that shouldn't have it                    |
| mprotect syscall        | Syscall audit                           | `mprotect(addr, len, PROT_READ\|PROT_WRITE\|PROT_EXEC)` on `.text` pages                             |
| STP X16,X17 pattern     | Non-function-entry hook                 | ShadowHook pushes scratch registers before branch                                                    |

---

## Evasion Capabilities

Known anti-detection techniques supported by this framework:

| Technique                  | Description                                                                                            |
| -------------------------- | ------------------------------------------------------------------------------------------------------ |
| Static linking             | Embed Dobby/ShadowHook into main SO — eliminates library name from maps                                |
| Pre-reserved `.text` slots | Compile trampoline slots (`__attribute__((section(".text")))`) into SO — no anonymous executable pages |
| ELF gap usage (ShadowHook) | Use LOAD segment padding for trampolines — no new memory mappings                                      |
| JIT Code Cache injection   | Place trampoline in ART's JIT Code Cache free space — blends with legitimate JIT code                  |
| Immediate RX restore       | `mprotect` back to `r-xp` immediately after write — no persistent RWX pages                            |
| Library name obfuscation   | Rename/strip SO name or statically link                                                                |
| Forced AOT compilation     | `cmd package compile -m speed` eliminates need for JIT-related ART hooks                               |
| BTI bypass                 | Use `RET Xn` instead of `BR Xn` to evade hardware Branch Target Identification                         |

---

## Techniques Used

| Technique                   | Doc                                                                            | Role in Detection                                               |
| --------------------------- | ------------------------------------------------------------------------------ | --------------------------------------------------------------- |
| Inline Code Patching        | [inline-code-patching.md](../techniques/inline-code-patching.md)               | Detect prologue overwrites via pattern matching                 |
| Memory Pattern Scan         | [memory-pattern-scan.md](../techniques/memory-pattern-scan.md)                 | Find trampoline byte signatures in anonymous memory             |
| Procfs Scanning             | [procfs-scanning.md](../techniques/procfs-scanning.md)                         | Detect anonymous executable pages and hook engine SO names      |
| Code Integrity Verification | [code-integrity-verification.md](../techniques/code-integrity-verification.md) | Compare `.text` disk bytes vs memory bytes                      |
| GOT/PLT Hook Detection      | [got-plt-hook.md](../techniques/got-plt-hook.md)                               | Detect inline hooks on GOT-resolved functions                   |
| ArtMethod Introspection     | [artmethod-introspection.md](../techniques/artmethod-introspection.md)         | Detect `kAccCompileDontBother` flag on Java methods             |
| ELF Segment Gap Analysis    | [elf-segment-gap-analysis.md](../techniques/elf-segment-gap-analysis.md)       | Detect trampolines hidden in LOAD segment padding               |
| Signal Handler Inspection   | [signal-handler-inspection.md](../techniques/signal-handler-inspection.md)     | Detect SIGSEGV handlers used for safe hooking                   |
| Return Address Validation   | [return-address-validation.md](../techniques/return-address-validation.md)     | Detect trampoline return addresses outside module `.text` range |
