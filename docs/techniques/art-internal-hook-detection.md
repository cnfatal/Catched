# ART Internal Function Hook Detection

> Detects inline hooks placed on ART runtime internal functions within `libart.so` that hooking frameworks require to operate correctly.

---

## Overview

Java method hooking frameworks like LSPlant/LSPosed must hook several internal ART runtime C++ functions inside `libart.so` to prevent the runtime from interfering with their hooks. These internal hook targets are well-known and finite — the set of functions that need hooking is constrained by ART's architecture that governs method dispatch, JIT compilation, and class initialization. Checking the prologue integrity of these functions reveals the presence of a hooking framework with high confidence.

This technique is distinct from ArtMethod field introspection (covered in [artmethod-introspection.md](artmethod-introspection.md)) — here we examine the **native code** of ART's own C++ functions rather than Java-level method metadata. Because these functions reside in a system library that should never be modified at runtime, any prologue modification constitutes strong evidence of an active hooking framework.

---

## Injection Side

### How Attackers Use This Technique

1. **Resolve ART internal function addresses** — The framework parses `libart.so`'s ELF symbol table (e.g., LSPlant's `ElfImg` or SandHook's symbol resolver) to locate specific C++ function addresses by their mangled names.
2. **Install inline hooks on ART functions** — Using an inline hook engine (Dobby, ShadowHook, or android-inline-hook), the framework patches the prologue of each target function with a branch instruction pointing to a replacement implementation.
3. **Override ART behavior** — The replacement functions intercept ART's method dispatch, JIT compilation, class initialization, and instrumentation logic to ensure hooked Java methods remain hooked across runtime events (GC, JIT recompilation, class re-initialization).
4. **Maintain framework control** — With these internal hooks in place, the framework can safely replace `ArtMethod` entry points without the runtime reverting them, enabling persistent Java method hooking.

### Artifacts

| Artifact                   | Location                    | Indicator                                                                |
| -------------------------- | --------------------------- | ------------------------------------------------------------------------ |
| Patched prologue           | `libart.so` `.text` section | First 4–16 bytes of target function differ from on-disk content          |
| Trampoline code            | Anonymous memory or ELF gap | Branch target of patched prologue resides in non-file-backed memory      |
| Symbol resolution traces   | Injected SO `.data`/`.bss`  | Resolved symbol addresses cached in attacker framework's data structures |
| ElfImg patterns            | Injected SO `.data`         | Stored copies of `/system/lib64/libart.so` symbol table or section data  |
| Transient writable `.text` | `/proc/self/maps`           | Brief `rwxp` permission on `libart.so` code page during patching         |

### Known ART Internal Hook Targets (LSPlant/LSPosed)

| Hook Target                          | Symbol (mangled)                                                                        | Why Needed                                                                         |
| ------------------------------------ | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `ShouldUseInterpreterEntrypoint`     | `_ZN3art11ClassLinker30ShouldUseInterpreterEntrypointEPNS_9ArtMethodEPKv`               | Prevents ART from detecting modified `entry_point` and falling back to interpreter |
| `FixupStaticTrampolines`             | `_ZN3art11ClassLinker22FixupStaticTrampolinesEPNS_6mirror5ClassE` (varies by API level) | Prevents class initialization from overwriting hooked entry points                 |
| `Class::SetStatus`                   | `_ZN3art6mirror5Class9SetStatusENS_7Handle...` (varies)                                 | Works with `FixupStaticTrampolines` to survive class initialization                |
| `ArtMethod::RegisterNative`          | `_ZN3art9ArtMethod14RegisterNativeEPKvb`                                                | Handles native method registration for backup methods                              |
| `ArtMethod::UnregisterNative`        | `_ZN3art9ArtMethod16UnregisterNativeEv`                                                 | Paired with `RegisterNative` for clean backup method management                    |
| `Instrumentation::UpdateMethodsCode` | `_ZN3art15instrumentation15Instrumentation17UpdateMethodsCodeEPNS_9ArtMethodEPKv`       | Prevents instrumentation subsystem from overwriting patched code                   |
| `Jit::EnqueueOptimizedCompilation`   | `_ZN3art3jit3Jit27EnqueueOptimizedCompilationEPNS_9ArtMethodEPNS_6ThreadE`              | Prevents JIT from recompiling hooked methods with original code                    |
| `JitCodeCache::GarbageCollectCache`  | `_ZN3art3jit12JitCodeCache19GarbageCollectCacheEPNS_6ThreadE`                           | Prevents JIT GC from reclaiming patched code regions                               |
| `ProcessProfilingInfo`               | ART internal (symbol varies)                                                            | Skips JIT profile saving to avoid crashes on modified methods                      |
| `RunBackgroundVerification`          | ART internal (symbol varies)                                                            | Disables OAT background verification that could conflict with hooks                |

### Evasion Techniques

| Evasion                | Description                                                                                                                                              | Bypass Difficulty |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| Forced AOT compilation | `cmd package compile -m speed` eliminates need for JIT-related hooks (`EnqueueOptimizedCompilation`, `GarbageCollectCache`), reducing the hook footprint | ★★★               |
| Reduced hook set       | Only hook the absolute minimum functions (`ShouldUseInterpreterEntrypoint` + `FixupStaticTrampolines`), leaving fewer targets to detect                  | ★★★               |
| Direct code patching   | Bypass `ArtMethod` replacement entirely — hook compiled Java code directly; eliminates need for most ART internal hooks                                  | ★★★★              |
| ShadowHook 4-byte `B`  | Minimal prologue modification (single 4-byte ARM64 `B` instruction) — harder to distinguish from legitimate compiler output                              | ★★★               |
| Symbol obfuscation     | Use alternative resolution methods (hash-based lookup, pattern scanning) instead of string-based symbol search to avoid detection of ElfImg artifacts    | ★★                |

---

## Detection Side

### Mechanism

ART internal functions are loaded from `libart.so`, a read-only system library whose `.text` section should never be modified at runtime. For each known hook target, the detector resolves its in-memory address from `libart.so`'s ELF symbol table and examines the first 4–20 bytes of the function prologue. These bytes are checked against known inline hook trampoline patterns (ARM64 `B`, `LDR X16, #imm; BR X16`, `ADRP+ADD+BR`) or compared byte-for-byte against the on-disk `libart.so` content. Any modification to any of these ~10 well-known targets proves a hooking framework is actively patching the ART runtime.

### Anti-Evasion Properties

| Property                    | Explanation                                                                                                                                              |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Resistant to libc hooks     | Memory reads via direct pointer dereference; file reads via SVC `openat`/`read` — no libc calls in the hot path                                          |
| Resistant to GOT/PLT hijack | Symbol resolution performed by custom ELF parser embedded in detection code, not via `dlsym` or linker APIs                                              |
| SVC bypass benefit          | On-disk `libart.so` read via direct SVC bypasses any userspace hook on `open`/`read`/`fstat`                                                             |
| Remaining bypass surface    | Attacker using forced AOT + direct code patching may not need most hooks; `ShouldUseInterpreterEntrypoint` remains required for LSPlant-style frameworks |

### Detection Strategy

1. **Locate `libart.so`** — Parse `/proc/self/maps` via SVC `openat`/`read` to find the `r-xp` mapping of `libart.so` with its base address and on-disk file path.
2. **Parse ELF symbol table** — Use a custom ELF parser to read `libart.so`'s `.dynsym`/`.symtab` from the in-memory image and resolve addresses of all known hook target symbols (see table above).
3. **Read function prologues** — For each resolved target, read the first 16 bytes from memory via direct pointer dereference.
4. **Pattern match against trampolines** — Check prologue bytes against known inline hook signatures:
   - `B #imm26` — ShadowHook single-instruction branch (4 bytes, opcode `0x14xxxxxx`)
   - `LDR X16, #8; BR X16; <addr>` — Dobby far branch (16 bytes)
   - `ADRP Xn, #page; ADD Xn, Xn, #off; BR Xn` — alternative far branch sequence (12 bytes)
5. **Optionally: disk comparison** — Open on-disk `libart.so` via SVC `openat`, read the corresponding `.text` offset, and compare bytes for ground-truth verification (see [code-integrity-verification.md](code-integrity-verification.md)).
6. **Verdict** — A hit on **any** of the ~10 known targets indicates an active ART method hooking framework. Multiple hits increase confidence.

### Detection PoC

```pseudocode
// ART Internal Function Hook Detection

KNOWN_TARGETS = [
    "_ZN3art11ClassLinker30ShouldUseInterpreterEntrypointEPNS_9ArtMethodEPKv",
    "_ZN3art11ClassLinker22FixupStaticTrampolinesEPNS_6mirror5ClassE",
    "_ZN3art9ArtMethod14RegisterNativeEPKvb",
    "_ZN3art9ArtMethod16UnregisterNativeEv",
    "_ZN3art15instrumentation15Instrumentation17UpdateMethodsCodeEPNS_9ArtMethodEPKv",
    "_ZN3art3jit3Jit27EnqueueOptimizedCompilationEPNS_9ArtMethodEPNS_6ThreadE",
    "_ZN3art3jit12JitCodeCache19GarbageCollectCacheEPNS_6ThreadE",
]

TRAMPOLINE_PATTERNS = [
    { mask: 0xFC000000, value: 0x14000000, size: 4  },  // B #imm26
    { bytes: [0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1F, 0xD6], size: 8 },  // LDR X16, #8; BR X16
]

// Step 1: Locate libart.so via SVC
maps_fd = svc_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY)
maps_data = svc_read(maps_fd, 0, MAX_MAPS_SIZE)
svc_close(maps_fd)

libart_base = 0
libart_path = ""
for each line in maps_data:
    if line.permissions == "r-xp" and "libart.so" in line.filepath:
        libart_base = line.start_addr
        libart_path = line.filepath
        break

if libart_base == 0:
    return ERROR  // libart.so not found

// Step 2: Parse ELF symbol table from memory
elf_header = read_memory(libart_base, sizeof(Elf64_Ehdr))
symtab = parse_elf_symtab(libart_base, elf_header)

// Step 3: Resolve and check each known target
for each symbol_name in KNOWN_TARGETS:
    addr = resolve_symbol(symtab, symbol_name)
    if addr == 0:
        continue  // Symbol not present on this API level

    func_addr = libart_base + addr
    prologue = read_memory(func_addr, 16)

    // Step 4: Pattern match
    for each pattern in TRAMPOLINE_PATTERNS:
        if matches(prologue, pattern):
            return DETECTED  // Hook found on ART internal function

    // Step 5: Optional disk comparison
    fd = svc_openat(AT_FDCWD, libart_path, O_RDONLY)
    disk_bytes = svc_read(fd, addr, 16)
    svc_close(fd)

    if prologue != disk_bytes:
        return DETECTED  // Prologue differs from disk

return CLEAN
```

### False Positive Risks

| Scenario                                | Mitigation                                                                                                                                    |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Android version-specific symbol changes | Maintain per-API-level symbol name mapping (mangled names vary across Android versions); gracefully skip symbols not found on current version |
| `libart.so` ASLR                        | Always use `/proc/self/maps` to resolve actual load address; resolve symbols as offsets relative to the in-memory base address                |
| System updates changing `libart.so`     | Always read current on-disk file for comparison; never hardcode expected prologue bytes — compare dynamically                                 |
| OEM-customized ART builds               | Some OEMs modify ART internals — symbol names or function signatures may differ; maintain an allowlist of known OEM variants                  |
| ART debug builds                        | `userdebug`/`eng` builds may have instrumentation hooks inserted by AOSP itself; check `ro.debuggable` and `ro.build.type` before flagging    |

---

## References

- LSPlant source — <https://github.com/LSPosed/LSPlant> (`lsplant/src/main/jni/`)
- ART runtime source — <https://android.googlesource.com/platform/art/>
- Dobby inline hook framework — <https://github.com/jmpews/Dobby>
- ShadowHook (ByteDance) — <https://github.com/bytedance/android-inline-hook>
- ELF specification — <https://refspecs.linuxfoundation.org/elf/elf.pdf>
- Code integrity verification technique — [code-integrity-verification.md](code-integrity-verification.md)
- ArtMethod introspection technique — [artmethod-introspection.md](artmethod-introspection.md)
