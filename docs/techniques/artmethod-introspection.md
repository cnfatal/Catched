# ArtMethod Introspection

> Analyzes the internal ART runtime method structures to detect hook-induced modifications such as unexpected native flags and tampered entry points.

---

## Overview

ArtMethod is the low-level C++ structure in Android's ART (Android Runtime) that represents every Java and Kotlin method. Each ArtMethod instance contains critical metadata including `access_flags_` (which encodes modifiers like public, static, native) and `entry_point_from_quick_compiled_code_` (a pointer to the machine code that executes when the method is called). Method-level hooking frameworks exploit this structure by modifying `access_flags_` to add the `kAccNative` flag and redirecting the entry point to hook handler code. ArtMethod Introspection detects these modifications by reading ArtMethod memory directly via JNI and validating the structural invariants that hold in an unmodified runtime.

From a defender's perspective, this technique is uniquely powerful because it targets the exact mechanism that Java/Kotlin hooking relies on. While filesystem and process artifacts can be hidden through various evasion strategies, the ArtMethod modification is a functional requirement — without changing `access_flags_` or `entry_point`, the hook cannot intercept method calls. This makes ArtMethod introspection a high-confidence detection signal for active method hooking.

---

## Injection Side

### How Attackers Use This Technique

1. **Obtain ArtMethod pointer** — The hooking framework uses JNI `FromReflectedMethod()` to convert a `java.lang.reflect.Method` object into an `ArtMethod*` pointer, gaining direct access to the runtime's internal representation.
2. **Modify access flags** — The framework sets the `kAccNative` bit (0x0100) in `access_flags_` at offset ~4 bytes from the ArtMethod base. This tells the ART runtime that the method is implemented in native code, causing ART to jump to the native entry point instead of executing the original Java bytecode or compiled code.
3. **Replace entry point** — The `entry_point_from_quick_compiled_code_` field is overwritten with a pointer to the hook framework's dispatch function. When the method is invoked, execution flows to the hook handler instead of the original implementation.
4. **Install callback chain** — The hook handler executes the attacker's "before" callback, optionally calls the original method (via a saved copy of the original ArtMethod), then executes the "after" callback, providing full control over the method's behavior and return value.
5. **Optionally extend ArtMethod size** — Some frameworks allocate additional memory adjacent to the ArtMethod struct to store hook metadata, which changes the effective ArtMethod size as seen by adjacent method address calculations.

### Artifacts

| Artifact                                       | Location                                          | Indicator                                                                                                                                                            |
| ---------------------------------------------- | ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| kAccNative flag on non-native method           | `ArtMethod.access_flags_` (offset ~4)             | Bit 0x0100 set on a method declared without `native` keyword                                                                                                         |
| kAccCompileDontBother flag                     | `ArtMethod.access_flags_` (offset ~4)             | Bit 0x02000000 set — prevents JIT recompilation; required by inline code patching of Java method AOT/JIT output                                                      |
| kAccPreCompiled cleared                        | `ArtMethod.access_flags_` (offset ~4)             | Bit 0x00200000 (Android R) or 0x00800000 (Android S+) cleared on a pre-compiled method — indicates attacker cleared it to prevent ART assuming code is pre-validated |
| kAccFastInterpreterToInterpreterInvoke cleared | `ArtMethod.access_flags_` (offset ~4)             | Bit 0x40000000 (Android Q+) cleared — attacker must clear this to force ART through `entry_point_` instead of fast interpreter path                                  |
| Entry point outside owning library             | `ArtMethod.entry_point_from_quick_compiled_code_` | Pointer falls outside the memory range of the method's declaring class's DEX/OAT file                                                                                |
| Abnormal ArtMethod struct size                 | Address delta between adjacent methods            | Size differs from expected 32–64 bytes on ARM64                                                                                                                      |
| Hook dispatch library in memory                | `/proc/self/maps`                                 | Additional shared library mapped with execute permission, containing the hook handler code                                                                           |
| Modified ArtMethod backup                      | Heap memory                                       | Copy of original ArtMethod stored by the framework for calling the original method                                                                                   |

### Injection PoC _(optional)_

```pseudocode
// Xposed-style hooking of a Java method
target_method = env->GetMethodID(clazz, "checkIntegrity", "()Z")
art_method_ptr = env->FromReflectedMethod(target_method)

// Save original ArtMethod for later invocation
backup = malloc(artmethod_size)
memcpy(backup, art_method_ptr, artmethod_size)

// Set kAccNative flag
access_flags = read_u32(art_method_ptr + 4)
access_flags |= 0x0100  // kAccNative
write_u32(art_method_ptr + 4, access_flags)

// Redirect entry point to hook handler
write_ptr(art_method_ptr + entry_point_offset, &hook_dispatch)
```

### Evasion Techniques

| Evasion                      | Description                                                                                                                                                                                                   |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Flag restoration on scan     | Temporarily remove kAccNative when a scan is detected, restore it afterward — requires detecting when introspection occurs                                                                                    |
| Entry point within ART range | Allocate hook handler code inside a memory region that mimics ART-generated code ranges                                                                                                                       |
| CallerSensitive hooking      | Use ART-internal mechanisms (e.g., class redefinition via JVMTI) that modify methods without setting kAccNative                                                                                               |
| Inline method patching       | Instead of modifying ArtMethod fields, directly patch the compiled code at the entry point address — but still requires kAccCompileDontBother to prevent JIT recompilation                                    |
| ArtMethod size preservation  | Avoid extending the ArtMethod struct by storing hook metadata externally, preserving the expected address delta                                                                                               |
| Forced AOT compilation       | Use `cmd package compile -m speed` before injection — AOT code in OAT resists JIT GC, reducing the need for some flags; kAccCompileDontBother may still be needed to prevent JIT recompilation of hot methods |

---

## Detection Side

### Mechanism

The invariant is threefold: (1) a Java method not declared with the `native` keyword must not have `kAccNative` (0x0100) set in its `access_flags_`; (2) the `entry_point_from_quick_compiled_code_` must point to an address within the expected memory range of the method's owning library (boot.oat, app-compiled OAT, or ART JIT code cache); and (3) the size of the ArtMethod struct (measured as the address difference between two adjacent methods of the same class) must fall within the expected range for the current Android version and architecture. Violation of any invariant indicates that the ART runtime's method structures have been tampered with.

### Anti-Evasion Properties

| Property                       | Explanation                                                                                                                                                                            |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Targets functional requirement | The kAccNative flag and entry point redirect are necessary for Xposed-style hooks to work — they cannot be omitted                                                                     |
| Direct memory read             | ArtMethod is read via JNI pointer arithmetic, not through Java reflection APIs that could themselves be hooked                                                                         |
| Multi-field validation         | Checking access_flags, entry_point, and struct size together catches different hooking strategies                                                                                      |
| SVC bypass benefit             | Reading `/proc/self/maps` via SVC to determine valid library ranges prevents hooked libc from reporting forged ranges                                                                  |
| Remaining bypass surface       | JVMTI-based class redefinition does not set kAccNative; inline code patching modifies the code but not the ArtMethod struct; flag-restoration races can temporarily hide modifications |

### Detection Strategy

1. **Measure ArtMethod size** — Select a class known to have multiple methods (e.g., `java.lang.String`). Use JNI `FromReflectedMethod()` to obtain pointers for two adjacent methods (e.g., `length()` and `isEmpty()`). Calculate the address difference. On ARM64, the expected size is typically 32–64 bytes depending on Android version. An anomalous size indicates the ART runtime or ArtMethod struct has been modified.
2. **Check access flags for kAccNative** — For a set of known non-native Java methods (framework methods such as `Thread.sleep()`, `String.length()`), obtain each ArtMethod pointer. Read the 4-byte `access_flags_` field at offset ~4. Check if bit 0x0100 (`kAccNative`) is set. If set on a method not declared `native`, the method has been hooked.
3. **Check access flags for compilation control anomalies** — For the same set of methods, check additional flags that indicate inline code patching of Java method compiled output:
   - `kAccCompileDontBother` (0x02000000): Prevents JIT recompilation. Required when attacker patches AOT/JIT compiled code — without it, JIT may overwrite the patch. Normal app methods should not have this flag unless ART itself set it on trivial methods.
   - `kAccPreCompiled` cleared: Android R uses 0x00200000, Android S+ uses 0x00800000. If a method was AOT-compiled but this flag is missing, the attacker may have cleared it.
   - `kAccFastInterpreterToInterpreterInvoke` (0x40000000, Android Q+): When cleared on a method that should have it, the attacker forced ART to use `entry_point_` instead of the fast interpreter path.
   - Detection of these flags is critical because **inline code patching of Java method compiled output does NOT set kAccNative** — it is invisible to step 2 above. These compilation-control flags are the only ArtMethod-level indicator of this attack.
4. **Validate entry point range** — Read the `entry_point_from_quick_compiled_code_` field from the ArtMethod. Parse `/proc/self/maps` to determine the address ranges of boot.oat, the app's OAT file, and the ART JIT code cache. Verify that the entry point falls within one of these legitimate ranges. An entry point pointing to an unknown or injected library indicates a hook.
5. **Repeat for critical methods** — Apply checks 2 and 3 to methods commonly targeted by hooking frameworks: integrity checks, certificate validation, authentication methods, and cryptographic operations.

### Detection PoC _(optional)_

```pseudocode
// Step 1: Measure ArtMethod size
method_a = env->FromReflectedMethod(String_length)
method_b = env->FromReflectedMethod(String_isEmpty)
artmethod_size = abs(method_b - method_a)
if artmethod_size < 32 or artmethod_size > 64:
    report("abnormal ArtMethod size", artmethod_size)

// Step 2: Check access_flags for kAccNative on non-native methods
probe_methods = [String_length, String_isEmpty, Thread_sleep, ...]
for method in probe_methods:
    art_ptr = env->FromReflectedMethod(method)
    access_flags = read_u32(art_ptr + 4)
    if access_flags & 0x0100:  // kAccNative
        report("unexpected kAccNative flag on non-native method", method)

// Step 3: Validate entry point range
valid_ranges = parse_maps_for_oat_and_jit_ranges("/proc/self/maps")
for method in probe_methods:
    art_ptr = env->FromReflectedMethod(method)
    entry_point = read_ptr(art_ptr + entry_point_offset)
    if not any(range.contains(entry_point) for range in valid_ranges):
        report("entry point outside valid range", method, entry_point)
```

### False Positive Risks

| Scenario                                             | Mitigation                                                                                                                                             |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| JNI methods legitimately marked as native            | Only probe methods that are known to be non-native in the Android source (e.g., pure Java framework methods)                                           |
| ArtMethod size varies across Android versions        | Calibrate expected size at runtime by measuring known-clean methods on first run; store expected size per Android API level                            |
| JIT-compiled code in unexpected memory regions       | Include JIT code cache regions (identifiable by `/memfd:jit-cache` in maps) in the set of valid entry point ranges                                     |
| Method deoptimization changing entry points          | ART may temporarily redirect methods to the interpreter entry point during deoptimization; include interpreter trampoline addresses as valid           |
| ART setting kAccCompileDontBother on trivial methods | ART may mark very simple methods with this flag on its own; cross-validate with method complexity or compare against a known-clean baseline at startup |
| kAccPreCompiled version differences                  | The bit position differs between Android R (0x00200000) and S+ (0x00800000); use `Build.VERSION.SDK_INT` to select the correct mask                    |

---

## References

- [Android ART runtime — ArtMethod source code](https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/art_method.h)
- [Android ART runtime — access flags](https://android.googlesource.com/platform/art/+/refs/heads/main/libdexfile/dex/modifiers.h)
- [JNI specification — FromReflectedMethod](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html)
- [JVMTI specification — class redefinition](https://docs.oracle.com/javase/8/docs/platform/jvmti/jvmti.html#RedefineClasses)
- [ARM64 calling convention and pointer sizes](https://developer.arm.com/documentation/102374/latest/)
