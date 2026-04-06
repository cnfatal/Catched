# Java Reflection

> Uses the Java reflection API to inspect runtime objects, read private fields, check method modifiers, and detect modifications to the ART virtual machine state caused by code injection and hooking.

---

## Overview

Java reflection (`java.lang.reflect`) allows code to inspect and interact with classes, methods, and fields at runtime, including private and hidden members that are not accessible through normal API calls. In the context of security detection, reflection serves as a powerful introspection tool: hook frameworks must modify runtime data structures (method flags, class caches, callback lists, application metadata) for their hooks to function, and these modifications are observable via reflection. Unlike native-level detection (procfs, SVC), reflection operates within the ART virtual machine and can detect semantic changes to the Java runtime — such as a method's access flags being changed to `native`, a class's `appComponentFactory` being replaced, or a hook framework's internal cache being populated.

From a defender's perspective, reflection-based detection is valuable because it targets the fundamental requirement of hooking: the runtime state must be altered for hooks to work. Attackers cannot hook methods without modifying method metadata, cannot inject stub classes without modifying `ApplicationInfo`, and cannot load framework JARs without populating internal caches. Reflection reads these very data structures, creating a detection mechanism that is intrinsically tied to the hooking mechanism itself.

---

## Injection Side

### How Attackers Use This Technique

1. **Replace method implementation via native flag** — Hook frameworks mark target methods with the `ACC_NATIVE` (0x0100) flag in ART's internal method structure, redirecting execution from compiled Java bytecode to a native hook handler. This allows interception of any Java method call.
2. **Register hook callbacks** — The framework maintains callback lists (e.g., `sHookedMethodCallbacks`) mapping hooked methods to their replacement implementations. These data structures must persist in memory for hooks to function.
3. **Populate method resolution caches** — Hook frameworks use internal caches (e.g., `methodCache`) to speed up method lookups. These caches are populated at hook registration time and remain non-empty throughout the process lifetime.
4. **Replace application component factory** — Repackaging tools replace the app's `appComponentFactory` field in `ApplicationInfo` with a stub class name to intercept component instantiation.
5. **Inject metadata** — Repackaging tools add entries to `ApplicationInfo.metaData` bundle to store configuration and version information for the injected module.

### Artifacts

| Artifact                                | Location                                   | Indicator                                                                                                                          |
| --------------------------------------- | ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| Native method flag on non-native method | `Method.getModifiers()`                    | `Modifier.isNative()` returns true for methods that should be Java-implemented (e.g., `Runtime.exec()`, `ClassLoader.loadClass()`) |
| Non-empty hook callback map             | Framework's `sHookedMethodCallbacks` field | Map size > 0 indicates active hooks are registered                                                                                 |
| Non-empty method cache                  | Framework's `methodCache` static field     | Cache containing entries proves methods have been resolved for hooking                                                             |
| Risk class loadable                     | `ClassLoader.loadClass()`                  | Successfully loading a hook framework's bridge class proves the framework JAR is in the classpath                                  |
| Replaced appComponentFactory            | `ApplicationInfo.appComponentFactory`      | Field contains class name with repackaging tool identifiers (e.g., containing "lsp", "npatch", "Stub")                             |
| Injected metadata keys                  | `ApplicationInfo.metaData`                 | Bundle contains unexpected keys added by the repackaging tool                                                                      |
| JDWP debugger attached                  | `Debug.isDebuggerConnected()`              | Returns true when a Java debugger is connected via JDWP protocol                                                                   |
| Hidden API access via SystemProperties  | `SystemProperties.get("ro.*")`             | Returns values indicating modified system state                                                                                    |

### Injection PoC _(optional)_

```pseudocode
// Hook framework modifies method at ART level
step_1: resolve target method (e.g., Activity.onCreate)
step_2: set method.access_flags |= ACC_NATIVE  // mark as native
step_3: save original entry_point to backup
step_4: set method.entry_point = hook_trampoline
step_5: register callback in sHookedMethodCallbacks[method] = handler
step_6: cache method in methodCache for fast lookup

// Repackaging tool modifies ApplicationInfo
step_1: replace appComponentFactory = "com.tool.StubComponentFactory"
step_2: add metaData("npatch_version", "1.0")
```

### Evasion Techniques

| Evasion                          | Description                                                                                   |
| -------------------------------- | --------------------------------------------------------------------------------------------- |
| Clean up caches on detection     | Clear `methodCache` and `sHookedMethodCallbacks` before detection code runs, repopulate after |
| Use non-standard field names     | Obfuscate framework class and field names so reflection-based lookups for known names fail    |
| Restore native flags temporarily | Temporarily clear `ACC_NATIVE` flag when detection is suspected, restore it afterward         |
| Hook reflection API itself       | Intercept `Field.get()`, `Method.getModifiers()`, or `Class.forName()` to return clean values |
| Avoid appComponentFactory        | Use alternative injection vectors that don't require modifying `ApplicationInfo` fields       |

---

## Detection Side

### Mechanism

The invariant is that hooking frameworks must modify observable Java runtime state to function. A method cannot be hooked without changing its flags or entry point. A framework JAR cannot be injected without being loadable from some ClassLoader. Application metadata cannot be used for configuration without being present in the `ApplicationInfo.metaData` bundle. Reflection provides direct read access to all of these data structures. The detection is inherently tied to the requirement of the attack: if the modifications are reverted to avoid detection, the hooks stop working.

### Anti-Evasion Properties

| Property                     | Explanation                                                                                                                                                   |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Intrinsic coupling           | Detection targets the same data structures that must be modified for hooking to work — removal breaks the hooks                                               |
| Multiple independent signals | Method flags, class loading, callback maps, metadata, and component factory provide independent detection vectors                                             |
| Hidden API access            | Using reflection to access hidden/private fields means detection can read internal framework state not intended for public access                             |
| Runtime verification         | Detection occurs at the JVM level against live objects, not static analysis — obfuscation of class names on disk does not help if the runtime names are known |
| Remaining bypass surface     | Framework can hook the reflection API itself (`Field.get()`, `Method.getModifiers()`); race conditions allow temporary cleanup during scanning window         |

### Detection Strategy

1. **Attempt to load risk classes** — Use `ClassLoader.loadClass()` with known hook framework class names (e.g., `de.robv.android.xposed.XposedBridge`). If the class loads without `ClassNotFoundException`, the framework JAR is present.
2. **Read hook callback structures** — If a framework class loads, use reflection to access its static hook registration fields (e.g., `sHookedMethodCallbacks`). If the map/collection is non-empty, hooks are actively registered.
3. **Read method resolution caches** — Access the framework's `methodCache` field to check for cached method resolutions — a non-empty cache proves hooking activity.
4. **Check method modifiers** — For critical Java methods (`Runtime.exec()`, `ClassLoader.loadClass()`, `Thread.sleep()`, etc.), call `method.getModifiers()` and check `Modifier.isNative()`. These methods are implemented in Java bytecode; if they report as native, their implementation has been replaced by a hook.
5. **Inspect ApplicationInfo fields** — Read `context.applicationInfo.appComponentFactory` and check if it contains repackaging tool class name patterns. Read `context.applicationInfo.metaData` and check for unexpected keys.
6. **Check debug state** — Call `Debug.isDebuggerConnected()` to detect JDWP debugger attachment.
7. **Enumerate runtime instances** — Use hidden API `VMDebug.getInstancesOfClasses()` to enumerate all live instances of framework classes. If instances exist, the framework is loaded and active.

### Detection PoC _(optional)_

```pseudocode
// Check 1: Attempt to load risk class
try:
    cls = ClassLoader.loadClass("de.robv.android.xposed.XposedBridge")
    flag("framework_class_loadable", cls.getName())

    // Check 2: Read hook callback map
    field = cls.getDeclaredField("sHookedMethodCallbacks")
    field.setAccessible(true)
    callbacks = field.get(null)
    if callbacks.size() > 0:
        flag("active_hooks_registered", callbacks.size())
catch ClassNotFoundException:
    pass  // framework not loaded

// Check 3: Method modifier verification
methods_to_check = [
    Runtime.class.getMethod("exec", String.class),
    ClassLoader.class.getMethod("loadClass", String.class)
]
for method in methods_to_check:
    if Modifier.isNative(method.getModifiers()):
        flag("method_hooked_native", method.getName())

// Check 4: ApplicationInfo inspection
info = context.getApplicationInfo()
if info.appComponentFactory != null:
    if info.appComponentFactory.contains("lsp") or
       info.appComponentFactory.contains("npatch") or
       info.appComponentFactory.contains("Stub"):
        flag("repackaged_component_factory", info.appComponentFactory)

// Check 5: Debug state
if Debug.isDebuggerConnected():
    flag("jdwp_debugger_attached")
```

### False Positive Risks

| Scenario                                                    | Mitigation                                                                                                                 |
| ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Legitimate use of native methods in JNI-heavy apps          | Only check methods known to be Java-implemented in AOSP source; maintain a whitelist of genuinely native framework methods |
| App framework using custom appComponentFactory              | Only flag component factory names matching known repackaging tool patterns, not all custom factory names                   |
| Debug.isDebuggerConnected() during development              | Check `ApplicationInfo.FLAG_DEBUGGABLE`; suppress JDWP detection for debug builds                                          |
| ClassLoader.loadClass() false hits from library class names | Use exact fully-qualified class name matching; verify loaded class has expected fields/methods before flagging             |
| Test/CI environments with debugging tools                   | Allow configuration to suppress reflection-based detection in known CI environments                                        |

---

## References

- [Java Reflection API documentation](https://docs.oracle.com/javase/8/docs/api/java/lang/reflect/package-summary.html)
- [Android ART method access flags (AOSP)](https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/art_method.h)
- [Android Debug class documentation](https://developer.android.com/reference/android/os/Debug)
- [Android ApplicationInfo documentation](https://developer.android.com/reference/android/content/pm/ApplicationInfo)
- [VMDebug hidden API (AOSP)](https://android.googlesource.com/platform/libcore/+/refs/heads/main/dalvik/src/main/java/dalvik/system/VMDebug.java)
