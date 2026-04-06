# Stack Trace Analysis

> Inspects the current thread's call stack at runtime to detect hook framework classes appearing in the execution path.

---

## Overview

Every method invocation on the JVM pushes a stack frame containing the declaring class name, method name, and source file. When a hook framework such as Xposed intercepts a method, its own dispatch classes (e.g., `XposedBridge`, `EdHooker`) become part of the call chain and are visible in any stack trace captured during that execution. Stack Trace Analysis exploits this by calling `Thread.currentThread().getStackTrace()` and scanning each `StackTraceElement.getClassName()` for patterns unique to known hooking frameworks.

From a defender's perspective, this technique is valuable because hooking frameworks cannot avoid inserting their dispatch logic into the call chain — without those intermediate frames, the hook callback would never execute. While some advanced frameworks attempt to scrub their frames from the stack trace, the fundamental requirement of being in the execution path makes this a useful detection signal, especially when combined with other techniques.

---

## Injection Side

### How Attackers Use This Technique

1. **Install hook module** — The attacker deploys a Xposed/LSPosed module that targets the victim application. The framework loads the module into the app's process at startup via Zygote injection or runtime attachment.
2. **Register method hook** — The module calls `XposedHelpers.findAndHookMethod()`, which internally modifies the target method's ArtMethod structure to redirect execution through `XposedBridge.handleHookedMethod()`.
3. **Method invocation triggers hook dispatch** — When the target method is called, execution passes through the framework's dispatch chain: `XposedBridge.handleHookedMethod()` → `XposedBridge.invokeOriginalMethodNative()` → callback methods. Each of these adds a stack frame.
4. **Callback executes** — The attacker's `beforeHookedMethod()` and `afterHookedMethod()` callbacks run within the call chain, adding further framework-specific frames to the stack.
5. **Stack trace reflects hook chain** — Any code that captures a stack trace during this execution will see framework class names such as `de.robv.android.xposed.XposedBridge` or `LSPHooker_` prefixed classes in the frame list.

### Artifacts

| Artifact                 | Location           | Indicator                                         |
| ------------------------ | ------------------ | ------------------------------------------------- |
| Xposed dispatch frame    | Thread stack trace | Class name containing `de.robv.android.xposed`    |
| LSPosed hooker frame     | Thread stack trace | Class name containing `lsposed` or `LSPHooker`    |
| EdXposed hooker frame    | Thread stack trace | Class name containing `EdHooker`                  |
| Substrate dispatch frame | Thread stack trace | Class name containing `com.saurik.substrate`      |
| Generic Xposed keyword   | Thread stack trace | Class name containing `xposed` (case-insensitive) |

### Injection PoC _(optional)_

```pseudocode
// Xposed module hooking a method — the hook dispatch adds frames to the call stack
XposedHelpers.findAndHookMethod(
    "com.target.app.Security", classLoader, "verify",
    new XC_MethodHook() {
        beforeHookedMethod(param):
            // This callback's class appears in stack traces
            param.setResult(true)  // bypass security check
    }
)

// When verify() is called, the stack trace includes:
//   com.target.app.Security.verify()
//   de.robv.android.xposed.XposedBridge.handleHookedMethod()
//   de.robv.android.xposed.XposedBridge.invokeOriginalMethodNative()
//   [attacker's callback class]
```

### Evasion Techniques

| Evasion                   | Description                                                                                                                   |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Stack trace frame removal | Framework intercepts `Thread.getStackTrace()` or `Throwable.getStackTrace()` to filter out its own frames before returning ★★ |
| Class name obfuscation    | Framework renames its internal classes to non-obvious names that don't match known patterns ★★★                               |
| Native-level hooking      | Use PLT/GOT hooks or inline hooks at the native layer, which don't add Java stack frames ★★★★                                 |
| Proxy class generation    | Generate dynamically-named proxy classes that don't contain recognizable framework keywords ★★★                               |

---

## Detection Side

### Mechanism

The invariant is that a clean application's call stack should never contain classes belonging to hook frameworks. The class names `de.robv.android.xposed`, `com.saurik.substrate`, `lsposed`, and `EdHooker` are unique identifiers of hook framework dispatch logic; their presence in any thread's stack trace indicates that the execution path passes through hooking infrastructure. Since the hook dispatch function must be on the call stack for the hook callback to execute, this is a structural requirement that cannot be bypassed without modifying the stack trace reporting mechanism itself.

### Anti-Evasion Properties

| Property                       | Explanation                                                                                                                                                                 |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Targets structural requirement | Hook dispatch classes must be in the call chain for callbacks to execute — they cannot be removed from the actual execution path                                            |
| Multiple pattern coverage      | Scanning for several distinct framework identifiers (Xposed, LSPosed, EdXposed, Substrate) catches variants                                                                 |
| Self-package filtering         | Filtering out the app's own package frames reduces noise and focuses detection on external injected code                                                                    |
| Remaining bypass surface       | Frameworks that hook `Thread.getStackTrace()` itself can return sanitized frames; class obfuscation defeats keyword matching; native-level hooks avoid Java frames entirely |

### Detection Strategy

1. **Capture stack trace** — Call `Thread.currentThread().getStackTrace()` to obtain the current thread's complete call stack as an array of `StackTraceElement` objects.
2. **Filter own package frames** — Remove all frames whose `className` starts with the application's own package prefix to reduce irrelevant results.
3. **Pattern-match remaining frames** — For each remaining `StackTraceElement`, convert `getClassName()` to lowercase and check if it contains any of the known framework patterns: `"xposed"`, `"de.robv.android.xposed"`, `"com.saurik.substrate"`, `"lsposed"`, `"edhooker"`.
4. **Report detection** — If any frame matches a known pattern, record the matched class name and method name as evidence of hook framework presence.

### Detection PoC _(optional)_

```pseudocode
// Capture and scan the current thread's call stack
app_package = "com.example.myapp"
suspicious_patterns = ["xposed", "de.robv.android.xposed",
                       "com.saurik.substrate", "lsposed", "edhooker"]

stack_frames = Thread.currentThread().getStackTrace()

for frame in stack_frames:
    class_name = frame.getClassName()

    // Skip own package frames
    if class_name.startsWith(app_package):
        continue

    // Check against known framework patterns
    class_lower = class_name.toLowerCase()
    for pattern in suspicious_patterns:
        if class_lower.contains(pattern):
            report("hook framework detected in stack trace",
                   class_name, frame.getMethodName())
```

### False Positive Risks

| Scenario                                        | Mitigation                                                                                               |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Third-party library with "xposed" in class name | Extremely unlikely — these names are unique to hook frameworks; no legitimate library uses them          |
| App using Xposed API for its own purposes       | Would only occur in hook framework apps themselves, not in normal applications                           |
| Obfuscated class names coincidentally matching  | The patterns are specific enough (multi-word, namespace-qualified) that random collisions are negligible |

---

## References

- [Android Thread.getStackTrace() documentation](<https://developer.android.com/reference/java/lang/Thread#getStackTrace()>)
- [Xposed Framework — XposedBridge source](https://github.com/rovo89/XposedBridge)
- [LSPosed — hooker implementation](https://github.com/LSPosed/LSPosed)
- [EdXposed — hook dispatch](https://github.com/ElderDrivers/EdXposed)
