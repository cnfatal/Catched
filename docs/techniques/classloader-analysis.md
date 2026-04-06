# ClassLoader Analysis

> Inspects the Java ClassLoader hierarchy, DexPathList entries, and runtime ClassLoader instances to detect externally injected code modules loaded into the process.

---

## Overview

In the Android runtime (ART), all Java code is loaded through ClassLoader instances that maintain references to DEX files via an internal `DexPathList` structure. Each `BaseDexClassLoader` contains a `pathList` field holding an array of `dexElements`, where each element references a `DexFile` with a file path. ClassLoaders also form a parent-child delegation chain. When code injection occurs — whether through Zygote hooking, APK repackaging, or runtime class loading — the injected code must be accessible to some ClassLoader in the process, either by adding entries to an existing ClassLoader's `dexElements` or by creating entirely new ClassLoader instances.

From a defender's perspective, ClassLoader analysis exploits an unavoidable requirement: injected Java/DEX code must be loadable, and loadability requires ClassLoader registration. By enumerating all ClassLoader instances in the process (via `VMDebug.getInstancesOfClasses()`), walking the ClassLoader parent chain, and inspecting every `dexElement` entry, the defender can identify any code module that did not originate from the app's own APK or from expected system paths. This technique provides comprehensive coverage because it operates at the level of ART's class loading mechanism, which injection cannot bypass.

---

## Injection Side

### How Attackers Use This Technique

1. **Inject JAR into ClassLoader** — Hook frameworks inject their bridge JAR (containing hook management classes) into the boot ClassLoader or a child ClassLoader. This adds new `dexElements` entries pointing to the injected JAR file.
2. **Create custom ClassLoader instances** — Some injection frameworks create entirely new `BaseDexClassLoader` or `InMemoryDexClassLoader` instances to load their code independently of the app's ClassLoader hierarchy.
3. **Add stub classes via repackaging** — Repackaging tools modify the app's APK to include stub DEX files and register them in the existing ClassLoader's `dexElements`, or create a secondary ClassLoader to host the injected classes.
4. **Load modules from non-standard paths** — Injected code is loaded from paths outside the expected locations (`/system/`, `/apex/`, `/vendor/`, or the app's APK directory), such as `/data/local/tmp/`, `/data/adb/modules/`, or temporary cache directories.

### Artifacts

| Artifact                                | Location                                            | Indicator                                                                                 |
| --------------------------------------- | --------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Foreign dexElements entry               | `BaseDexClassLoader.pathList.dexElements[].dexFile` | DEX file path not matching app's APK or system paths (`/system/`, `/apex/`, `/vendor/`)   |
| Custom ClassLoader class                | ClassLoader parent chain                            | ClassLoader whose class name does not start with `dalvik.system.`, `java.`, or `android.` |
| Extra ClassLoader instances             | Runtime heap (enumerable via VMDebug)               | `BaseDexClassLoader` instances beyond expected system and app loaders                     |
| Framework-named ClassLoader             | Runtime heap                                        | ClassLoader whose class name contains injection framework identifiers                     |
| Risk class loadable from foreign loader | Foreign ClassLoader instance                        | `classLoader.loadClass("framework.BridgeClass")` succeeds                                 |
| Unexpected DEX count                    | `pathList.dexElements.length`                       | More dexElements than the app's APK contains (split APKs accounted for)                   |

### Injection PoC _(optional)_

```pseudocode
// Hook framework injects bridge JAR into ClassLoader

// Approach 1: Add to existing ClassLoader's dexElements
step_1: get target classLoader = context.getClassLoader()
step_2: reflect into classLoader.pathList (DexPathList)
step_3: reflect into pathList.dexElements (Element[])
step_4: create new Element for bridge.jar
step_5: prepend new Element to dexElements array
// Result: dexElements now contains bridge.jar as first entry

// Approach 2: Create new ClassLoader instance
step_1: bridgeLoader = new InMemoryDexClassLoader(bridgeDex, parentLoader)
step_2: use bridgeLoader to load hook management classes
// Result: new BaseDexClassLoader instance exists in heap

// Approach 3: Repackaging tool adds stub DEX
step_1: add stub.dex to APK's assets/
step_2: at runtime, create ClassLoader for stub.dex
step_3: replace appComponentFactory to use stub ClassLoader
// Result: foreign ClassLoader in parent chain
```

### Evasion Techniques

| Evasion                                   | Description                                                                                                                            |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Load from memory (InMemoryDexClassLoader) | Load DEX bytes directly from memory instead of a file path; `dexFile.getName()` returns a synthetic name rather than a filesystem path |
| Remove dexElements after loading          | After loading all needed classes, remove the injected `dexElement` entry from the array to hide the evidence                           |
| Use system ClassLoader names              | Name the custom ClassLoader class with a `dalvik.system.` or `java.` prefix to bypass class name filtering                             |
| Hook reflection API                       | Intercept `Field.get()` calls on `pathList` or `dexElements` to return a filtered array that omits injected entries                    |
| Unload ClassLoader                        | Null out references to the injected ClassLoader after initialization, relying on already-loaded classes remaining in memory            |

---

## Detection Side

### Mechanism

The invariant is that a clean app process should only contain ClassLoader instances from the Android system (with class names starting with `dalvik.system.`, `java.`, or `android.`) and the app's own ClassLoader whose DEX entries point exclusively to the app's APK and system directories. Any ClassLoader with a non-system class name, any `dexElement` pointing to a path outside expected locations, and any ClassLoader from which framework-specific classes can be loaded, indicates code injection. This invariant holds because ART requires all loadable Java code to be registered with a ClassLoader.

### Anti-Evasion Properties

| Property                  | Explanation                                                                                                                                                                           |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Heap-wide enumeration     | `VMDebug.getInstancesOfClasses()` enumerates ALL ClassLoader instances in the entire heap, including ones not reachable from any known reference chain                                |
| Multi-strategy redundancy | Three independent strategies (chain walk, instance enumeration, dexElements scan) make it necessary to evade all three simultaneously                                                 |
| Path-based validation     | Checking DEX file paths against a whitelist of expected locations catches any file-backed injection regardless of ClassLoader naming                                                  |
| Class loading probe       | Attempting `loadClass()` from each discovered ClassLoader tests whether framework code is actually accessible, not just whether the loader exists                                     |
| Remaining bypass surface  | InMemoryDexClassLoader with synthetic names; hooking VMDebug or reflection APIs; removing ClassLoader references before enumeration; using system-like class names for custom loaders |

### Detection Strategy

1. **ClassLoader chain walk** — Starting from `context.getClassLoader()`, traverse the `parent` field recursively until reaching null (the bootstrap ClassLoader). For each ClassLoader in the chain, get its class name via `getClass().getName()`. Flag any ClassLoader whose class name does not start with `dalvik.system.`, `java.`, or `android.`.
2. **VMDebug instance enumeration** — Use the hidden API `VMDebug.getInstancesOfClasses(new Class[]{BaseDexClassLoader.class}, true)` to retrieve all `BaseDexClassLoader` instances currently alive in the process heap. For each instance:
   - Check if the ClassLoader's class name contains framework-related identifiers.
   - Attempt to load known risk classes (e.g., `de.robv.android.xposed.XposedBridge`) from the ClassLoader. If it succeeds, the framework code is accessible from that loader.
3. **DexPathList.dexElements scan** — For each ClassLoader found (from both chain walk and VMDebug enumeration):
   - Reflect into `BaseDexClassLoader.pathList` to get the `DexPathList` instance.
   - Reflect into `DexPathList.dexElements` to get the `Element[]` array.
   - For each element, reflect into `element.dexFile` and call `dexFile.getName()` to get the DEX file path.
   - Compare the path against a whitelist of expected locations: paths starting with `/system/`, `/apex/`, `/vendor/`, or matching the app's own `sourceDir`. Any path outside this whitelist indicates an externally injected module.
4. **Cross-reference findings** — Combine results from all three strategies. Multiple signals from different strategies provide higher confidence.

### Detection PoC _(optional)_

```pseudocode
// Strategy 1: ClassLoader chain walk
loader = context.getClassLoader()
while loader != null:
    className = loader.getClass().getName()
    if not className.startsWith("dalvik.system.") and
       not className.startsWith("java.") and
       not className.startsWith("android."):
        flag("custom_classloader_in_chain", className)
    loader = loader.getParent()

// Strategy 2: VMDebug instance enumeration
allLoaders = VMDebug.getInstancesOfClasses(
    [BaseDexClassLoader.class], true
)
for loader in allLoaders:
    name = loader.getClass().getName().toLowerCase()
    if name contains "xposed" or name contains "lsposed":
        flag("framework_classloader", name)

    // Probe for risk classes
    try:
        cls = loader.loadClass("de.robv.android.xposed.XposedBridge")
        flag("risk_class_loadable_from", loader)
    catch ClassNotFoundException:
        pass

// Strategy 3: DexPathList.dexElements scan
for loader in allLoaders:
    pathListField = BaseDexClassLoader.getDeclaredField("pathList")
    pathListField.setAccessible(true)
    pathList = pathListField.get(loader)

    dexElementsField = pathList.getClass().getDeclaredField("dexElements")
    dexElementsField.setAccessible(true)
    elements = dexElementsField.get(pathList)

    for element in elements:
        dexFileField = element.getClass().getDeclaredField("dexFile")
        dexFileField.setAccessible(true)
        dexFile = dexFileField.get(element)
        if dexFile != null:
            path = dexFile.getName()
            if not isExpectedPath(path):
                flag("foreign_dex_entry", path)

function isExpectedPath(path):
    return path.startsWith("/system/") or
           path.startsWith("/apex/") or
           path.startsWith("/vendor/") or
           path == app.sourceDir or
           path in app.splitSourceDirs
```

### False Positive Risks

| Scenario                                                                         | Mitigation                                                                                                     |
| -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Dynamic class loading by legitimate plugins (e.g., Google Play Feature Delivery) | Whitelist DEX paths under the app's own data directory that match known plugin loading patterns                |
| MultiDex in legacy apps (pre-API 21)                                             | Account for secondary DEX files in the app's own APK directory (classes2.dex, classes3.dex, etc.)              |
| WebView ClassLoader (org.chromium.\*)                                            | Add WebView-related ClassLoader class names to the system prefix whitelist                                     |
| Split APKs (app bundles)                                                         | Include `ApplicationInfo.splitSourceDirs` entries in the expected path whitelist                               |
| React Native / Flutter custom ClassLoaders                                       | Some cross-platform frameworks use custom ClassLoader subclasses; whitelist by class name if known and trusted |
| Instant Apps ClassLoader                                                         | Google Instant Apps may use special ClassLoader implementations; verify class name prefix before flagging      |

---

## References

- [Android ClassLoader documentation](https://developer.android.com/reference/java/lang/ClassLoader)
- [Android BaseDexClassLoader (AOSP)](https://android.googlesource.com/platform/libcore/+/refs/heads/main/dalvik/src/main/java/dalvik/system/BaseDexClassLoader.java)
- [Android DexPathList (AOSP)](https://android.googlesource.com/platform/libcore/+/refs/heads/main/dalvik/src/main/java/dalvik/system/DexPathList.java)
- [VMDebug.getInstancesOfClasses (AOSP)](https://android.googlesource.com/platform/libcore/+/refs/heads/main/dalvik/src/main/java/dalvik/system/VMDebug.java)
- [Android App Bundle and split APKs](https://developer.android.com/guide/app-bundle)
