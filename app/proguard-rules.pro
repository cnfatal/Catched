# Catched ProGuard Rules

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep NativeBridge
-keep class cn.fatalc.catched.native.NativeBridge { *; }

# Keep model classes for serialization
-keep class cn.fatalc.catched.model.** { *; }
