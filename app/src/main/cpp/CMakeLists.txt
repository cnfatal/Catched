cmake_minimum_required(VERSION 3.22.1)

project("catched" C ASM)

# 所有源文件
add_library(catched SHARED
    catched.c
    syscall_wrapper.c
    maps_scanner.c
    root_detect.c
    hook_detect.c
    frida_detect.c
    art_method.c
    npatch_detect.c
    seccomp_detect.c
    signal_detect.c
    integrity_detect.c
    apk_signature.c
)

# 编译选项
target_compile_options(catched PRIVATE
    -Wall
    -Wextra
    -O2
    -fvisibility=hidden          # 隐藏所有符号
    -ffunction-sections
    -fdata-sections
    -DLOG_TAG=\"Catched\"
)

# 链接选项
target_link_options(catched PRIVATE
    -Wl,--gc-sections            # 移除未使用代码段
    -Wl,--exclude-libs,ALL       # 排除静态库符号
)

# 链接 Android log 库
find_library(log-lib log)
target_link_libraries(catched ${log-lib})
