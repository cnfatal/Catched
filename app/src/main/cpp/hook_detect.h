#ifndef CATCHED_HOOK_DETECT_H
#define CATCHED_HOOK_DETECT_H

#include <jni.h>

int check_got_hook(const char *so_name);
int check_inline_hook(void *func_addr);
int check_openat_hook(void);

int detect_xposed_maps(void);
int detect_xposed_libart(void);
int detect_xposed_app_process(void);

int detect_hook_native(JNIEnv *env);

#endif // CATCHED_HOOK_DETECT_H
