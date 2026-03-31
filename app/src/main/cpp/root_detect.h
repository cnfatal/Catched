#ifndef CATCHED_ROOT_DETECT_H
#define CATCHED_ROOT_DETECT_H

#include <jni.h>

// 返回 0=安全 1=检测到
int detect_su_paths_svc(void);
int detect_su_stat_native(void);
int detect_magisk_mount(void);
int detect_mountinfo(void);
int detect_selinux_context(void);
int detect_selinux_prev(void);
int detect_magisk_socket(void);
int detect_system_properties(void);

int detect_root_native(JNIEnv *env, jobjectArray results);

#endif // CATCHED_ROOT_DETECT_H
