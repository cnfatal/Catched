#ifndef CATCHED_NPATCH_DETECT_H
#define CATCHED_NPATCH_DETECT_H

#include <jni.h>

int detect_npatch_so_maps(void);
int detect_npatch_openat_hook(void);
int detect_npatch_cache_dir(JNIEnv *env, const char *data_dir);
int detect_npatch_profile(JNIEnv *env, const char *data_dir);

int detect_npatch_native(JNIEnv *env, const char *data_dir);

#endif // CATCHED_NPATCH_DETECT_H
