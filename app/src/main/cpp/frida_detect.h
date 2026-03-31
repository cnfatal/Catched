#ifndef CATCHED_FRIDA_DETECT_H
#define CATCHED_FRIDA_DETECT_H

#include <jni.h>

int detect_frida_maps(void);
int detect_frida_port(void);
int detect_frida_proc_tcp(void);
int detect_frida_server_file(void);
int detect_frida_named_pipe(void);
int detect_frida_dbus(void);
int detect_frida_memory(void);
int detect_frida_thread(void);

int detect_frida_native(JNIEnv *env);

#endif // CATCHED_FRIDA_DETECT_H
