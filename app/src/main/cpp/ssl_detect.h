#ifndef CATCHED_SSL_DETECT_H
#define CATCHED_SSL_DETECT_H

#include <jni.h>

// Returns 1 if any well-known BoringSSL/OpenSSL verification function in
// libssl.so or libconscrypt_jni.so appears to be inline-hooked.
int detect_ssl_func_hook(void);

// Returns 1 if libssl.so is mapped from a non-system path
// (/data/... /sdcard/... /storage/... — typical for repackaged /
// frida-gadget-style replacement).
int detect_libssl_path_anomaly(void);

// Returns 1 if more than one distinct libssl.so file is mapped, which is
// what most "drop-in BoringSSL" pinning bypass loaders do.
int detect_multiple_libssl(void);

// Returns 1 if any known SSL pinning bypass library is in /proc/self/maps
// (sslkillswitch, objection-helper, custom unpinning .so).
int detect_ssl_bypass_libs(void);

#endif // CATCHED_SSL_DETECT_H
