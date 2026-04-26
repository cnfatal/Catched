#include "ssl_detect.h"
#include "hook_detect.h"
#include "maps_scanner.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <android/log.h>

#define TAG "Catched"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

// BoringSSL / OpenSSL verification entry points commonly rewritten by
// pinning-bypass scripts (objection / frida-multiple-bypass / sslkill).
static const char *ssl_target_symbols[] = {
    "SSL_CTX_set_verify",
    "SSL_set_verify",
    "SSL_set_custom_verify",
    "SSL_CTX_set_custom_verify",
    "SSL_get_verify_result",
    "SSL_CTX_set_cert_verify_callback",
    "X509_verify_cert",
};
static const int ssl_target_count =
    sizeof(ssl_target_symbols) / sizeof(ssl_target_symbols[0]);

static const char *ssl_libs[] = {"libssl.so", "libcrypto.so",
                                 "libconscrypt_jni.so", "libconscrypt_gmscore_jni.so"};
static const int ssl_libs_count = sizeof(ssl_libs) / sizeof(ssl_libs[0]);

// Known SSL-pinning bypass / MITM helper libs.
static const char *ssl_bypass_blacklist[] = {
    "libsslkill",
    "sslkillswitch",
    "libsslunpinning",
    "ssl_unpinning",
    "libuntrusted",
    "libpinningbypass",
    "libtrustkit",   // legitimate iOS-origin lib but ports often abused
    "libtrustmealready",
    "objection",
    "libsubstratehook",
};
static const int ssl_bypass_count =
    sizeof(ssl_bypass_blacklist) / sizeof(ssl_bypass_blacklist[0]);

int detect_ssl_func_hook(void)
{
    int hits = 0;
    for (int i = 0; i < ssl_libs_count; i++)
    {
        void *h = dlopen(ssl_libs[i], RTLD_NOLOAD);
        if (!h)
            continue;
        for (int j = 0; j < ssl_target_count; j++)
        {
            void *addr = dlsym(h, ssl_target_symbols[j]);
            if (!addr)
                continue;
            if (check_inline_hook(addr))
            {
                LOGD("SSL: %s!%s appears inline-hooked at %p",
                     ssl_libs[i], ssl_target_symbols[j], addr);
                hits++;
            }
        }
        dlclose(h);
    }
    return hits > 0 ? 1 : 0;
}

int detect_libssl_path_anomaly(void)
{
    char buf[32768];
    ssize_t n = sg_read_maps(buf, sizeof(buf));
    if (n <= 0)
        return 0;

    int anomaly = 0;
    char *line = buf;
    while (*line)
    {
        char *next = line;
        while (*next && *next != '\n')
            next++;
        char saved = *next;
        *next = '\0';

        // Path is the trailing field after the last whitespace
        const char *path = strrchr(line, ' ');
        if (path && (strstr(path, "libssl.so") || strstr(path, "libcrypto.so")))
        {
            if (!(strstr(path, "/system/") || strstr(path, "/apex/") ||
                  strstr(path, "/vendor/") || strstr(path, "/product/")))
            {
                LOGD("SSL: libssl/libcrypto mapped from non-system path: %s", path);
                anomaly = 1;
            }
        }

        *next = saved;
        if (*next)
            next++;
        line = next;
    }
    return anomaly;
}

int detect_multiple_libssl(void)
{
    char buf[32768];
    ssize_t n = sg_read_maps(buf, sizeof(buf));
    if (n <= 0)
        return 0;

    // Collect distinct libssl pathnames
    char paths[8][256] = {{0}};
    int path_count = 0;

    char *line = buf;
    while (*line && path_count < 8)
    {
        char *next = line;
        while (*next && *next != '\n')
            next++;
        char saved = *next;
        *next = '\0';

        const char *p = strrchr(line, ' ');
        if (p && strstr(p, "libssl.so"))
        {
            // skip leading space
            while (*p == ' ')
                p++;
            int dup = 0;
            for (int i = 0; i < path_count; i++)
            {
                if (strcmp(paths[i], p) == 0)
                {
                    dup = 1;
                    break;
                }
            }
            if (!dup)
            {
                strncpy(paths[path_count], p, sizeof(paths[0]) - 1);
                path_count++;
            }
        }

        *next = saved;
        if (*next)
            next++;
        line = next;
    }

    if (path_count > 1)
    {
        LOGD("SSL: %d distinct libssl.so mappings found", path_count);
        for (int i = 0; i < path_count; i++)
            LOGD("  [%d] %s", i, paths[i]);
        return 1;
    }
    return 0;
}

int detect_ssl_bypass_libs(void)
{
    SgMapScanResult res;
    int n = sg_scan_maps(ssl_bypass_blacklist, ssl_bypass_count, &res);
    if (n > 0)
    {
        for (int i = 0; i < res.count; i++)
        {
            LOGD("SSL bypass lib in maps: %s [0x%lx-0x%lx]",
                 res.matches[i].library, res.matches[i].start, res.matches[i].end);
        }
        return 1;
    }
    return 0;
}
