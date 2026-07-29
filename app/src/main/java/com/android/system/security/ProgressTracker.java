package com.android.system.security;

import android.content.Context;
import android.util.Log;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks which capabilities work on the target device.
 * Writes a detailed capability report to device storage.
 * Used to understand what's available without guessing.
 */
public class ProgressTracker {

    private static final String TAG = "ProgressTracker";
    private static final String REPORT_FILE = "capability_report.txt";

    private final Context context;
    private final Map<String, CapabilityEntry> capabilities = new ConcurrentHashMap<>();
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);

    public ProgressTracker(Context context) {
        this.context = context;
    }

    /**
     * Record a capability attempt with result.
     */
    public void record(String capability, boolean success, String detail) {
        CapabilityEntry entry = capabilities.get(capability);
        if (entry == null) {
            entry = new CapabilityEntry(capability);
            capabilities.put(capability, entry);
        }

        if (success) {
            entry.successCount++;
        } else {
            entry.failCount++;
        }
        entry.lastAttempt = System.currentTimeMillis();
        entry.lastDetail = detail;
        entry.lastSuccess = success;

        if (success) {
            Log.i(TAG, "[OK] " + capability + " — " + detail);
        } else {
            Log.w(TAG, "[FAIL] " + capability + " — " + detail);
        }
    }

    /**
     * Check if a capability has ever succeeded.
     */
    public boolean isWorking(String capability) {
        CapabilityEntry entry = capabilities.get(capability);
        return entry != null && entry.successCount > 0;
    }

    /**
     * Get a summary of all capabilities.
     */
    public Map<String, Object> getSummary() {
        Map<String, Object> summary = new HashMap<>();
        summary.put("timestamp", System.currentTimeMillis());
        summary.put("device", android.os.Build.MODEL + " (API " + android.os.Build.VERSION.SDK_INT + ")");

        Map<String, Object> caps = new LinkedHashMap<>();
        for (CapabilityEntry entry : capabilities.values()) {
            Map<String, Object> cap = new HashMap<>();
            cap.put("working", entry.successCount > 0);
            cap.put("success", entry.successCount);
            cap.put("failures", entry.failCount);
            cap.put("last_detail", entry.lastDetail);
            cap.put("last_attempt", dateFormat.format(new Date(entry.lastAttempt)));
            caps.put(entry.name, cap);
        }
        summary.put("capabilities", caps);

        int working = 0;
        for (CapabilityEntry e : capabilities.values()) {
            if (e.successCount > 0) working++;
        }
        summary.put("working_count", working);
        summary.put("total", capabilities.size());

        return summary;
    }

    /**
     * Write a human-readable report to the device.
     */
    public void writeReport() {
        try {
            File reportFile = new File(context.getExternalFilesDir(null), REPORT_FILE);
            File parent = reportFile.getParentFile();
            if (parent != null) parent.mkdirs();

            try (PrintWriter pw = new PrintWriter(new FileWriter(reportFile))) {
                pw.println("╔══════════════════════════════════════════════╗");
                pw.println("║    CAPABILITY PROGRESS REPORT                ║");
                pw.println("║    Generated: " + dateFormat.format(new Date()) + "         ║");
                pw.println("║    Device: " + android.os.Build.MODEL + " (API " + android.os.Build.VERSION.SDK_INT + ")");
                pw.println("╚══════════════════════════════════════════════╝");
                pw.println();

                int working = 0;
                for (CapabilityEntry entry : capabilities.values()) {
                    String status = entry.successCount > 0 ? "[✓]" : "[✗]";
                    if (entry.successCount > 0) working++;

                    pw.printf("%s %s%n", status, entry.name);
                    pw.printf("    Success: %d  |  Failures: %d%n", entry.successCount, entry.failCount);
                    pw.printf("    Last: %s%n", entry.lastDetail);
                    pw.printf("    Time: %s%n", dateFormat.format(new Date(entry.lastAttempt)));
                    pw.println();
                }

                pw.printf("Working: %d/%d capabilities%n", working, capabilities.size());
            }

            Log.i(TAG, "Report written to: " + reportFile.getAbsolutePath());

        } catch (Exception e) {
            Log.w(TAG, "Failed to write report: " + e.getMessage());
        }
    }

    // ============================================================

    private static class CapabilityEntry {
        final String name;
        int successCount = 0;
        int failCount = 0;
        long lastAttempt = 0;
        String lastDetail = "";
        boolean lastSuccess = false;

        CapabilityEntry(String name) {
            this.name = name;
        }
    }

    /**
     * Quick one-liner for inline capability checks.
     */
    public static class Check {
        private final ProgressTracker tracker;
        private final String name;

        public Check(ProgressTracker tracker, String name) {
            this.tracker = tracker;
            this.name = name;
        }

        public boolean ok(String detail) {
            tracker.record(name, true, detail);
            return true;
        }

        public boolean fail(String detail) {
            tracker.record(name, false, detail);
            return false;
        }

        public boolean result(boolean success, String detail) {
            tracker.record(name, success, detail);
            return success;
        }
    }
}
