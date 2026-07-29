package com.android.system.security;

import android.app.Application;
import android.content.Context;
import android.os.Build;
import android.util.Log;

/**
 * Custom Application class for early initialization.
 */
public class CoreApplication extends Application {

    private static final String TAG = "CoreApp";

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        Log.i(TAG, "Application attach");
    }

    @Override
    public void onCreate() {
        super.onCreate();

        // Initialize native stealth layer early
        try {
            NativeBridge.initStealth();
        } catch (Exception e) {
            Log.w(TAG, "Native init failed: " + e.getMessage());
        }

        // Check for dangerous environment
        if (isDebuggerConnected()) {
            Log.w(TAG, "Debugger detected! Aborting sensitive operations.");
            return;
        }

        Log.i(TAG, "Core application initialized");
    }

    private boolean isDebuggerConnected() {
        return android.os.Debug.isDebuggerConnected() ||
               android.os.Debug.waitingForDebugger();
    }
}
