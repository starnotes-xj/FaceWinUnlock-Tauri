# OpenCV Packaging And Camera Compatibility

## Runtime Layout

The installed UI, Unlock service, and Credential Provider depend on the same OpenCV 4.12 runtime. The release pipeline builds Rust outputs, obtains the maintained OpenCV/OpenVINO bundle, and packages `opencv_world4120.dll` with `FaceWinUnlock-Server.exe` under Tauri resources/NSIS mappings.

Tauri resource remapping previously omitted root-level single files from some NSIS builds. Current hooks copy the bundled runtime into the expected install location and preserve a recovery copy for the runtime healer.

Release verification must inspect the actual installer, not only `target\release`:

```text
FaceWinUnlock-Server.exe
FaceWinUnlock_Tauri.dll
opencv_world4120.dll
face_detection_yunet_2023mar.onnx
face_recognition_sface_2021dec.onnx
face_liveness.onnx
face_detection_yunet_2023mar.xml
face_detection_yunet_2023mar.bin
face_recognition_sface_2021dec.xml
face_recognition_sface_2021dec.bin
```

## Camera Backend Order

Enrollment and Unlock must use compatible capture paths. The maintained Windows fallback order is:

1. Media Foundation (MSMF)
2. DirectShow
3. OpenCV Any

MSMF hardware transforms are disabled before the first open. This avoids long blocking opens on affected Windows 10 systems while keeping enrollment and lock-screen color/exposure behavior aligned. Per-backend open duration is logged for diagnosis.

Physical cameras can complete warmup after stable frames. Virtual cameras such as NVIDIA Broadcast retain the longer fallback warmup because their initial frames may be black or malformed.

## Inference Backends

- CPU is the release-gate default and widest compatibility path.
- OpenCL and OpenCL FP16 are optional. Kernel tuning cache must use a persistent writable location.
- Intel NPU requires the packaged OpenVINO runtime and a compatible driver.
- Slow startup, repeated tuning, black consistency checks, or matching regressions should be reproduced on CPU before changing recognition logic.

## Intel NPU Model Loading (issue #32)

OpenCV 4.12's built-in ONNX importer fails on some SFace/YuNet operators with
`Cannot create opencv ngraph layer onnx node! minscalar0 ... unsupported opset:
extension`, so the NPU backend must not load `.onnx` directly.

Both Unlock (`load_models`) and the UI (`build_opencv_models`) therefore select
pre-converted **OpenVINO IR** (`.xml` + `.bin`) files when the backend is
`(2, 9)` (INFERENCE_ENGINE / NPU); all other backends keep using `.onnx`:

- `face_detection_yunet_2023mar.{xml,bin}`
- `face_recognition_sface_2021dec.{xml,bin}`

The YuNet IR is converted with a static `1,3,640,640` input. OpenCV 4.12's
OpenVINO bridge queries a concrete IR shape while creating the network, and
Intel NPU does not reliably support the dynamic YuNet path there. The runtime
letterboxes each camera frame to 640x640 before detection and maps the box and
landmarks back to the original frame, so the aspect ratio is preserved.

The liveness model intentionally remains `face_liveness.onnx` and uses
OpenCL, or CPU when OpenCL is unavailable, even when the selected primary
backend is Intel NPU. Its dynamic batch dimension is not a supported NPU
path.

`UI/resources/download_models.ps1` regenerates the IR with `ovc` whenever the
converter is on PATH and the IR is older than its ONNX source; it also
regenerates YuNet when an older non-640x640 shape is detected. The IR files
are committed so installed builds work without the converter. Blank-image
detection and SFace feature probes run at model load for non-CPU backends so a
broken NPU path falls back to CPU before the first unlock attempt.

## Camera Ownership

The UI sends `ui_release` before enrollment/preview and `ui_done` on every completion or error path. Unlock suppresses prewarm while the UI owns the camera. Manual PIN unlock also releases the device and prevents the old session from immediately reopening it.

## Regression Checks

- Build and inspect the CI installer contents.
- Test physical MSMF and DirectShow fallback cameras.
- Test at least one virtual camera when camera code changes.
- Compare enrollment and lock-screen recognition on Windows 10 and Windows 11.
- Verify no enabled face records means no camera prewarm.
- Verify camera off within 5 seconds after manual PIN unlock and UI cancellation.
- Run the enrollment and sleep/resume loops in [testing.md](testing.md).
