# 下载 ONNX 模型文件到 UI/resources/
# 这些模型是 FaceWinUnlock-Tauri 人脸识别必需的

$ResourceDir = "$PSScriptRoot"

Write-Host "=== 下载 ONNX 模型文件 ===" -ForegroundColor Cyan

# 1. YuNet 人脸检测模型 (2023-03)
$yunet = "$ResourceDir\face_detection_yunet_2023mar.onnx"
if (-not (Test-Path $yunet)) {
    Write-Host "[1/3] 下载 YuNet 人脸检测模型..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx" -OutFile $yunet
    Write-Host "  ✓ YuNet 完成" -ForegroundColor Green
} else {
    Write-Host "[1/3] YuNet 已存在, 跳过" -ForegroundColor Gray
}

# 2. SFace 人脸识别模型 (2021-12)
$sface = "$ResourceDir\face_recognition_sface_2021dec.onnx"
if (-not (Test-Path $sface)) {
    Write-Host "[2/3] 下载 SFace 人脸识别模型..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx" -OutFile $sface
    Write-Host "  ✓ SFace 完成" -ForegroundColor Green
} else {
    Write-Host "[2/3] SFace 已存在, 跳过" -ForegroundColor Gray
}

# 3. 活体检测模型 (ModelScope MiniFASNetV2 → ONNX)
$liveness = "$ResourceDir\face_liveness.onnx"
if (-not (Test-Path $liveness)) {
    Write-Host "[3/3] 下载活体检测模型..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://github.com/minivision-ai/Silent-Face-Anti-Spoofing/raw/master/resources/anti_spoof_models/2.7_80x80_MiniFASNetV2.onnx" -OutFile $liveness
    Write-Host "  ✓ 活体检测模型完成" -ForegroundColor Green
} else {
    Write-Host "[3/3] 活体检测模型已存在, 跳过" -ForegroundColor Gray
}

Write-Host ""
Write-Host "=== 全部完成 ===" -ForegroundColor Cyan
Write-Host "模型文件保存在: $ResourceDir" -ForegroundColor White
