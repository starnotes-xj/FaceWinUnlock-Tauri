# 下载 ONNX 模型文件到 UI/resources/
# 这些模型是 FaceWinUnlock-Tauri 人脸识别必需的

$ResourceDir = "$PSScriptRoot"

Write-Host "=== 下载 ONNX 模型文件 ===" -ForegroundColor Cyan

# 1. YuNet 人脸检测模型 (2023-03)
$yunet = "$ResourceDir\face_detection_yunet_2023mar.onnx"
if (-not (Test-Path $yunet)) {
    Write-Host "[1/5] 下载 YuNet 人脸检测模型..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx" -OutFile $yunet
    Write-Host "  ✓ YuNet 完成" -ForegroundColor Green
} else {
    Write-Host "[1/5] YuNet 已存在, 跳过" -ForegroundColor Gray
}

# 2. SFace 人脸识别模型 (2021-12)
$sface = "$ResourceDir\face_recognition_sface_2021dec.onnx"
if (-not (Test-Path $sface)) {
    Write-Host "[2/5] 下载 SFace 人脸识别模型..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx" -OutFile $sface
    Write-Host "  ✓ SFace 完成" -ForegroundColor Green
} else {
    Write-Host "[2/5] SFace 已存在, 跳过" -ForegroundColor Gray
}

# 3. Open Model Zoo anti-spoof-mn3（主活体模型）
$antiSpoof = "$ResourceDir\anti_spoof_mn3.onnx"
$antiSpoofSha384 = "6DE4534964B723397B3E8C995CADCF43BC007CC2F9930B95AE25F76ADCCECE5D1D4D058D0B15117B9E4A9F758424F92A"
$antiSpoofValid = (Test-Path $antiSpoof) -and
    ((Get-FileHash $antiSpoof -Algorithm SHA384).Hash -eq $antiSpoofSha384)
if (-not $antiSpoofValid) {
    Write-Host "[3/5] 下载 anti-spoof-mn3 活体检测模型..." -ForegroundColor Yellow
    $antiSpoofTemp = "$antiSpoof.download"
    Invoke-WebRequest `
        -Uri "https://storage.openvinotoolkit.org/repositories/open_model_zoo/public/2022.1/anti-spoof-mn3/anti-spoof-mn3.onnx" `
        -OutFile $antiSpoofTemp
    if ((Get-FileHash $antiSpoofTemp -Algorithm SHA384).Hash -ne $antiSpoofSha384) {
        Remove-Item $antiSpoofTemp -Force
        throw "anti-spoof-mn3 SHA-384 校验失败"
    }
    Move-Item $antiSpoofTemp $antiSpoof -Force
    Write-Host "  ✓ anti-spoof-mn3 完成并通过 SHA-384 校验" -ForegroundColor Green
} else {
    Write-Host "[3/5] anti-spoof-mn3 已存在且校验通过, 跳过" -ForegroundColor Gray
}

# 4. MiniFASNetV2（辅助活体模型）
$liveness = "$ResourceDir\face_liveness.onnx"
$livenessSha384 = "0E3EC9E62C09E3387B27E44D7C6122AC617A4F3ACF512EEB3B7D789757B5C251CCF5EE601384D58FF474CE3FC57A6B22"
$livenessValid = (Test-Path $liveness) -and
    ((Get-FileHash $liveness -Algorithm SHA384).Hash -eq $livenessSha384)
if (-not $livenessValid) {
    Write-Host "[4/5] 下载 MiniFASNetV2 活体检测模型..." -ForegroundColor Yellow
    $livenessTemp = "$liveness.download"
    Invoke-WebRequest `
        -Uri "https://github.com/minivision-ai/Silent-Face-Anti-Spoofing/raw/master/resources/anti_spoof_models/2.7_80x80_MiniFASNetV2.onnx" `
        -OutFile $livenessTemp
    if ((Get-FileHash $livenessTemp -Algorithm SHA384).Hash -ne $livenessSha384) {
        Remove-Item $livenessTemp -Force
        throw "MiniFASNetV2 SHA-384 校验失败"
    }
    Move-Item $livenessTemp $liveness -Force
    Write-Host "  ✓ MiniFASNetV2 完成并通过 SHA-384 校验" -ForegroundColor Green
} else {
    Write-Host "[4/5] MiniFASNetV2 已存在且校验通过, 跳过" -ForegroundColor Gray
}

# 5. 68点人脸关键点模型 (PIPNet, 用于静默眨眼检测)
$landmark = "$ResourceDir\face_landmark_68.onnx"
if (-not (Test-Path $landmark)) {
    Write-Host "[5/5] 下载68点人脸关键点模型..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://github.com/yakhyo/pipnet-onnx/releases/download/weights/pipnet_r18_300w_celeba_68.onnx" -OutFile $landmark
    Write-Host "  ✓ 关键点模型完成" -ForegroundColor Green
} else {
    Write-Host "[5/5] 关键点模型已存在, 跳过" -ForegroundColor Gray
}

Write-Host ""
Write-Host "=== 全部完成 ===" -ForegroundColor Cyan
Write-Host "模型文件保存在: $ResourceDir" -ForegroundColor White
