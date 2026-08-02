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

# 3. 录入一致性验证的 facenox 98.20 模型。
# 固定到已审计提交并校验哈希，避免上游分支变化导致模型与 UI 预处理契约不一致。
$liveness = "$ResourceDir\face_liveness.onnx"
$livenessSha256 = "AF2381B88F38769222ED93379E12444E2A50814575DE1C46170DE570C55A42B6"
if (-not (Test-Path $liveness)) {
    Write-Host "[3/5] 下载录入活体检测模型..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/facenox/face-antispoof-onnx/2b0a221fda633ac0aa0b0797b578580ecbbb4f81/models/best/98.20/best_model.onnx" -OutFile $liveness
} else {
    Write-Host "[3/5] 录入活体模型已存在, 校验哈希" -ForegroundColor Gray
}
$actualLivenessSha256 = (Get-FileHash -LiteralPath $liveness -Algorithm SHA256).Hash
if ($actualLivenessSha256 -ne $livenessSha256) {
    throw "录入活体模型 SHA-256 校验失败：期望 $livenessSha256，实际 $actualLivenessSha256"
}
Write-Host "  ✓ 录入活体模型哈希正确" -ForegroundColor Green

# 4. 登录阶段主活体模型。Unlock 与录入模型使用不同文件，避免模型契约误用。
$antiSpoof = "$ResourceDir\anti_spoof_mn3.onnx"
$antiSpoofSha384 = "6DE4534964B723397B3E8C995CADCF43BC007CC2F9930B95AE25F76ADCCECE5D1D4D058D0B15117B9E4A9F758424F92A"
$antiSpoofValid = (Test-Path $antiSpoof) -and
    ((Get-FileHash -LiteralPath $antiSpoof -Algorithm SHA384).Hash -eq $antiSpoofSha384)
if (-not $antiSpoofValid) {
    Write-Host "[4/5] 下载登录主活体模型..." -ForegroundColor Yellow
    $antiSpoofTemp = "$antiSpoof.download"
    Invoke-WebRequest `
        -Uri "https://storage.openvinotoolkit.org/repositories/open_model_zoo/public/2022.1/anti-spoof-mn3/anti-spoof-mn3.onnx" `
        -OutFile $antiSpoofTemp
    if ((Get-FileHash -LiteralPath $antiSpoofTemp -Algorithm SHA384).Hash -ne $antiSpoofSha384) {
        Remove-Item -LiteralPath $antiSpoofTemp -Force
        throw "登录主活体模型 SHA-384 校验失败"
    }
    Move-Item -LiteralPath $antiSpoofTemp -Destination $antiSpoof -Force
} else {
    Write-Host "[4/5] 登录主活体模型已存在且校验通过" -ForegroundColor Gray
}

# 5. 登录阶段辅助 MiniFASNetV2。它与录入阶段的 face_liveness.onnx 分开命名。
$loginLiveness = "$ResourceDir\face_liveness_mini_fasnet_v2.onnx"
$loginLivenessSha384 = "0E3EC9E62C09E3387B27E44D7C6122AC617A4F3ACF512EEB3B7D789757B5C251CCF5EE601384D58FF474CE3FC57A6B22"
$loginLivenessValid = (Test-Path $loginLiveness) -and
    ((Get-FileHash -LiteralPath $loginLiveness -Algorithm SHA384).Hash -eq $loginLivenessSha384)
if (-not $loginLivenessValid) {
    Write-Host "[5/5] 下载登录辅助活体模型..." -ForegroundColor Yellow
    $loginLivenessTemp = "$loginLiveness.download"
    Invoke-WebRequest `
        -Uri "https://github.com/minivision-ai/Silent-Face-Anti-Spoofing/raw/master/resources/anti_spoof_models/2.7_80x80_MiniFASNetV2.onnx" `
        -OutFile $loginLivenessTemp
    if ((Get-FileHash -LiteralPath $loginLivenessTemp -Algorithm SHA384).Hash -ne $loginLivenessSha384) {
        Remove-Item -LiteralPath $loginLivenessTemp -Force
        throw "登录辅助活体模型 SHA-384 校验失败"
    }
    Move-Item -LiteralPath $loginLivenessTemp -Destination $loginLiveness -Force
} else {
    Write-Host "[5/5] 登录辅助活体模型已存在且校验通过" -ForegroundColor Gray
}

# OpenVINO NPU 使用预转换 IR；CPU/其他后端继续使用 ONNX。
$ovc = Get-Command ovc -ErrorAction SilentlyContinue
if ($null -ne $ovc) {
    foreach ($model in @($yunet, $sface, $antiSpoof, $loginLiveness)) {
        $xml = [System.IO.Path]::ChangeExtension($model, ".xml")
        $bin = [System.IO.Path]::ChangeExtension($model, ".bin")
        if (-not (Test-Path $xml) -or -not (Test-Path $bin) -or
            (Get-Item -LiteralPath $xml).LastWriteTimeUtc -lt (Get-Item -LiteralPath $model).LastWriteTimeUtc) {
            & $ovc.Source $model --output_model $xml --compress_to_fp16 True
            if ($LASTEXITCODE -ne 0) {
                throw "OpenVINO IR 转换失败: $model"
            }
        }
    }
    Write-Host "  ✓ OpenVINO IR 已生成" -ForegroundColor Green
} else {
    Write-Host "  未找到 ovc，保留仓库内已有 OpenVINO IR" -ForegroundColor Gray
}

Write-Host ""
Write-Host "=== 全部完成 ===" -ForegroundColor Cyan
Write-Host "模型文件保存在: $ResourceDir" -ForegroundColor White
