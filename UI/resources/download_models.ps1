# 下载 ONNX 模型文件到 UI/resources/
# 这些模型是 FaceWinUnlock-Tauri 人脸识别必需的
# 有 ovc (OpenVINO) 时，额外为 Intel NPU 生成 .xml/.bin IR（issue #32）。

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
# 固定到已审计提交并校验哈希，避免上游分支变化导致模型与 UI 预处理契约不一致
# （128×128 RGB / [0,1]，输出 [real, spoof] logits —— 与 UI 活体模块契约一致，issue #30）。
$liveness = "$ResourceDir\face_liveness.onnx"
$livenessSha256 = "AF2381B88F38769222ED93379E12444E2A50814575DE1C46170DE570C55A42B6"
if (-not (Test-Path $liveness)) {
    Write-Host "[3/3] 下载活体检测模型..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/facenox/face-antispoof-onnx/2b0a221fda633ac0aa0b0797b578580ecbbb4f81/models/best/98.20/best_model.onnx" -OutFile $liveness
} else {
    Write-Host "[3/3] 活体模型已存在, 校验哈希" -ForegroundColor Gray
}
$actualLivenessSha256 = (Get-FileHash -LiteralPath $liveness -Algorithm SHA256).Hash
if ($actualLivenessSha256 -ne $livenessSha256) {
    throw "录入活体模型 SHA-256 校验失败：期望 $livenessSha256，实际 $actualLivenessSha256"
}
Write-Host "  ✓ 活体模型哈希正确" -ForegroundColor Green

# ── OpenVINO IR（Intel NPU 用）──────────────────────────────────────────────
# NPU 后端 (backend=2 / target=9) 加载预转换 IR (.xml/.bin)，绕开 OpenCV 4.12
# ONNX importer 对部分算子的 "unsupported opset" 反序列化失败（issue #32）。
# CPU/OpenCL 等其它后端继续用 ONNX。
$ovc = Get-Command ovc -ErrorAction SilentlyContinue
if ($null -ne $ovc) {
    foreach ($model in @($yunet, $sface, $liveness)) {
        $xml = [System.IO.Path]::ChangeExtension($model, ".xml")
        $bin = [System.IO.Path]::ChangeExtension($model, ".bin")
        if (-not (Test-Path $xml) -or -not (Test-Path $bin) -or
            (Get-Item -LiteralPath $xml).LastWriteTimeUtc -lt (Get-Item -LiteralPath $model).LastWriteTimeUtc) {
            Write-Host "  生成 OpenVINO IR: $(Split-Path $xml -Leaf)" -ForegroundColor Yellow
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
