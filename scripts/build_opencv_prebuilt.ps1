<#
.SYNOPSIS
  本地预构建 OpenCV（含 OpenVINO 支持），生成 zip 供 CI 工作流直接下载使用。
  目的：避免每次 release 在 CI 中从源码编译 OpenCV（~17 分钟）。

.DESCRIPTION
  使用与 release.yml 相同的 CMake 参数编译 OpenCV，输出到 .\opencv-prebuilt\ 目录，
  自动打包为 opencv-<VERSION>-prebuilt.zip。

  前置要求：
    - Visual Studio 2022 (含 C++ 桌面开发工作负载)
    - CMake 3.15+
    - OpenVINO 运行时（从 https://storage.openvinotoolkit.org 下载）
    - Git

.PARAMETER OpenCVVersion
  OpenCV 版本号，默认 4.12.0

.PARAMETER OpenVINOVersion
  OpenVINO 版本号，默认 2024.6

.PARAMETER InstallDir
  OpenCV 安装目标目录，默认 .\opencv-prebuilt\install

.PARAMETER OpenVINODir
  OpenVINO 运行时目录（已解压的），留空则自动下载

.EXAMPLE
  .\scripts\build_opencv_prebuilt.ps1

.EXAMPLE
  .\scripts\build_opencv_prebuilt.ps1 -OpenCVVersion "4.10.0" -OpenVINOVersion "2024.5"
#>

param(
    [string]$OpenCVVersion = "4.12.0",
    [string]$OpenVINOVersion = "2024.6",
    [string]$InstallDir = "$PSScriptRoot\..\opencv-prebuilt\install",
    [string]$OpenVINODir = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$workspace = "$PSScriptRoot\..\opencv-prebuilt"
$srcDir = "$workspace\opencv-src"
$buildDir = "$workspace\opencv-build"
$zipOutput = "$PSScriptRoot\..\opencv-${OpenCVVersion}-prebuilt.zip"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " OpenCV 预构建脚本" -ForegroundColor Cyan
Write-Host "   OpenCV: $OpenCVVersion" -ForegroundColor Cyan
Write-Host "   OpenVINO: $OpenVINOVersion" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# ---- 0. 清理旧构建 ----
if (Test-Path $workspace) {
    Write-Host "清理旧构建目录..." -ForegroundColor Yellow
    Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $workspace -Force | Out-Null
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

# ---- 1. 准备 OpenVINO 运行时 ----
if (-not $OpenVINODir) {
    Write-Host ""
    Write-Host "[1/5] 下载 OpenVINO 运行时..." -ForegroundColor Green
    $treeUrl = "https://storage.openvinotoolkit.org/filetree.json"
    Write-Host "  解析 filetree.json..."
    $tree = (Invoke-WebRequest -Uri $treeUrl -UseBasicParsing).Content
    $pattern = "w_openvino_toolkit_windows_" + [regex]::Escape($OpenVINOVersion) + "[^`"]*_x86_64\.zip"
    $zipName = [regex]::Matches($tree, $pattern) | ForEach-Object { $_.Value } |
        Where-Object { $_ -notmatch 'dev|nightly|rc|pre|beta' } | Sort-Object -Unique | Select-Object -First 1
    if (-not $zipName) {
        throw "在 filetree.json 中找不到 OpenVINO $OpenVINOVersion 的正式发布包"
    }

    $baseUrl = "https://storage.openvinotoolkit.org/repositories/openvino/packages/$OpenVINOVersion/windows/"
    $url = $baseUrl + $zipName
    $ovZip = "$workspace\openvino.zip"
    Write-Host "  下载: $url"
    Invoke-WebRequest -Uri $url -OutFile $ovZip -RetryIntervalSec 10 -MaximumRetryCount 3
    Write-Host "  解压..."
    Expand-Archive -Path $ovZip -DestinationPath "$workspace\openvino_tmp" -Force
    $extracted = Get-ChildItem "$workspace\openvino_tmp" -Directory | Select-Object -First 1
    $OpenVINODir = "$workspace\openvino"
    Move-Item $extracted.FullName $OpenVINODir
    Remove-Item "$workspace\openvino_tmp" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $ovZip -Force
} else {
    Write-Host ""
    Write-Host "[1/5] 使用已有 OpenVINO: $OpenVINODir" -ForegroundColor Green
}

$ovCmake = "$OpenVINODir\runtime\cmake"
if (-not (Test-Path $ovCmake)) {
    throw "OpenVINO cmake 配置未找到: $ovCmake"
}
Write-Host "  OpenVINO_DIR = $ovCmake"

# ---- 2. 下载 OpenCV 源码 ----
Write-Host ""
Write-Host "[2/5] 下载 OpenCV $OpenCVVersion 源码..." -ForegroundColor Green
$srcZip = "$workspace\opencv-src.zip"
$url = "https://github.com/opencv/opencv/archive/refs/tags/$OpenCVVersion.zip"
Invoke-WebRequest -Uri $url -OutFile $srcZip -RetryIntervalSec 10 -MaximumRetryCount 3
Expand-Archive -Path $srcZip -DestinationPath "$workspace\opencv_src_tmp" -Force
$extracted = Get-ChildItem "$workspace\opencv_src_tmp" -Directory | Select-Object -First 1
Move-Item $extracted.FullName $srcDir
Remove-Item $srcZip -Force
Remove-Item "$workspace\opencv_src_tmp" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "  源码已就绪: $srcDir"

# ---- 3. CMake 配置 ----
Write-Host ""
Write-Host "[3/5] CMake 配置 (WITH_OPENVINO=ON)..." -ForegroundColor Green
cmake -S $srcDir -B $buildDir -G "Visual Studio 17 2022" -A x64 `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_INSTALL_PREFIX="$InstallDir" `
    -DBUILD_opencv_world=ON `
    -DBUILD_LIST="core,imgproc,imgcodecs,dnn,objdetect,videoio,calib3d,features2d,flann,photo,highgui" `
    -DWITH_OPENVINO=ON `
    -DOpenVINO_DIR="$ovCmake" `
    -DBUILD_TESTS=OFF `
    -DBUILD_PERF_TESTS=OFF `
    -DBUILD_EXAMPLES=OFF `
    -DBUILD_DOCS=OFF `
    -DBUILD_opencv_apps=OFF `
    -DBUILD_opencv_python3=OFF `
    -DBUILD_JAVA=OFF `
    -DWITH_FFMPEG=OFF

if ($LASTEXITCODE -ne 0) { throw "CMake 配置失败" }

# ---- 4. 编译 & 安装 ----
Write-Host ""
Write-Host "[4/5] 编译 OpenCV（可能需要 10-20 分钟）..." -ForegroundColor Green
$sw = [System.Diagnostics.Stopwatch]::StartNew()
cmake --build $buildDir --config Release --target install --parallel
if ($LASTEXITCODE -ne 0) { throw "OpenCV 编译失败" }
$sw.Stop()
Write-Host "  编译完成，耗时: $([math]::Round($sw.Elapsed.TotalMinutes, 1)) 分钟" -ForegroundColor Yellow

# ---- 5. 校验 & 打包 ----
Write-Host ""
Write-Host "[5/5] 校验 & 打包..." -ForegroundColor Green

$worldLib = Get-ChildItem $InstallDir -Recurse -Filter "opencv_world*.lib" | Select-Object -First 1
$worldDll = Get-ChildItem $InstallDir -Recurse -Filter "opencv_world*.dll" | Select-Object -First 1
if (-not $worldLib) { throw "未找到 opencv_world*.lib，编译可能未成功" }
if (-not $worldDll) { throw "未找到 opencv_world*.dll，编译可能未成功" }

Write-Host "  库文件: $($worldLib.FullName)"
Write-Host "  DLL: $($worldDll.FullName)"
Write-Host "  Include: $InstallDir\include"

# 打包
$files = Get-ChildItem $InstallDir -Recurse -File
Write-Host "  打包 $($files.Count) 个文件..."
Compress-Archive -Path "$InstallDir\*" -DestinationPath $zipOutput -Force

$zipSize = [math]::Round((Get-Item $zipOutput).Length / 1MB, 1)
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  预构建完成！" -ForegroundColor Green
Write-Host "  输出文件: $zipOutput ($zipSize MB)" -ForegroundColor Green
Write-Host ""
Write-Host "  下一步：" -ForegroundColor Yellow
Write-Host "  1. 在 GitHub 上创建 Release: opencv-prebuilt-v1" -ForegroundColor Yellow
Write-Host "  2. 上传 $zipOutput 作为 Release Asset" -ForegroundColor Yellow
Write-Host "  3. CI 工作流将自动下载使用" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Green
