# FaceWinUnlock-Tauri 一键构建脚本
# 用法: 在 PowerShell 中运行 .\build.ps1
# 前置条件:
#   1. Rust 已安装在 D:\Rust
#   2. Node.js 已安装
#   3. OpenCV DLL 在 D:\OpenCV\build\x64\vc16\bin\ (如需修改路径见 tauri.conf.json)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " FaceWinUnlock-Tauri 构建脚本" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# ── 1. 设置 Rust 环境 ──────────────────────────────────────
Write-Host "`n[1/4] 设置 Rust 环境..." -ForegroundColor Yellow
$env:RUSTUP_HOME = "D:\Rust"
$env:CARGO_HOME  = "D:\Rust\CARGO"
$env:PATH        = "D:\Rust\CARGO\bin;" + $env:PATH

# 验证 cargo 可用
try {
    cargo --version 2>&1 | Out-Null
    Write-Host "  cargo 版本: $(cargo --version)" -ForegroundColor Green
} catch {
    Write-Host "  [错误] cargo 未找到，请检查 D:\Rust\CARGO\bin" -ForegroundColor Red
    exit 1
}

# ── 2. 构建 Rust 项目 (工作区: Server + Unlock + UI) ─────────
Write-Host "`n[2/4] 构建 Rust 工作区 (Server DLL + Unlock EXE + UI)..." -ForegroundColor Yellow
Write-Host "  这可能需要几分钟，取决于 CPU 性能..." -ForegroundColor Gray

Push-Location $ScriptDir
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "cargo build 失败" }
    Write-Host "  Rust 构建完成" -ForegroundColor Green
} finally {
    Pop-Location
}

# ── 3. 验证关键产物 ─────────────────────────────────────────
Write-Host "`n[3/4] 验证构建产物..." -ForegroundColor Yellow

$targetDir = Join-Path $ScriptDir "target\release"
$dll  = Join-Path $targetDir "FaceWinUnlock_Tauri.dll"
$exe  = Join-Path $targetDir "FaceWinUnlock-Server.exe"
$ui   = Join-Path $targetDir "facewinunlock-tauri.exe"

$allGood = $true
if (-not (Test-Path $dll)) {
    Write-Host "  [缺失] $dll" -ForegroundColor Red
    $allGood = $false
} else {
    Write-Host "  [✓] Server DLL: FaceWinUnlock_Tauri.dll ($((Get-Item $dll).Length) bytes)" -ForegroundColor Green
}

if (-not (Test-Path $exe)) {
    Write-Host "  [缺失] $exe" -ForegroundColor Red
    $allGood = $false
} else {
    Write-Host "  [✓] Unlock EXE: FaceWinUnlock-Server.exe ($((Get-Item $exe).Length) bytes)" -ForegroundColor Green
}

if (-not (Test-Path $ui)) {
    Write-Host "  [缺失] $ui" -ForegroundColor Red
    $allGood = $false
} else {
    Write-Host "  [✓] UI EXE: facewinunlock-tauri.exe ($((Get-Item $ui).Length) bytes)" -ForegroundColor Green
}

if (-not $allGood) {
    Write-Host "`n  构建产物不完整，请检查上方缺失项" -ForegroundColor Red
    exit 1
}

# ── 4. 构建 Tauri 安装包 (NSIS) ─────────────────────────────
Write-Host "`n[4/4] 构建 Tauri 安装包..." -ForegroundColor Yellow
Push-Location (Join-Path $ScriptDir "UI")
try {
    # 首次构建需要 npm install
    if (-not (Test-Path "node_modules")) {
        Write-Host "  首次构建，正在 npm install..." -ForegroundColor Gray
        npm install
    }

    npm run tauri build
    if ($LASTEXITCODE -ne 0) { throw "tauri build 失败" }
    Write-Host "  Tauri 安装包构建完成" -ForegroundColor Green
} finally {
    Pop-Location
}

# ── 输出结果 ─────────────────────────────────────────────────
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " 构建完成！" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

# workspace 模式下 Tauri 输出到根 target/release/bundle/
$bundleDir = Join-Path $ScriptDir "target\release\bundle"
$installer = $null
if (Test-Path $bundleDir) {
    $installer = Get-ChildItem -Path $bundleDir -Filter "*.exe" -Recurse |
        Where-Object { $_.Name -like "*setup*" -or $_.Name -like "*install*" } |
        Select-Object -First 1
}

if ($installer) {
    Write-Host "`n  NSIS 安装包: $($installer.FullName)" -ForegroundColor Green
} else {
    # 可能是 msi 格式
    if (Test-Path $bundleDir) {
        $msi = Get-ChildItem -Path $bundleDir -Filter "*.msi" -Recurse | Select-Object -First 1
        if ($msi) {
            Write-Host "`n  MSI 安装包: $($msi.FullName)" -ForegroundColor Green
        }
    }
    if (-not $installer -and -not $msi) {
        Write-Host "`n  安装包路径: $bundleDir" -ForegroundColor Yellow
        Write-Host "  请在该目录下查找 .exe 或 .msi 文件" -ForegroundColor Yellow
    }
}
