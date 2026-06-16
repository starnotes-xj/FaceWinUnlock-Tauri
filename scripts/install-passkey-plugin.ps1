param(
    [string]$PackagePath = "",
    [string]$CertificatePath = "",
    [switch]$ReplaceSample,
    [switch]$OpenManager
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $PackagePath) {
    $repoPackage = Join-Path $repoRoot "target\release\FaceWinUnlock-Passkey.msix"
    $installedPackage = Join-Path $repoRoot "FaceWinUnlock-Passkey.msix"
    $PackagePath = if (Test-Path $repoPackage) { $repoPackage } else { $installedPackage }
}
if (-not $CertificatePath) {
    $repoCertificate = Join-Path $repoRoot "target\release\FaceWinUnlock-Passkey.cer"
    $installedCertificate = Join-Path $repoRoot "FaceWinUnlock-Passkey.cer"
    $CertificatePath = if (Test-Path $repoCertificate) { $repoCertificate } else { $installedCertificate }
}

if (-not (Test-Path $PackagePath)) {
    throw "Passkey plugin package not found: $PackagePath"
}

if (Test-Path $CertificatePath) {
    # 自签名 MSIX 部署要求签名链终结于“受信任的根”。机器级信任需要管理员权限：
    # 提权时导入 LocalMachine\TrustedPeople + Root（与 NSIS 安装器 hooks.nsh 一致），
    # 否则 Add-AppxPackage 会报 0x800B0109（应用包签名的根证书必须是受信任的证书）。
    # 非提权时退回 CurrentUser\TrustedPeople（对自签名通常不足）并给出明确提示。
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Import-Certificate -FilePath $CertificatePath -CertStoreLocation Cert:\LocalMachine\TrustedPeople | Out-Null
        Import-Certificate -FilePath $CertificatePath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    } else {
        Import-Certificate -FilePath $CertificatePath -CertStoreLocation Cert:\CurrentUser\TrustedPeople | Out-Null
        Write-Warning "未以管理员运行：证书仅导入 CurrentUser\TrustedPeople，自签名包可能因根证书不受信任而安装失败 (0x800B0109)。请以管理员重跑，或让安装器完成机器级证书信任。"
    }
}

$sample = Get-AppxPackage -Name Contoso.PasskeyManager | Select-Object -First 1
if ($sample -and -not $ReplaceSample) {
    throw "Contoso test plugin is installed. Re-run with -ReplaceSample only after confirming its local passkeys may be deleted."
}

Get-Process -Name PasskeyManager -ErrorAction SilentlyContinue | Stop-Process -Force
if ($sample -and $ReplaceSample) {
    $sample | Remove-AppxPackage -ErrorAction Stop
}
Add-AppxPackage -Path $PackagePath -ForceApplicationShutdown -ForceUpdateFromAnyVersion

$package = Get-AppxPackage -Name FaceWinUnlock.PasskeyManager
if (-not $package) {
    throw "FaceWinUnlock Passkey package was not installed."
}

if ($OpenManager) {
    Start-Process "shell:AppsFolder\$($package.PackageFamilyName)!FaceWinUnlock.PasskeyManager"
}
Write-Host "FaceWinUnlock Passkey installed. Open its management window to register and enable the provider." -ForegroundColor Green
Write-Host "Windows passkey advanced settings require one system verification when enabling the provider." -ForegroundColor Yellow
