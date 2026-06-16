param(
    [string]$CertificatePath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $CertificatePath) {
    $repoCertificate = Join-Path $repoRoot "target\release\FaceWinUnlock-Passkey.cer"
    $installedCertificate = Join-Path $repoRoot "FaceWinUnlock-Passkey.cer"
    $CertificatePath = if (Test-Path $repoCertificate) { $repoCertificate } else { $installedCertificate }
}

Get-Process -Name PasskeyManager -ErrorAction SilentlyContinue | Stop-Process -Force
Get-AppxPackage -Name FaceWinUnlock.PasskeyManager |
    Remove-AppxPackage -ErrorAction Stop

if (Test-Path $CertificatePath) {
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
    $stores = @(
        "Cert:\CurrentUser\TrustedPeople",
        "Cert:\CurrentUser\Root"
    )

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        $stores += @(
            "Cert:\LocalMachine\TrustedPeople",
            "Cert:\LocalMachine\Root"
        )
    } else {
        Write-Warning "未以管理员运行：只清理当前用户证书；安装器导入的机器级证书需通过管理员卸载清理。"
    }

    foreach ($store in $stores) {
        Get-ChildItem $store -ErrorAction SilentlyContinue |
            Where-Object Thumbprint -eq $certificate.Thumbprint |
            Remove-Item -Force
    }
}

Write-Host "FaceWinUnlock Passkey package removed." -ForegroundColor Green
