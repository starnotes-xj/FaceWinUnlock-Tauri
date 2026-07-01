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

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not (Test-Path $PackagePath)) {
    throw "Passkey plugin package not found: $PackagePath"
}

if (Test-Path $CertificatePath) {
    # A self-signed MSIX must chain to a trusted root. Machine-level trust
    # matches the NSIS installer and requires administrator privileges.
    if ($isAdmin) {
        Import-Certificate -FilePath $CertificatePath -CertStoreLocation Cert:\LocalMachine\TrustedPeople | Out-Null
        Import-Certificate -FilePath $CertificatePath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    } else {
        Import-Certificate -FilePath $CertificatePath -CertStoreLocation Cert:\CurrentUser\TrustedPeople | Out-Null
        Write-Warning "Not running as admin: the certificate was imported only into CurrentUser\TrustedPeople. Re-run as admin if Add-AppxPackage reports 0x800B0109."
    }
}

$sample = Get-AppxPackage -Name Contoso.PasskeyManager -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $sample -and $isAdmin) {
    $sample = Get-AppxPackage -AllUsers -Name Contoso.PasskeyManager -ErrorAction SilentlyContinue | Select-Object -First 1
}
if ($sample -and -not $ReplaceSample) {
    throw "Contoso test plugin is installed. Re-run with -ReplaceSample only after confirming its local passkeys may be deleted."
}

Get-Process -Name PasskeyManager -ErrorAction SilentlyContinue | Stop-Process -Force
if ($sample -and $ReplaceSample) {
    # Merge both package views so the sample plugin is removed in every context.
    $samplePkgs = @(Get-AppxPackage -Name Contoso.PasskeyManager -ErrorAction SilentlyContinue)
    if ($isAdmin) { $samplePkgs += @(Get-AppxPackage -AllUsers -Name Contoso.PasskeyManager -ErrorAction SilentlyContinue) }
    if ($samplePkgs.Count -gt 1) { $samplePkgs = $samplePkgs | Sort-Object PackageFullName -Unique }
    $samplePkgs | Remove-AppxPackage -ErrorAction Stop
}

$existing = Get-AppxPackage -Name FaceWinUnlock.PasskeyManager -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $existing -and $isAdmin) {
    $existing = Get-AppxPackage -AllUsers -Name FaceWinUnlock.PasskeyManager -ErrorAction SilentlyContinue | Select-Object -First 1
}
if ($existing) {
    Add-AppxPackage -Update -Path $PackagePath -ForceApplicationShutdown -ForceUpdateFromAnyVersion
} else {
    Add-AppxPackage -Path $PackagePath -ForceApplicationShutdown -ForceUpdateFromAnyVersion
}

$package = Get-AppxPackage -Name FaceWinUnlock.PasskeyManager -ErrorAction SilentlyContinue
if (-not $package -and $isAdmin) {
    $package = Get-AppxPackage -AllUsers -Name FaceWinUnlock.PasskeyManager -ErrorAction SilentlyContinue | Select-Object -First 1
}
if (-not $package) {
    throw "FaceWinUnlock Passkey package was not installed."
}

if ($OpenManager) {
    Start-Process "shell:AppsFolder\$($package.PackageFamilyName)!FaceWinUnlock.PasskeyManager"
}
Write-Host "FaceWinUnlock Passkey installed. Open its management window to register and enable the provider." -ForegroundColor Green
Write-Host "Windows passkey advanced settings require one system verification when enabling the provider." -ForegroundColor Yellow
