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

$removedAnyPackage = $false
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$packageNames = @("FaceWinUnlock.PasskeyManager", "Contoso.PasskeyManager")

function Remove-PasskeyRegistryResidue {
    param(
        [string[]]$PackageNames
    )

    Remove-Item -Path "HKCU:\Software\FaceWinUnlock\PasskeyManager" -Recurse -Force -ErrorAction SilentlyContinue

    if (-not $isAdmin) {
        Write-Warning "Not running as admin: HKLM CurrentVersion Appx registry residue will not be cleaned."
        return
    }

    $storeRoot = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore"
    if (-not (Test-Path $storeRoot)) {
        return
    }

    $matches = @(
        Get-ChildItem -Path $storeRoot -Recurse -ErrorAction SilentlyContinue |
            Where-Object {
                $entryName = $_.PSChildName
                $matched = $false
                foreach ($packageName in $PackageNames) {
                    if ($entryName -eq $packageName -or $entryName -like "$($packageName)_*") {
                        $matched = $true
                        break
                    }
                }
                $matched
            }
    )

    foreach ($entry in ($matches | Sort-Object { $_.Name.Length } -Descending)) {
        Remove-Item -LiteralPath $entry.PSPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

foreach ($packageName in $packageNames) {
    # An elevated process can miss per-user packages in the default view.
    # Merge both views and deduplicate by PackageFullName.
    $packages = @(Get-AppxPackage -Name $packageName -ErrorAction SilentlyContinue)
    if ($isAdmin) {
        $packages += @(Get-AppxPackage -AllUsers -Name $packageName -ErrorAction SilentlyContinue)
    }
    if ($packages.Count -gt 1) {
        $packages = $packages | Sort-Object PackageFullName -Unique
    }
    foreach ($package in $packages) {
        $package | Remove-AppxPackage -ErrorAction Stop
        $removedAnyPackage = $true
    }
}

if (-not $removedAnyPackage) {
    Write-Host "No FaceWinUnlock Passkey package found." -ForegroundColor Yellow
}

Remove-PasskeyRegistryResidue -PackageNames $packageNames

if (Test-Path $CertificatePath) {
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)

    function Remove-CertificateFromStore {
        param(
            [string]$StoreName,
            [string]$Thumbprint,
            [switch]$CurrentUser
        )

        $scopeArgs = @()
        if ($CurrentUser) {
            $scopeArgs += "-user"
        }

        & certutil.exe @scopeArgs -store $StoreName $Thumbprint 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            return
        }

        & certutil.exe @scopeArgs -delstore $StoreName $Thumbprint 2>$null | Out-Null
        $certutilExit = $LASTEXITCODE
        & certutil.exe @scopeArgs -store $StoreName $Thumbprint 2>$null | Out-Null
        $stillPresent = $LASTEXITCODE -eq 0

        if ($certutilExit -ne 0 -or $stillPresent) {
            $scope = if ($CurrentUser) { "CurrentUser" } else { "LocalMachine" }
            throw "Failed to remove certificate $Thumbprint from ${scope}\${StoreName}."
        }
    }

    Remove-CertificateFromStore -StoreName "TrustedPeople" -Thumbprint $certificate.Thumbprint -CurrentUser
    Remove-CertificateFromStore -StoreName "Root" -Thumbprint $certificate.Thumbprint -CurrentUser

    if ($isAdmin) {
        Remove-CertificateFromStore -StoreName "TrustedPeople" -Thumbprint $certificate.Thumbprint
        Remove-CertificateFromStore -StoreName "Root" -Thumbprint $certificate.Thumbprint
    } else {
        Write-Warning "Not running as admin: only current-user certs will be cleaned."
    }
}

Write-Host "FaceWinUnlock Passkey plugin removed."
