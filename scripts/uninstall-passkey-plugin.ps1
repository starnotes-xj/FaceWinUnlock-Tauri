param(
    [string]$CertificatePath = "",
    # 保留模式（默认行为由调用方传入）：Remove-AppxPackage 用 -PreserveApplicationData 留住
    # LocalState 凭据元数据；不删证书/注册表/KSP 私钥，便于重装后免重新注册。
    [switch]$PreserveApplicationData,
    # 彻底清除：删 MSIX 数据 + 证书 + 注册表残留 + KSP 私钥(facewinunlock/*)。
    [switch]$Purge
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

# 卸载前先让插件以自身身份反注册 WebAuthn 认证器。认证器注册（WebAuthNPluginAddAuthenticator）
# 独立于 MSIX 包，Remove-AppxPackage 删不掉，残留后仍列在「保存通行密钥的位置」里、点了报错
# （后端 exe 已删）。做法：写 HKCU 标志 PendingUnregister=1，再用 explorer 以中等完整性（用户
# 上下文）拉起插件——NSIS/Geek 卸载器提权(高完整性)运行、无法直接激活 MSIX，故走 explorer；
# 插件无参启动读到标志即调 WebAuthNPluginRemoveAuthenticator 后退出（不显示界面）。Keep/Purge 都做。
function Invoke-PasskeyPluginUnregister {
    param([string[]]$PackageNames)
    $regPath = "HKCU:\Software\FaceWinUnlock\PasskeyManager"
    $launched = $false
    foreach ($packageName in $PackageNames) {
        $pkg = Get-AppxPackage -Name $packageName -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $pkg) { continue }
        try {
            $manifest = Get-AppxPackageManifest $pkg -ErrorAction Stop
            $appId = $manifest.Package.Applications.Application.Id
            if ($appId -is [array]) { $appId = $appId[0] }
            $aumid = "$($pkg.PackageFamilyName)!$appId"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            New-ItemProperty -Path $regPath -Name "PendingUnregister" -Value 1 -PropertyType DWord -Force | Out-Null
            Write-Host "Launching $aumid via explorer to self-unregister WebAuthn authenticator..."
            Start-Process -FilePath "explorer.exe" -ArgumentList "shell:AppsFolder\$aumid" -ErrorAction SilentlyContinue
            $launched = $true
        } catch {
            Write-Warning "Plugin self-unregister launch failed for ${packageName}: $($_.Exception.Message)"
        }
    }
    if ($launched) {
        Start-Sleep -Seconds 6
        Get-Process -Name PasskeyManager -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        # 清理标志，避免插件未能启动时标志残留（重装后误反注册）
        Remove-ItemProperty -Path $regPath -Name "PendingUnregister" -ErrorAction SilentlyContinue
    }
}

Invoke-PasskeyPluginUnregister -PackageNames $packageNames
$removeAppxCommand = Get-Command Remove-AppxPackage -ErrorAction Stop
$removeAppxArgs = @{ ErrorAction = "Stop" }
if (-not $Purge) {
    if ($removeAppxCommand.Parameters.ContainsKey("PreserveApplicationData")) {
        $removeAppxArgs["PreserveApplicationData"] = $true
    } else {
        Write-Warning "Remove-AppxPackage does not support -PreserveApplicationData on this system; keeping the Passkey package installed to avoid deleting local passkeys."
        $skipPackageRemoval = $true
    }
}

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
    if ($skipPackageRemoval) {
        break
    }
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
        # 保留模式用 -PreserveApplicationData 留住 LocalState 凭据元数据；Purge 才连数据一起删。
        $package | Remove-AppxPackage @removeAppxArgs
        $removedAnyPackage = $true
    }
}

if (-not $removedAnyPackage) {
    Write-Host "No FaceWinUnlock Passkey package found." -ForegroundColor Yellow
}

if (-not $Purge) {
    # 保留模式：凭据元数据已由 -PreserveApplicationData 留住，私钥本就在 KSP 中不删；
    # 证书信任与注册表配置也保留，便于重装后免重新注册。
    Write-Host "FaceWinUnlock Passkey plugin removed; credentials preserved for reinstall."
    return
}

# 以下仅彻底清除 (-Purge) 时执行：清注册表残留 + 删证书 + 删 KSP 私钥。
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

# 删除 KSP 私钥（facewinunlock/*，best-effort；密钥名 = facewinunlock/<userId>）
$keys = & certutil.exe -user -key -csp "Microsoft Software Key Storage Provider" 2>$null
if ($keys) {
    foreach ($line in $keys) {
        $t = "$line".Trim()
        if ($t -like "facewinunlock/*") {
            & certutil.exe -user -csp "Microsoft Software Key Storage Provider" -delkey "$t" 2>$null | Out-Null
        }
    }
}

Write-Host "FaceWinUnlock Passkey plugin purged (credentials and keys removed)."
