param(
    [string]$CertificatePath = "",
    # 保留模式（默认行为由调用方传入）：Remove-AppxPackage 用 -PreserveApplicationData 留住
    # LocalState 凭据元数据；不删证书/注册表/KSP 私钥，便于重装后免重新注册。
    [switch]$PreserveApplicationData,
    # 彻底清除：删 MSIX 数据 + 证书 + 注册表残留 + KSP 私钥(facewinunlock/*)。
    [switch]$Purge
)

$ErrorActionPreference = "Stop"

# 兜底：卸载认证器 + 移除插件是 best-effort，任何未预期的终止错误都不应让 NSIS/Geek 卸载器
# 显示「卸载脚本返回非零状态」吓到用户、也不该中断主程序卸载。捕获后降级为警告并以 0 退出。
trap {
    Write-Warning "FaceWinUnlock passkey uninstall (non-fatal): $($_.Exception.Message)"
    exit 0
}

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $CertificatePath) {
    $repoCertificate = Join-Path $repoRoot "target\release\FaceWinUnlock-Passkey.cer"
    $installedCertificate = Join-Path $repoRoot "FaceWinUnlock-Passkey.cer"
    $CertificatePath = if (Test-Path $repoCertificate) { $repoCertificate } else { $installedCertificate }
}

Get-Process -Name PasskeyManager -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

$removedAnyPackage = $false
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$packageNames = @("FaceWinUnlock.PasskeyManager", "Contoso.PasskeyManager")

function Initialize-PasskeyUnregisterInterop {
    if ("FaceWinUnlock.Uninstall.PackagedAppActivation" -as [type]) {
        return $true
    }

    try {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace FaceWinUnlock.Uninstall
{
    [ComImport]
    [Guid("2E941141-7F97-4756-BA1D-9DECDE894A3D")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IApplicationActivationManager
    {
        [PreserveSig]
        int ActivateApplication(
            [MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
            [MarshalAs(UnmanagedType.LPWStr)] string arguments,
            uint options,
            out uint processId);
    }

    [ComImport]
    [Guid("45BA127D-10A8-46EA-8AB7-56EA9078943C")]
    internal class ApplicationActivationManager
    {
    }

    public static class PackagedAppActivation
    {
        [DllImport("user32.dll")]
        public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

        public static uint Activate(string appUserModelId, string arguments)
        {
            IApplicationActivationManager manager =
                (IApplicationActivationManager)new ApplicationActivationManager();
            try
            {
                uint processId;
                int result = manager.ActivateApplication(appUserModelId, arguments, 0, out processId);
                Marshal.ThrowExceptionForHR(result);
                return processId;
            }
            finally
            {
                if (Marshal.IsComObject(manager))
                {
                    Marshal.FinalReleaseComObject(manager);
                }
            }
        }
    }
}
"@ -ErrorAction Stop | Out-Null
        return $true
    } catch {
        Write-Warning "Packaged-app activation interop is unavailable; using Explorer fallback: $($_.Exception.Message)"
        return $false
    }
}

# 卸载前先让插件以自身身份反注册 WebAuthn 认证器。认证器注册（WebAuthNPluginAddAuthenticator）
# 独立于 MSIX 包，Remove-AppxPackage 删不掉，残留后仍列在「保存通行密钥的位置」里、点了报错
# （后端 exe 已删）。优先通过 IApplicationActivationManager 显式传入 -UnregisterPlugin；高完整性
# 上下文拒绝直接激活时，再写 HKCU 标志 PendingUnregister=1，并用 Explorer 在用户上下文拉起插件。
# 插件读取参数或标志后调用 WebAuthNPluginRemoveAuthenticator，再 Exit（不显示界面）。Keep/Purge 都做。
#
# 插件读到标志走的是静默路径（不建窗口）。极少数情况下（跨账户提权卸载、HKCU 上下文不一致、
# 激活落到旧实例）会读不到标志、走交互模式弹出窗口——此时轮询检测到窗口句柄立即 SW_HIDE 隐藏，
# 用户几乎无感，最后统一杀掉进程。
function Invoke-PasskeyPluginUnregister {
    param([string[]]$PackageNames)
    $regPath = "HKCU:\Software\FaceWinUnlock\PasskeyManager"
    $launched = $false
    $interopAvailable = Initialize-PasskeyUnregisterInterop

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
            # 激活前杀掉任何现有实例，确保新进程执行反注册启动路径。
            Get-Process -Name PasskeyManager -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

            $activated = $false
            if ($interopAvailable) {
                try {
                    $processId = [FaceWinUnlock.Uninstall.PackagedAppActivation]::Activate($aumid, "-UnregisterPlugin")
                    Write-Host "Activated $aumid in explicit silent unregister mode (PID $processId)."
                    $activated = $true
                } catch {
                    Write-Warning "Explicit packaged-app activation failed for ${packageName}; using Explorer fallback: $($_.Exception.Message)"
                }
            }

            if (-not $activated) {
                Write-Host "Launching $aumid via Explorer to self-unregister WebAuthn authenticator..."
                Start-Process -FilePath "explorer.exe" -ArgumentList "shell:AppsFolder\$aumid" -ErrorAction Stop
            }
            $launched = $true
        } catch {
            Write-Warning "Plugin self-unregister launch failed for ${packageName}: $($_.Exception.Message)"
        }
    }

    if ($launched) {
        # 轮询最多 ~9s。插件进入反注册路径后会先删除 PendingUnregister，再调 API 并退出；
        # 同时等待“标志已消费 + 进程已退出”，避免固定睡眠后过早杀进程导致反注册未完成。
        $flagConsumed = $false
        for ($i = 0; $i -lt 30; $i++) {
            Start-Sleep -Milliseconds 300
            $pending = Get-ItemProperty -Path $regPath -Name "PendingUnregister" -ErrorAction SilentlyContinue
            if (-not $pending) { $flagConsumed = $true }
            $procs = @(Get-Process -Name PasskeyManager -ErrorAction SilentlyContinue)
            if ($flagConsumed -and $procs.Count -eq 0) { break }
            foreach ($proc in $procs) {
                if ($proc.MainWindowHandle -ne [System.IntPtr]::Zero) {
                    try {
                        if ($interopAvailable) {
                            [FaceWinUnlock.Uninstall.PackagedAppActivation]::ShowWindowAsync($proc.MainWindowHandle, 0) | Out-Null
                        }
                    } catch {}
                }
            }
        }
        if (-not $flagConsumed) {
            Write-Warning "Passkey plugin did not acknowledge the silent unregister request before timeout."
        }
        Get-Process -Name PasskeyManager -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        # 清理标志，避免插件未能启动时标志残留（重装后误反注册）
        Remove-ItemProperty -Path $regPath -Name "PendingUnregister" -ErrorAction SilentlyContinue
    }
}

Invoke-PasskeyPluginUnregister -PackageNames $packageNames

$removeAppxCommand = Get-Command Remove-AppxPackage -ErrorAction SilentlyContinue
if (-not $removeAppxCommand) {
    Write-Warning "Remove-AppxPackage is unavailable on this system; skipping MSIX removal."
    if (-not $Purge) {
        Write-Host "FaceWinUnlock Passkey plugin authenticator unregistered; MSIX left in place."
        exit 0
    }
}

$removeAppxArgs = @{ ErrorAction = "Stop" }
$skipPackageRemoval = $false
if ($removeAppxCommand -and -not $Purge) {
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

if ($removeAppxCommand) {
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
            # Remove-AppxPackage 在提权 + PreserveApplicationData 下偶发抛错（如 0x80073CFA），
            # 属非致命：反注册已在前面完成，这里失败只警告、不让整个卸载显示「非零状态」。
            try {
                $package | Remove-AppxPackage @removeAppxArgs
                $removedAnyPackage = $true
            } catch {
                Write-Warning "Remove-AppxPackage failed for $($package.PackageFullName): $($_.Exception.Message)"
            }
        }
    }
}

if (-not $removedAnyPackage) {
    Write-Host "No FaceWinUnlock Passkey package removed (already absent or kept intentionally)." -ForegroundColor Yellow
}

if (-not $Purge) {
    # 保留模式：凭据元数据已由 -PreserveApplicationData 留住，私钥本就在 KSP 中不删；
    # 证书信任与注册表配置也保留，便于重装后免重新注册。
    Write-Host "FaceWinUnlock Passkey plugin removed; credentials preserved for reinstall."
    exit 0
}

# 以下仅彻底清除 (-Purge) 时执行：清注册表残留 + 删证书 + 删 KSP 私钥。全部 best-effort。
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
            Write-Warning "Failed to remove certificate $Thumbprint from ${scope}\${StoreName}."
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
exit 0
