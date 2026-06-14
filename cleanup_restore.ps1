# FaceWinUnlock 残留清理 + ngcksp.dll 还原脚本
# 用途：撤销部署残留（UIA-Helper、计划任务），并把被补丁的 ngcksp.dll 还原为微软原版
#       （修复"设不了 PIN"）。磁贴的注册表/主 DLL 已被卸载删除，重启即消失。
#
# 用法：右键「以管理员身份运行 PowerShell」，然后执行本脚本。
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   D:\RustProject\FaceWinUnlock-Tauri\cleanup_restore.ps1
#
# 安全设计：① 还原前校验 ngcksp_old.dll 确为微软 Valid 签名才动手；
#           ② 不删除被补丁的 ngcksp.dll，而是改名留档（可恢复）；③ 每步独立 try/catch。

$ErrorActionPreference = 'Continue'

# ── 0. 必须管理员 ──
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "✗ 请以【管理员】身份运行本脚本。" -ForegroundColor Red
    return
}

$sys32  = "$env:SystemRoot\System32"
$cur    = Join-Path $sys32 "ngcksp.dll"
$old    = Join-Path $sys32 "ngcksp_old.dll"
$stamp  = Get-Date -Format "yyyyMMddHHmmss"

Write-Host "==================== FaceWinUnlock 清理 + 还原 ====================" -ForegroundColor Cyan

# ── 1. ★关键★ 还原 ngcksp.dll（修复设 PIN）──
Write-Host "`n[1] 还原 ngcksp.dll（Windows Hello PIN 核心）..." -ForegroundColor Yellow
$curSig = (Get-AuthenticodeSignature $cur).Status
if ($curSig -eq 'Valid') {
    Write-Host "    当前 ngcksp.dll 已是 Valid 签名，无需还原（跳过）。" -ForegroundColor Green
} elseif (-not (Test-Path $old)) {
    Write-Host "    ✗ 找不到备份 ngcksp_old.dll。改用 sfc 还原：稍后手动跑 'sfc /scannow'。" -ForegroundColor Red
} else {
    $oldSig = Get-AuthenticodeSignature $old
    $oldSubj = $oldSig.SignerCertificate.Subject
    if ($oldSig.Status -ne 'Valid' -or $oldSubj -notmatch 'Microsoft') {
        Write-Host "    ✗ 备份 ngcksp_old.dll 签名异常（$($oldSig.Status) / $oldSubj），不敢用它还原。" -ForegroundColor Red
        Write-Host "      请改用：sfc /scannow  或  DISM /Online /Cleanup-Image /RestoreHealth" -ForegroundColor Red
    } else {
        try {
            # 取得所有权 + 授权（System32 默认 TrustedInstaller 所有）
            & takeown /f $cur 2>&1 | Out-Null
            & icacls $cur /grant "*S-1-5-32-544:F" 2>&1 | Out-Null   # *S-1-5-32-544 = Administrators
            # 不删——把被补丁的改名留档（loaded 文件也可改名）
            $bak = Join-Path $sys32 "ngcksp_patched_$stamp.bak"
            Rename-Item -LiteralPath $cur -NewName (Split-Path $bak -Leaf) -Force
            Copy-Item -LiteralPath $old -Destination $cur -Force
            # 还原默认所有者给 TrustedInstaller（系统卫生）
            & icacls $cur /setowner "NT SERVICE\TrustedInstaller" 2>&1 | Out-Null
            $newSig = (Get-AuthenticodeSignature $cur).Status
            Write-Host "    ✓ 已用原版还原 ngcksp.dll（新签名: $newSig）。被补丁版留档: $bak" -ForegroundColor Green
        } catch {
            Write-Host "    ✗ 还原失败: $_" -ForegroundColor Red
            Write-Host "      若提示占用，改用 'sfc /scannow' 重启后还原。" -ForegroundColor Red
        }
    }
}

# ── 2. 删除计划任务 ──
Write-Host "`n[2] 删除残留计划任务..." -ForegroundColor Yellow
Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object { $_.TaskName -match 'FaceWinUnlock' -or ($_.Actions.Execute -match 'FaceWinUnlock') } |
    ForEach-Object {
        try { Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false; Write-Host "    ✓ 已删任务: $($_.TaskName)" -ForegroundColor Green }
        catch { Write-Host "    ✗ 删任务失败 $($_.TaskName): $_" -ForegroundColor Red }
    }

# ── 3. 删除 System32 残留文件 ──
Write-Host "`n[3] 删除 System32 残留文件..." -ForegroundColor Yellow
foreach ($f in @("FaceWinUnlock-UIA-Helper.exe","FaceWinUnlock-Tauri.dll")) {
    $p = Join-Path $sys32 $f
    if (Test-Path $p) {
        try { & takeown /f $p 2>&1 | Out-Null; & icacls $p /grant "*S-1-5-32-544:F" 2>&1 | Out-Null
              Remove-Item $p -Force; Write-Host "    ✓ 已删: $f" -ForegroundColor Green }
        catch { Write-Host "    ✗ 删除失败 $f（可能占用，重启后再删）: $_" -ForegroundColor Red }
    } else { Write-Host "    - 已无: $f" -ForegroundColor DarkGray }
}

# ── 4. 兜底清注册表（若卸载没删干净）──
Write-Host "`n[4] 兜底清理注册表残留..." -ForegroundColor Yellow
$g = "{8a7b9c6d-4e5f-89a0-8b7c-6d5e4f3e2d1c}"
$keys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$g",
    "HKLM:\SOFTWARE\Classes\CLSID\$g",
    "HKLM:\SOFTWARE\facewinunlock-tauri"
)
foreach ($k in $keys) {
    if (Test-Path $k) {
        try { Remove-Item $k -Recurse -Force; Write-Host "    ✓ 已删键: $k" -ForegroundColor Green }
        catch { Write-Host "    ✗ 删键失败: $k : $_" -ForegroundColor Red }
    } else { Write-Host "    - 已无: $(Split-Path $k -Leaf)" -ForegroundColor DarkGray }
}

Write-Host "`n==================== 完成。请【重启电脑】 ====================" -ForegroundColor Cyan
Write-Host "重启后：① 幽灵磁贴消失；② 重新去 设置→账户→登录选项→PIN 设置 PIN。" -ForegroundColor White
Write-Host "若 PIN 仍设不了，再跑：sfc /scannow  和  DISM /Online /Cleanup-Image /RestoreHealth" -ForegroundColor White
