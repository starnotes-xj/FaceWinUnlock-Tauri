# FaceWinUnlock 运行时文件自愈脚本 (resilience.ps1)
#
# 背景 / 根因：
#   opencv_world4120.dll 与 FaceWinUnlock-Server.exe 是安装目录里仅有的两个
#   「无数字签名 + 行为可疑」二进制（一个 61MB 的 OpenCV DLL；一个会开摄像头、
#   注入凭据、走命名管道的后台服务，在杀软启发式眼里是教科书级 RAT）。
#   实测火绒/Defender 云查杀会在安装后延迟扫描时把它们删掉（常【不进隔离区】，
#   所以用户在隔离区看不到）。安装目录每个文件只剩一份、无备份 → 一删，主程序就
#   报「找不到 opencv_world4120.dll」启动失败，只能重装 → 下次扫描再删 → 循环。
#
# 为什么自愈不能放在主程序里：
#   facewinunlock-tauri.exe 与 FaceWinUnlock-Server.exe 都【静态链接】opencv，
#   一旦 opencv 缺失它们自身都加载不起来，无法自救。本脚本是纯 PowerShell（不依赖
#   opencv），由独立计划任务在开机/登录/定时触发，因此即便两文件都被删也能跑。
#
# 为什么备份用压缩包：
#   备份若是原始 DLL/EXE，杀软同样会按 PE 特征把备份一起删。压缩成 zip 后磁盘上不再
#   有连续的 PE 头，实时扫描匹配不到，备份得以存活；需要时解压恢复即可。
#
# 三种模式：
#   -Mode Setup     安装时：用安装根目录里的两个关键文件生成压缩备份、注册自愈计划
#                   任务（开机+登录+每15分钟）、尝试加 Windows Defender 排除，最后立即自愈一次。
#   -Mode Heal      计划任务调用：检测到关键文件缺失就从压缩备份解压恢复，并拉起核心服务。
#   -Mode Teardown  卸载时：删除自愈计划任务与 Defender 排除。
param(
    [ValidateSet('Setup', 'Heal', 'Teardown')]
    [string]$Mode = 'Heal',
    [string]$InstallDir
)

$ErrorActionPreference = 'Stop'

if (-not $InstallDir -or $InstallDir.Trim() -eq '') {
    # 脚本位于 <InstallDir>\nsis\resilience.ps1 → 上两级即安装根目录
    if ($PSCommandPath) {
        $InstallDir = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    }
}
if (-not $InstallDir) { throw 'InstallDir 未提供且无法从脚本路径推断' }
$InstallDir = $InstallDir.TrimEnd('\')

$TaskName  = 'FaceWinUnlockHealer'
$BackupZip = Join-Path $InstallDir 'resources\runtime-backup.zip'
$LogDir    = Join-Path $InstallDir 'logs'
$LogFile   = Join-Path $LogDir 'heal.log'

# 受保护的关键文件：安装根目录下、无签名、杀软易误删、且无独立备份。
$Protected = @('opencv_world4120.dll', 'FaceWinUnlock-Server.exe')

function Write-Log([string]$msg) {
    try {
        if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
        $line = '{0} [resilience:{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Mode, $msg
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
    } catch {}
}

function New-Backup {
    # 已有有效备份则跳过（幂等；避免升级/重跑时重新压缩 61MB，也避免压缩失败中断后续步骤）。
    if ((Test-Path $BackupZip) -and ((Get-Item $BackupZip).Length -gt 1MB)) {
        Write-Log ('Setup: 压缩备份已存在，跳过重建：{0} ({1:N1} MB)' -f $BackupZip, ((Get-Item $BackupZip).Length / 1MB))
        return
    }
    $sources = @()
    foreach ($name in $Protected) {
        $p = Join-Path $InstallDir $name
        if (Test-Path $p) { $sources += $p } else { Write-Log "Setup: 源文件缺失，跳过备份：$name" }
    }
    if ($sources.Count -eq 0) { Write-Log 'Setup: 无可备份的源文件，未生成备份'; return }
    if (Test-Path $BackupZip) { Remove-Item $BackupZip -Force -ErrorAction SilentlyContinue }
    Compress-Archive -Path $sources -DestinationPath $BackupZip -CompressionLevel Optimal -Force
    Write-Log ('Setup: 已生成压缩备份 {0} ({1:N1} MB)' -f $BackupZip, ((Get-Item $BackupZip).Length / 1MB))
}

function Register-HealerTask {
    # 用任务 XML 注册，确保 开机 + 登录 + 每15分钟 触发可靠（New-ScheduledTaskTrigger 的
    # 无限重复在不同 PowerShell 版本上表现不一致，XML 最稳）。SYSTEM 账户、最高权限运行。
    $escDir   = $InstallDir.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
    $taskArgs = ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}\nsis\resilience.ps1" -Mode Heal -InstallDir "{0}"' -f $escDir)
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
    <TimeTrigger>
      <StartBoundary>2024-01-01T00:00:00</StartBoundary>
      <Repetition>
        <Interval>PT15M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <StartWhenAvailable>true</StartWhenAvailable>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions>
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>$taskArgs</Arguments>
    </Exec>
  </Actions>
</Task>
"@
    # 方法一：Register-ScheduledTask（PowerShell 原生，但可能被火绒 HIPS 拦截）
    try {
        Register-ScheduledTask -TaskName $TaskName -Xml $xml -Force -ErrorAction Stop | Out-Null
        Write-Log "Setup: 已通过 Register-ScheduledTask 注册自愈计划任务 $TaskName"
        return
    } catch {
        Write-Log "Setup: Register-ScheduledTask 失败（可能被安全软件拦截），尝试 schtasks.exe 回退：$($_.Exception.Message)"
    }

    # 方法二：schtasks.exe 回退（绕过 PowerShell HIPS，直接在 NSIS 提权进程调用）
    # 火绒 HIPS 主要拦截 PowerShell cmdlet，对 schtasks.exe 命令行工具通常放行。
    try {
        $xmlPath = Join-Path $env:TEMP ('fwu_task_{0}.xml' -f [guid]::NewGuid().ToString('N'))
        # schtasks /Create /XML 需要 UTF-16 LE 编码（与 Rust 侧 add_scheduled_task 一致）
        $utf16 = [System.Text.Encoding]::Unicode.GetBytes($xml)
        [System.IO.File]::WriteAllBytes($xmlPath, $utf16)
        $result = Start-Process -FilePath 'schtasks.exe' `
            -ArgumentList '/Create', '/TN', $TaskName, '/XML', "`"$xmlPath`"", '/F' `
            -WindowStyle Hidden -Wait -NoNewWindow -PassThru
        Remove-Item $xmlPath -Force -ErrorAction SilentlyContinue
        if ($result.ExitCode -eq 0) {
            Write-Log "Setup: 已通过 schtasks.exe 回退注册自愈计划任务 $TaskName"
        } else {
            Write-Log "Setup: schtasks.exe 回退也失败（exit code $($result.ExitCode)）。请手动将安装目录加入安全软件信任区。"
        }
    } catch {
        Write-Log "Setup: schtasks.exe 回退异常：$($_.Exception.Message)"
    }
}

function Add-DefenderExclusion {
    # Defender 被第三方杀软接管/关闭时 Add-MpPreference 会失败，忽略即可（不影响其它机制）。
    try {
        Add-MpPreference -ExclusionPath $InstallDir -ErrorAction Stop
        Write-Log "Setup: 已添加 Windows Defender 排除目录 $InstallDir"
    } catch {
        Write-Log "Setup: Defender 排除未生效（可能已被第三方杀软接管/关闭）：$($_.Exception.Message)"
    }
}

function Invoke-Heal {
    $restored = @()
    $ResourcesDir = Join-Path $InstallDir 'resources'
    foreach ($name in $Protected) {
        $dst = Join-Path $InstallDir $name
        if (Test-Path $dst) { continue }
        Write-Log "Heal: 检测到关键文件缺失：$name"

        # 优先尝试从 resources/ 副本复制（快速路径，比解压 zip 更快）
        $resourcesCopy = Join-Path $ResourcesDir $name
        if (Test-Path $resourcesCopy) {
            try {
                Copy-Item $resourcesCopy $dst -Force
                $restored += $name
                Write-Log "Heal: 已从 resources 副本恢复 $name（快速路径）"
                continue
            } catch {
                Write-Log "Heal: 从 resources 副本恢复 $name 失败，尝试 zip 备份：$($_.Exception.Message)"
            }
        }

        # 回退：从压缩备份解压恢复
        if (-not (Test-Path $BackupZip)) { Write-Log "Heal: 压缩备份不存在，无法恢复 $name"; continue }
        try {
            $tmp = Join-Path $env:TEMP ('fwu_heal_' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Force -Path $tmp | Out-Null
            Expand-Archive -Path $BackupZip -DestinationPath $tmp -Force
            $src = Join-Path $tmp $name
            if (Test-Path $src) {
                Copy-Item $src $dst -Force
                $restored += $name
                Write-Log "Heal: 已从压缩备份恢复 $name"
            } else {
                Write-Log "Heal: 备份内未找到 $name"
            }
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Heal: 恢复 $name 失败：$($_.Exception.Message)"
        }
    }
    if ($restored -contains 'FaceWinUnlock-Server.exe') {
        try {
            Start-Process -FilePath 'schtasks.exe' -ArgumentList '/Run', '/TN', 'FaceWinUnlockServer' `
                -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
            Write-Log 'Heal: 核心服务已恢复，重新拉起 FaceWinUnlockServer'
        } catch {
            Write-Log "Heal: 拉起核心服务失败：$($_.Exception.Message)"
        }
    }
    if ($restored.Count -eq 0) { Write-Log 'Heal: 关键文件完整，无需恢复' }
}

function Invoke-Teardown {
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log "Teardown: 已删除自愈计划任务 $TaskName"
    } catch {}
    try {
        Remove-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
        Write-Log "Teardown: 已移除 Defender 排除目录 $InstallDir"
    } catch {}
}

switch ($Mode) {
    'Setup' {
        # 各步骤互相独立：任一失败都不应阻断其余（例如备份重建失败不应导致任务未注册）。
        try { New-Backup } catch { Write-Log "Setup: 备份步骤异常：$($_.Exception.Message)" }
        try { Register-HealerTask } catch { Write-Log "Setup: 注册任务步骤异常：$($_.Exception.Message)" }
        try { Add-DefenderExclusion } catch { Write-Log "Setup: Defender 排除步骤异常：$($_.Exception.Message)" }
        try { Invoke-Heal } catch { Write-Log "Setup: 自愈步骤异常：$($_.Exception.Message)" }
    }
    'Heal' { Invoke-Heal }
    'Teardown' { Invoke-Teardown }
}
