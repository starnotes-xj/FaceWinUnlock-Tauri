# FaceWinUnlock 卸载：清理开始菜单磁贴备份注册表
# Windows 自动生成的 AppListBackup 子键名可能带后缀（如 _3378948040）
$parent = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppListBackup"

function Get-FaceWinUnlockTileNames($keyPath) {
    # 直接读取原始注册表值：Get-ItemProperty 对 REG_BINARY 只能拿到 byte[]，
    # .ToString() 返回 "System.Byte[]" 而非实际内容 —— 用 reg query 导出原始数据解析。
    $raw = & reg.exe query $($keyPath -replace 'HKCU:','HKCU') /s 2>$null
    $names = @()
    foreach ($line in $raw) {
        if ($line -match '^\s{4}([^\s]{4,})\s+REG_' -and $line -match 'facewinunlock') {
            $names += $Matches[1].Trim()
        }
    }
    return $names
}

try {
    $keys = Get-ChildItem -Path $parent -ErrorAction Stop | Where-Object {
        $_.PSChildName -like "ListOfEventDrivenBackedUpTiles*"
    }
    foreach ($k in $keys) {
        $tileNames = Get-FaceWinUnlockTileNames $k.PSPath
        foreach ($name in $tileNames) {
            Remove-ItemProperty -Path $k.PSPath -Name $name -ErrorAction SilentlyContinue
            Write-Host "Removed tile backup: $($k.PSChildName)\$name"
        }
        # 键已清空则删除键本身
        $remaining = @(Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue).PSObject.Properties |
            Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') }
        if ($remaining.Count -eq 0) {
            Remove-Item -Path $k.PSPath -Recurse -ErrorAction SilentlyContinue
            Write-Host "Removed empty tile backup key: $($k.PSChildName)"
        }
    }
} catch { }
