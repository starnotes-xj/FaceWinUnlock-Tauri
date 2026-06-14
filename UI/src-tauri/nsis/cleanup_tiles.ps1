# FaceWinUnlock 卸载：清理开始菜单磁贴备份注册表
$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppListBackup\ListOfEventDrivenBackedUpTiles"
try {
    $props = Get-ItemProperty -Path $key -ErrorAction Stop
    $props.PSObject.Properties | Where-Object {
        $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') -and
        $_.Value -and $_.Value.ToString().Contains('facewinunlock')
    } | ForEach-Object {
        Remove-ItemProperty -Path $key -Name $_.Name -ErrorAction SilentlyContinue
        Write-Host "Removed tile backup: $($_.Name)"
    }
} catch { }
