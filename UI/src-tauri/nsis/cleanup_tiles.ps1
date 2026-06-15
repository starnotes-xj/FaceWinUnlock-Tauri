# FaceWinUnlock 卸载：清理开始菜单磁贴备份注册表
# Windows 自动生成的 AppListBackup 子键名可能带后缀（如 _3378948040）
$parent = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppListBackup"

try {
    $keys = Get-ChildItem -Path $parent -ErrorAction Stop | Where-Object {
        $_.PSChildName -like "ListOfEventDrivenBackedUpTiles*"
    }
    foreach ($k in $keys) {
        $props = Get-ItemProperty -Path $k.PSPath -ErrorAction Stop
        $props.PSObject.Properties | Where-Object {
            $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') -and
            $_.Value -and $_.Value.ToString().Contains('facewinunlock')
        } | ForEach-Object {
            Remove-ItemProperty -Path $k.PSPath -Name $_.Name -ErrorAction SilentlyContinue
            Write-Host "Removed tile backup: $($k.PSChildName)\$($_.Name)"
        }
    }
} catch { }
