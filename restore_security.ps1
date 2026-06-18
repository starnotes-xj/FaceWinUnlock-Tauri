# 恢复 Windows 安全设置（修复反作弊兼容性）
# 管理员 PowerShell 运行

Write-Host "=== 恢复安全设置 ===" -ForegroundColor Cyan

# 1. 关闭测试签名
Write-Host "1. 关闭测试签名..." -ForegroundColor Yellow
bcdedit /set testsigning off

# 2. 关闭内核调试
Write-Host "2. 关闭内核调试..." -ForegroundColor Yellow
bcdedit /set debug off
bcdedit /dbgsettings local

# 3. 恢复 Hypervisor
Write-Host "3. 恢复 Hypervisor..." -ForegroundColor Yellow
bcdedit /set hypervisorlaunchtype auto

# 4. 恢复 VBS 注册表
Write-Host "4. 恢复 VBS / Windows Hello 注册表..." -ForegroundColor Yellow
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\WindowsHello" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 0 /f

# 5. 恢复 isolatedcontext（IUM/VTL1）
Write-Host "5. 恢复 isolatedcontext..." -ForegroundColor Yellow
bcdedit /set isolatedcontext Yes

Write-Host ""
Write-Host "=== 验证 ===" -ForegroundColor Cyan
bcdedit /enum | Select-String "testsigning|debug|hypervisorlaunchtype|isolatedcontext"

Write-Host ""
Write-Host "=== 还需手动操作 ===" -ForegroundColor Yellow
Write-Host "1. 进 BIOS 开启 Secure Boot"
Write-Host "2. 重启电脑（必须冷启动：shutdown /s /t 0）"
Write-Host "3. 重启后去 设置 → 核心隔离 → 开启内存完整性"
Write-Host "4. 删除 PPL 驱动服务: sc delete PPLBypass"
