# WinDbg Runbook — 动态分析 NgcIso.exe 解密链

## 目标

确定 NGC 解密出口是否有内存明文，为 key_capture hook 提供精确偏移/API。

## 前置条件（破坏性，须在 VM 或测试机执行）

### 步骤 1：关闭 VBS / 虚拟机监控程序
```powershell
# 管理员 PowerShell
bcdedit /set hypervisorlaunchtype off
# 关闭内存完整性：Windows 安全中心 → 设备安全性 → 内核隔离 → 关
# 关闭 Credential Guard（如果启用）：
#   gpedit.msc → 计算机配置 → 管理模板 → 系统 → Device Guard → 关闭
```

**重启后验证**：
```powershell
msinfo32 | findstr "Virtualization-based security"
# 应显示 "Not enabled"
Get-ComputerInfo -Property "HyperVisorPresent"
# 应为 False
```

### 步骤 2：关 Secure Boot + 开测试签名
```powershell
# BIOS/UEFI → 关 Secure Boot
bcdedit /set testsigning on
# 重启
```

### 步骤 3：剥离 PPL 保护（NgcIso.exe 是 PPL-WinTcb 级别）
**选项 A**：使用内核调试器
- WinDbg → 内核调试模式 → 双机调试
- 设 NgcIso.exe 进程断点

**选项 B**：使用 PPL 剥离工具（需要测试签名）
- 编译/加载一个简单的 WDM 驱动，调用 `PsProtectedTypeNone` 清除保护
- 或使用现成工具（如 `PPLdump` / `PPLcontrol`）

## 调试步骤

### 第 1 步：WinDbg attach NgcIso.exe
```
# 确认 NgcIso.exe PID
tasklist | findstr NgcIso

# WinDbg 附加（需要内核调试或已剥 PPL）
windbg -p <NgcIso_PID>
```

### 第 2 步：设断点 — 解密 API 出口
```
# DPAPI 解密出口
bp crypt32!CryptUnprotectData "r @rcx; dd @rdx L8; g"

# NCrypt 解密出口（符号可能需要 .reload）
bp ncrypt!NCryptDecrypt "r @rcx; r @rdx; g"

# BCrypt 解密出口
bp bcrypt!BCryptDecrypt "r @rcx; r @rdx; g"

# TPM 命令出口
bp tbs!Tbsip_Submit_Command "r @rcx; g"
```

### 第 3 步：触发解密流程
- 方法 A：在 Chrome 中触发查看密码 → 输入 PIN
- 方法 B：用 `--ngc-ncrypt` 命令（`PsExec -s -i ... --ngc-ncrypt "星记" <PIN>`）

### 第 4 步：当断点命中时
```
# 检查输出缓冲区（pDataOut / pbOutput）
k           # 看调用栈
r           # 看寄存器
db @rdx L100 # dump 输出缓冲区 256 字节

# 如果看到明文密码：
.writemem C:\FaceWinUnlock\dbg_dump.bin @rdx L<size>
```

## 关键观察点

| API | 关注参数 | 预期内容 |
|-----|---------|---------|
| `CryptUnprotectData` | `pDataOut->pbData` | 解保护后的明文（可能是密钥材料） |
| `NCryptDecrypt` | `pbOutput` | RSA/对称解密后的明文 |
| `BCryptDecrypt` | `pbOutput` | AES-GCM/CBC 解密后的 vault 数据 |
| `Tbsip_Submit_Command` | `pabResult` | 原始 TPM 响应（多为不透明） |

## 分析决策树

```
断点命中
  ├─ pDataOut/pbOutput 可读 ASCII/UTF-16 → 明文密码 ✅ → 记录偏移，交给 key_capture 做 hook
  ├─ pDataOut/pbOutput 二进制不可读 → 可能是密钥材料 → 记下长度/格式
  └─ 无断点命中 → 解密在 TPM 内部完成（不可观测）→ 路不通，止损
```

## 恢复（完成后务必执行）
```powershell
bcdedit /set hypervisorlaunchtype auto
bcdedit /set testsigning off
# 重启 + 重开 Secure Boot + 重开内存完整性/Credential Guard
```
