# 交接文档 — FaceWinUnlock NGC KSP 增强版

## 目标

实现人脸识别 → 自动注入 Windows Hello PIN → Chrome 查看密码等功能

---

## ⚠️ 重要纠正（IAT 解析后验证，推翻此前两条结论）

1. **`FUN_180048c08` 不是 KDF。** IAT 解析证实：
   - `MOV EDX,0x2710` + `CALL [0x180093f18]` = `WaitForSingleObjectEx(handle, 10000ms, FALSE)`——`0x2710` 是 **10 秒超时**，不是"PBKDF2 10000 迭代"。
   - `CALL [0x180093f68]` = `WaitForMultipleObjects`。
   - 该函数是**线程同步/等待**（等 RPC/trustlet 操作完成），与密钥派生无关。此前"KDF 定位 + PBKDF2 确认"是误读，请勿再追。

2. **`NgcIsoCtnr.dll` 没有 BCryptSecretAgreement/BCryptDeriveKey/HKDF。** 其 IAT 里这些**全不存在**（NgcIso_analysis.txt 对 SecretAgreement/DeriveKey/HKDF/KDF 的搜索全空）。"现代容器 AES key 经 BCryptSecretAgreement 派生"结论**不成立**。
   - 真实加密面：`Tbsip_Submit_Command`/`Tbsi_Context_Create`（**直接 TPM 命令**）、`NCrypt*`（KSP）、`CryptProtectData/UnprotectData`（DPAPI）、`WinBioNgcGetAuthorizationWithTicket`/`WinBioNgcOpenAuthorizationSession`（**NGC 授权票据**）。

3. **结论：不存在可离线复刻的纯文件 KDF。** 现代保护链 = TPM + NGC 授权票据 + DPAPI，**全部在 VTL1/PPL 保护的 NgcIso.exe trustlet 内执行**。路 B（离线解密文件得密钥）**判定不可行**。

### 修正后的唯一深度路径
动态分析 NgcIso.exe（需 **关 VBS + 剥 PPL**）：
- 关 VBS/核心隔离：`bcdedit /set hypervisorlaunchtype off` + 关内存完整性/Credential Guard。
- 关 Secure Boot + 开测试签名 → 加载剥 PPL 驱动（或内核调试器）解除 NgcIso.exe 保护。
- WinDbg attach 或 key_capture 注入 NgcIso.exe → hook `CryptUnprotectData`/`Tbsip_Submit_Command`/`NCryptDecrypt`/数据解密出口 → 捕获**明文密码/解密结果**。
- 现实天花板：FIDO/账户私钥若 TPM 封装，签名在 TPM 内完成、私钥永不出 trustlet 内存；最好情况只能截获**明文密码**或**断言签名结果**，拿不到可移植私钥。
- 与已验证可行的 **SendInput 自动填充**相比，RE 仅多出"完全无弹框 + 安全桌面更稳"，性价比需自行权衡。

---

## 当前进度总览

### ✅ 已完成的方案

| 方案 | 状态 | 关键代码 |
|------|------|---------|
| **SendInput 盲打 PIN** | ✅ 验证可行 | `Unlock/src/uia.rs` - send_keys_digits/send_enter |
| **DLL 管道 PIN 注入** | ✅ 代码完成 | `Server/src/CPipeListener.rs` - inject_pin_sendinput |
| **Unlock 端 PIN 加载** | ✅ 代码完成 | `Unlock/src/main.rs` - pin_to_inject + 管道发送 |
| **PIN 存储 (pin_store)** | ✅ 后端完成 | `Unlock/src/ngc/pin_store.rs` + `UI/src-tauri/src/modules/pin_commands.rs` |
| **ECDSA P256 签名** | ✅ 已完成 | `Unlock/src/passkey/signer.rs` - p256 crate + BCryptImportKeyPair |
| **Ghidra 分析 ngcksp.dll** | ✅ 完成 | 是 RPC 客户端，补丁无效 |
| **Ghidra 分析 NgcIsoCtnr.dll** | ✅ 完成（结论见上方⚠️纠正） | FUN_180048c08 实为 WaitForSingleObjectEx 非 KDF；真实加密=TPM/NGC票据/DPAPI |

### ❌ 未成功的方案

| 方案 | 状态 | 失败原因 |
|------|------|---------|
| NCryptExportKey 导出 NGC 密钥 | ❌ | 所有5种格式 sz=0 |
| ngcksp.dll 二进制补丁 (EDI=1) | ❌ | 服务端不检查客户端传来的flag |
| NGC 文件系统 KDF 解密 | ❌ 判定不可行 | 无纯文件 KDF；保护链=TPM+NGC票据+DPAPI，全在 VTL1/PPL trustlet 内（详见⚠️纠正） |
| KSP 函数表劫持 | ❌ | GetKeyStorageInterface 返回 STATUS_NOT_SUPPORTED |
| key_capture DLL 注入 NgcIso.exe | ❌ | Session 0 保护进程 |

---

## 所有文件改动

### Unlock/src/ngc/pin.rs
**作用**: PIN → DPAPI entropy 派生
**改动**: 新增 `PinEncoding` 枚举 + `derive_entropy_all_variants` 函数，支持4种 PIN 编码变体 (HexUtf16/RawUtf16/RawBytes/HexLower)

### Unlock/src/ngc/mod.rs
**作用**: NGC 解密核心模块
**改动**: 
- 声明 `pub mod pin_store`
- `try_multiple_key_derivations` 新增: HKDF/SRK派生、直接 SHA512 当 key、字节滑动窗口

### Unlock/src/ngc/ncrypt.rs
**作用**: NCrypt API 接口
**改动**: NCryptExportKey 在签名成功后尝试导出（全部 sz=0）

### Unlock/src/ngc/pin_store.rs
**作用**: PIN 加密存储
**改动**: 
- 新增 `load_pin_with_sid(user, sid)` 供 SYSTEM 进程调用
- DPAPI 改为 `CRYPTPROTECT_LOCAL_MACHINE`（跨用户解密）
- DB 路径改为 `database.db`

### Unlock/src/main.rs
**作用**: 人脸识别主循环
**改动**:
- State 新增 `pin_to_inject` 字段
- 人脸匹配后加载 PIN → 通过管道发送 `inject_pin:XXXX` 给 DLL
- `handle_unlock_client` 先发 PIN 再发凭据
- 新增 CLI: `--uia-dump-all`, `--uia-blind-inject`

### Unlock/src/uia.rs
**作用**: UIA + SendInput 工具
**改动**: 完全重写，公开 `send_keys_digits` 和 `send_enter`

### Unlock/src/passkey/signer.rs
**作用**: FIDO2 签名器
**改动**:
- 新增 `raw_ecdsa_sign` + `raw_d_to_ecc_private_blob`（p256 crate）
- `decrypt_ecdsa_key` 尝试所有 PIN 编码变体

### Unlock/Cargo.toml
**改动**: 新增 `hex`, `p256`, `hmac`

### Server/src/CPipeListener.rs
**作用**: DLL 管道监听器
**改动**:
- Creds 线程处理 `inject_pin:XXXX` 命令
- 新增 `inject_pin_sendinput` 函数（DLL 端 SendInput）

### Server/Cargo.toml
**改动**: 新增 `Win32_UI_Input_KeyboardAndMouse`

### UI/src-tauri/src/modules/pin_commands.rs (新建)
**作用**: Tauri 命令（前端 PIN 存储）
**改动**: `encrypt_pin`, `verify_pin_hash_stored`, `get_user_sid`

### UI/src-tauri/Cargo.toml
**改动**: 新增 `sha2`, `hex`, `Win32_Security_Cryptography`

### UI/src-tauri/src/lib.rs
**改动**: 注册 `encrypt_pin`, `verify_pin_hash_stored`, `get_user_sid` 命令

### key_capture/ (新建 crate)
**作用**: KSP 内存密钥捕获注入 DLL + 注入器
**文件**: `key_capture/Cargo.toml`, `src/lib.rs`, `src/injector.rs`
**功能**: inline-hook NCryptSignHash/NCryptDecrypt/BCryptSignHash，尝试 NCryptExportKey 捕获密钥
**输出**: C:\FaceWinUnlock\captured_keys\

### reverse_analysis/
**作用**: Ghidra 逆向工程
- `ngcksp.dll` - RPC 客户端分析
- `ngcsvc.dll` - NGC 服务端分析
- `NgcIsoCtnr.dll` - 隔离容器分析（KDF 定位）
- `ngcksp_patched.dll` - 二进制补丁版
- `ghidra_project/NGC_Analysis/` - Ghidra 项目

---

## 如何继续

### 1. 投产 SendInput 方案（最可行）
**还需完成**:
- Vue 前端 PIN 输入组件（Options.vue 加 PIN 框）
- 端到端部署测试

### 2. 继续 KDF 逆向（WinDbg 动态分析）
**突破口**: 在 NgcIso.exe 中下断点 `FUN_180048c08`，看 PBKDF2 的输入到底是什么格式
**难度**: 极高（Session 0 保护进程 + VBS 隔离）

### 3. key_capture 捕获密钥
**关键发现**: PIN 弹窗时 `CredentialUIBroker.exe` 运行，注入它后 hook NCryptSignHash
**问题**: Chrome 查看密码不调用任何 NCrypt/BCrypt 加密函数
**突破方向**: 在 `--ngc-ncrypt` 运行时注入，KSP 内部签名后尝试导出

### 4. 测试命令速查
```powershell
# 测试 NGC 签名 (弹 PIN 框)
PsExec -s -i "D:\RustProject\FaceWinUnlock-Tauri\target\release\FaceWinUnlock-Server.exe" --ngc-ncrypt "星记" <PIN>

# 盲打SendInput注入PIN
D:\RustProject\FaceWinUnlock-Tauri\target\release\FaceWinUnlock-Server.exe --uia-blind-inject <PIN> 3

# 注入key_capture到指定PID
D:\RustProject\FaceWinUnlock-Tauri\target\release\key_capture_injector.exe <PID> D:\RustProject\FaceWinUnlock-Tauri\target\release\key_capture.dll

# NGC ECDSA签名 (文件系统KDF)
PsExec -s -i "D:\RustProject\FaceWinUnlock-Tauri\target\release\FaceWinUnlock-Server.exe" --ngc-sign "星记" <PIN>

# Ghidra 项目路径
D:\RustProject\FaceWinUnlock-Tauri\reverse_analysis\ghidra_project\NGC_Analysis

# 构建所有
cargo build --release -p unlock -p winlogon -p key_capture -p facewinunlock-tauri
```

### 5. 重要注意事项
- `C:\Windows\System32\ngcksp_old.dll` 是补丁备份，如需恢复先恢复
- DLL 部署后需要停止 NgcSvc + NgcCtnrSvc 服务才能替换
- `key_capture_injector.exe` 被杀软删除 → 已添加 Windows Defender 排除
- Ghidra 锁定问题 → 删除 `ghidra_project\NGC_Analysis.lock` 或杀 java 进程
