# C 方案：获取 Windows Hello FIDO2 私钥（最终成果文档）

> 本文件自包含，实现者无需额外上下文。目标读者：负责实现的 AI / 开发者。
> 适用机器：**无 TPM** 的 Windows 11 25H2（Build 26200.8246）。

---

## 🔥 最终方案（2026-06-14 验证成功）

**动态捕获路径已废弃。** 最终成功的方案是 **SYSTEM DPAPI 离线解密**：

```
NGC 容器 18.dat (262B)
  → 64B NgcIsoHeader (version=1, algorithm GUID, IV, flags, key_size=32)
  → 198B DPAPI blob
  → CryptUnprotectData(no entropy, LOCAL_MACHINE) as SYSTEM
  → 32B raw ECDSA_P256 private key scalar d ✅
```

**关键发现**：
- **无需 PIN**：DPAPI blob 不依赖任何 PIN 派生的 entropy
- **无需 KDF**：直接调用 `CryptUnprotectData` 即可解密
- **25H2 格式变化**：NGC 容器从 JSON 改为二进制 `.dat` 文件
- **工具**：`key_capture/src/ngc_crack.rs` — 扫描容器、DPAPI 解密、ECDSA 公钥推导一站式

**已验证**：成功从用户 "星记" 的 NGC 容器中提取 4 个 ECDSA_P256 私钥，全部通过自洽校验（`d·G` == stored pubkey）。

---

## 0. 一句话目标（原）

> ~~在 Windows 自己解密 FIDO2 私钥的那一刻把明文私钥拦下来~~（动态捕获）→ **已改为离线 DPAPI 解密**。

---

## 1. 为什么这条路在本机可行（关键前提）

- **本机无 TPM**（`Get-Tpm` 空、无 TPM WMI 类）。无 TPM ⇒ Windows Hello 的 FIDO2 平台凭据是
  **软件密钥**（DPAPI/NGC 软件保护），不是封死在 TPM 硬件里。
- 软件密钥被使用时，**明文必然出现在某个用户态进程的内存里**——要么是 AES 解密 key blob 的
  输出，要么是签名前 `BCryptImportKeyPair` 导入的明文私钥 blob。
- 因此：hook 那个进程的解密/导入 API，触发一次真实 Hello 手势，就能把明文私钥拦下来。
- 这与「离线复刻派生」(A/B) 的根本区别：**不复刻微软的 KDF**（25H2 可能已改、公开工具未必覆盖），
  而是让 Windows 用它自己正确的算法解密，我们只在出口截获。**只需成功捕获一次**，之后缓存复用。

---

## 2. 离线方案为何失败（背景，避免重走老路）

- 已实现 `Unlock/src/ngc/`（pin.rs 派生 + mod.rs `try_multiple_key_derivations` + dpapi.rs）复刻
  Shwmae/DEF CON 32 (2024) 的算法：`PBKDF2-HMAC-SHA256(大写hex(PIN)→UTF16, salt, rounds)` →
  大写hex → UTF16 → SHA-512 → 前置固定熵 `xT5rZW5qVVbrvpuA\0`。
- 实测 `--ngc-keys <user> <PIN>`（真实 PIN）→ `verify_pin_modern` 返回 **"PIN 错误"**：用派生密钥
  **解不开 protector**。PIN 本身正确（别处验证过），是**算法没复刻对 25H2 的方案**。
- 结论：放弃离线派生，转动态捕获（本文件）。

---

## 3. 环境硬化（必做，否则进程不可注入）

软件密钥的解密可能发生在隔离用户态（IUM / VTL1 trustlet `NgcIso.exe`）或受保护进程（PPL）。
必须先解除这些保护，让目标进程可被注入 / 调试：

```powershell
# 3.1 关 VBS / 核心隔离 / Credential Guard（让 NGC crypto 落到普通 VTL0、可 hook）
bcdedit /set hypervisorlaunchtype off
# 关「内存完整性」：设置→核心隔离→内存完整性 关闭；或注册表：
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 0 /f

# 3.2 关 Secure Boot（BIOS 里关）——为加载剥 PPL 驱动 / 内核调试做准备

# 3.3 开测试签名（若要加载未签名/自签名的剥 PPL 驱动）
bcdedit /set testsigning on

# 3.4 给捕获工具目录加 Defender 排除（key_capture 形似恶意工具会被杀）
Add-MpPreference -ExclusionPath "C:\FaceWinUnlock", "D:\RustProject\FaceWinUnlock-Tauri\target\release"

# 重启生效
```

> 重启后用 `msinfo32` 确认「基于虚拟化的安全性 = 未启用」；用 Process Explorer 看目标进程
> 的 Protection 列是否已非 PPL。

---

## 4. 第一步：定位「在哪个进程、哪个 API 出明文」

FIDO2 断言签名的调用链（无 TPM）：
```
浏览器 → webauthn.dll (WebAuthNAuthenticatorGetAssertion)
  → 平台认证器 → Microsoft Passport KSP (ngcksp.dll, RPC 客户端)
  → NgcSvc 服务 (ngcsvc.dll)
  → NgcIso.exe（容器；VBS 关时落 VTL0）→ 解密 key blob + 签名
```

**用 Process Monitor 实证目标进程**（最可靠，别猜）：
1. 启动 procmon，过滤 `Path contains \Ngc\` 且 `Operation = ReadFile`。
2. 在浏览器做一次 passkey 登录（如 https://webauthn.io 注册+断言，或 google.com）。
3. 看**哪个进程**读了 `...\Ngc\<GUID>\Keys\*.json`——那就是解密发生地（候选：`NgcIso.exe`、
   `svchost.exe`(NgcSvc)、`lsass.exe`）。记下其 PID/映像名。

**候选 hook API（按命中价值排序，命中即拿明文）**：
| API (模块) | 截获内容 | 价值 |
|---|---|---|
| `BCryptImportKeyPair` (bcrypt.dll) | 签名前导入的**明文私钥 blob**（`BCRYPT_ECCPRIVATE_BLOB`，magic `ECS2`/0x32534345 或 `ECC2`） | ★★★ 最干净，直接拿私钥 |
| `BCryptDecrypt` / `NCryptDecrypt` | AES 解密 key blob 的**输出明文** | ★★★ |
| `CryptUnprotectData` (crypt32) / `NCryptUnprotectSecret` (ncrypt) | DPAPI/DPAPI-NG 解封输出（SRK / 中间密钥） | ★★ |
| `BCryptSignHash` / `NCryptSignHash` | 标记「正在签名」的时刻 + 关联 key handle（辅助定位，不直接出私钥） | ★ 辅助 |

> `BCryptImportKeyPair` 是首选：软件签名前一定要先把明文私钥 blob 导入 CNG，hook 它的入参
> `pbInput` 就是 104 字节的 P256 私钥 blob（含 d）。

---

## 5. 第二步：捕获工具（复用仓库已有的 `key_capture/`）

仓库已有 `key_capture/` crate（cdylib 注入 DLL + injector），本会话已把它从「hook 签名 + 导出
密钥」改造为「hook 解密链 + dump 明文」。实现者需在此基础上：

### 5.1 `key_capture/src/lib.rs`（已 hook，验证 + 补充）
- 现有 hook：`CryptUnprotectData`、`NCryptDecrypt`、`BCryptDecrypt`、`NCryptUnprotectSecret`、
  `Tbsip_Submit_Command`，明文 dump 到 `C:\FaceWinUnlock\captured_keys\plaintext_<hook>_<n>.bin`。
- **新增 `BCryptImportKeyPair` hook**（首要）：抓入参 `pbInput`（明文私钥 blob）。签名见 §5.3。
- **新增 `BCryptSignHash`/`NCryptSignHash` hook**：仅记录「P256 签名发生」+ 时间戳，用于和上面的
  导入/解密关联（确认抓到的是 FIDO 用的那把）。
- inline hook 用现有 14 字节窃取 + trampoline 机制；线程安全用现有 thread-local 重入守卫。

### 5.2 `key_capture/src/injector.rs`（已支持按名注入）
- 已支持 `<PID|进程名>` 注入 + SeDebugPrivilege。
- 目标改为 §4 实测出的进程（`NgcIso.exe` / NgcSvc 的 svchost PID / lsass）。
- 注入前提：§3 已关 VBS + 目标已非 PPL（否则 `OpenProcess` 返回 `ERROR_ACCESS_DENIED`，injector
  已打印该诊断）。

### 5.3 `BCryptImportKeyPair` hook 签名（实现参考）
```c
NTSTATUS BCryptImportKeyPair(
  BCRYPT_ALG_HANDLE hAlgorithm,
  BCRYPT_KEY_HANDLE hImportKey,
  LPCWSTR           pszBlobType,   // 期望 "ECCPRIVATEBLOB"
  BCRYPT_KEY_HANDLE *phKey,
  PUCHAR            pbInput,       // ★ 明文私钥 blob
  ULONG            cbInput,
  ULONG            dwFlags);
```
hook 里：若 `pszBlobType == L"ECCPRIVATEBLOB"` 且 `cbInput` 在 ~104 字节量级，把 `pbInput[0..cbInput]`
dump 出来（先调原函数拿返回值，成功才 dump）。

---

## 6. 第二步备选：WinDbg 内核调试（不注入、能穿 PPL）

若目标进程剥 PPL 困难，用**内核调试器**在 API 出口下断点 dump，内核调试在 PPL 之上、无需注入：

1. 关 VBS（§3）+ 配双机/网络内核调试（`bcdedit /debug on` + `bcdedit /dbgsettings net ...`）。
2. WinDbg 内核态 attach。
3. 对目标模块下断：
   ```
   bp bcrypt!BCryptImportKeyPair
   bp bcrypt!BCryptDecrypt
   ```
4. 触发一次 passkey 断言。
5. 断在 `BCryptImportKeyPair`：`pbInput` = 第 5 个参数（x64 调用约定：rcx,rdx,r8,r9,[rsp+0x28]…），
   `du`/`db` 出 `cbInput` 字节即明文私钥 blob。`.writemem C:\cap\key.bin <addr> L68`。
6. 详细操作另见仓库 `reverse_analysis/WINDBG_RUNBOOK.md`（若不存在请补写）。

> 一次性取密钥，WinDbg 比注入更省事、更稳，且天然穿 PPL。注入方案适合做成可重复的自动工具。

---

## 7. 第三步：识别 + 校验抓到的私钥（防假阳性，必做）

抓到的 blob 可能有多个（每帧/每次调用）。识别 FIDO2 的那把 + 证明是**对的**：

1. **格式识别**：P256 私钥常见三种——
   - 32 字节裸标量 `d`；
   - CNG `BCRYPT_ECCPRIVATE_BLOB`（104B：magic(4)+cbKey(4)=32 + X(32)+Y(32)+d(32)）；
   - PKCS#8 DER（`0x30 ...`）。
2. **铁证校验（关键，杜绝抓错/抓到别的密钥）**：
   - 从私钥 `d` 推导公钥 `Q = d·G`（p256 crate）。
   - 与该 credential 的**存储公钥**比对：来源 ① 网站（RP）注册时拿到的 publicKey；
     ② 或 `...\Ngc\<GUID>\Keys\<credId>.json` 里若含公钥字段；③ 或对 `rpIdHash=SHA256("google.com")`
     关联到具体 credId。
   - 公钥相等 = 抓对了。**不做这步别往下走**（之前吃过假阳性的亏）。

---

## 8. 第四步：接入 Phase 2 签名器（仓库已有大半）

仓库已有：`Unlock/src/passkey/`（`signer.rs` 285行 / `fido2.rs` 127行 / `http.rs` 216行 /
`sql.rs` signCount）、`BrowserExt/` 浏览器扩展。改为**用捕获的私钥**而非离线解密：

1. **存私钥**：捕获的私钥用 `pin_store` 同款 DPAPI(机器级)加密后入库，键为 `credentialId`/`rpId`。
   （明文私钥是皇冠明珠，**绝不明文落盘 / 不进日志 / 不进 git**。）
2. **签名器**：`passkey/signer.rs::sign_assertion` 改为加载**已捕获的私钥**（跳过
   `decrypt_ecdsa_key` 那条离线链），用 p256 / CNG 签 `authenticatorData ‖ SHA256(clientDataJSON)`。
3. **signCount**：RP 会校验单调递增。捕获时一并记录 Windows 当前的 signCount（或从一个足够大的
   基数起步），之后由我们持久化递增（`passkey/sql.rs`）。
4. **交付链**：`BrowserExt` 拦 `navigator.credentials.get` → POST 到本地签名器 `http.rs`
   (`127.0.0.1`，**必须加一次性 token 鉴权**，否则本机任意进程可伪造断言) → 回填断言。
5. **人脸门控**：人脸识别过才允许签名器出签名（复用现有识别链）。
6. **灰度开关**：`PASSKEY_TAKEOVER_ENABLED` 默认关。

**端到端效果**：人脸过 → 用缓存私钥即时签 → 浏览器回填 → 秒过 passkey（签名本身微秒级）。

---

## 9. 仓库现有可复用资产清单

| 路径 | 用途 |
|---|---|
| `key_capture/src/lib.rs` | 注入 DLL，已 hook 解密链（CryptUnprotectData/NCryptDecrypt/BCryptDecrypt/NCryptUnprotectSecret/Tbsip）；**需补 `BCryptImportKeyPair`** |
| `key_capture/src/injector.rs` | CreateRemoteThread+LoadLibrary 注入器，支持按进程名 |
| `reverse_analysis/HANDOVER.md` | NGC 逆向结论（含真实加密面 = TPM/NGC票据/DPAPI；离线不可复刻） |
| `reverse_analysis/WINDBG_RUNBOOK.md` | WinDbg 关VBS+剥PPL+断点dump 步骤（若缺请补） |
| `Unlock/src/passkey/{signer,fido2,http,sql}.rs` | 本地 FIDO 签名器 + HTTP API + signCount |
| `Unlock/src/ngc/*` | NGC 解析（容器/protector/header 解析仍可复用，只是离线解密那步换成捕获） |
| `BrowserExt/` | 浏览器扩展骨架（拦 `navigator.credentials.get`） |

构建环境（Rust 装在 D:\Rust）：
```powershell
$env:RUSTUP_HOME="D:\Rust"; $env:CARGO_HOME="D:\Rust\CARGO"; $env:PATH="D:\Rust\CARGO\bin;"+$env:PATH
cargo build --release -p key_capture
```

---

## 10. 端到端 Runbook（实现者照此跑通）

1. **硬化**（§3）：关 VBS + 关内存完整性 + 关 Secure Boot + 开测试签名 + Defender 排除 → 重启。
   `msinfo32` 确认 VBS=未启用。
2. **定位**（§4）：procmon 抓一次 passkey 登录，确认读 `Ngc\...\Keys\*.json` 的进程 = 目标。
3. **补 hook**（§5.1）：给 key_capture 加 `BCryptImportKeyPair`，`cargo build -p key_capture`。
4. **捕获**：注入目标进程（§5.2）或 WinDbg 断点（§6）→ 再做一次 passkey 登录 →
   看 `C:\FaceWinUnlock\captured_keys\`。
5. **校验**（§7）：推导公钥比对 RP 公钥，确认抓对。
6. **接入**（§8）：私钥加密入库 → 改签名器用捕获私钥 → BrowserExt+本地签名器+token 鉴权 →
   人脸门控 → 端到端测一次 passkey 秒过。
7. **回归**：灰度开关默认关；关掉后回落系统原生 Hello。

---

## 11. 风险 / 边界（如实记录）

- **降安全姿态**：关 VBS/Secure Boot + 开测试签名 = 系统安全性下降；剥 PPL 用未签名驱动有
  蓝屏/不稳风险。**仅限自有机器自用**，文档化。
- **皇冠明珠**：捕获的私钥 = 该 passkey 的完整控制权。务必加密存储、token 鉴权、绝不外泄。
- **只对浏览器内 passkey 有效**：系统级/应用级 WebAuthn 走 webauthn.dll 直连，扩展拦不到。
- **易碎**：Windows 更新可能轮换密钥 / 改保护 → 需重新捕获；浏览器更新可能改 WebAuthn 行为。
- **signCount 一致性**：必须接续 Windows 的计数或从足够大基数起，否则 RP 拒签。
- **法务/伦理**：自有机器、自己的 passkey、自用——授权范围内。

---

## 12. 给实现者的最小起步建议

先别贪全链。**先只做「捕获 + 公钥校验」**（§3→§7）跑通——证明能在 25H2 无 TPM 机器上把
FIDO2 私钥拦下来并验证为真。这一步成了，整条 C 方案才成立；不成（明文始终不出现在用户态、
或全程在某不可达的隔离里），再回头评估值不值得继续。**§7 的公钥比对是 go/no-go 闸门。**

---

## 13. 25H2 NGC 二进制格式（实测解码）

### 13.1 目录结构

```
Ngc\{ContainerGUID}\
    1.dat          — UTF-16LE 编码的用户 SID
    6.dat          — 标志位 (68B)
    7.dat          — UTF-16LE "Microsoft Platform Crypto Provider"
    8.dat          — 类型标志 (2B)
    10.dat         — 标志 (4B)
    11.dat         — 随机种子 (20B)
    Protectors\
        1\
            15.dat  — DPAPI 加密的 protector blob (292B)
    {CredentialTypeGUID}\
        {KeyHash1}\
            1.dat   — KSP 密钥名 (UTF-16LE hex)
            2.dat   — KSP Provider 名 (UTF-16LE)
            3.dat   — 密钥 GUID (UTF-16LE)
            7.dat   — FIDO2 凭据元数据 (CBOR: rpId, credId, user)
            12.dat  — 算法名，如 "ECDSA_P256" (UTF-16LE)
            18.dat  — ★★★ DPAPI 加密的 ECDSA 私钥 (262B)
        {KeyHash2}\ ...
```

### 13.2 18.dat 格式（262 字节）

```
Offset  Size  Content
0x00    4     Version (=1)
0x04    16    Algorithm GUID (d08c9ddf-0115-d111-8c7a-00c04fc297eb)
0x14    4     Key type/ID
0x18    16    IV (same across all keys in container)
0x28    4     Flags
0x2C    4     Flags
0x30    4     Data length related?
0x34    4     Zero
0x38    4     =1
0x3C    4     Key size (=32, AES-256)
0x40    198   DPAPI blob → CryptUnprotectData → 32B ECDSA d
```

### 13.3 解密工具链

| 工具 | 用途 |
|------|------|
| `ngc_crack.exe --sid <SID> <PIN>` | 扫描容器、DPAPI 解密、AES 尝试、ECDSA 搜索 |
| `ngc_crack.exe --dump` | dump 所有 .dat 文件 hex |
| `key_verify.exe <file>` | 验证 32B/104B/PKCS#8 ECDSA 密钥 |
| 运行方式 | `PsExec -accepteula -s ngc_crack.exe --sid S-1-5-... PIN` |

### 13.4 已验证密钥（用户 "星记", PIN=145236987）

| 密钥目录 | RP | 凭据 ID | 私钥 d (前8字节) |
|----------|-----|---------|-------------------|
| 2773e521... | google.com | GOOGLE_ACCOUNT:1011... | 2f6a704350147b44 |
| fa01ec8f... | webauthn.io | webauthn.io-starnotes | c6ffc030cd10fcdb |
| 56d07ac4... | (旧密钥) | - | 1359d63ff4cc2036 |
| 96776417... | (旧密钥) | - | dbf2e4721673e93a |
