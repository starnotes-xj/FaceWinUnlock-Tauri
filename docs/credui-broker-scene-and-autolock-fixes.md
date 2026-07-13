# broker CredUI 场景区分 + 自动锁屏闪烁 —— 修复档案与防回归

> **这两个问题（尤其第一个）反复折腾了 ≥6 个方案才彻底解决。** 本文件记录症状、根因、
> **所有失败的试错方案（别再走）**、最终方案、实证日志，以及一份防回归清单。
> **改动任何 broker / CREDUI / auto_lock 相关代码前，先读本文件。**
>
> 解决于 2026-06-20。相关提交：
> - `8f56a51` — Server DLL：broker 用前台窗口标题区分查看密码/passkey/设置PIN
> - `0858e28` — Unlock auto_lock_monitor 加 60s 授权冷却（修闪烁）

---

## 问题一：broker CredUI 三场景无法区分（核心）

### 症状

`credentialuibroker.exe` 托管的 CredUI 场景下，三种操作互相干扰：

1. **Windows 设置里启用 Passkey 插件、输入 PIN 后卡死**（输入 PIN 时键盘被拦、动画遮挡）。
2. **Chrome 用通行密钥登录、选「Windows 原生 Hello」时，移动鼠标/敲键盘触发人脸识别**，
   摄像头乱亮、无法正常输 PIN。
3. 但 **Chrome 查看已保存密码必须走人脸**；网页登录框里**填充已保存密码**也需要可选覆盖。

期望行为：
| 场景 | 走人脸？ |
|---|---|
| Chrome 查看密码 | ✅ 要 |
| Chrome / Edge 网页内填充保存密码 | ✅ 要（默认 `CREDUI_BROWSER_PASSWORD_FILL=1`） |
| 通行密钥选「使用插件」 | ✅ 要（走插件独立通道 `passkey_face_gate`，本来就走） |
| 通行密钥选「Windows 原生 Hello」 | ❌ 不要 |
| 设置启用插件输 PIN | ❌ 不要 |
| 锁屏 / 登录 | ✅ 要（主场景，不走 broker） |

### 根因：三场景在 Credential Provider 层完全同构

`credentialuibroker.exe` 同时托管「查看密码」「通行密钥验证」「设置启用插件 PIN」，
在 DLL 能拿到的所有信号上**完全一致**（2026-06-20 实测）：

- `cpus` 都是 `CPUS_CREDUI`(4)
- `dwflags` 都是 `0x250`（同场景第二次调用变 `0x200`/`0x210`，但查看密码和通行密钥都出现过 `0x210`，**无法区分**）
- `CLSID` / auth package / `rgbSerialization` 一致
- `GetForegroundWindow` 都是 `CredentialUIBroker.exe`，标题 `Windows 安全中心`，类名 `Credential Dialog Xaml Host`

→ **进程名、cpus、dwflags、前台窗口本身都区分不了。**

### 试错史（全部失败或有致命缺陷，不要再走）

| # | 方案 | 做法 | 为什么不行 |
|---|------|------|-----------|
| 1 | **UIA `broker_detect`** | 用 UI Automation 读 broker 弹窗 XAML 文本（"密码"/"通行密钥"）分类 | broker 是受限进程，进程内 UIA COM 被封：`CoCreateInstance`→`REGDB_E_CLASSNOTREG`、`DllGetClassObject`→`CLASS_E_CLASSNOTAVAILABLE`，**读不到文本**。其安全兜底 `Unknown→跳过` 会把查看密码也跳过（不走人脸）。 |
| 2 | **broker 无条件先人脸**（`16b4e44`/`c495971`）| broker 一律启动人脸监听，超时回退 PIN | passkey 选原生 / 设置 PIN 时也启动人脸 → 全局输入 Hook（`WH_KEYBOARD_LL`）拦截 PIN 键盘 + DComp topmost 动画遮挡 PIN 框 → **输 PIN 卡死**；移动鼠标乱触发人脸、摄像头乱亮。 |
| 3 | **`broker_release` 35s 冷却**（`54b0dd4`）| 人脸超时后设 35s 冷却，拒绝后续 `run` | **死亡螺旋**：用户重试查看密码落在 35s 冷却期内 → `run` 被拒 → 必然超时 → 又刷新 35s 冷却 → 永久锁死，查看密码再也走不了人脸。passkey 走独立 gate 不受影响，呈现"passkey 能刷脸、查看密码不能"。 |
| 4 | **`has_browser_window`**（`ca31fa3`）| 检测前台是否浏览器窗口：有→人脸，无→跳过 | 查看密码和通行密钥验证**都是 Chrome 前台**（`has_browser=true`），区分不开 → 通行密钥选原生也触发人脸（回到问题 2）。只能解决"设置 PIN（无浏览器）不卡死"。 |

> **关键教训**：问题 3 的冷却（`54b0dd4`）比"恢复查看密码人脸"的修复（`c495971`）更早埋下，
> 而那次修复**只验证了首次成功、没验证重试**，所以同一症状反复回归。**改 broker 代码后必须
> 验证"连续重试"和"四个场景各一遍"，不能只验证 happy path。**

### 最终方案（2026-07-13）：WebAuthn 活动守卫 + Win32 owner 上下文

窗口标题能识别明确的“密码管理器”或“通行密钥”文本，但 QQ 邮箱填充只暴露普通网页标题，
不能把“无 passkey 关键词”直接等同于密码。最终方案使用两个互补信号，全程不检查 broker 内部控件：

1. `Unlock/src/webauthn_activity.rs` 使用 Windows Event Log API 订阅
   `Microsoft-Windows-WebAuthN/Operational`。1000/1003/1006 表示顶层事务开始，
   1001–1002/1004–1005/1007–1008 表示结束，以 TransactionId 维护活动集合。
2. 监视器先订阅、再回放最近十分钟，并校验 channel、provider 和 1000–1008 元数据。
   健康和活动状态通过只读命名事件 `FaceWinUnlockTauriWebAuthnReady/Active` 暴露。
3. DLL 收集前台、owner、root-owner 的标题和进程名。`dwflags` 只记录诊断，不参与意图判定。
4. 分类优先级固定为：Active WebAuthn → passkey/security-key/PIN/settings 明确信号 →
   Settings/BioEnrollmentHost/Incognito/InPrivate → 明确 password/reveal/fill → Unknown browser fallback。
5. Unknown 只有在 owner 是 `chrome.exe`/`msedge.exe`、监视器 Ready、非 Active、非隐私窗口，
   且 `CREDUI_BROWSER_PASSWORD_FILL=1` 时才能走人脸；其它情况返回 `E_NOTIMPL`。
6. `SetUsageScenario`、`Advise` 和发送 `prepare/run` 前都会复查 Active。若事务中途变为
   WebAuthn，只停止通用 broker 识别，不取消官方 Passkey 插件自己的 `passkey_face_gate`。

监视器缺失、channel 被禁用或未来 Windows 事件契约变化时，Unknown 浏览器场景安全降级为
Windows PIN；明确的查看/显示/填充密码文本仍可走人脸。

### 根因订正（2026-07-13 实测日志）——填充密码走不了人脸的真凶

用 v0.5.9-webauthn-guard 测试包实测 `unlock.log` + `facewinunlock.log`，发现监视器**从未真正工作**，
QQ 邮箱填密码全部落到 `MonitorUnavailable → 跳过人脸`。根因两点，都已修复：

1. **`TransactionId` 是 GUID 变体（`EvtVarTypeGuid`=15），不是字符串**。`webauthn_activity.rs`
   的 `variant_string` 只认 `EvtVarTypeString` → 每次收到真实 CTAP 事件就报
   `unexpected string variant type 15` → 回调标记 `unhealthy` → `Ready` 事件被 Reset →
   DLL 读到 `webauthn_ready=false` → 浏览器填密码一律回退 PIN。**这是"填密码没走人脸"的真凶**，
   不是分类逻辑问题。修复：`variant_string` 增加 GUID 分支，手写格式化成规范 GUID 字符串作事务键
   （started/completed 同一事务产生一致键）。已加回归单测
   `transaction_id_guid_variant_parses_to_canonical_string`。

2. **实测事件语义**（`Get-WinEvent 'Microsoft-Windows-WebAuthN/Operational'`）：
   - `1000/1001/1002` = **Ctap MakeCredential**（创建/保存 passkey）开始/完成/失败
   - `1003/1004/1005` = **Ctap GetAssertion**（passkey 登录）开始/完成/失败
   - `1006/1007/1008` = **Ctap SendCommand** 开始/完成/失败
   - 这些才是"需要用户验证（UV）的顶层 passkey 事务"，`active` 判定**只该看它们**。
   - `2100/2102`（含 `Command=GetAllPlatformCredentials`）是底层 API 枚举，**填充密码也会触发**，
     绝不能计入 `active`（否则填密码被误判 passkey）。监视器只订阅 1000–1008 是对的。
   - 时间线验证：填密码 broker 弹窗时，最近的 GetAssertion 已 completed（`active=false`）→ 人脸；
     真 passkey 的 broker UV 弹窗发生在 GetAssertion started 未 completed 期间（`active=true`）→ 跳过。

### 不靠标题名单的重构（2026-07-13）

监视器修好后 `webauthn_active` 成为**可靠的、非本地化文本**的 passkey 信号，`classify_broker_context`
据此重构，**正常路径完全不看标题关键词**：

- **监视器 Ready（常态）**：`active=true` → Passkey 跳过；`active=false` + owner 是浏览器 + 非私密
  → `BrowserPasswordFill` 走人脸。**不检查任何标题关键词**——这才真正解决 QQ 邮箱/任意语言登录页。
- owner 进程 `SystemSettings.exe`/`BioEnrollmentHost.exe` → PinOrSettings 跳过（结构信号，非标题）。
- **标题关键词名单降级为兜底**：仅在监视器 **不可用**（Ready=false，启动窗口/通道禁用/异常）时才用
  `PASSKEY/PIN/PASSWORD/PASSWORD_FILL_KEYWORDS` 保守判定，避免把进行中的 passkey 误引到人脸。
- 回归单测 `ready_monitor_lets_browser_fill_use_face_without_title_keywords`（QQ 邮箱 Ready 场景）
  与 `active_ctap_transaction_skips_face_even_on_plain_login_page`（同页 active 时跳过）固化该语义。

### 实证日志（2026-06-20 验证通过）

中文 Chrome 环境，`facewinunlock.log`：

```
18:45:43 classify_broker_scene - 前台窗口标题: "windows 安全中心 google 密码管理工具 - google chrome ..."
18:45:43 broker 场景分类: Password
18:45:43 「查看密码」场景，启用先人脸、失败后回退 Windows PIN          ← 查看密码 → 人脸 ✓

18:46:31 classify_broker_scene - 前台窗口标题: "windows 安全中心 登录 - google 账号 - google chrome ..."
18:46:31 broker 场景分类: Unknown
18:46:31 非「查看密码」场景，跳过人脸，交还 Windows                    ← 登录 → 跳过 ✓

18:47:05 classify_broker_scene - 前台窗口标题: "windows 安全中心 通行密钥和安全密钥 - google chrome ..."
18:47:05 broker 场景分类: Passkey
18:47:05 非「查看密码」场景，跳过人脸，交还 Windows                    ← 通行密钥 → 跳过 ✓
```

> 注意通行密钥实际标题是「通行密钥和安全密钥」（与早期诊断的「请使用您的通行密钥…」不同），
> 但 `通行密钥` + `安全密钥` 两个关键词都命中，稳。

### 防回归清单（改 broker / CREDUI 代码前必读）

- ❌ **不要**只用 `cpus` / `dwflags` / 单一进程名 / 前台窗口本身区分场景——实测不足。
- ❌ **不要**在 broker 进程内用 UIA COM（`CoCreateInstance`）——被封，死路。
- ❌ **不要**恢复任何 PIN 键盘注入、窗口控件定位或自动提交方案。
- ❌ **不要**让 broker「无条件先人脸超时回退」——会拦 passkey/设置 PIN 的键盘输入、动画遮挡、摄像头乱亮。
- ❌ **不要**用「按时间冷却拒绝 run」抑制重复触发——必然死亡螺旋，永久锁死查看密码人脸。
- ✅ WebAuthn Active 是强否决信号；Unknown fallback 必须要求监视器 Ready。
- ✅ 网页内填充保存密码默认走 `CREDUI_BROWSER_PASSWORD_FILL=1`，且 owner 必须是 Chrome/Edge。
- ✅ `webauthn` / `fido2` / `save passkey` 属于保存通行密钥注册流，必须在浏览器 Unknown fallback 前跳过。
- ✅ 通行密钥选「使用插件」走的是 `passkey_face_gate`（Unlock 独立 HTTP/管道通道），与 face CP broker **无关**，不要混。
- ✅ 改 `classify_broker_scene` 关键词后，**必须看日志**确认四个场景（查看密码/通行密钥/设置PIN/登录）分类正确。
- ✅ **英文或其它语言 Chrome 标题不同**（如 "Password Manager" / "passkey"），需补关键词；
  日志会打印 `前台窗口标题: "..."`，照着补即可。
- ✅ 改完务必验证「连续重试」+「四场景各一遍」，不要只验证首次成功。
- ✅ **WebAuthn 事件的 `TransactionId` 渲染为 GUID 变体（`EvtVarTypeGuid`=15），不是字符串**——
  `variant_string` **必须**支持 GUID 分支，否则监视器一收到真实 passkey 事件就崩溃、Ready 被清、
  填密码永远回退 PIN（2026-07-13 实测根因）。改 `webauthn_activity.rs` 解析层后必须跑
  `transaction_id_guid_variant_parses_to_canonical_string`。
- ✅ **`active` 只看 1000–1008（CTAP MakeCredential/GetAssertion/SendCommand）**；`2100/2102`
  的 `GetAllPlatformCredentials` 是枚举、填密码也会触发，**绝不能计入 active**（否则填密码被误判 passkey）。
- ✅ **监视器 Ready 的正常路径不靠标题名单**：`active=false` + owner 浏览器 → 人脸。标题关键词
  名单只在监视器 **不可用** 时兜底，不要把它挪回正常路径当主判据。

---

## 问题二：自动锁屏每秒开摄像头闪烁

### 症状

开启自动锁屏后，人坐在屏幕前不动，摄像头**每秒亮一次**（LED 闪烁、CPU/耗电）。

### 根因

`Unlock/src/main.rs` 的 `auto_lock_monitor` 循环 1 秒一轮：
1. 读系统空闲 `get_idle_millis()`（基于 `GetLastInputInfo`）
2. idle 超 `autoLockTimeout` → 开摄像头识别
3. 识别到授权用户 → **只更新 `state.last_user_active`**（程序内部时间戳）

但**人脸识别不会重置 OS 的 `GetLastInputInfo`**（用户没有真实键鼠输入）→ 下一轮 OS idle 仍然
超时 → 又开摄像头识别 → **每秒重复**。

### 修复（两次）

**第一次（`0858e28`）** 增加 `AUTH_COOLDOWN = 60s` 局部冷却，把「每秒」降到「每 60s」：
- 授权成功后记录 `auth_cooldown_until = now + 60s`；
- 冷却期内即使 OS idle 仍超时，也跳过开摄像头（`continue`）；
- **用户真实键鼠输入**（idle < timeout）或**锁屏**（未授权）时清空冷却。

**第二次（2026-06-21）** 把固定 60s 改为 `max(60s, autoLockTimeout)` 并补全日志：
- 冷却时长 = `max(60s, 用户设的 autoLockTimeout)`。固定 60s 仍嫌频繁——用户在场
  （看屏幕、读网页、盯终端，手不碰键鼠）超时后，每 60s 就开一次摄像头复查在场，摄像头乱亮。
  按用户设的检测间隔（通常 5 分钟）周期复查才合理，频率直接降 5 倍。
- **开摄像头 / 授权 / 锁屏都写 `unlock.log`**（`auto-lock: ...`）：这处开摄像头原来**没有任何日志**
  （face_recognition_loop 有、auto_lock 没有），用户只看到摄像头亮、`unlock.log` 却空白，
  无从判断是 auto-lock 正常复查还是异常调用——排障时一度误判为「非人脸场景乱亮摄像头」的 bug。

### 防回归

- ✅ 记住：人脸识别成功**不会**重置 `GetLastInputInfo`，所以授权后必须有冷却，否则必然每秒重复开摄像头。
- ✅ 冷却时长用 `max(60s, autoLockTimeout)`，不要写死 60s；这处开摄像头**必须有日志**，否则用户无法区分正常复查与异常调用。
- ❌ 不要试图用 `state.last_user_active` 来抑制——它是程序内部时间戳，OS idle 看不到它。

---

## 一句话总结

- **broker 三场景区分**：用 WebAuthn 活动守卫做强否决，再组合明确标题语义、owner 进程、隐私状态和健康开关；禁止 UIA 和 PIN 注入。
- **自动锁屏闪烁**：人脸识别不重置 OS idle，授权后必须加冷却。
