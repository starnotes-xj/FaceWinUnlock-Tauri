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
3. 但 **Chrome 查看已保存密码必须走人脸**。

期望行为：
| 场景 | 走人脸？ |
|---|---|
| Chrome 查看密码 | ✅ 要 |
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

### 最终方案（已验证）：读「触发应用窗口标题」分类

**关键洞察**：broker 弹窗（`GetForegroundWindow`）本身无区分信息，但它的**所有者窗口**
（`GW_OWNER` / `GA_ROOTOWNER`）就是**触发它的应用**（Chrome / 设置），其标题直接说明用户意图。
而且这是用 `GetWindowTextW` 读**应用进程**的窗口（非受限），能稳定读到——
**不像 broker 进程内 UIA COM 被封**。

实现：`Server/src/lib.rs` 的 `classify_broker_scene()` + `CSampleProvider::SetUsageScenario`：

1. `GetForegroundWindow` → 读它 + `GW_OWNER` + `GA_ROOTOWNER` 三个窗口标题，拼接小写。
2. 关键词分类（**passkey 优先**，因为"通行密钥"含"密钥"但绝不含"密码"，与"密码管理工具"无交集）：
   - 含 `通行密钥`/`passkey`/`安全密钥`/`security key`/`证实是您本人`/`确保是你本人` → **Passkey**
   - 含 `密码`/`password` → **Password**
   - 否则 → **Unknown**
3. `SetUsageScenario` 中只有 `Password` 启用人脸；`Passkey`/`Unknown` 一律 `return Err(E_NOTIMPL)`，
   本 Provider **完全不参与**——不启动监听、不装输入 Hook、不创建动画、摄像头不亮，交还 Windows
   原生 PIN/Hello。

这样一次满足全部需求：查看密码走人脸、通行密钥选原生不触发、设置 PIN 不卡死、不需要时不乱触发。

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

- ❌ **不要**用 `cpus` / `dwflags` / 进程名 / 前台窗口本身区分这三个场景——实测全同构。
- ❌ **不要**在 broker 进程内用 UIA COM（`CoCreateInstance`）——被封，死路。
- ❌ **不要**让 broker「无条件先人脸超时回退」——会拦 passkey/设置 PIN 的键盘输入、动画遮挡、摄像头乱亮。
- ❌ **不要**用「按时间冷却拒绝 run」抑制重复触发——必然死亡螺旋，永久锁死查看密码人脸。
- ✅ 区分**只能**靠 `classify_broker_scene()` 读触发应用的窗口标题。
- ✅ 通行密钥选「使用插件」走的是 `passkey_face_gate`（Unlock 独立 HTTP/管道通道），与 face CP broker **无关**，不要混。
- ✅ 改 `classify_broker_scene` 关键词后，**必须看日志**确认四个场景（查看密码/通行密钥/设置PIN/登录）分类正确。
- ✅ **英文或其它语言 Chrome 标题不同**（如 "Password Manager" / "passkey"），需补关键词；
  日志会打印 `前台窗口标题: "..."`，照着补即可。
- ✅ 改完务必验证「连续重试」+「四场景各一遍」，不要只验证首次成功。

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

### 修复

`auto_lock_monitor` 增加 `AUTH_COOLDOWN = 60s` 局部冷却：
- 授权成功后记录 `auth_cooldown_until = now + 60s`；
- 冷却期内即使 OS idle 仍超时，也跳过开摄像头（`continue`）；
- 冷却期满后才重新检测；
- **用户真实键鼠输入**（idle < timeout）或**锁屏**（未授权）时清空冷却。

### 防回归

- ✅ 记住：人脸识别成功**不会**重置 `GetLastInputInfo`，所以授权后必须有冷却，否则必然每秒重复开摄像头。
- ❌ 不要试图用 `state.last_user_active` 来抑制——它是程序内部时间戳，OS idle 看不到它。

---

## 一句话总结

- **broker 三场景区分**：唯一可靠信号是「触发弹窗的应用窗口标题」（`GetWindowTextW` 读 owner 窗口），不是 dwflags、不是 UIA、不是进程名。
- **自动锁屏闪烁**：人脸识别不重置 OS idle，授权后必须加冷却。
