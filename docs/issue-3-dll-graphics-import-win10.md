# issue #3 — 旧 Win10 锁屏无面容磁贴 / 无 DLL 日志 / 解锁失败 —— 修复档案与防回归

> 解决于 2026-06-21。原仓库 [issue #3](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/3)。
> 症状：Win10 用户装 0.5.x 后初始化，锁屏不出现面容磁贴、不自动解锁；安装目录只有
> `app.log` + `unlock.log`，**没有 `facewinunlock.log`（DLL 日志）**；而装回原版 0.3.5 一切正常。
> 初始化第三步「Passkey 插件」还弹红色错误 `Add-AppxPackage ... HRESULT: 0x80073CFD`。

本 issue 实为**两个互相独立**的问题。作者一度以为「第三步报错导致第四步失败」，
**这个因果是错的**——见下文「因果澄清」。

---

## 根因 A（核心：解锁失败）—— CP DLL 静态依赖图形库，旧 Win10 加载失败

### 证据链（决定性）

1. `app.log` 显示初始化第二步 `deploy_core_components` **完全成功**：DLL 已复制到
   `C:\WINDOWS\system32`、CP/CLSID 注册表已写、计划任务已建。用户截图也确认 System32 有 DLL。
   → 注册没问题。
2. 用户**完全没有 `facewinunlock.log`**。而 `Server/src/lib.rs` 的 `DllMain` 在
   `DLL_PROCESS_ATTACH` 一加载就会创建该日志并写「DllMain: 基础框架初始化完成」。
   → **DllMain 从未运行 = DLL 从未被 LogonUI 加载**（失败发生在更早的 PE loader 阶段）。
3. 对用户实际安装的 `FaceWinUnlock_Tauri.dll`（0.5.1 release 资产）跑 `dumpbin /imports`：

   | DLL | 导入函数 | 最低系统 |
   |-----|---------|---------|
   | `dcomp.dll` | **`DCompositionWaitForCompositorClock`** | **Windows 10 1803 (17134)** |
   | `dcomp.dll` | `DCompositionCreateDevice2` | Win8.1 |
   | `d3d11.dll` | `D3D11CreateDevice` | Win7 |
   | `d2d1.dll` | `D2D1CreateFactory` | Win7 |
   | `dwrite.dll` | `DWriteCreateFactory` | Win7 |

4. 这些图形依赖来自 fork 新增的**动画 UI**（`Server/src/animation.rs`），是 fork 相对原版
   唯一的 PE 层新增依赖。原版 0.3.5 无动画/无图形依赖 → 能加载。

**结论**：动画用 windows-rs 的**静态导入**调用图形自由函数，CP DLL 的 PE 导入表因此硬依赖
`dcomp.dll!DCompositionWaitForCompositorClock`（1803+）。在更旧的 Win10 上，LogonUI 加载本 DLL
时静态导入解析失败（`STATUS_ENTRYPOINT_NOT_FOUND`），整个凭据提供程序无法加载 →
锁屏无磁贴、无日志、面容解锁完全失效。运行时的灰度开关 `ANIMATION_UI_ENABLED` 救不了——
静态导入在 PE 加载阶段就要解析，与运行时是否启用动画无关。

### 修复 A

`Server/src/animation.rs` 新增 `dyngfx` 子模块，把 5 个图形自由函数改为运行时
`LoadLibrary + GetProcAddress` 动态加载（COM 接口方法走 vtable，本就不产生导入，无需改）：

- `D3D11CreateDevice`、`DCompositionCreateDevice2`、`DCompositionWaitForCompositorClock`、
  `D2D1CreateFactory`、`DWriteCreateFactory`

动态加载后导入表不再含这些库；某导出缺失（老系统）时返回 `Err`，渲染线程优雅退出，动画不显示
但**面容解锁完全不受影响**。`DCompositionWaitForCompositorClock` 缺失时退化为返回 0（不等待），
渲染主循环有挂钟兜底限速，不会空转。

### 验证（决定性）

重新编译后对新 DLL 跑 `dumpbin /imports`：`d3d11.dll / dcomp.dll / dwrite.dll / d2d1.dll`
**全部消失**，只剩 Win10 全版本自带的核心系统 DLL（kernel32/user32/advapi32/ole32/credui/
ntdll/secur32 + UCRT + VCRUNTIME140）。LogonUI 在任意 Win8.1+/Win10/Win11 都能加载本 DLL。

---

## 根因 B（第三步报错）—— Passkey MSIX MinVersion = Win11 24H2

`PasskeyPlugin/Package.appxmanifest`：

```xml
<TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.26100.0" .../>
```

`10.0.26100` = **Windows 11 24H2**。Win10（build < 26100）执行 `Add-AppxPackage` 直接报
`0x80073CFD`（`ERROR_INSTALL_PREREQUISITE_FAILED`，OS 版本先决条件不满足）。

这个 MinVersion **不是写错**：第三方通行密钥（passkey）凭据 Provider 本身就是 Windows 11 24H2
引入的系统功能，全部 Win10 都无法注册/使用该插件。所以正确做法不是「降版本硬装」（装上也用不了），
而是在不支持的系统上**优雅跳过**。

### 修复 B

- `UI/src-tauri/src/modules/passkey_plugin.rs`：新增 `current_os_build()` /
  `is_passkey_os_supported()`（读注册表 `CurrentBuildNumber`，≥ 26100 才支持），
  `get_passkey_plugin_status` 返回新增字段 `os_supported`；`install_passkey_plugin` 在不支持时
  直接返回可读提示，不再把 `0x80073CFD` 原始错误透传。
- `UI/src/views/Init.vue`：读取 `os_supported`，不支持时第三步显示「当前系统无需配置通行密钥
  （需 Win11 24H2+），已自动跳过，不影响面容解锁」，不自动尝试安装、不弹红色错误、禁用安装按钮。

---

## 因果澄清（重要）

根因 A 与 B **完全独立**：

- 第三步 passkey 报错 **不会**阻断解锁。CP 注册在第二步 `deploy_core_components` 就完成，
  第三步「下一步」按钮无条件可点，用户能继续到第四步。
- 真正导致解锁失败的是根因 A（DLL 在旧 Win10 加载不了）。即使 passkey 第三步成功，旧 Win10
  仍然解锁失败。
- 反之在 Win11 24H2 上，根因 A 不触发（图形导出都在），但旧版本仍会因 B 在第三步弹错。

---

## 防回归清单

- ❌ **绝不**在 `Server/`（注入 LogonUI 的 CP DLL）里用 windows-rs 的图形/新系统 API
  **静态导入自由函数**（`D3D11CreateDevice` / `DCompositionCreateDevice2` /
  `DCompositionWaitForCompositorClock` / `D2D1CreateFactory` / `DWriteCreateFactory` 等）。
  一律走 `animation.rs` 的 `dyngfx` 运行时动态加载。新增图形调用前先想：它会不会进 PE 导入表？
- ✅ 改动 `Server` DLL 后用 `dumpbin /imports FaceWinUnlock_Tauri.dll` 复核：导入表只应有
  核心系统 DLL，**不得**出现 `d3d11/dcomp/dwrite/d2d1` 等图形库。
- ❌ **绝不**为了「让 Win10 装上 passkey」去降 MSIX `MinVersion`——功能要 24H2，装上也用不了。
  旧系统一律在 UI 层按 `os_supported` 优雅跳过。
- ✅ 判断「DLL 有没有被 LogonUI 加载」看 `facewinunlock.log` 是否有当次启动记录（含 PID）；
  无日志 = 没加载 = PE 加载阶段失败（查导入表/依赖），不是运行时逻辑问题。
