# Windows Hello 风格动画 UI 开发计划

> 本文档跟踪 Credential Provider DLL 动画 UI 功能的设计与实现进度。
> 起源于 [issue #99](https://github.com/zs1083339604/FaceWinUnlock-Tauri/issues/99) 提出的"增加动画引导提示"建议。

---

## 一、背景

### 1.1 issue #99 拆解状态

| 建议 | 状态 |
|---|---|
| 解锁时提升屏幕亮度 | ✅ 已实现（Unlock.exe + WMI，v0.3.5-fork） |
| **增加动画引导提示** | 🔄 **本文档跟踪** |
| 监测电脑活动状态决定调用 | ✅ 已通过 `faceRecogType=operation` 实现 |
| 触屏适配 | ✅ Windows 自动把触摸转为指针事件，兼容 |

### 1.2 可行性结论（Opus 深度调研得出）

原以为"动画受 Credential Provider 架构限制"是**错误结论**。深入调研后确认完全可行：

1. `ICredentialProviderCredentialEvents::SetFieldBitmap` 官方支持动态磁贴位图更新
2. `OnCreatingWindow` 返回 LogonUI 父窗口 HWND，可创建**自定义子窗口**
3. DLL 加载在 LogonUI 进程内，**可同进程使用 DirectComposition**（跨进程会被拒绝）
4. Windows 10 SDK 已包含 `ICredentialProviderCredentialEvents3::SetFieldBitmapBuffer`（GUID `2D8DEEB8-1322-4973-8DF9-B282F2468290`）

### 1.3 不可行路径（已排除）

- ❌ **WebView2**：Microsoft 自家示例都在登录界面失败（[WebView2Feedback#2868](https://github.com/MicrosoftEdge/WebView2Feedback/issues/2868)、[#4231](https://github.com/MicrosoftEdge/WebView2Feedback/issues/4231)）
- ❌ **Windows Biometric Framework**：需 WHQL 签名驱动 + ESS 限制，开源项目几乎做不到
- ❌ **Hook LogonUI 内部接口**：跨版本 ABI 不稳定，会被 AV/EDR 标记
- ❌ **Nt\*/Rtl\* 原生 API**：解决的是内核交互（文件/内存/线程），不是 UI 渲染问题
- ❌ **Sciter/Ultralight 嵌入浏览器**：未验证 winlogon 环境，风险过高

---

## 二、技术决策

### 2.1 选定方案

- **架构层**：第 2 层 - DirectComposition 自定义子窗口（"我们的窗口"）
- **绘制层**：路径 ② - 手工翻译 CSS 到 Direct2D 原生绘制

### 2.2 技术栈

| 组件 | DLL | 用途 |
|---|---|---|
| DirectComposition | `dcomp.dll` | 硬件加速合成，60 FPS 平滑动画 |
| Direct2D 1.3 | `d2d1.dll` | 矢量绘制（路径、渐变、变换） |
| Direct3D 11 | `d3d11.dll` | DComp 设备所需的底层 GPU 设备 |
| DXGI 1.2+ | `dxgi.dll` | 交换链/Surface |
| Win32 子窗口 | `user32.dll` (`CreateWindowEx`) | DComp Target 绑定载体 |

依赖 (Server/Cargo.toml)：

```toml
windows = { version = "0.59", features = [
    # 现有 features 之外补充：
    "Win32_Graphics_DirectComposition",
    "Win32_Graphics_Direct2D",
    "Win32_Graphics_Direct2D_Common",
    "Win32_Graphics_Direct3D",
    "Win32_Graphics_Direct3D11",
    "Win32_Graphics_Dxgi",
    "Win32_Graphics_Dxgi_Common",
    "Win32_Graphics_Gdi",
] }
```

### 2.3 整体架构

```
┌──────────────────────────────────────────────────────────────┐
│   Server DLL (loaded in LogonUI.exe)                         │
│                                                              │
│   ┌─────────────────────────────────────────────────┐        │
│   │ CSampleCredential                               │        │
│   │   - Advise()        → 缓存 pEvents              │        │
│   │   - OnCreatingWindow → 拿到 LogonUI 父 HWND    │        │
│   │   - 创建子窗口（128×128 在磁贴位置）            │        │
│   │   - 初始化 DComp Device + Target                │        │
│   │   - 启动渲染线程                                │        │
│   └─────────────────┬───────────────────────────────┘        │
│                     │                                        │
│                     ▼                                        │
│   ┌─────────────────────────────────────────────────┐        │
│   │ AnimationRenderer (独立线程)                    │        │
│   │   - 状态机：Idle / Scanning / Success / Fail    │        │
│   │   - D2D 绘制：旋转环 / 扫描线 / 边框脉冲        │        │
│   │   - 16ms 帧率（60 FPS）                         │        │
│   │   - DComp Commit → 硬件合成                     │        │
│   └─────────────────────────────────────────────────┘        │
│                     ▲                                        │
│                     │ 状态变更                               │
│   ┌─────────────────┴───────────────────────────────┐        │
│   │ CPipeListener                                   │        │
│   │   - 收到 Unlock.exe 的状态消息 → 切换状态       │        │
│   └─────────────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────────────┘
```

---

## 三、阶段分解

### 阶段 A：DComp 子窗口管线打通 + 亮度功能迁移 🎯 **当前阶段**

**目标**：在 Credential Provider DLL 里成功创建并显示一个 DComp 渲染的子窗口，并把现有的 issue #99 亮度提升功能从 Unlock.exe 迁移到 DLL（DLL 更接近凭据提供时机，亮度控制时序更好）。

**子任务**：

- [ ] **A1**: `OnCreatingWindow` 接收父 HWND 并缓存（修改 `CSampleCredential.rs`）
- [ ] **A2**: `CreateWindowEx` 创建子窗口（位置贴磁贴区域，128×128 起步）
- [ ] **A3**: 初始化 D3D11 设备 + DXGI Factory
- [ ] **A4**: 创建 DComp Device 和 Target（绑定子窗口）
- [ ] **A5**: 创建 Direct2D Factory + 渲染目标
- [ ] **A6**: PoC：纯色填充（亮蓝色）→ DComp Commit → 锁屏可见
- [ ] **A7**: 把亮度功能从 `Unlock/src/main.rs` 迁移到 `Server/src/CPipeListener.rs`
  - DLL 在"prepare"阶段调用 WMI 提升亮度（注册表读取目标值）
  - DLL 在 `stop_and_join` 或解锁完成时恢复亮度
- [ ] **A8**: UnAdvise 清理：DComp Target 释放、子窗口销毁、渲染线程退出（防止 LogonUI 崩溃）
- [ ] **A9**: 注册表开关：`ANIMATION_UI_ENABLED`（默认 `"0"`，灰度发布）

**验收**：
- VM 内锁屏时，磁贴区域显示一个亮蓝色方块
- 解锁触发时屏幕变亮，识别完成后恢复原亮度
- VM 内连续 100 次锁屏/解锁，LogonUI 不崩溃
- DLL 卸载后无 GDI/COM 句柄泄漏

---

### 阶段 B：D2D 基础动画 PoC（一个旋转环）

**目标**：把一个 uiverse loader（待用户挑选）翻译成 D2D 原生调用，跑出 60 FPS 旋转效果。

**子任务**：

- [ ] **B1**: 用户从 uiverse 挑选一个"旋转环" loader（建议简单单色）
- [ ] **B2**: 分析 CSS：拆出形状（圆环）、颜色、关键帧（旋转角度）
- [ ] **B3**: D2D 翻译：
  - `border-radius:50%` → `D2D1Ellipse`
  - `linear-gradient` → `ID2D1LinearGradientBrush`
  - `transform:rotate()` → `D2D1::Matrix3x2F::Rotation()`
- [ ] **B4**: 渲染线程 16ms 重绘（基于 `QueryPerformanceCounter` 计算角度）
- [ ] **B5**: VSync 同步：`IDXGISwapChain::Present(1, 0)` 或 DComp Commit
- [ ] **B6**: 帧率监控（开发期 ETW 事件，发布前去掉）

**验收**：
- 60 FPS 平滑旋转
- CPU 占用 < 2%
- GPU 占用 < 5%

---

### 阶段 C：状态机动画

**目标**：完整状态机，根据人脸识别进展显示对应动画。

**状态机**：

```
        ┌──────┐    收到 "run"     ┌──────────┐
        │ Idle │ ───────────────►  │ Scanning │
        └──────┘                   └────┬─────┘
           ▲                            │
           │                  匹配      │   未匹配/超时
           │                  ┌─────────┴─────────┐
           │                  ▼                   ▼
           │             ┌─────────┐         ┌─────────┐
           └─────────────┤ Success │         │ Failure ├──┐
                         └─────────┘         └─────────┘  │
                              ▲                           │
                              └──── 2 秒后 ───────────────┘
```

**子任务**：

- [ ] **C1**: 定义状态枚举与切换原子操作
- [ ] **C2**: Idle 动画：呼吸/脉冲（用户引导）
- [ ] **C3**: Scanning 动画：扫描线 + 旋转环
- [ ] **C4**: Success 动画：绿色对号 + 淡出
- [ ] **C5**: Failure 动画：红色边框抖动 + 淡出
- [ ] **C6**: Unlock.exe → DLL 状态推送（通过现有管道扩展消息类型）

**验收**：
- 状态切换无视觉撕裂
- 所有过渡动画 < 400ms
- 完整流程：等待 → 识别 → 成功，体验顺滑

---

### 阶段 D：（可选高级）摄像头预览到磁贴

**目标**：把摄像头实时画面渲染到磁贴上，达到接近 Windows Hello 的体验。

**子任务**：

- [ ] **D1**: Unlock.exe 每抓一帧 → 缩到 128×128 → JPEG 编码 → 推管道
- [ ] **D2**: DLL 接收管道帧 → JPEG 解码 → BGRA → D2D Bitmap
- [ ] **D3**: 渲染线程混合摄像头画面 + 扫描线动画
- [ ] **D4**: 帧率限制 10-15 FPS（避免 CPU 飙升）

**验收**：
- 磁贴显示实时摄像头画面
- 端到端延迟 < 200ms
- CPU 占用 < 5%（加上人脸识别本身）

---

## 四、进度跟踪

| 阶段 | 任务 | 状态 | 完成日期 | 提交哈希 |
|---|---|---|---|---|
| A | A1 OnCreatingWindow | ⏳ 待开始 | - | - |
| A | A2 CreateWindowEx | ⏳ 待开始 | - | - |
| A | A3 D3D11 设备 | ⏳ 待开始 | - | - |
| A | A4 DComp Device + Target | ⏳ 待开始 | - | - |
| A | A5 D2D 渲染目标 | ⏳ 待开始 | - | - |
| A | A6 纯色填充 PoC | ⏳ 待开始 | - | - |
| A | A7 亮度功能迁移 | ⏳ 待开始 | - | - |
| A | A8 资源清理 | ⏳ 待开始 | - | - |
| A | A9 注册表开关 | ⏳ 待开始 | - | - |
| B | B1-B6 旋转环 PoC | ⏳ 阶段 A 完成后 | - | - |
| C | C1-C6 状态机 | ⏳ 阶段 B 完成后 | - | - |
| D | D1-D4 摄像头预览 | ⏳ 可选 | - | - |

状态图例：⏳ 待开始 / 🔄 进行中 / ✅ 完成 / ⏸️ 阻塞 / ❌ 取消

---

## 五、AI 协作规则

### 5.1 模型分工

| 任务类型 | 模型 | 原因 |
|---|---|---|
| 阶段规划、技术选型 | **Opus** | 深度推理，调研复杂技术问题 |
| 架构设计、跨阶段决策 | **Opus** | 需要全局视野 |
| WebSearch 调研、文档对比 | **Opus** | 推理质量高 |
| 代码编写、Bug 修复 | **Sonnet** | 快速、低成本 |
| 编译错误排查 | **Sonnet** | 模式匹配为主 |
| Git 操作、文档更新 | **Sonnet** | 机械执行 |
| 调试逻辑 Bug（Sonnet 卡住时） | **Opus** | 兜底深度推理 |

### 5.2 切换信号

- 用户说"用 Opus 设计/分析"或 `/model claude-opus-4-7` → 使用 Opus
- 用户说"执行/继续推进"或 `/model claude-sonnet-4-6` → 使用 Sonnet
- 默认按当前 model 配置执行

---

## 六、技术风险与缓解

### 6.1 关键风险

1. **LogonUI 崩溃 → 无法登录**
   - 任何 DLL panic 或非法访问都会导致登录界面黑屏
   - 必须 VM 测试，每个阶段验证通过后再合并

2. **DComp 跨线程问题**
   - 合成线程 ≠ Advise 调用线程
   - DComp Device 的 Commit 必须从创建它的线程调用
   - 渲染线程要正确同步状态

3. **HBITMAP/GDI 资源泄漏**
   - 长时间锁屏会耗尽 GDI 句柄
   - 必须 `DeleteObject` 旧 HBITMAP，COM 接口要 `Release`

4. **Windows 7/8 兼容性**
   - DComp Win8+，D2D 1.3 Win10+
   - 必须运行时检测系统版本，旧系统降级到静态磁贴

5. **DLL 卸载顺序**
   - LogonUI 可能在动画播放中突然 UnAdvise
   - 渲染线程要响应 stop 信号在 100ms 内退出

### 6.2 缓解措施

- 每阶段单独提交，可独立 `git revert`
- 注册表开关 `ANIMATION_UI_ENABLED`（默认 `"0"`）控制功能启用
- 阶段 A 必须在 VM 内连续测试 100 次锁屏后才推到 main
- 添加 SEH 异常处理（`__try`/`__except`），防 DLL 异常导致 LogonUI 崩
- 添加运行时 OS 版本检测，旧系统直接跳过动画初始化
- 全程使用 Rust 的 `Drop` trait 自动管理资源

---

## 七、参考资料

### 核心 API
- [ICredentialProviderCredentialEvents::OnCreatingWindow](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovidercredentialevents-oncreatingwindow)
- [DirectComposition Architecture](https://learn.microsoft.com/en-us/windows/win32/directcomp/architecture-and-components)
- [IDCompositionDesktopDevice::CreateTargetForHwnd](https://learn.microsoft.com/en-us/windows/win32/api/dcomp/nf-dcomp-idcompositiondesktopdevice-createtargetforhwnd)
- [Direct2D + DComp 入门 (Kenny Kerr)](https://learn.microsoft.com/en-us/archive/msdn-magazine/2014/september/windows-with-c-directcomposition-transforms-and-animation)
- [ID2D1HwndRenderTarget](https://learn.microsoft.com/en-us/windows/win32/api/d2d1/nn-d2d1-id2d1hwndrendertarget)

### Credential Provider 深度文章
- [Dennis Babkin: Credential Providers Part 1](https://dennisbabkin.com/blog/?t=primer-on-writing-credential-provider-in-windows)
- [Dennis Babkin: Credential Providers Part 2](https://dennisbabkin.com/blog/?t=sequence-of-calls-to-credential-provider-in-windows)
- [rbmm: Credential Provider Interfaces 2025](https://medium.com/@_dm_sh_/list-of-credentials-provider-interfeces-begin-of-2025-67f6a966935e)

### 同类项目参考
- [GliderousTigers/NFCLogon_Windows](https://github.com/GliderousTigers/NFCLogon_Windows) — NFC 凭据提供，动态 `SetFieldBitmap`
- [privacyidea/privacyidea-credential-provider](https://github.com/privacyidea/privacyidea-credential-provider) — 企业级 2FA CP
- [Microsoft Windows-classic-samples](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/CredentialProvider) — 官方 C++ 样例

---

**最后更新**：2026-05-26
**当前阶段**：A（DComp 子窗口管线 + 亮度迁移）
**下一里程碑**：A6 锁屏纯色方块 PoC
