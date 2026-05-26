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

### 2.3 整体架构（路径 C）

```
LogonUI.exe 窗口（父 HWND，来自 OnCreatingWindow）
│
├── [DComp Topmost Layer] ← 我们的动画（绑定到此窗口，topmost=true）
│   └── DComp Visual { OffsetX, OffsetY = 磁贴中心位置 }
│       └── DComp Surface (128×128) ← D2D 旋转环 (60 FPS GPU)
│
├── [Child Windows Layer] ← LogonUI 正常内容
│   ├── 用户1 磁贴
│   ├── 用户2 磁贴
│   └── 我们的凭据磁贴 ← EnumChildWindows("FaceWinUnlock") 定位
│       └── 头像 (CPFT_TILE_IMAGE)
│
└── [DComp Bottom Layer]

Server DLL 内部：
┌──────────────────────────────────────────────────┐
│ CSampleCredential                                │
│   - Advise() → OnCreatingWindow → 父 HWND        │
│   - 启动 AnimationContext（渲染线程）             │
│   - UnAdvise() → 停止渲染 → 释放资源              │
│                                                  │
│ AnimationContext（主线程）                        │
│   - 保存父 HWND                                   │
│   - Drop 时 signal stop + join 线程               │
│                                                  │
│ Render Thread（后台）                             │
│   - D3D11 → DXGI → DComp (topmost)               │
│   - EnumChildWindows 搜索磁贴位置                 │
│   - Visual.SetOffsetX2/Y2 定位                   │
│   - D2D 旋转环 60 FPS                            │
│   - 状态机：Idle / Scanning                       │
└──────────────────────────────────────────────────┘
```

---

## 三、阶段分解

### 阶段 A：DComp 子窗口管线打通 + 亮度功能迁移

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
| A | A1-A6, A8-A9 子窗口管线 | ✅ 完成 | 2026-05-26 | （本次） |
| A | A7 亮度功能迁移到 DLL | ⏸️ 延后 | - | C 阶段之后再做 |
| B | 旋转环 PoC（D2D + DComp 子窗口） | ✅ 完成 | 2026-05-26 | （本次） |
| B | **路径 C：DComp Topmost + 磁贴定位** | ✅ 完成 | 2026-05-26 | （本次） |
| C | C1-C6 状态机 | 🔄 进行中 | 2026-05-26 | 动画状态机+管道驱动已实现；VM 测试修复两个 Bug（弧截断 + 位置偏低）→ 待回归验证 |
| D | D1-D4 摄像头预览 | ⏳ 可选 | - | - |

状态图例：⏳ 待开始 / 🔄 进行中 / ✅ 完成 / ⏸️ 阻塞 / ❌ 取消

### 阶段 B 完成情况 · 路径 C 架构变更

**调研决策：** SetFieldBitmap 无法达到 60 FPS（受限于 GDI HBITMAP 转换 + LogonUI 内部刷新率）。经过多轮深度调研，选择**路径 C**：

```
LogonUI 父 HWND (OnCreatingWindow 返回)
│
├── [DComp Topmost Layer] ← 我们的动画（SetOffsetX2/Y2 定位）
│   └── DComp Visual → Surface ← D2D 旋转环 (60 FPS GPU)
│
└── [Child Windows] ← LogonUI 正常内容
    └── 凭据磁贴 ← EnumChildWindows 文本匹配定位
```

核心改动：
- **不再创建独立子窗口** — 直接绑定 DComp 到 LogonUI 父 HWND（`topmost=true`），动画渲染在所有凭据磁贴之上
- **`EnumChildWindows` 定位磁贴** — 搜索子窗口文本 "FaceWinUnlock" 匹配凭据磁贴，`GetWindowRect` 拿到屏幕坐标后换算为父窗口 client 坐标
- **`IDCompositionVisual::SetOffsetX2/Y2` 定位** — 将 128×128 动画表面精确放到磁贴中心位置
- **重试机制** — 启动时最多重试 15 次（3 秒），等待 LogonUI 创建磁贴窗口；失败后回退到父窗口 client 区域 **1/3** 高度居中位置（VM 测试证明 2/3 高度 = PIN 输入区，偏低；1/3 高度 ≈ 磁贴图像区）
- **无 GDI 泄漏风险** — 不再创建窗口类/HWND/HBITMAP，纯 COM 对象由 Rust Drop 自动管理

**已落地文件：**
- `Server/src/animation.rs`（~340 行）：
  - DComp target 绑定父 HWND（`topmost=true`）
  - `find_tile_position()` + `enum_child_callback()` — EnumChildWindows 定位
  - 矩阵辅助函数（identity/rotation/scale/mul）手动实现（windows-rs 0.59 的 Matrix3x2 是纯数据 struct）
  - `render_scanning()` / `render_idle()` — 旋转环 + 呼吸脉冲
  - 弧几何体预创建（`ID2D1PathGeometry1`），每帧 `SetTransform` 旋转
  - 帧率控制（~16.67ms/帧）
- `Server/src/CSampleCredential.rs`：`Advise()` 传父 HWND + 磁贴文本 "FaceWinUnlock" 给 AnimationContext
- `Server/Cargo.toml`：新增 `"Foundation_Numerics"` feature（Matrix3x2 类型需要）

**编译状态：** `cargo check -p winlogon` 通过（只有项目原有的命名规范警告）

**VM 实测：** 待用户启用注册表开关 `ANIMATION_UI_ENABLED=1` 后在 VM 内验证

### 阶段 C 完成情况（状态机动画 + 管道驱动）

**状态机：**
```
        ┌──────┐   CPipeListener 发送 "run"   ┌──────────┐
        │ Idle │ ──────────────────────────►  │ Scanning │
        └──────┘                               └────┬─────┘
           ▲                            凭据到达  │   │ 重试3次未匹配
           │                           ┌──────────┘   └──────────┐
           │                           ▼                          ▼
           │                      ┌─────────┐              ┌─────────┐
           └──────────────────────│ Success │              │ Failure │
              2 秒后自动退回      └─────────┘              └─────────┘
                                       ▲ 2s → Idle            ▲ 2s → Idle
```

**已实现：**
- `AnimState::Success` + `AnimState::Failure`（`animation.rs`）
- `render_success()` — 绿色圆 + 白色对号 + 2 秒淡出
- `render_failure()` — 红色圆 + 叉号 + 水平抖动 + 2 秒淡出
- 自动超时退回：Success/Failure 2 秒后自动 → Idle
- `AnimationSlot` 改为 `Arc<Mutex<Option<AnimationContext>>>`，三方共享
- `CPipeListener::start()` 接受 `AnimationSlot`
- Client 线程：发送 "run" → 设置 Scanning；3 次重试未匹配 → 触发 Failure
- Creds 线程：收到凭据 → 触发 Success
- `CSampleProvider` 创建 `AnimationSlot` 并传给 CPipeListener 和 CSampleCredential

**文件变更：**
| 文件 | 变更 |
|---|---|
| `Server/src/animation.rs` | +Success/Failure 状态、render_success/failure、PrebuiltGeo、auto-transition |
| `Server/src/CPipeListener.rs` | +AnimationSlot 参数、set_anim_state()、Client/Creds 线程驱动状态 |
| `Server/src/CSampleProvider.rs` | +animation_slot 字段、传递到 CPipeListener 和 SampleCredential |
| `Server/src/CSampleCredential.rs` | 接受外部 AnimationSlot，不再自建

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

**最后更新**：2026-05-26（阶段 C 状态机+管道驱动实现完成）
**当前阶段**：C 状态机+管道驱动已实现，等待 VM 实测
**下一里程碑**：VM 锁屏验证 4 状态动画（Idle → Scanning → Success/Failure），验证通过后进入阶段 D（摄像头预览）或考虑合并
