# FaceWinUnlock-Tauri 代码地图

> 精简版代码地图，覆盖三个可执行组件的架构、IPC 协议、动画管线与关键数据流。
> 最后更新：2026-05-26

---

## 一、三大组件总览

```
UI/                          Tauri 桌面 GUI（Vue3 + Rust 后端）
├── 人脸录入、设置管理、日志查看
├── 调用 Server DLL 注册/卸载 COM
└── 通过管道检测/停止 Unlock.exe

Server/                      Windows Credential Provider DLL
├── 注入 winlogon.exe / credentialuibroker.exe
├── 显示锁屏磁贴，驱动自动登录
└── 通过管道与 Unlock.exe 通信

Unlock/                      人脸识别后台服务（独立进程）
├── 摄像头捕帧 + YuNet 检测 + SFace 识别
├── 匹配成功 → 凭据推送给 DLL
└── 两路命名管道 Server 端
```

依赖路径：
```
工作区 Cargo.toml (workspace)
├── Server/Cargo.toml  → cdylib → FaceWinUnlock_Tauri.dll
├── UI/src-tauri/Cargo.toml → exe → facewinunlock-tauri.exe
└── Unlock/Cargo.toml → bin:FaceWinUnlock-Server → FaceWinUnlock-Server.exe
```

---

## 二、Server DLL — COM 对象层次

```
DllGetClassObject
└── SampleClassFactory (IClassFactory)
    └── CreateInstance → SampleProvider (ICredentialProvider)
        ├── SetUsageScenario  ← 过滤场景（UNLOCK_SCENE 注册表）
        ├── Advise            ← 启动 CPipeListener
        ├── GetCredentialAt   → SampleCredential (ICredentialProviderCredential)
        │   ├── Advise        ← OnCreatingWindow → AnimationContext（阶段 A）
        │   ├── GetSerialization  ← CredPackAuthenticationBufferW + 重置 is_unlocked
        │   ├── ReportResult  ← 失败时清空凭据（#102）
        │   └── UnAdvise      ← 释放 AnimationContext
        └── UnAdvise          ← stop_and_join CPipeListener
```

### SampleProvider 内部状态（ProviderInner）

| 字段 | 类型 | 用途 |
|------|------|------|
| `usage_scenario` | `CREDENTIAL_PROVIDER_USAGE_SCENARIO` | 当前场景（登录/解锁/CredUI） |
| `is_scenario_supported` | `bool` | SetUsageScenario 过滤结果 |
| `shared_creds` | `Arc<Mutex<SharedCredentials>>` | 跨线程传递凭据 |
| `auth_package_id` | `u32` | Negotiate 包 ID（LSA 查询） |
| `listener` | `Option<Arc<Mutex<CPipeListener>>>` | 后台管道线程句柄 |

### SharedCredentials（核心状态）

```rust
pub struct SharedCredentials {
    pub username: String,
    pub password: String,
    pub domain: String,
    pub is_ready: bool,      // 凭据已就绪（可序列化）
    pub is_unlocked: bool,   // 脉冲信号：GetSerialization 消费后重置（#112）
}
```

---

## 三、CPipeListener — 后台线程架构

```
CPipeListener::start()
│
├── Client 线程（发送者）
│   ├── 连接 MansonWindowsUnlockRustServer
│   ├── 写 "prepare"
│   ├── 等待宽限期 UNLOCK_GRACE_PERIOD（#116，默认 5s）
│   └── 循环写 "run"（指数退避 #115：≤10次正常 / ≤30次 5× / >30次 20×）
│
└── Creds 线程（接收者）
    ├── 连接 MansonWindowsUnlockRustUnlock（5s 超时，失败重试）
    ├── ReadFile 阻塞等待凭据
    ├── parse_credentials() → SharedCredentials
    └── CredentialsChanged() → 触发 Windows 自动登录

stop_and_join():
├── 设置 stop_flag
├── CloseHandle(creds_pipe_raw) → 打断 ReadFile
├── join 两个线程
└── 主场景 + 未面容解锁 → 发送 "exit" 给 Unlock EXE（#117 释放摄像头）
```

---

## 四、管道 IPC 协议（Pipe.rs）

| 管道名称 | 方向 | 用途 |
|---------|------|------|
| `MansonWindowsUnlockRustServer` | DLL→Unlock | "prepare" / "run" 指令 |
| `MansonWindowsUnlockRustUnlock` | Unlock→DLL / UI→Unlock | 凭据推送 / 健康检查 / 退出 |

凭据格式（两种均支持）：
```
格式1（null分隔）：  username\0password\0domain\0
格式2（简单JSON）：  {"user_name":"...","user_pwd":"...","domain":"..."}
```

UI 使用管道做健康检查：
- `"hello server"` → 检测 Unlock EXE 是否存活
- `"exit"` → 通知 Unlock EXE 退出

---

## 五、注册表键（HKLM\SOFTWARE\facewinunlock-tauri）

| 键名 | 默认值 | 用途 |
|-----|--------|------|
| `UNLOCK_SCENE` | `"1,2,4"` | 启用的场景（1=登录,2=解锁,4=CredUI） |
| `RETRY_DELAY` | `10.0`（秒） | "run" 发送间隔（指数退避基准） |
| `CONNECT_TO_PIPE` | `"1"` | 是否连接 Unlock EXE |
| `SHOW_TILE` | `"1"` | 是否显示磁贴 |
| `DLL_LOG_PATH` | `"C:"` | 日志目录 |
| `CREDUI_ALLOW_GENERIC` | `"0"` | 是否允许 RDP 等 Generic CredUI（#114） |
| `UNLOCK_GRACE_PERIOD` | `"5.0"` | 锁屏后宽限期秒数（#116） |
| `ANIMATION_UI_ENABLED` | `"0"` | 动画 UI 开关（灰度，默认关） |

---

## 六、动画管线（Server/src/animation.rs）— 当前阶段 A

### 管线层次

```
LogonUI 父 HWND（OnCreatingWindow 返回）
├── CreateWindowExW → 子窗口 HWND（128×128，WS_CHILD）
├── D3D11CreateDevice（BGRA_SUPPORT）→ ID3D11Device
├── IDXGIDevice（cast from D3D11）
├── DCompositionCreateDevice2 → IDCompositionDesktopDevice
│   ├── CreateTargetForHwnd(child_hwnd, topmost=true) → IDCompositionTarget
│   ├── CreateVisual → IDCompositionVisual2
│   │   └── SetContent(surface)
│   └── CreateVirtualSurface(128, 128, BGRA_UNORM, Premultiplied)
│       └── BeginDraw() → IDXGISurface
│           └── CreateBitmapFromDxgiSurface → ID2D1Bitmap1
└── D2D1Factory → ID2D1Device → ID2D1DeviceContext
    ├── SetTarget(bitmap)
    ├── BeginDraw
    ├── Clear(color)          ← PoC：亮蓝色 (0.2, 0.6, 0.9, 1.0)
    └── EndDraw → DComp Commit
```

### AnimationContext 结构

```rust
pub struct AnimationContext {
    parent_hwnd: HWND,                      // LogonUI 父窗口（不拥有）
    child_hwnd: HWND,                       // 子窗口（Drop 时 DestroyWindow）
    d2d_bitmap: Option<ID2D1Bitmap1>,       // 当前渲染帧 bitmap
    d2d_context: ID2D1DeviceContext,
    d2d_device: ID2D1Device,
    d2d_factory: ID2D1Factory1,
    dcomp_surface: IDCompositionVirtualSurface,
    dcomp_visual: IDCompositionVisual2,
    dcomp_target: IDCompositionTarget,
    dcomp_device: IDCompositionDesktopDevice,
    d3d_device: ID3D11Device,
}
unsafe impl Send for AnimationContext {}    // LogonUI 串行化 Advise/UnAdvise 调用
```

### 当前进度

| 阶段 | 任务 | 状态 |
|------|------|------|
| A1-A6 | 子窗口 + DComp/D3D/D2D 管线 + PoC 纯色填充 | ✅ 编译通过 |
| A7 | 亮度功能从 Unlock.exe 迁移到 DLL | ⏸️ 延后 |
| A8 | UnAdvise 清理（Drop AnimationContext） | ✅ |
| A9 | 灰度开关 ANIMATION_UI_ENABLED | ✅ |
| B | D2D 旋转环动画 60 FPS | ✅ 已实现（DComp topmost 路径 C）|
| C | 状态机（Idle/Scanning/Success/Failure） | 🔄 已实现，待 VM 回归验证 |
| D | 摄像头预览到磁贴 | ⏳ 可选 |

**下一步（阶段 B）**：用 Opus 设计旋转环渲染方案，Sonnet 实现后编译验证。

---

## 七、Unlock.exe — 人脸识别主循环

```
main()
├── run_control_server()    → MansonWindowsUnlockRustServer（接收 "run"）
├── run_unlock_server()     → MansonWindowsUnlockRustUnlock（推送凭据）
├── face_recognition_loop() → 每帧捕获 → 检测 → 识别 → 余弦相似度
│   ├── 加载 SQLite faces 表（每 30s 刷新）
│   ├── block/test_creds.tmp → 测试模式
│   └── 匹配成功 → 写管道（凭据格式1或2）
└── auto_lock_monitor()     → GetLastInputInfo 空闲检测 → LockWorkStation
```

摄像头启动顺序：`CAP_MSMF → CAP_DSHOW → CAP_ANY`，索引 0-3，预热 10 帧（#94）

---

## 八、UI 后端关键命令（ui/src-tauri/src/）

| 文件 | 关键 Tauri 命令 |
|------|----------------|
| `modules/init.rs` | `check_admin_privileges`, `deploy_core_components`, `uninstall_init` |
| `modules/faces.rs` | `check_face_from_camera`, `verify_face`（含 `VERIFY_CACHE` #121）|
| `modules/options.rs` | `write_to_registry` |
| `utils/api.rs` | `open_camera`, `add_scheduled_task`（+SessionUnlock #108）, `restart_unlock_service` (#113) |
| `utils/pipe.rs` | `check_process_running`, `delete_process_running` |

---

## 九、关键已修复 Issue 速查

| Issue | 修复位置 | 一句话说明 |
|-------|---------|-----------|
| #102 | `CSampleCredential::ReportResult` | 失败清空凭据，防止 Windows 无限重试 |
| #103 | Unlock + Creds 线程 | 过滤禁用/锁定人脸 + 拒绝空用户名 |
| #104 | Unlock + UI | 域账户支持 |
| #108 | `add_scheduled_task` | 添加 SessionUnlock 触发器 |
| #112 | `GetCredentialCount` + `is_unlocked` | 输出指针初始化 + 脉冲信号防竞态 |
| #113 | CPipeListener Client 线程 | 外层重连循环处理崩溃重启 |
| #114 | `SetUsageScenario` | CREDUIWIN_GENERIC 过滤（RDP/mstsc） |
| #115 | Client 线程退避 | ≤10/≤30/>30 次三档延迟，防风扇狂转 |
| #116 | Client 线程宽限期 | 锁屏后 5s 才开始识别，兼容动态锁 |
| #117 | `stop_and_join` | 手动解锁 → 发送 "exit" 释放摄像头 |
| #118 | `SetUsageScenario` | 不支持场景返回 E_NOTIMPL，防 PIN 冻结 |
| #121 | `faces.rs::VERIFY_CACHE` | 缓存首帧特征，验证从 1FPS 升到 30FPS |
| #126 | `GetSerialization` | CRED_PACK_PROTECTED_CREDENTIALS |

---

## 十、windows-rs 0.59 关键坑

| 坑 | 正确写法 |
|----|---------|
| `D2D1CreateFactory` 是泛型，只有 2 个参数 | `D2D1CreateFactory(type, None)?` |
| `IDCompositionVirtualSurface::BeginDraw` 第二参数是 `*mut POINT`（出参） | `BeginDraw(Some(&rect), &mut offset)?` |
| `SetTransform` 不在 `ID2D1DeviceContext` 上直接暴露 | 阶段 A 跳过变换，或 cast 到 `ID2D1RenderTarget` |
| `CreateNamedPipeW` 返回 `HANDLE`（非 `Result`） | 手动 `handle.is_invalid()` 检查 |
| COM trait impl 中用 `Foundation::BOOL`，不是 `windows_core::BOOL` | 看错误 E0308 |
| Rust 2021 partial capture：闭包捕获字段而非整个结构体 | 用 wrapper 方法（见 `SendableEvents::notify_changed`） |
