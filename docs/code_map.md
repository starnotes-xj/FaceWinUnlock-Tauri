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

## 六、动画管线（Server/src/animation.rs）— 阶段 C

### 架构（路径 C：DComp Topmost Layer）

放弃了阶段 A 的独立子窗口方案，改为 DComp topmost 层直接绑定 LogonUI 父 HWND：

```
LogonUI 父 HWND（OnCreatingWindow 返回）
│
├── [DComp Topmost Layer] ← 我们的动画（topmost=true）
│   └── DComp Visual { SetOffsetX2/Y2 = 磁贴位置 }
│       └── DComp VirtualSurface (128×128)
│           └── BeginDraw → IDXGISurface → ID2D1Bitmap1
│               └── D2D 旋转环 / 状态动画 (60 FPS GPU)
│
├── [Child Windows Layer] ← LogonUI 正常内容
│   ├── 用户磁贴
│   └── 凭据磁贴 ← EnumChildWindows 尺寸启发式定位
│
└── GPU 管线初始化：
    ├── D3D11CreateDevice（BGRA_SUPPORT）→ ID3D11Device
    ├── IDXGIDevice → DCompositionCreateDevice2 → IDCompositionDesktopDevice
    ├── CreateTargetForHwnd(parent_hwnd, topmost=true) → IDCompositionTarget
    ├── CreateVisual → IDCompositionVisual2 → SetContent(surface)
    └── D2D1Factory → ID2D1Device → ID2D1DeviceContext
```

### 状态机

```
    ┌──────┐   CPipeListener "run"   ┌──────────┐
    │ Idle │ ───────────────────►   │ Scanning │
    └──────┘                         └────┬─────┘
       ▲                     凭据到达  │   │ 重试3次未匹配
       │                    ┌──────────┘   └──────────┐
       │                    ▼                          ▼
       │               ┌─────────┐              ┌─────────┐
       └───────────────│ Success │              │ Failure │
          2 秒后退回   └─────────┘              └─────────┘
```

驱动方式：`CPipeListener` 的 Client 线程（发 "run" → Scanning）和 Creds 线程（收凭据 → Success）通过 `AnimationSlot` 推送状态变化。

### 磁贴定位策略

`find_tile_position()` 按优先级尝试：
1. **尺寸+可见性启发式** — EnumChildWindows 枚举子窗口，按尺寸接近 128-384px 的可见正方形窗口打分，上半区 +50 分（偏好头像区域）
2. **注册表偏移** — `ANIMATION_OFFSET_X/Y`（保留，未实现）
3. **兜底** — 父窗口 client 区域水平居中、垂直 **1/4** 处（VM 实测：2/3 = PIN 输入区；1/3 = 与用户头像重合；1/4 = 头像上方，位置最佳）

### AnimationContext 结构

```rust
pub enum AnimState { Idle, Scanning, Success, Failure }

pub type AnimationSlot = Arc<Mutex<Option<AnimationContext>>>;

pub struct AnimationContext {
    parent_hwnd: HWND,                      // LogonUI 父窗口（不拥有）
    render_state: Arc<RenderState>,         // 原子 stop flag + 状态机数据
    render_thread: Option<JoinHandle<()>>,  // 渲染线程句柄
}
unsafe impl Send for AnimationContext {}

// RenderState 内部：
//   stop: AtomicBool              — Drop 时设置，渲染线程退出
//   anim: Mutex<AnimStateData>    — 当前状态 + 进入时间（用于动画过渡）
```

GPU 资源（DComp/D3D/D2D）全部在渲染线程内创建和销毁，`AnimationContext` 主线程侧只保留 HWND 和线程句柄。`Drop` 时 signal stop + join 线程，确保无资源泄漏。

### 当前进度

| 阶段 | 任务 | 状态 |
|------|------|------|
| A1-A6 | DComp/D3D/D2D 管线 + PoC 纯色填充 | ✅ |
| A7 | 亮度功能从 Unlock.exe 迁移到 DLL | ⏸️ 延后 |
| A8 | UnAdvise 清理（Drop AnimationContext） | ✅ |
| A9 | 灰度开关 ANIMATION_UI_ENABLED | ✅ |
| B | DComp topmost 路径 C + D2D 旋转环 60 FPS | ✅ |
| C | 状态机（Idle/Scanning/Success/Failure）+ 管道驱动 | ✅ 已实现，VM 修复两个 Bug（弧截断 + 位置偏低），待回归验证 |
| D | 摄像头预览到磁贴 | ⏳ 可选 |

**下一步**：VM 回归验证 4 状态动画，通过后考虑合并主分支或进入阶段 D。

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
