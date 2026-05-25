# Rust Windows 自动解锁核心DLL

本目录是 FaceWinUnlock-Tauri 的 Windows Credential Provider COM DLL 实现，由 `windows-rs 0.59` 编写，注入 `winlogon.exe` 实现锁屏界面的面容自动登录。

## 功能特性

* **Rust 原生实现**：利用 `windows-rs` 库直接调用 Win32 API，保证内存安全与高性能。
* **命名管道监听**：后台线程监听自定义管道，支持非接触式凭据注入。
* **自动登录触发**：接收到凭据后自动调用 `CredentialsChanged` 触发系统登录流程。
* **场景过滤**：读取注册表 `UNLOCK_SCENE`（默认 `"1,2,4"`）决定在哪些场景下激活，对不在列表中的场景返回 `E_NOTIMPL`，避免浏览器通行密钥 PIN 弹窗卡顿。支持登录（1）、锁屏解锁（2）、UAC/应用层（4，含浏览器查看存储密码等），可在 UI 首选项→系统集成中通过复选框调整，无需手动改注册表。
* **多进程日志**：日志文件以追加 + `FILE_SHARE_READ|WRITE` 模式打开，`winlogon.exe` 与 `credentialuibroker.exe` 可同时写入同一 `facewinunlock.log`；每次 DLL 初始化记录 PID，方便区分来源进程。

## 核心架构

该项目由四个核心部分组成：

1. **`lib.rs`**: COM DLL 出口（`DllMain`/`DllGetClassObject`/`DllCanUnloadNow`），管理注册与引用计数，读取注册表配置。日志以追加+共享写入模式打开，支持多进程同时写入，启动时记录 PID。
2. **`CSampleProvider`**: 实现了 `ICredentialProvider`，负责管理磁贴（Tile）的生命周期，以及在 `Advise()` 中启动管道监听线程。
3. **`CSampleCredential`**: 实现了 `ICredentialProviderCredential`，`GetSerialization` 通过 `CredPackAuthenticationBufferW` 将明文密码打包为系统序列化缓冲区，`ReportResult` 在登录失败时清除凭据。
4. **`CPipeListener`**: 独立的后台监听线程对（Client 线程 + Server 线程），负责管道通信。
5. **`Pipe.rs`**: 命名管道底层封装。

## 管道协议

| 管道名称 | 角色 | 方向 | 用途 |
|---------|------|------|------|
| `MansonWindowsUnlockRustServer` | Unlock EXE 作服务端，DLL 作客户端 | DLL → Unlock EXE | DLL Client线程发送 `"prepare"` / `"run"` 控制命令，驱动面容识别 |
| `MansonWindowsUnlockRustUnlock` | DLL 作服务端，Unlock EXE 作客户端 | Unlock EXE → DLL | Unlock EXE 发送凭据（null分隔: `user\0pwd\0domain\0`；或简单JSON），DLL收到后调用 `CredentialsChanged` 触发自动登录 |

UI（Tauri 主程序）通过连接 `MansonWindowsUnlockRustUnlock` 发送 `"hello server"` / `"exit"` 来检测和控制 Unlock EXE 是否运行。

## 实现流程

![实现流程](data/Windows自动解锁.png "实现流程")

## 安装与编译

### 前置条件

1. **Rust**: 1.90.0+ (包含 `cargo` 工具链)
2. **Visual Studio**: 包含 C++ 桌面开发组件

### 编译

```powershell
# 如果 Rust 不在默认路径，先设置环境变量：
$env:RUSTUP_HOME = "D:\Rust"
$env:CARGO_HOME  = "D:\Rust\CARGO"
$env:PATH        = "D:\Rust\CARGO\bin;" + $env:PATH

cargo build --release
# 输出：target/release/FaceWinUnlock_Tauri.dll
```

### 部署测试

编译完成后，将 DLL 复制到安装目录并重新锁定计算机即可生效：

```powershell
Copy-Item target\release\FaceWinUnlock_Tauri.dll D:\facewinunlock-tauri\resources\
```

### 调试工具

`pipe_sniffer.ps1` 以管理员身份运行，可以拦截管道通信、向 DLL 注入测试凭据，无需启动完整的 Unlock EXE。

## ⚠️ 安全警告

* **明文传输风险**：当前管道通信未加密，本地恶意软件可能嗅探到传输的密码。
* **凭据存储**：本程序在内存中短暂持有明文凭据，请确保内存清理逻辑严密。

## ⚠️ 免责声明

本项目涉及修改 Windows 系统注册表及 `C:\Windows\System32` 目录。在使用或二次开发时，请务必了解以下风险：

* 错误修改注册表可能导致系统无法正常登录。
* 建议在虚拟机 (VMware/Hyper-V) 环境中进行调试。
* 作者不对因使用本软件导致的任何数据丢失或系统崩溃负责。
