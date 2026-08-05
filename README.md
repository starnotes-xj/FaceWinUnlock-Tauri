# FaceWinUnlock-Tauri

## 求打赏

我现在暑假留校维护这个项目，生活费真的快撑不住、要吃不起饭了。如果这个项目对你有帮助，欢迎扫码请我吃顿饭；量力而行，每一份支持我都会记在心里，感谢！

<p align="center">
  <img src="docs/donation-wechat.png" alt="微信赞赏码" width="480">
</p>

[English](README_EN.md) | [Releases](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/releases) | [测试指南](docs/testing.md)

FaceWinUnlock-Tauri 为不支持 Windows Hello 人脸的普通摄像头提供本地面容解锁。项目由 Tauri/Vue 管理界面、Rust 人脸识别服务、Windows Credential Provider 和可选的 Windows Passkey Provider 组成。

本仓库是完整可构建的开源 Fork。当前实现不使用 UI Automation，不探测系统控件，不模拟键盘输入 PIN，也不包含已经移除的锁屏动画。

## 功能

- Windows 登录、锁屏解锁和 UAC 场景的人脸验证。
- Chrome、Edge、Brave、Opera、Vivaldi、360 和 Chromium 的密码查看及密码填充验证。
- WebAuthn 活动守卫：Passkey、安全密钥、FIDO2 和设置 PIN 不会误走通用 Credential Provider。
- Windows 11 24H2+ 可选 FaceWinUnlock Passkey Provider；插件持有自己的不可导出密钥，人脸只作为本地用户验证门。
- 摄像头预热、自动锁屏、亮度调节、摄像头旋转、CPU/OpenCL 推理后端和本地增量更新。
- Passkey 元数据备份到 `%ProgramData%\facewinunlock-tauri\PasskeyBackup`，用于普通卸载或第三方卸载后的恢复。

## 安全边界

这不是 Windows Hello 的等价替代品。普通 RGB 摄像头和本项目的活体检测不能提供 Windows Hello 红外摄像头、TPM 与系统生物识别栈相同的安全保证。Credential Provider 需要在本机读取并提交用户配置的 Windows 账户凭据，适合个人、受控设备使用。

所有识别和凭据处理都在本机完成。项目不会上传面容数据。请只从本仓库 Release 安装，并在首次使用前备份可用的 Windows 登录方式。

## 系统要求

- Windows 10/11 x64；Passkey Provider 仅支持 Windows 11 24H2（build 26100）及更新版本。
- 可被 Windows Media Foundation 或 DirectShow 打开的摄像头。
- 安装、Credential Provider 注册和计划任务创建需要管理员权限。
- OpenCL/FP16 后端依赖设备驱动，遇到慢或识别失败时应切回 CPU。

## 安装

1. 从 [Releases](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/releases) 下载最新正式版安装程序。
2. 以管理员身份安装并完成初始化向导。
3. 添加面容，先用应用内一致性验证确认阈值和摄像头。
4. 保留可用的密码或 Windows PIN，再测试 `Win+L` 解锁。
5. Windows 11 24H2+ 用户可在应用中安装并启用 Passkey 插件；网站必须重新保存一枚由 FaceWinUnlock 创建的通行密钥。

候选版本应按 [docs/testing.md](docs/testing.md) 完整回归后再发布正式版。

## 架构

```text
UI (Tauri + Vue)
  |-- SQLite 配置、面容录入、组件部署、更新
  |-- ui_release / ui_done 协调摄像头所有权

Credential Provider DLL (Server)
  |-- Windows 登录/解锁/UAC/CredUI 场景
  |-- WebAuthn Active 时拒绝通用 Provider
  `-- 通过命名管道驱动 Unlock 并提交凭据

FaceWinUnlock-Server.exe (Unlock)
  |-- OpenCV 人脸检测、特征比对、预热、自动锁屏
  |-- WebAuthn Operational 事件监视
  `-- Passkey 插件独立人脸授权管道

PasskeyPlugin (可选 MSIX)
  `-- 官方 Windows 插件 API、自持密钥、请求本地人脸授权
```

详见 [架构说明](docs/architecture.md) 和 [代码地图](docs/code_map.md)。

## 从源码构建

本机约定 Rust 安装在 `D:\Rust`，OpenCV 4.12 位于 `D:\OpenCV`：

```powershell
$env:RUSTUP_HOME = "D:\Rust"
$env:CARGO_HOME = "D:\Rust\CARGO"
$env:PATH = "D:\Rust\CARGO\bin;$env:PATH"

cargo build --release
.\scripts\build-passkey-plugin.ps1
Set-Location UI
npm ci
npm run build
npm run tauri build
```

也可以在仓库根目录运行 `.\build.ps1`。正式安装包由 [GitHub Actions](.github/workflows/release.yml) 构建，tag 中的版本会同步到 Tauri、Cargo 和 Passkey manifest。

## 验证

```powershell
cargo test -p winlogon
cargo test -p unlock
cargo test -p facewinunlock-tauri --lib
cargo check --workspace
```

UI 二进制测试进程带管理员 manifest，普通终端直接运行完整 harness 可能返回 Windows 错误 740；库测试不受影响。

## 文档

- [测试与发布检查表](docs/testing.md)
- [当前架构](docs/architecture.md)
- [CredUI 与自动锁屏设计](docs/credui-broker-scene-and-autolock-fixes.md)
- [Passkey Provider 约束](docs/passkey-provider-lessons.md)
- [更新系统](docs/incremental-update-design.md)
- [OpenCV 打包与 Win10 摄像头兼容](docs/opencv-world-packaging-fix.md)

## 许可证

项目许可证见 [LICENSE](LICENSE)。Passkey 插件包含微软示例派生代码，其第三方声明见 `PasskeyPlugin/THIRD_PARTY_LICENSE.txt`。
