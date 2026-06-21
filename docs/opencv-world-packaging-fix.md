# opencv_world4120.dll / FaceWinUnlock-Server.exe 从 NSIS 安装包丢失 —— 修复档案与防回归

> 解决于 2026-06-21（随 0.5.0 覆盖重发）。
> 症状：装好 0.5.0 后运行报「由于找不到 opencv_world4120.dll，无法继续执行代码。重新安装
> 程序可能会解决此问题」；后台人脸服务也无法开机自启（安装目录缺 `FaceWinUnlock-Server.exe`）。

---

## 症状

- 双击 `facewinunlock-tauri.exe`（UI 主程序）弹「由于找不到 opencv_world4120.dll，无法继续执行代码」。
- 后台人脸识别服务开机后没自启：`unlock.log` 无当天 `supervisor started`，人脸解锁不工作（被迫用 PIN/密码）。
- **诡异点**：重装前若旧 `FaceWinUnlock-Server.exe` 进程还在内存跑（启动时 DLL 已载入内存），解锁
  看似正常；一旦关机终止旧进程，开机就再也起不来——容易误判为「时好时坏」「昨晚还正常」。

## 根因

`UI/src-tauri/tauri.conf.json` 的 `bundle.resources` 是「源 → 目标」映射。提交 `1b1d30a` 为随附
OpenVINO 运行时，新增了一条**目录展开到安装根**的映射：

```json
"D:\\OpenCV\\openvino_runtime\\": "."
```

实测：加入 `"."` 目录展开后，Tauri v2 + NSIS 打包会**漏掉同样映射到安装根目录的「单文件」资源**。
安装目录实证（0.5.0）：

| 资源 | 映射目标 | 是否进安装包 |
|------|---------|------------|
| `resources/*.onnx`、`resources/FaceWinUnlock-Tauri.dll` | `resources/` 子目录 | ✅ 在 |
| OpenVINO 运行时（`openvino*.dll` / `tbb*.dll`） | `"."` 目录展开到根 | ✅ 在 |
| `FaceWinUnlock-Server.exe` | 根（无前缀） | ❌ **丢** |
| `opencv_world4120.dll` | 根（无前缀） | ❌ **丢** |
| `FaceWinUnlock-Passkey.msix` / `.cer` | 根（无前缀） | ✅ 侥幸在 |

> CI 的「Verify runtime binaries」步骤确认 build 时 `target\release\FaceWinUnlock-Server.exe`
> **存在**，opencv_world 也由「Stage runtime DLLs」复制到位——所以**不是源缺失，是打包阶段丢的**。
> 而 `hooks.nsh` 早有 `resources\opencv_world4120.dll → 根` 的兜底，但 `1b1d30a` 把 DLL 配成
> 直接放根（不经 `resources/`），把这条兜底**架空**了，于是根没装上、`resources/` 里也没有 → 彻底缺失。

## 修复

**确定性方案：让两个文件走「已验证 100% 成功的 `resources/` 子目录通道」+ NSIS hooks 复制到根。**

1. `UI/src-tauri/tauri.conf.json`：
   ```diff
   - "../../target/release/FaceWinUnlock-Server.exe": "FaceWinUnlock-Server.exe",
   + "../../target/release/FaceWinUnlock-Server.exe": "resources/FaceWinUnlock-Server.exe",
   - "D:\\OpenCV\\build\\x64\\vc16\\bin\\opencv_world4120.dll": "opencv_world4120.dll",
   + "D:\\OpenCV\\build\\x64\\vc16\\bin\\opencv_world4120.dll": "resources/opencv_world4120.dll",
   ```
   OpenVINO 的 `"."` 保留（它本来就成功）。

2. `UI/src-tauri/nsis/hooks.nsh`（`NSIS_HOOK_POSTINSTALL`）：把这两个文件从 `resources/` 复制到
   安装根（= 主 EXE 同目录 = Windows DLL 搜索路径起点），并删除 `resources/` 副本避免 61MB 双份：
   ```nsis
   IfFileExists "$INSTDIR\resources\opencv_world4120.dll" 0 +3
     CopyFiles /SILENT "$INSTDIR\resources\opencv_world4120.dll" "$INSTDIR\"
     Delete "$INSTDIR\resources\opencv_world4120.dll"
   IfFileExists "$INSTDIR\resources\FaceWinUnlock-Server.exe" 0 +3
     CopyFiles /SILENT "$INSTDIR\resources\FaceWinUnlock-Server.exe" "$INSTDIR\"
     Delete "$INSTDIR\resources\FaceWinUnlock-Server.exe"
   ```

**NPU 链路完整性**：`opencv_world4120.dll` 是 `WITH_OPENVINO=ON` 编译的（加载时导入 `openvino.dll`），
配合安装根的 `openvino.dll` + `openvino_intel_npu_plugin.dll` + `tbb*.dll`，用户装好 Intel NPU 驱动后
在「首选项 → 识别参数 → 推理后端」选 `intel_npu` 即可用。

## 防回归

- ❌ **不要**在 `tauri.conf.json` 的 `bundle.resources` 里把运行时**单文件**直接映射到安装根（无
  `resources/` 前缀），尤其在同时存在 `"."` 目录展开时——Tauri v2 + NSIS 会漏掉它们。
- ✅ 需要落在安装根（与主 EXE 同目录）的运行时文件，**统一走 `resources/` 子目录打包 + `hooks.nsh`
  复制到根**（这正是 `hooks.nsh` 既有的设计，别再改成直接放根把它架空）。
- ✅ 改打包后**必须**实际装一遍，确认安装根同时有 `opencv_world4120.dll` 和
  `FaceWinUnlock-Server.exe`，再双击主程序确认不报「找不到 DLL」。
- ✅ 排障口诀：UI 报「找不到 opencv_world4120.dll」= 安装根缺该 DLL（或其依赖 `openvino.dll`）；
  人脸服务不自启 + `unlock.log` 无当天 `supervisor started` = 安装根缺 `FaceWinUnlock-Server.exe`。
