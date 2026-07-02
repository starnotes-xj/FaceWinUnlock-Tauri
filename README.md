# FaceWinUnlock-Tauri

**FaceWinUnlock-Tauri** 是一款基于 Tauri 框架开发的现代化 Windows 面容识别解锁增强软件。它通过自定义 Credential Provider (DLL) 注入 Windows 登录界面，结合前端 Vue 3 和后端 OpenCV 人脸识别算法，为用户提供类似 Windows Hello 的解锁体验。

## 关于本 Fork

本仓库是原项目的 Fork，在原作者删除核心代码（v0.3.5）后，通过动态分析和逆向工程**复原了 `Server/` 目录下的全部 DLL 源代码**，使其可以重新编译。同时修复了若干 issue，并添加了新特性。

**Fork 相对原版的主要变化：**
- ✅ 复原全部 Rust 核心源码：Server DLL（5文件）、UI 后端（init/faces/api）、Unlock 服务（607行完整人脸识别管线）——均可编译
- ✅ 修复/实现 13 个原仓库 Issue：#102 #118 #112 #113 #114 #115 #116 #117 #108 #126 #121 #96 #99
- ✅ 新增摄像头旋转选项：0° / 顺时针 90° / 180° / 逆时针 90°，适用于笔记本侧放等特殊摆放场景，在「首选项 → 识别参数」中配置，录入预览及解锁识别均实时生效 ([#96](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/96))
- ✅ 新增解锁时屏幕亮度调节：面容识别期间自动提升至目标亮度（0=不调节），识别结束后恢复原始亮度，改善弱光环境解锁成功率 ([#99](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/99))
- ✅ 新增推理后端选择：CPU / OpenCL GPU / OpenCL FP16 / Intel NPU（#125），在「首选项 → 识别参数」中配置
- ✅ 面容解锁场景可按场景独立配置（登录/解锁/UAC应用层），在「首选项 → 系统集成」中通过复选框调整
- ✅ 修复多进程日志丢失：Chrome 的 CredUI 在独立进程 `credentialuibroker.exe` 中加载 DLL，现在日志以追加+共享写入模式打开
- ✅ 调整 Google/passkey（WebAuthn）回退：`credentialuibroker.exe` 托管的 CredUI 默认先尝试人脸，若 passkey 无法接受该凭据或识别超时，则自动交还 Windows PIN；Chrome/Edge 查看密码继续保留人脸识别

**源码说明（原版）：** 原作者因软件被盗卖，于 2026 年 3 月 1 日起将原项目闭源，核心 Rust 代码已删除，仅保留 v0.3.2 框架。本 Fork 为学习研究目的对缺失代码进行了重建。

**当前构建状态：** 作者在 v0.3.4 中删除了所有 `Cargo.toml` 和 `Cargo.lock` 文件。本 Fork 已复原所有构建配置和核心 Rust 源码，**三大组件均可完整编译**：Server DLL、UI Tauri 应用、Unlock 后台服务。`cargo build --release` 可从仓库根目录正常执行。Vue 3 前端（`UI/src/`）完整可用。详见下方「从源码构建」章节。

如果你对程序某一块功能感兴趣，可以提交 issues。

## 📖 前言

这个项目的诞生源于一次小小的“心理落差”：

某天，公司新来的同桌入职了，他那台自带红外摄像头的笔记本每次开机只需“看一眼”就能秒进桌面。反观我手里这台性能拉满但摄像头不支持 Windows Hello 的设备，每天还要苦哈哈地敲那一串复杂的密码。

**“凭什么他能刷脸，我不行？”**

秉着“硬件不够，代码凑”的精神，我决定自己动手整一个。既然系统原生不支持普通摄像头面容解锁，那我就自己写一个注入 Windows 登录界面的组件。这就是 FaceWinUnlock-Tauri 的由来——为了让所有带摄像头的 Windows 设备都能体验到这份“优雅”。

## 📝 更新记录
| 版本号 | 更新日期 | 更新内容 | 备注 |
|--------|----------|----------|------|
| v0.3.5-fork | 2026-05-25 | Fork 代码复原、Bug修复、特性增强 | **本 Fork 新增：**<br />复原全部 Rust 源码（Server DLL + UI 后端 + Unlock 服务，均可编译）<br />修复密码错误后继续尝试登录 (#102)<br />修复浏览器PIN弹窗卡顿 (#118)<br />修复 UAC 面容解锁磁贴弹一下就消失 (#112)<br />修复解锁核心服务突然故障 (#113)<br />修复应用和UAC解锁冲突/RDP干扰 (#114)<br />修复锁屏后风扇狂转 (#115)<br />修复 Win11 原生动态锁失效 (#116)<br />修复开机不自启 + 手动解锁后摄像头占用 (#117)<br />修复休眠/重启后不自启动 (#108)<br />修复微软应用程式密码不支持 (#126)<br />修复一致性验证卡顿 (#121)<br />面容识别场景可在 UI 中配置（首选项→系统集成）<br />修复多进程日志丢失（Chrome CredUI 日志现可正常记录）<br />**新增摄像头旋转选项（0°/顺时针90°/180°/逆时针90°）**，适用于笔记本侧放等场景，录入预览与解锁识别均实时生效 (#96)<br />**新增解锁时屏幕亮度调节**，识别期间自动提亮、结束后恢复，改善弱光环境解锁成功率 (#99)<br />**新增推理后端选择（CPU / OpenCL GPU / OpenCL FP16 / Intel NPU）**<br />**新增深色模式** (#92)<br />**新增解锁磁贴优化** (#91)<br />**新增域账户登录支持** (#104)<br />**修复 NVIDIA Broadcast 虚拟摄像头花屏** (#94)<br />**修复面容禁用后虚空登录** (#103) |
| v0.4.0 | 2026-05-29 | 功能添加、Bug修复 | **自 v0.3.5-fork 以来的主要变更：**<br />**Windows Hello 风格动画 UI**：DComp Topmost + Direct2D 原生绘制，60 FPS，Idle/Scanning/Success/Failure 四状态，帧率自适应<br />**Chrome 密码查看器双次人脸识别修复**：输入 Hook 统一触发<br />**开机人脸识别可靠性增强**：BootTrigger 延迟 + LogonTrigger 兜底<br />**无人脸自动重试**：Unlock EXE 内部最多 3 轮<br />**新增推理后端选择**（CPU / OpenCL GPU / OpenCL FP16 / Intel NPU）<br />**新增摄像头旋转**（0°/90°/180°/270°）（#96）<br />**新增解锁亮度调节**，改善弱光环境（#99）<br />**新增深色模式**（#92）<br />**新增域账户登录**（#104）<br />**解锁磁贴优化**（#91）<br />修复面容禁用后虚空登录（#103）<br />修复 NVIDIA Broadcast 虚拟摄像头花屏（#94）<br />修复初始化向导环境检查卡死<br />修复仪表盘页面切换白屏<br />修复动画管线竞态/卡死<br />**新增 GitHub Actions 自动构建发布工作流**
| v0.4.1 | 2026-05-29 | CI/发布流程修复 | 修正 NSIS/MSI 发布产物上传路径（产物实际位于 workspace 根 target）<br />将 ONNX 模型与 animation_frames.bin 纳入仓库供 CI 构建<br />规范化 LLVM 到 `D:\LLVM` 并校验 libclang<br />修复 tauri.conf.json 尾部空字节 |
| v0.4.2 | 2026-05-30 | Bug修复 | 修复开机面容识别冷启动 / 静默崩溃后无法自愈的问题 |
| v0.4.3 | 2026-05-30 | 性能优化、Bug修复 | 模型加载改为持续重试而非轻易放弃<br />大幅缩短开机面容恢复时间 |
| v0.4.4 | 2026-06-05 | 重要Bug修复、稳定性加固 | **彻底修复开机/锁屏人脸识别需等约 30 秒才触发摄像头的问题**：根因为 Unlock 服务在开机头 60 秒内 `Instant::now() - Duration` 算术下溢 panic（exit 101）反复崩溃重启，改用 `checked_sub` 安全回退，worker 开机一次启动成功、识别仅需 1-2 秒<br />supervisor 重启改为指数退避，杜绝崩溃风暴刷爆日志 / 空耗 CPU<br />panic 安全加固：修复 SystemTime 时钟异常 unwrap、并发句柄 double-close<br />新增 worker panic 日志（位置+原因写入 unlock.log），崩溃定位更快<br />Intel NPU 推理后端在缺少 OpenVINO 运行时时自动回退 CPU，选择不再报错 |
| v0.4.5 | 2026-06-06 | 重要Bug修复 | **保留浏览器查看密码人脸识别，并为 Google/passkey（WebAuthn）增加 PIN 回退**：实测浏览器查看密码与 passkey 验证在 Credential Provider 层的 `CPUS_CREDUI`、`dwflags`、auth package、CLSID、`rgbSerialization` 完全一致，无法精准区分；因此 `credentialuibroker.exe` 中的 CredUI 默认先尝试面容识别，若 5 秒内未拿到凭据或 `ReportResult` 表明凭据被拒绝，则隐藏本 Provider 并交还 Windows 原生 PIN。 |
| v0.5.0 | 2026-06-21 | Passkey Provider 正式路线 + 稳定性修复 | **新增 FaceWinUnlock Passkey Provider 正式插件**：插件自持不可导出 WebAuthn 密钥，网站端可保存该插件生成的通行密钥并完成登录认证<br />FaceWinUnlock 通过命名管道人脸 UV gate 授权插件签名，不提取 Windows Hello 私钥、不保存 PIN、不依赖浏览器扩展<br />支持静默人脸授权：刷脸成功后不再弹出额外确认窗口，远程/无人脸场景会按预期拒绝<br />安装包内置 MSIX 与证书，NSIS 只做机器级证书信任，MSIX 由当前桌面用户在应用内安装/更新/打开管理器<br />停用旧的密钥捕获/浏览器接管实验路线，避免发布不可验证的伪签名路径<br />**Chrome 查看密码强制走人脸**：broker 用触发应用窗口标题区分查看密码/通行密钥/设置PIN，通行密钥选 Windows 原生 Hello 不再误触发人脸<br />**修复自动锁屏摄像头乱亮**：授权冷却由固定 60s 改为 max(60s, 检测间隔)，在场时复查频率降 5 倍，并补全 auto-lock 摄像头日志<br />**修复 opencv_world4120.dll / FaceWinUnlock-Server.exe 从安装包丢失**（运行报「找不到 opencv_world4120.dll」、后台服务不自启）：Tauri v2 + NSIS 存在目录展开映射时会漏掉映射到安装根的单文件，改走 resources/ 子目录 + NSIS hooks 复制到根<br />**Intel NPU 推理可用**：随附 OpenVINO 运行时 + WITH_OPENVINO 编译的 opencv_world，装好 NPU 驱动后可选 intel_npu 后端<br />**OpenCV 预构建移出 git 历史**（.git 493MB→81MB）|
| v0.5.1 | 2026-06-21 | 性能与交互优化、兼容性修复 | **显著降低界面 GPU 占用**：窗口失焦或隐藏时暂停动画，移除持续背景漂移，减少装饰粒子并降低背景模糊成本<br />**提升界面流畅性**：3D 视差改为逐帧节流，缩短路由切换和仪表盘卡片动画，页面响应更跟手<br />**修复非 C 盘 Windows 的核心组件部署**：动态获取真实 System32 路径，初始化、注册及卸载不再依赖 `C:\Windows\System32` |
| v0.5.2 | 2026-06-21 | 重要兼容性修复（旧 Win10） | **修复旧版 Win10 锁屏无面容磁贴 / 不自动解锁 / 无 DLL 日志**（[issue #3](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/3)）：动画 UI 让 Credential Provider DLL 静态依赖 `dcomp.dll!DCompositionWaitForCompositorClock`（Win10 1803+ 才有）等图形导出，旧 Win10 的 LogonUI 加载 DLL 即失败、凭据提供程序完全不工作（无磁贴、无 `facewinunlock.log`、解锁失败），而原版无图形依赖可正常加载；改为运行时 `LoadLibrary`+`GetProcAddress` 动态加载图形 API，`dumpbin` 验证 DLL 不再静态依赖 d3d11/dcomp/dwrite/d2d1，任意 Win8.1+/Win10/Win11 均可加载，缺图形导出时动画优雅降级、面容解锁不受影响<br />**修复初始化第三步 Passkey 插件在 Win10 报错 `0x80073CFD`**：第三方通行密钥 Provider 是 Win11 24H2 专属功能，向导现按系统 build 检测，旧系统自动跳过该步并给友好提示，不再弹安装错误（不影响面容解锁） |
| v0.5.3 | 2026-06-22 | GPU 后端优化 + Passkey 卸载保留 + 多项修复 | **Passkey 卸载默认保留通行密钥**（[issue #3](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/3)）：卸载 / 全量更新 / 重装后免重新注册——私钥在 Microsoft Software KSP（密钥名 `facewinunlock/<userId>`，per-user，本就不随 MSIX 卸载删除），凭据元数据改用 `Remove-AppxPackage -PreserveApplicationData` 保留 + 包外备份/恢复兜底；卸载提供「保留密钥」「彻底清除」二选项，核心 / NSIS 卸载默认保留<br />**OpenCL kernel tuning 缓存优化**：Unlock 服务与 UI 启动时设置 `OPENCV_OCL4DNN_CONFIG_PATH` 到持久可写目录（SYSTEM→ProgramData、UI→LOCALAPPDATA）。此前不设该目录，OpenCV 的 ocl4dnn 每次 `forward` 都对卷积层重新做 OpenCL kernel 编译 + auto-tuning（GPU/FP16 首次推理可达 ~90s）且结果不持久化导致**每次解锁/识别都重复**；设置后只首次 tuning、后续从缓存秒加载（只解决「慢」，FP16 精度导致的「匹配不上」仍需改回 CPU）<br />**GPU（OpenCL / OpenCL FP16）后端实验性警告**：部分设备选 GPU 后端识别极慢甚至匹配不上（锁屏一直转圈不解锁、一致性检查黑屏、占用偏高），切换时明确提示实验性并引导遇异常改回 CPU<br />**修复「已是最新版仍反复提示更新」**：更新检查的 `CARGO_PKG_VERSION`（`UI/src-tauri/Cargo.toml`）此前漏随发版同步；现已 bump 并由 CI 从 tag **同时**同步 `tauri.conf.json` 与 `Cargo.toml`，杜绝复发<br />**修复初次打开「首选项 → 软件配置」明显卡顿**：原在 setup 同步阶段一次性发起 schtasks / 命名管道 / PowerShell `Get-AppxPackage` 等多个外部进程、与首屏渲染竞争，改到 `onMounted` 错开，最慢的 Passkey 状态查询再延迟加载<br />**清理编译警告**：Server 7→1（命名风格 `#![allow]` + 删死代码，仅保留 workspace profile 提示）、Unlock 32→0（NGC 实验模块 module 级 allow + 清理）、UI 3→0（清理 unused import / 字段） |
| v0.5.4 | 2026-06-22 | 重要修复（Win10 锁屏不自动解锁） | **修复 Win10 锁屏人脸"检测到但匹配不上"、不自动解锁**（[issue #3](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/3)）：同版本 Win11 能解锁、Win10 不能。根因——v0.5.3 为启动提速把**解锁端摄像头后端改成 DShow 优先**，而**录入端**用 CAP_ANY（Windows 上通常解析到 MSMF）；DShow(DirectShow) 与 MSMF 在部分设备 / 系统上色彩、曝光、分辨率不同，使同一张脸经 SFace 提取的 128 维特征偏移、cosine 跌破阈值（默认 0.60）→ 检测到脸但匹配不上（登录磁贴出现、圆圈一直转、摄像头亮但不登录）。Win11 上两后端帧恰好接近掩盖了问题、Win10 暴露；旧版本在同机锁屏用 CAP_ANY 即可匹配成功亦佐证。修复：解锁端改回 **CAP_ANY 优先**，与录入端同一特征空间，Win10 / Win11 一致<br />**MSIX 清单版本随 tag 自动同步（彻底根治插件 UI 改动推不动）**：插件 MSIX 清单版本此前写死、CI 不同步，导致插件 UI/代码改动（如本次删除菜单简化）因包版本号不变而被应用内「更新」按同版本跳过、推不到已安装用户；现 CI 从 tag 同步清单版本（x.y.z→x.y.z.0），点「更新」即生效、无需卸载重装。<br />**修复检查更新弹窗点击不跳转下载页**：更新通知点击改用 Tauri opener（openUrl）打开发布页——此前 window.open 在 webview 内被拦截、点了没反应。 |
| v0.5.5 | 2026-07-02 | 移除解锁动画、杀软误删自愈、秒解锁、稳定性加固 | **彻底移除 Windows Hello 风格解锁动画**（[issue #3](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/3)、[#14](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/14)、[#15](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/15)、[#16](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/16)、[#17](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/17)）：删除 DComp/D2D/D3D11/DWrite 图形管线、动画帧资源与注册表开关，Credential Provider DLL 不再静态或动态依赖图形库，旧 Win10 LogonUI 加载失败、锁屏闪烁、睡眠唤醒后卡转圈等问题改为从根上规避；锁屏界面保留轻量文字状态提示。<br />**修复 Win10 上触发识别后摄像头 40 秒左右才打开的问题**：离线分析 #3 附件日志确认不是模型加载或 worker 崩溃，而是 v0.5.4 的 CAP_ANY-first 在部分 Win10 摄像头上打开阻塞；现解锁端改为与 UI 录入端一致的 `MSMF → DShow → Any` 顺序，并记录每个后端打开耗时，避免 DShow-first 的特征不一致，也避开 CAP_ANY 长阻塞。<br />**修复卸载主程序后 Passkey 管理器残留**（[#17](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/17)）：管理员卸载时先备份各用户 `credentials.dat`，再用 `Remove-AppxPackage -AllUsers` 移除 MSIX，避免提权上下文只卸载管理员账户而桌面用户仍看到管理器；KSP 私钥仍保留，重装后可从备份恢复元数据。<br />**新增运行时文件自愈机制**：安装时将 `opencv_world4120.dll` 与 `FaceWinUnlock-Server.exe` 打成 `resources/runtime-backup.zip` 压缩备份，并注册 `FaceWinUnlockHealer` 计划任务（开机 / 登录 / 每 15 分钟检测缺失即恢复并拉起核心服务），用于缓解火绒 / Defender 等杀软误删无签名运行时导致的「找不到 opencv_world4120.dll」和服务缺失。<br />**安装器尝试加入 Windows Defender 排除目录**；使用火绒等第三方杀软时，请手动把安装目录加入信任区。<br />**秒解锁：锁屏预热摄像头**：锁屏出现后即在后台预开摄像头（MSMF 打开约 2-3 秒是硬件下限），用户动鼠标触发识别时摄像头已就绪、几乎瞬时完成比对，免去每次等 2-3 秒开摄像头；空闲 45 秒自动释放关灯，预热打开失败（摄像头被占用/不存在）即抑制重试、有关闭/释放请求待处理时避让。<br />**修复自动锁屏"启用了却没效果"**：自动锁屏开关此前需再点「保存」才写库，现拨动即时存库生效；并在屏幕已锁时跳过复查，避免与预热抢摄像头、避免对已锁屏重复锁定。<br />**录入一致性验证收尾**（[#12](https://github.com/starnotes-xj/FaceWinUnlock-Tauri/issues/12)）：修复切换推理后端后报「模型未加载」（`ensureModelLoaded` 改为幂等重载）、点「返回 / 确认更改」离开页面即停验证并关摄像头、从摄像头重新拍摄后可正常保存。<br />**修复插件已安装却显示"未安装"**：Passkey 插件状态判断的 v-if 链断裂导致误判，已修正显示逻辑。<br />**Passkey 卸载重装凭据恢复兜底**：查询插件状态时主动备份各用户 `credentials.dat`，第三方工具（如 Geek）卸载后重装可从备份恢复元数据，补齐 v0.5.4 卸载重装丢密钥的缺口。<br />**更新提示新增「前往下载」按钮**：有新版本时弹窗改为可点击「前往下载」直接打开 Release 页。 |

---

## 📢 重要通知

> **风险预警：** 由于本项目涉及底层 **注册表修改** 及 **Winlogon 进程操作**，在极端情况下（如 DLL 崩溃、路径配置错误等）可能会导致 Windows 登录界面无法正常显示，甚至**导致无法进入系统桌面**。

> **建议：** 在部署前仔细阅读程序的弹窗通知，并拍照留档，以便出问题后恢复（虽然概率极小）

> **重要提示：** 密码请输入账户中的密码，非Pin码！很多用户是用Pin解锁的，然后在软件输入的Pin码，会提示账户或密码错误。**软件不支持Pin码，请输入账户密码**

> **如果多次提示密码错误，请卸载软件，不要使用，否则微软官方会锁定账户！**

> **杀毒软件误删提示：** 本程序的 `opencv_world4120.dll`（OpenCV 运行库）与 `FaceWinUnlock-Server.exe`（后台人脸服务）目前无数字签名，部分杀软（火绒、Windows Defender 等）可能将其误判为可疑文件并删除，表现为「使用一两天后启动报找不到 `opencv_world4120.dll`」。v0.5.5 起安装包会创建压缩备份和 `FaceWinUnlockHealer` 自愈计划任务，并尝试加入 Windows Defender 排除；若你使用火绒等第三方杀软，请手动把安装目录加入「信任区/白名单」。

---

## 🎯 适用范围与安全性说明

* **安全性警告**：本项目基于 **2D 面容识别** 技术。相比于 Windows Hello 的 3D 结构光或红外活体检测，2D 识别存在被照片、视频绕过的风险。
* **建议场景**：仅建议在**对安全性要求不高**、追求便捷体验的个人家用电脑或开发机环境使用。**严禁用于存储高机密数据的办公或服务器环境。**
* **系统环境**：Windows 10/11 64位系统（Win7 64位尚未测试）
* **注意事项**：请勿将本软件用于非法用途，如用于非法用途，请自行负责。

---

## 🛠️ 安装与使用

> 在开始之前，请确保你已经阅读并理解了顶部的 **风险预警**。

1. **第一步：系统初始化**
运行软件后，系统会自动检测摄像头权限及注册表环境。强烈推荐在第2步拍照留档，一旦出错方便恢复。
![重要通知](data/1-1.png "重要通知")
![1-2](data/1-2.png "1-2")
点击执行后，软件会锁定账户，5秒后自动解锁，请勿手动解锁。解锁成功即初始化完成。

2. **第二步：个性化设置**
初始化成功后，点击首选项，选择一个摄像头设备。
![2-1](data/2-1.png "2-1")
3. **第三步：面容录入**
点击面容管理->添加新面容，即可添加，图片如下：
![3-1](data/3-1.png "3-1")
选择下面任意方式添加面容
![3-2](data/3-2.png "3-2")
4. **第四步：关联账户**
上一步面容添加成功后，输入别名、Windows账户类型，用户名（自动检查）和密码，点击添加即可完成。
![4-1](data/4-1.png "4-1")
面容列表功能如下图：
![4-2](data/4-2.png "4-2")
5. **第五步：测试**
按下 `Win + L` 锁定屏幕，滑动鼠标或按键盘（如果你选的延迟时间，请等待相应的秒数），将调用面容识别代码。
![5-1](data/5-1.png "5-1")
6. **第六步：卸载**
点击首选项->点击卸载核心组件（不走这一步，直接卸载软件会有残留）
![6-1](data/6-1.png "6-1")
打开软件安装目录的 *uninstall.exe* 卸载主程序即可
![6-2](data/6-2.png "6-2")
最后删除残留的数据库和日志文件，程序卸载完成，无残留文件。
![6-3](data/6-3.png "6-3")
7. **附加说明：一致性验证**
添加或编辑面容界面，有一致性验证，可以验证当前面容和对比面容的一致性。
![7-1](data/7-1.png "7-1")
点击后软件将调用摄像头，面容一致性实时显示在右侧。
![7-2](data/7-2.png "7-2")
8. **附加说明：性能**
这是面容验证时的系统资源占用情况
![8-1](data/8-1.png "8-1")
后台程序占用情况
![8-2](data/8-2.png "8-2")

## 💡 开发计划 (Roadmap)

* [x] 系统初始化向导
* [x] 实时摄像头人脸录入
* [x] 多面容关联单账户
* [x] 多面容关联多账户（代码提供者：[@Xiao-yu233](https://github.com/Xiao-yu233)，万分感谢）
* [x] DLL 和软件的个性化配置
* [x] Log 日志查看
* [x] 静默自启
* [x] 本地账号与联机账户支持
* [x] 活体检测 （[@tztztzy提供](https://github.com/tztztzy)）
* [x] 登录安全功能（[@tztztzy提供](https://github.com/tztztzy)）
* [x] 解锁失败时记录最后一帧画面
* [x] 交互优化：仅在用户有操作时调用面容识别（26-01-18完成）

## 后续计划

* [ ] Windows登录凭证加密存储
* [x] 解锁服务的性能优化（13号优化的一次够了，不用在优化了）
* [x] 日志清除功能
* [ ] 解决睡眠、休眠前进行面容解锁的问题
* [x] 无面容时添加超时关闭功能
* [ ] 登录密码找回密码的功能
* [ ] 简化软件缓存清除功能
* [x] 延迟时间支持重试
* [ ] 新的面容识别调用模式
* [x] 面容解锁分级支持（开机、锁屏、UAC、用户层）（Fork 已实现，首选项→系统集成可配置）
* [ ] 活体检测优化（仍无法与2.2相比，待优化）
* [x] 一键卸载脚本（由claude生成）
* [x] 检查更新与增量下载（详见下方说明）
* [ ] 识别时的动态反馈（26.02.17完成，样式有待优化）
* [ ] 放弃OpenCV，减少70M体积并解决中文目录无法使用问题（考虑中……）

## ⚠️ 遗留问题 (Known Issues)

以下是目前开发中遇到的技术瓶颈，欢迎有能力的开发者提交 PR 协助修复：

* **锁屏 UI 增强**：受限于 Windows 锁屏界面隔离机制，暂无法实现类似 Win Hello 的原生动画与动态通知。（26.02.17进行了优化，但还不够）

## ✨ 特性

* **现代化 UI**: 基于 Vue 3 + Element Plus 构建，告别传统软件的“土味”界面。
* **系统级集成**: 自动注册 WinLogon 凭据提供程序 (Credential Provider)。
* **双账户支持**: 同时支持本地账户 (Local Account) 与微软联机账户 (MSA) 解锁。
* **轻量级后端**: Rust 后端确保了高效的文件 IO 处理与注册表操作安全性。
* **隐私保护**: 系统凭据通过 SQLite 本地存储，**绝不上传云端**。

## 🛠️ 技术栈

* **前端界面**: Vue 3 (Composition API), Pinia, Element Plus
* **后端接口**: Rust (Tauri), Windows API
* **数据库**: SQLite 3
* **面容识别**: OpenCV (人脸检测与特征比对)
* **解锁组件**: 基于 Rust 编写的 WinLogon 注入组件 (Credential Provider DLL)

## 📦 代码库结构

* [WinLogon DLL](Server/) - 负责与系统登录界面交互的核心组件。
* [图形化界面](UI/) - 负责面容录入、配置管理的主程序。
* [解锁服务](Unlock/) - 负责处理解锁请求，与 WinLogon DLL 交互。
* [管道库](windows_pipes/) - 为上面3个的管道使用提供接口。
* [面容识别](face_library/) - 为解锁服务和图形化界面提供面容识别功能。

## 🔨 从源码构建

本项目由三个独立的 Rust 组件组成，**没有根级 `Cargo.toml`**（无 Cargo workspace），直接在仓库根目录运行 `cargo build --release` 会报错。

### 当前可构建状态

| 组件 | Cargo.toml | 可编译？ |
|------|-----------|----------|
| 根级 workspace | ✅ 已复原 | ✅ `cargo build --release`（从仓库根目录） |
| `Server/` (DLL) | ✅ 已复原 | ✅ 可编译，全部5个源文件完整 |
| `UI/src-tauri/` (Tauri 后端) | ✅ 已复原 | ✅ 可编译，所有模块完整实现 |
| `Unlock/` (解锁服务) | ✅ 已复原 | ✅ 可编译，607行完整人脸识别管线 |

### 构建全部（从根目录）

```powershell
# 先设置 Rust 环境变量，然后：
cd D:\RustProject\FaceWinUnlock-Tauri
cargo build --release
```

这会构建工作区的全部三个成员：Server DLL、UI Tauri 应用、Unlock 服务。

### Server DLL（可编译）

```powershell
cd Server
cargo build --release
# 产物: Server/target/release/FaceWinUnlock_Tauri.dll
```

### UI 前端（可独立运行）

Vue 3 前端代码完整，可通过 Vite 开发服务器预览（不含 Rust 后端）：

```powershell
cd UI
npm install
npm run dev
```

完整的 Tauri 构建（`npm run tauri build`）需要先恢复 `UI/src-tauri/Cargo.toml`。

### 完整构建的前提

- **`tauri.conf.json` bundle.resources 为空 `{}`** — 需手动将 ONNX 模型文件、DLL 和 EXE 放入安装目录的 `resources/` 文件夹
- 模型文件需自行下载：`face_detection_yunet_2023mar.onnx`、`face_recognition_sface_2021dec.onnx`、`face_liveness.onnx`

### Rust 环境说明

Rust 安装在非默认路径 `D:\Rust`，编译前需设置环境变量：

```powershell
$env:RUSTUP_HOME = "D:\Rust"
$env:CARGO_HOME  = "D:\Rust\CARGO"
$env:PATH        = "D:\Rust\CARGO\bin;" + $env:PATH
```

## ⚠️ 免责声明

本项目涉及修改 Windows 系统内核登录行为。在使用或二次开发时，请务必了解：

1. 错误的操作可能导致系统无法正常登录。
2. 建议在虚拟机 (VMware/Hyper-V) 环境中进行调试。
3. 作者不对因使用本软件导致的任何数据丢失、系统崩溃或安全漏洞承担责任。

## 🔐 Passkey Provider（官方插件路线）

FaceWinUnlock 现在使用 Windows 官方 Passkey Provider 插件路线：

1. 安装包内置 `FaceWinUnlock-Passkey.msix` 和签名证书。
2. 在“初始化向导”或“首选项 → 系统集成”中安装/更新 FaceWinUnlock Passkey 插件。
3. 打开插件管理器，按 Windows 要求完成一次注册和启用。
4. 使用该插件在网站重新注册通行密钥；之后登录时由插件持有的不可导出密钥签名，FaceWinUnlock 只负责人脸识别用户验证。

旧的浏览器扩展拦截、NGC 私钥提取和 PIN 自动填充路线已经停用。Windows Hello 已有通行密钥的私钥不可导出，不能被迁移到本插件；迁移到正式插件时需要在网站端重新注册通行密钥。请确保账户保留其他恢复登录方式。

## 🔍 检查更新

程序启动时会联网检查 GitHub Release，并按**语义版本**判断是否需要更新：只有最新版本高于当前版本时才提示；若版本号相同，则继续用 `update_manifest.json` 的 SHA256 与本地运行时文件比对，只要 hash 不一致也会提醒同步最新构建。需要下载时，客户端只拉取发生变化的文件，完成大小与哈希校验后暂存，并在应用退出时替换。旧版 Release 没有 manifest 时仍回退为“点击通知打开 Release 页面”。

| 项目 | 内容 |
|------|------|
| 联网地址 | `https://api.github.com/repos/starnotes-xj/FaceWinUnlock-Tauri/releases/latest` |
| 请求方式 | GET |
| 请求内容 | 仅标准 HTTP 头（User-Agent），不发送任何用户数据 |
| 下载内容 | 官方 Release 的 `update_manifest.json` 与其中列出的变化文件 |
| 完整性校验 | 文件大小和 SHA256 必须同时匹配，才会进入更新暂存目录 |
| 应用方式 | 退出程序时替换运行时文件；仍被占用的文件沿用 `.new` 延迟替换恢复路径 |

**相关代码文件**（完整链路，可从任意文件开始追溯）：

| 层 | 文件 | 说明 |
|----|------|------|
| 版本检查 | `UI/src-tauri/src/modules/update_check.rs` | `check_update`：GET GitHub API → 语义版本比较 → 同版本时继续做 manifest/hash 校验 |
| 增量下载 | `UI/src-tauri/src/modules/update_download.rs` | 下载 manifest、计算差异、下载并校验变化文件 |
| 文件落盘 | `UI/src-tauri/src/utils/api.rs` | `close_app` 时应用 `update_temp` 中的已校验文件 |
| 前端调用 | `UI/src/layout/MainLayout.vue` | 检查新版 → 展示差异 → 下载 → 提示退出应用 |

## 📄 开源协议

本项目采用 [GNU Affero General Public License v3.0](LICENSE) 开源。

---

**如果你觉得这个项目有点意思，欢迎点个 ⭐ Star 关注进度！**
