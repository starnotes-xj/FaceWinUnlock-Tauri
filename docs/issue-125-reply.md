@用户名 感谢反馈，我定位到原因了。

这个报错 `StsNotImplemented -213 "Backend(plugin) is not available"` **不是缺某个单独的文件**，而是底层 OpenCV 本身没有编译进 OpenVINO 支持。

简单说：Intel NPU 走的是 OpenCV DNN 的 OpenVINO 后端（backend=2 / target=9），但官方预编译的 Windows 版 OpenCV 是在 `WITH_OPENVINO=OFF` 下构建的，根本没有把 OpenVINO 后端插件编进去，所以选 NPU 时一定会报这个错。光在系统里装 OpenVINO 运行时也没用，因为这版 OpenCV 不会去加载它。

**当前版本临时处理**：我已经加了 CPU 自动回退——选 NPU 若不可用会自动回退到 CPU 并弹提示，录入/解锁不再硬失败。在 NPU 真正可用前，**建议先用 OpenCL 或 OpenCL FP16**（这两个官方预编译版本自带，开箱即用，速度也比纯 CPU 快）。

**彻底修复**：我会在**下个发布版本**里解决。已经改好了发布工作流，改为从源码编译开启了 `WITH_OPENVINO=ON` 的 OpenCV，并随安装包附带一份 OpenVINO 运行时（`FaceWinUnlock-NPU-Runtime.zip`）。下版发布后，启用 NPU 需要：

1. 下载并解压 `FaceWinUnlock-NPU-Runtime.zip` 到安装目录的 `resources\` 文件夹；
2. 安装 Intel 官方的 NPU 驱动（这是硬件驱动，无法随软件打包，需要你自己装）；
3. 在设置里选择 Intel NPU。

辛苦再等一个版本，到时我会在 release 说明里附上具体步骤。
