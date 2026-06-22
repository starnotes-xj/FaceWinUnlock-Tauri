# issue #3：Win10 锁屏人脸"检测到但匹配不上"（解锁端摄像头后端不一致）

## 症状

同一份 v0.5.3：

- **Win11**（作者本机）：录入人脸后 Win+L 锁屏能正常自动解锁。
- **Win10**（用户 ViCrack）：锁屏界面**不自动解锁**——登录磁贴出现、居中圆圈一直转且疯狂闪、
  摄像头灯亮着，但始终不登录，直到手动输入密码。
- 初始化最后一步"自动测试解锁"成功、面容管理"一致性检查"也通过（能出图像、能检查到）。

## 日志定位（unlock.log）

```
# 旧版本（中文日志）——同一台 Win10，锁屏解锁是成功的：
18:58:51 运行面容识别代码
18:58:52 尝试第1个后端 None 成功打开摄像头      ← CAP_ANY
18:58:59 面容匹配成功，发送用户名密码            ← 匹配成功

# v0.5.3（英文日志，supervisor 架构）——匹配不上：
12:00:13 run requested from credential provider
12:00:14 camera opened at configured index 0 via DShow   ← DShow
12:00:24 face recognition finished without a match (consecutive failures: 1)
12:00:36 face recognition finished without a match (consecutive failures: 2)
```

关键：v0.5.3 日志中**没有** `no face detected timeout` 也**没有** `no face in round N, retrying`，
却在整 10 秒（一个 `hard_deadline`）后直接 `without a match`。按 `face_recognition_loop` 逻辑
（`if matched || saw_face { break; }`），这意味着 **`saw_face == true`——脸被检测到了，
但 cosine 相似度始终 < 阈值**。即不是"开不了摄像头/黑帧/检测不到脸"，而是**检测到脸但特征匹配不上**。

## 根因：解锁端摄像头后端与录入端不一致

- **录入端**（UI，`face_library::camera`）用 **CAP_ANY**（app.log："尝试第1个后端 None 成功打开摄像头"）。
  写入的 `.face` 特征是经 CAP_ANY 解析到的实际后端（Windows 上通常是 **MSMF**）提取的。
- **解锁端** v0.5.3 的 `open_configured_camera` 为"少一次后端枚举"的启动提速，改成
  **DShow-first**（`DShow → MSMF → Any`），DShow 一旦 `is_opened()` 成功就返回、不再试 Any。
- DShow(DirectShow) 与 MSMF 是两条不同的采集管线，在部分设备/系统上**色彩/曝光/分辨率不同**，
  同一张脸经 SFace 提取的 128 维特征会偏移，cosine 跌破阈值（默认 `threshold/100 = 0.60`，对 SFace 偏高）。

**为什么 Win11 行、Win10 不行？** Win11 上该摄像头的 DShow 帧与 MSMF 帧恰好足够接近，cosine 仍 ≥ 0.60，
**掩盖**了后端不一致；Win10 上两者差异大就**暴露**了。这正是"后端不一致"的证据，而非反证。
旧版本在同一台 Win10 锁屏界面用 CAP_ANY 就能匹配成功，进一步佐证 CAP_ANY 才是与录入端一致的正确后端。

## 修复（`Unlock/src/main.rs::open_configured_camera`）

后端顺序改回 **CAP_ANY 优先**（`Any → DShow → MSMF`），与录入端对齐：

```rust
for (backend_name, backend) in [
    ("Any", videoio::CAP_ANY),     // 与录入端(UI)一致——同一特征空间
    ("DShow", videoio::CAP_DSHOW), // 仅当 CAP_ANY 打不开才回退
    ("MSMF", videoio::CAP_MSMF),
] { ... }
```

- CAP_ANY 几乎总能打开（录入端就是它开的），所以 DShow/MSMF 回退基本不会触发，正常路径两端一致。
- `#94`（NVIDIA Broadcast 虚拟摄像头）的 640×480 + 10 帧预热在该函数内部，与后端顺序无关、保持有效。
- `open_configured_camera` 是唯一摄像头打开点（识别循环、重试轮、auto_lock 都走它），一处修复全覆盖。
- 代价仅是 CAP_ANY 内部多一次后端枚举（几百 ms 启动延迟），远小于"完全不解锁"的代价。

## 防回归

- **绝不**为启动提速让解锁端用 DShow-first 或任何与录入端不同的后端顺序——必须 CAP_ANY 优先。
- 验证：解锁后看 unlock.log 应为 `camera opened ... via Any`；Win10/Win11 实机各跑一遍 Win+L 自动解锁。
- 与"识别慢（~6s 才出图）"是**两个不同问题**：后者是模型加载/摄像头冷启动，属预期，不在本修复范围。
