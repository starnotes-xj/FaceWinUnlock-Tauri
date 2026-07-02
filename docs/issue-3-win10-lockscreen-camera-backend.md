# issue #3：Win10 锁屏摄像头后端一致性与打开延迟

## 症状

同一份 v0.5.3 / v0.5.4 在不同 Win10 设备上暴露出两类相邻问题：

- **Win11**（作者本机）：录入人脸后 Win+L 锁屏能正常自动解锁。
- **Win10 v0.5.3**（用户 ViCrack）：锁屏界面**不自动解锁**——登录磁贴出现、居中圆圈一直转且疯狂闪、
  摄像头灯亮着，但始终不登录，直到手动输入密码。
- 初始化最后一步"自动测试解锁"成功、面容管理"一致性检查"也通过（能出图像、能检查到）。
- **Win10 v0.5.4**：改成 CAP_ANY-first 后仍有用户反馈触发后摄像头几十秒才亮，CPU 高。

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

# v0.5.4（CAP_ANY-first）——触发后很久才真正打开摄像头：
13:59:38 run requested from credential provider
14:00:18 camera opened at configured index 0 via Any     ← CAP_ANY 阻塞约 40s
14:00:28 face recognition finished without a match
14:02:51 run requested from credential provider
14:03:32 camera opened at configured index 0 via Any     ← 再次阻塞约 41s
```

v0.5.3 关键点：日志中**没有** `no face detected timeout` 也**没有** `no face in round N, retrying`，
却在整 10 秒（一个 `hard_deadline`）后直接 `without a match`。按 `face_recognition_loop` 逻辑
（`if matched || saw_face { break; }`），这意味着 **`saw_face == true`——脸被检测到了，
但 cosine 相似度始终 < 阈值**。即不是"开不了摄像头/黑帧/检测不到脸"，而是**检测到脸但特征匹配不上**。

v0.5.4 关键点：模型已在后台加载，没有 `exit 101` / panic，`run requested` 也已到达 Unlock；时间洞在
`VideoCapture::new(index, CAP_ANY)` 返回前。因此不是模型加载或 worker 崩溃，而是 CAP_ANY 后端探测/打开在
部分 Win10 设备上会长时间阻塞。

## 根因：必须同时满足"后端一致"和"避免 CAP_ANY 长阻塞"

- **录入端**当前代码（`UI/src-tauri/src/utils/api.rs::open_camera(None)`）默认顺序是
  **MSMF → DShow → Any**，并在成功后使用该后端提取 `.face` 特征。
- **解锁端** v0.5.3 的 `open_configured_camera` 为"少一次后端枚举"的启动提速，改成
  **DShow-first**（`DShow → MSMF → Any`），DShow 一旦 `is_opened()` 成功就返回、不再试 Any。
- DShow(DirectShow) 与 MSMF 是两条不同的采集管线，在部分设备/系统上**色彩/曝光/分辨率不同**，
  同一张脸经 SFace 提取的 128 维特征会偏移，cosine 跌破阈值（默认 `threshold/100 = 0.60`，对 SFace 偏高）。
- v0.5.4 的 **CAP_ANY-first** 规避了 DShow-first 的特征不一致，但 #3 新日志证明 CAP_ANY 在某些 Win10
  上会阻塞约 40 秒才打开摄像头，导致用户误以为一直转圈、不触发识别。

**为什么 Win11 行、Win10 不行？** Win11 上该摄像头的 DShow 帧与 MSMF 帧恰好足够接近，cosine 仍 ≥ 0.60，
**掩盖**了后端不一致；Win10 上两者差异大就**暴露**了。这正是"后端不一致"的证据，而非反证。
不同 Win10 上 CAP_ANY 还可能有明显打开延迟，因此最终约束是：**解锁端必须跟随 UI 录入端的真实默认顺序**。

## 修复（`Unlock/src/main.rs::open_configured_camera`）

v0.5.5 后端顺序改为 **MSMF → DShow → Any**，与当前 UI 录入端对齐，并记录每个后端打开耗时：

```rust
for (backend_name, backend) in [
    ("MSMF", videoio::CAP_MSMF),
    ("DShow", videoio::CAP_DSHOW),
    ("Any", videoio::CAP_ANY),
] { ... }
```

- MSMF 是 UI 当前默认首选后端，避免 v0.5.3 的 DShow 特征偏移。
- Any 只作为最终兜底，避免 v0.5.4 在部分 Win10 上优先走 CAP_ANY 时长时间阻塞。
- `#94`（NVIDIA Broadcast 虚拟摄像头）的 640×480 + 10 帧预热在该函数内部，与后端顺序无关、保持有效。
- `open_configured_camera` 是唯一摄像头打开点（识别循环、重试轮、auto_lock 都走它），一处修复全覆盖。
- 新增日志：`camera backend MSMF opened in ...ms` / `camera backend ... unavailable after ...ms`，下次用户贴日志可直接看哪个后端卡住。

## 防回归

- **绝不**为启动提速让解锁端用 DShow-first。
- **不要再按旧记忆改回 CAP_ANY-first**；#3 附件已证明 CAP_ANY-first 在部分 Win10 上会带来 40s 级打开延迟。
- 若未来 UI 录入端默认后端顺序变化，必须同步修改 `Unlock/src/main.rs::open_configured_camera`。
- 验证：解锁后看 unlock.log 应为 `camera backend MSMF opened in ...ms`，随后 `camera opened ... via MSMF`；
  Win10/Win11 实机各跑一遍 Win+L 自动解锁。
