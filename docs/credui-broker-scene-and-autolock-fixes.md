# CredUI Broker Scene Classification & Auto-Lock Fixes (v0.5.10)

## 1. Passkey 登录时移动鼠标触发人脸识别

### 根因

Google passkey 弹窗在 CredUIBroker 出现**之后**才启动 CTAP 事务。`classify_broker_scene`
运行时 `webauthn_active=false`，旧逻辑仅凭 `webauthn_ready=true` + 浏览器进程就归类为
`BrowserPasswordFill`，启用了人脸识别。

### 修复方案: 三层防线

#### 第一层: 枚举事件提前检测

新增事件 2250/2251 监听（`Unlock/src/webauthn_activity.rs`）：

- 2250 = 凭据枚举开始（弹窗之前 ~1-2s）
- 2251 = 凭据枚举结束

近期枚举（5s TTL）视为 `active=true`，在 classify step ② 被截获 → `Passkey` → 不参与。

#### 第二层: ready-monitor 恢复

枚举事件提供区分能力后，classify step ⑥ 恢复旧行为（`Server/src/lib.rs`）：

```rust
// ★ 监视器 Ready 且无 active（CTAP + 枚举均无）：必为密码填充
if context.webauthn_ready {
    return BrokerScene::BrowserPasswordFill;
}
```

此分支仅在 `active=false`（无 CTAP 也无近期枚举）时到达。

#### 第三层: DLL 发 "run" 前复查

`Server/src/CPipeListener.rs` 在 `pipe_write_raw("run")` 紧前面增加 guard 检查，关闭 ~20ms 竞态窗口。

### 为什么不用关键词/白名单

- passkey 弹窗标题多变（"登录 - google 账号" vs "通行密钥"）
- 密码填充标题同样多变（QQ邮箱: "登录qq邮箱"）
- 确定性信号: 枚举事件在弹窗**之前**发生

---

## 2. 自动锁屏误锁

### 根因

旧在场检测只扫 15 帧（~0.5-1.5s），摄像头传感器稳定期未过 → 无脸帧 → 误锁。

### 修复 (`Unlock/src/main.rs`)

1. 替换 15 帧为 10s deadline + `not_face_delay` 超时退避
2. 新增重试: 第一次失败 → 等 3s → 重新开摄像头做第二轮 (8s deadline)
3. 与主识别循环逻辑一致

---

## 3. Win+L 后预热延迟

### 根因

`power_resume_requires_run` 被虚假 power event 置为 true，阻止新凭据会话恢复预热。

### 修复 (`Unlock/src/main.rs`)

```rust
if !power_resume_requires_run || !state.power.is_camera_blocked() {
    prewarm_suppressed = false;
    power_resume_requires_run = false;
}
```

`is_camera_blocked()` = false 时强制清除抑制。

---

## 相关文件

| 文件 | 改动 |
|------|------|
| `Unlock/src/webauthn_activity.rs` | 枚举事件 2250/2251 + 5s TTL |
| `Server/src/lib.rs` | classify step ⑥: ready-monitor 恢复 |
| `Server/src/CPipeListener.rs` | "run" 前 guard 复查 |
| `Unlock/src/main.rs` | auto-lock 在场检测 + prewarm 抑制修复 |
| `Unlock/src/power_events.rs` | GUID_CONSOLE_DISPLAY_STATE (Modern Standby) |
| `PasskeyPlugin/PluginManagement/PluginCredentialManager.h` | PurgeRequested.flag |
| `UI/src-tauri/src/modules/passkey_plugin.rs` | 密钥清理补齐元数据 |
| `UI/src/views/Dashboard.vue` | faceCount computed + 轮询刷新 |
| `UI/src/stores/faces.js` | init() 幂等化 |
