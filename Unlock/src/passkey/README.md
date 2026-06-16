# Unlock/src/passkey — 模块说明

当前**有效**的入口只有 [`mod.rs`](mod.rs)：它实现 `FaceAuthorizationGate`，
为官方 Windows Passkey Provider 插件提供**一次人脸用户验证（UV）gate**。
插件自己持有不可导出的 WebAuthn 密钥并自行签名，FaceWinUnlock 只通过命名管道
`\\.\pipe\FaceWinUnlockPasskeyFaceAuth` 返回 `AUTHORIZED` / `REJECTED` / `TIMEOUT`。

## 已停用的历史实验代码（Approach B，勿恢复）

以下文件是早期“浏览器扩展拦截 WebAuthn + 自行给现有 passkey 签名”路线的残留，
**已不在编译图内**（`mod.rs` 不再 `mod` 它们，`main.rs` 也不引用），保留仅供查阅：

| 文件 | 旧用途 | 停用原因 |
|------|--------|----------|
| `http.rs` | 本地 HTTP signer，监听 `127.0.0.1:19531`，接收浏览器扩展的断言请求 | 路线作废 |
| `signer.rs` | 组装 authenticatorData、调用 NGC/KSP 或捕获密钥签名 | 见下 |
| `key_store.rs` | 加载“捕获”的 ECDSA 私钥 | 密钥非真实注册公钥对应私钥 |
| `sql.rs` | passkey signCount 持久化 | 随旧路线停用 |
| `fido2.rs` | CTAP2/WebAuthn 数据结构与编码 | 随旧路线停用 |

**为什么彻底放弃 Approach B（实测结论，勿重试）：**
现有 Windows Hello passkey 的私钥不可导出、Passport KSP 拒绝第三方静默签名
（实测 `NCryptSignHash` → `NTE_BAD_KEY 0x80090003`）。能“构造一个 P-256 标量”
不等于“匹配网站注册的公钥”，webauthn.io 会拒绝不匹配的签名。
正确路线是官方插件自建/自持密钥、网站用该插件重新注册公钥，
FaceWinUnlock 只做人脸 UV gate。
