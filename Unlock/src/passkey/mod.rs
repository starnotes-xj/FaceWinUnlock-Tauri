//! Passkey 自接管模块（Phase 2）
//!
//! 复用 Phase 1 的 `ngc` 模块解出 Hello FIDO2 平台凭据私钥，
//! 在浏览器层接管 `navigator.credentials.get`（登录断言）。
//!
//! ## 架构
//!
//! ```text
//! 网站 navigator.credentials.get()
//!   → 浏览器扩展 webauthn-inject.js 拦截
//!   → POST to http://127.0.0.1:<port>/assertion (token 鉴权)
//!   → 签名器(SYSTEM): 弹窗要 PIN → ngc → FIDO2 私钥
//!       → 构造 authenticatorData + 签名
//!   → 返回 assertion → 扩展回填 → RP 验证
//! ```
//!
//! ## 灰度开关
//!
//! 注册表 `PASSKEY_TAKEOVER_ENABLED`（默认 `"0"`）。
//! 设为 `"1"` 后，Unlock EXE 启动 HTTP 签名服务。

pub mod fido2;
pub mod signer;
mod http;
mod sql;

use std::path::Path;

/// 本地 HTTP API 的鉴权 token 文件名
const TOKEN_FILE: &str = "passkey_token";

/// 启动 passkey 签名服务
///
/// 如果注册表 `PASSKEY_TAKEOVER_ENABLED != "1"`，直接返回不启动。
pub fn start_if_enabled(exe_dir: &Path, db_path: &Path) {
    let enabled = crate::read_registry_string("PASSKEY_TAKEOVER_ENABLED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);

    if !enabled {
        return;
    }

    let token = load_or_create_token(exe_dir);
    let exe_dir_owned = exe_dir.to_path_buf();
    let db_path_owned = db_path.to_path_buf();

    std::thread::spawn(move || {
        http::run_server(token, exe_dir_owned, db_path_owned);
    });
}

/// 加载或创建本地鉴权 token
fn load_or_create_token(exe_dir: &Path) -> String {
    let token_path = exe_dir.join(TOKEN_FILE);
    if let Ok(token) = std::fs::read_to_string(&token_path) {
        let token = token.trim().to_string();
        if !token.is_empty() {
            return token;
        }
    }
    // 生成随机 token
    let token = uuid::Uuid::new_v4().to_string();
    let _ = std::fs::write(&token_path, &token);
    token
}
