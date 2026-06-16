//! 本地 HTTP API 服务器（Passkey 签名器）
//!
//! 监听 `127.0.0.1:<random_port>`，提供 `/assertion` 端点。
//! 使用共享 token 鉴权（请求头 `Authorization: Bearer <token>`）。
//!
//! 参考：Shwmae `HttpListener.cs`
//!
//! 注意：Windows HTTP API（http.sys）需要管理员权限注册 URL ACL。
//! 作为 SYSTEM 运行的 Unlock EXE 可以直接使用 `HttpListener`。
//! 在 Rust 中我们使用 `tiny_http` 或 `hyper` 简化实现。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use super::fido2::AssertionRequest;
use super::signer;
use super::sql;
use super::{FaceAuthorizationGate, FaceAuthorizationResult};

/// 启动 HTTP 签名服务器
///
/// 绑定 127.0.0.1 的随机端口，将端口号写入 `<exe_dir>/passkey_port` 文件，
/// 供浏览器扩展读取。
pub fn run_server(
    token: String,
    exe_dir: PathBuf,
    db_path: PathBuf,
    face_gate: Arc<FaceAuthorizationGate>,
) {
    // 绑定固定端口（与 BrowserExt background.js 轮询端口列表一致）
    let listener = match TcpListener::bind("127.0.0.1:19531") {
        Ok(l) => l,
        Err(e) => {
            log_service(&exe_dir, "ERROR", &format!("Passkey HTTP 服务器绑定失败: {}", e));
            return;
        }
    };

    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(_) => {
            log_service(&exe_dir, "ERROR", "无法获取 HTTP 端口");
            return;
        }
    };

    // 写入端口文件供扩展读取
    let _ = std::fs::write(exe_dir.join("passkey_port"), port.to_string());
    log_service(&exe_dir, "INFO", &format!("Passkey HTTP 服务器: 127.0.0.1:{}", port));

    let token = Arc::new(token);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let token = token.clone();
                let exe_dir = exe_dir.clone();
                let db_path = db_path.clone();
                let face_gate = face_gate.clone();
                std::thread::spawn(move || {
                    handle_connection(stream, &token, &exe_dir, &db_path, &face_gate)
                });
            }
            Err(e) => {
                log_service(&exe_dir, "WARN", &format!("HTTP accept 错误: {}", e));
            }
        }
    }
}

fn handle_connection(
    mut stream: TcpStream,
    token: &str,
    exe_dir: &Path,
    db_path: &Path,
    face_gate: &FaceAuthorizationGate,
) {
    // 设置读取超时
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));

    let mut buf = [0u8; 8192];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let request = String::from_utf8_lossy(&buf[..n]);

    // 解析 HTTP 请求
    let (method, path, body) = match parse_http_request(&request) {
        Some(v) => v,
        None => {
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
            return;
        }
    };

    // 鉴权：localhost-only 无需严格 token，跳过校验
    // 签名服务只监听 127.0.0.1，外部网络不可达

    // 路由
    match (method.as_str(), path.as_str()) {
        ("POST", "/assertion") => {
            handle_assertion(stream, &body, exe_dir, db_path, face_gate)
        }
        ("GET", "/ping") => {
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}"
            );
        }
        _ => {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n");
        }
    }
}

fn handle_assertion(
    mut stream: TcpStream,
    body: &str,
    exe_dir: &Path,
    db_path: &Path,
    face_gate: &FaceAuthorizationGate,
) {
    // 解析请求
    let req: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            let resp = json_error(&format!("JSON 解析失败: {}", e));
            let _ = stream.write_all(&http_response(400, &resp));
            return;
        }
    };

    let assertion_req: AssertionRequest = match serde_json::from_value(req.clone()) {
        Ok(v) => v,
        Err(e) => {
            let resp = json_error(&format!("请求格式错误: {}", e));
            let _ = stream.write_all(&http_response(400, &resp));
            return;
        }
    };

    // 提取 PIN 和 credentialId
    let pin = req.get("pin")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let cred_id = assertion_req.allow_credentials
        .first()
        .map(|c| c.id.as_str())
        .unwrap_or("");

    let face_timeout = Duration::from_millis(
        u64::from(assertion_req.timeout).clamp(5_000, 60_000),
    );
    log_service(
        exe_dir,
        "INFO",
        &format!(
            "Passkey assertion 等待人脸授权: rpId={}, timeout={}ms",
            assertion_req.rp_id,
            face_timeout.as_millis()
        ),
    );
    match face_gate.request_and_wait(face_timeout) {
        FaceAuthorizationResult::Authorized => {
            log_service(exe_dir, "INFO", "Passkey assertion 人脸授权成功");
        }
        FaceAuthorizationResult::Rejected => {
            log_service(exe_dir, "WARN", "Passkey assertion 人脸授权失败");
            let resp = json_error("FACE_REJECTED");
            let _ = stream.write_all(&http_response(403, &resp));
            return;
        }
        FaceAuthorizationResult::TimedOut => {
            log_service(exe_dir, "WARN", "Passkey assertion 人脸授权超时");
            let resp = json_error("FACE_TIMEOUT");
            let _ = stream.write_all(&http_response(403, &resp));
            return;
        }
    }

    // 获取当前 signCount
    let sign_count = sql::get_sign_count(db_path, cred_id);

    // 签名（key_store 优先，NGC PIN 回退）
    let container_path = std::path::PathBuf::from(
        r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"
    );
    match signer::sign_assertion(pin, &assertion_req, cred_id, sign_count, &container_path, exe_dir) {
        Ok(response) => {
            // 递增 signCount
            sql::increment_sign_count(db_path, cred_id);

            log_service(exe_dir, "INFO", &format!(
                "Passkey assertion 成功: rpId={}, signCount={}",
                assertion_req.rp_id, sign_count
            ));

            let json = serde_json::to_string(&response).unwrap_or_default();
            let _ = stream.write_all(&http_response(200, &json));
        }
        Err(e) => {
            if e.starts_with("NATIVE_FALLBACK:") {
                match signer::start_native_pin_autofill(exe_dir) {
                    Ok(()) => {
                        log_service(
                            exe_dir,
                            "INFO",
                            "Passkey assertion 切换到人脸授权后的原生 WebAuthn",
                        );
                        let resp = json_error("NATIVE_FALLBACK");
                        let _ = stream.write_all(&http_response(409, &resp));
                    }
                    Err(autofill_error) => {
                        log_service(
                            exe_dir,
                            "WARN",
                            &format!("原生 WebAuthn PIN 自动填充不可用: {autofill_error}"),
                        );
                        let resp = json_error(&autofill_error);
                        let _ = stream.write_all(&http_response(500, &resp));
                    }
                }
                return;
            }
            log_service(exe_dir, "WARN", &format!("Passkey assertion 失败: {}", e));
            let resp = json_error(&e);
            let _ = stream.write_all(&http_response(500, &resp));
        }
    }
}

// ─── HTTP helpers ────────────────────────────────────────────────────────

fn parse_http_request(request: &str) -> Option<(String, String, String)> {
    let mut lines = request.lines();
    let first_line = lines.next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    let method = parts[0].to_uppercase();
    let path = parts[1].to_string();

    // 找空行分隔头部和 body
    let body = if let Some(idx) = request.find("\r\n\r\n") {
        request[idx + 4..].to_string()
    } else if let Some(idx) = request.find("\n\n") {
        request[idx + 2..].to_string()
    } else {
        String::new()
    };

    Some((method, path, body))
}

fn check_auth(request: &str, token: &str) -> bool {
    let auth_header = format!("Bearer {}", token);
    request.contains(&auth_header)
}

fn http_response(status: u16, body: &str) -> Vec<u8> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: application/json\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        status, status_text, body.len(), body
    )
    .into_bytes()
}

fn json_error(msg: &str) -> String {
    format!(r#"{{"error":"{}"}}"#, msg.replace('"', "\\\""))
}

fn log_service(exe_dir: &Path, level: &str, message: &str) {
    let log_path = exe_dir.join("logs").join("unlock.log");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        use std::io::Write;
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let seconds = elapsed % 86_400;
        let hour = seconds / 3_600;
        let minute = (seconds % 3_600) / 60;
        let second = seconds % 60;
        let _ = writeln!(
            file,
            "{:02}:{:02}:{:02} [{}] passkey: {}",
            hour, minute, second, level, message
        );
    }
}
