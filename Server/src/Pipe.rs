use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Pipes::*;
use windows_core::PCWSTR;

pub const PIPE_SERVER_NAME: &str = "\\\\.\\pipe\\MansonWindowsUnlockRustServer";
pub const PIPE_UNLOCK_NAME: &str = "\\\\.\\pipe\\MansonWindowsUnlockRustUnlock";
const BUF_SIZE: u32 = 4096;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// 写原始字节到管道（无帧头，适用于控制命令 "prepare" / "run"）
pub fn pipe_write_raw(pipe: HANDLE, data: &[u8]) -> windows::core::Result<()> {
    let mut written = 0u32;
    unsafe { WriteFile(pipe, Some(data), Some(&mut written), None) }
}

/// 从管道读取一次原始数据（阻塞直到有数据）
pub fn pipe_read_raw(pipe: HANDLE) -> windows::core::Result<Vec<u8>> {
    let mut buf = vec![0u8; BUF_SIZE as usize];
    let mut read = 0u32;
    unsafe {
        ReadFile(pipe, Some(&mut buf), Some(&mut read), None)?;
        buf.truncate(read as usize);
    }
    Ok(buf)
}

/// 连接到已存在的命名管道（Server EXE 侧，DLL 作为 Client）
/// timeout_ms: 等待管道出现的最大毫秒数
pub fn pipe_connect_to_server(name: &str, timeout_ms: u64) -> windows::core::Result<HANDLE> {
    pipe_connect_to_server_with_stop(name, timeout_ms, None)
}

/// 同上，但额外接受 stop_flag，循环间隔 200ms 检查可提前退出，
/// 用于 CPipeListener::stop_and_join 时不被多秒的 connect 超时卡住。
pub fn pipe_connect_to_server_with_stop(
    name: &str,
    timeout_ms: u64,
    stop: Option<&std::sync::atomic::AtomicBool>,
) -> windows::core::Result<HANDLE> {
    use std::sync::atomic::Ordering;
    let wide = to_wide(name);
    let ptr = PCWSTR::from_raw(wide.as_ptr());
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);

    loop {
        if let Some(s) = stop {
            if s.load(Ordering::SeqCst) {
                return Err(windows::core::Error::from_hresult(windows_core::HRESULT(
                    0x800704c7u32 as i32, // ERROR_CANCELLED
                )));
            }
        }

        // WaitNamedPipeW 最多等待 1 秒让管道出现
        let _ = unsafe { WaitNamedPipeW(ptr, 1000) };

        match unsafe {
            CreateFileW(
                ptr,
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        } {
            Ok(h) => return Ok(h),
            Err(_) => {
                if Instant::now() >= deadline {
                    return Err(windows::core::Error::from_hresult(windows_core::HRESULT(
                        0x800700e7u32 as i32, // ERROR_PIPE_BUSY -> timeout
                    )));
                }
                // 200ms 重试间隔，拆为短轮询以响应 stop_flag
                let retry_deadline = Instant::now() + Duration::from_millis(200);
                while Instant::now() < retry_deadline {
                    if let Some(s) = stop {
                        if s.load(Ordering::SeqCst) {
                            return Err(windows::core::Error::from_hresult(windows_core::HRESULT(
                                0x800704c7u32 as i32,
                            )));
                        }
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
}

/// 创建解锁管道（DLL 作为 Server，等待 Server EXE 发来凭据）
pub fn pipe_create_unlock_server() -> windows::core::Result<HANDLE> {
    let wide = to_wide(PIPE_UNLOCK_NAME);
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR::from_raw(wide.as_ptr()),
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,          // 只允许一个连接实例
            BUF_SIZE,
            BUF_SIZE,
            0,          // 默认超时
            None,       // 默认安全描述符
        )
    };
    if handle.is_invalid() {
        Err(windows::core::Error::from_win32())
    } else {
        Ok(handle)
    }
}

/// 等待 Server EXE 连接到解锁管道
/// ERROR_PIPE_CONNECTED (0x80070217): 调用前客户端已连接，视为成功
pub fn pipe_wait_for_unlock_client(pipe: HANDLE) -> windows::core::Result<()> {
    match unsafe { ConnectNamedPipe(pipe, None) } {
        Err(e) if e.code() == windows_core::HRESULT(0x80070217u32 as i32) => Ok(()),
        result => result,
    }
}

/// 以写入方式连接到单向（INBOUND）命名管道（用于停止时解除 ConnectNamedPipe 阻塞）
pub fn pipe_connect_write_only(name: &str) -> windows::core::Result<HANDLE> {
    let wide = to_wide(name);
    let ptr = PCWSTR::from_raw(wide.as_ptr());
    unsafe {
        CreateFileW(
            ptr,
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
}

/// 断开解锁管道连接（准备下一次）
pub fn pipe_disconnect(pipe: HANDLE) {
    unsafe { let _ = DisconnectNamedPipe(pipe); }
}

/// 解析从 Server EXE 收到的凭据数据
/// 支持两种格式：
///   1. null 分隔字符串: "username\0password\0domain\0"
///   2. JSON 字符串: {"user_name":"...","user_pwd":"...","domain":"..."}
pub fn parse_credentials(data: &[u8]) -> Option<(String, String, String)> {
    // 格式1：null 分隔
    let parts: Vec<&str> = data
        .split(|&b| b == 0u8)
        .filter_map(|s| std::str::from_utf8(s).ok().filter(|s| !s.is_empty()))
        .collect();

    if parts.len() >= 2 {
        let user = parts[0].to_string();
        let pwd = parts[1].to_string();
        let domain = parts.get(2).copied().unwrap_or(".").to_string();
        return Some((user, pwd, domain));
    }

    // 格式2：简单 JSON（无需 serde 库）
    let text = std::str::from_utf8(data).ok()?;
    let user = extract_json_str(text, "user_name")?;
    let pwd = extract_json_str(text, "user_pwd")?;
    let domain = extract_json_str(text, "domain").unwrap_or_else(|| ".".to_string());
    Some((user, pwd, domain))
}

/// 从简单 JSON 字符串中提取指定字段值（不处理转义字符）
fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":\"", key);
    let start = json.find(&needle)? + needle.len();
    // 找下一个非转义的双引号
    let rest = &json[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
