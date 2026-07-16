use std::fs;
use std::path::{Path, PathBuf};

use opencv::videoio::{VideoCapture, VideoCaptureTrait, VideoCaptureTraitConst};
use tauri_plugin_log::log;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use winreg::enums::{HKEY_CLASSES_ROOT, HKEY_LOCAL_MACHINE, KEY_WRITE};
use winreg::RegKey;

use crate::utils::custom_result::CustomResult;
use crate::ROOT_DIR;

/// DLL 文件名（不含路径）
const DLL_NAME: &str = "FaceWinUnlock-Tauri.dll";
/// 动态解析真实 System32 目录。系统盘可能不是 C:（issue #137 —— DLL 路径硬编码
/// `C:\Windows\System32`，在系统盘为 D:/E: 等的机器上部署失败、解锁失效）。
/// 优先 `GetSystemDirectoryW`（最权威，64 位进程不受 WOW64 重定向），回退 `%SystemRoot%`，
/// 再兜底 `C:\Windows\System32`。
fn system32_dir() -> PathBuf {
    unsafe {
        let mut buf = [0u16; 260]; // MAX_PATH
        let len = GetSystemDirectoryW(Some(&mut buf)) as usize;
        if len > 0 && len <= buf.len() {
            return PathBuf::from(String::from_utf16_lossy(&buf[..len]));
        }
    }
    std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .map(|w| PathBuf::from(w).join("System32"))
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32"))
}
/// Credential Provider GUID
const CP_GUID: &str = "{8a7b9c6d-4e5f-89a0-8b7c-6d5e4f3e2d1c}";
/// CP 注册表路径（Credential Providers 列表）
const CP_REG_PATH: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers";
/// CLSID 注册表根路径
const CLSID_ROOT: &str = r"CLSID";

// ──────────────────────────────────────────────────────────────────────────────
// 检查是否以管理员身份运行
// ──────────────────────────────────────────────────────────────────────────────
#[tauri::command]
pub fn check_admin_privileges() -> Result<CustomResult, CustomResult> {
    let elevated = is_elevated();
    if elevated {
        Ok(CustomResult::success(None, None))
    } else {
        Err(CustomResult::error(
            Some("请以管理员身份运行本程序".to_string()),
            None,
        ))
    }
}

fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        )
        .is_ok();
        let _ = windows::Win32::Foundation::CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// 清理 System32 下残留的 .new 文件（旧版安装/更新未重启留下的）
// ──────────────────────────────────────────────────────────────────────────────
#[tauri::command]
pub fn cleanup_stale_cp_dll() -> Result<CustomResult, CustomResult> {
    if !is_elevated() {
        return Err(CustomResult::error(
            Some("需要管理员权限才能清理 System32 文件".to_string()),
            None,
        ));
    }
    let sys32 = system32_dir();
    let mut cleaned = Vec::new();
    for name in &["FaceWinUnlock-Tauri.dll.new"] {
        let path = sys32.join(name);
        if path.exists() {
            match std::fs::remove_file(&path) {
                Ok(_) => cleaned.push(name.to_string()),
                Err(e) => log::warn!("清理 System32 残留失败: {} - {}", name, e),
            }
        }
    }
    Ok(CustomResult::success(
        Some(if cleaned.is_empty() {
            "没有需要清理的残留文件".to_string()
        } else {
            format!("已清理: {}", cleaned.join(", "))
        }),
        Some(json!({"cleaned": cleaned})),
    ))
}

// ──────────────────────────────────────────────────────────────────────────────
// 检查摄像头是否可用
// ──────────────────────────────────────────────────────────────────────────────
#[tauri::command]
pub fn check_camera_status() -> Result<CustomResult, CustomResult> {
    for index in 0i32..4 {
        match VideoCapture::new(index, opencv::videoio::CAP_ANY) {
            Ok(mut cap) => {
                if cap.is_opened().unwrap_or(false) {
                    let _ = cap.release();
                    return Ok(CustomResult::success(None, None));
                }
            }
            Err(_) => continue,
        }
    }
    Err(CustomResult::error(
        Some("未检测到可用摄像头".to_string()),
        None,
    ))
}

// ──────────────────────────────────────────────────────────────────────────────
// 部署核心组件（复制 DLL + 写注册表）
// ──────────────────────────────────────────────────────────────────────────────
#[tauri::command]
pub fn deploy_core_components() -> Result<CustomResult, CustomResult> {
    if !is_elevated() {
        return Err(CustomResult::error(
            Some("需要管理员权限才能部署核心组件".to_string()),
            None,
        ));
    }

    // 1. 复制核心文件到 System32
    let copy_to_system32 = |name: &str| -> Result<(), CustomResult> {
        let src = ROOT_DIR.join("resources").join(name);
        let dst = system32_dir().join(name);
        if !src.exists() {
            log::info!("deploy: {} 不存在，跳过", src.display());
            return Ok(());
        }
        std::fs::copy(&src, &dst).map_err(|e| {
            CustomResult::error(
                Some(format!(
                    "复制 {} 失败: {} → {}: {}",
                    name,
                    src.display(),
                    dst.display(),
                    e
                )),
                None,
            )
        })?;
        log::info!("deploy: 已复制 {} → {}", name, dst.display());
        Ok(())
    };

    copy_to_system32(DLL_NAME)?;

    // 2. 注册 Credential Provider（HKLM）
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cp_path = format!(r"{}\{}", CP_REG_PATH, CP_GUID);
    let (cp_key, _) = hklm
        .create_subkey_with_flags(&cp_path, KEY_WRITE)
        .map_err(|e| CustomResult::error(Some(format!("写注册表失败: {}", e)), None))?;
    cp_key
        .set_value("", &"FaceWinUnlock-Tauri")
        .map_err(|e| CustomResult::error(Some(format!("写注册表值失败: {}", e)), None))?;

    // 3. 注册 CLSID（HKCR）
    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);

    let clsid_path = format!(r"{}\{}", CLSID_ROOT, CP_GUID);
    let (clsid_key, _) = hkcr
        .create_subkey_with_flags(&clsid_path, KEY_WRITE)
        .map_err(|e| CustomResult::error(Some(format!("写 CLSID 注册表失败: {}", e)), None))?;
    clsid_key
        .set_value("", &"FaceWinUnlock-Tauri")
        .map_err(|e| CustomResult::error(Some(format!("写 CLSID 名称失败: {}", e)), None))?;

    let inproc_path = format!(r"{}\{}\InprocServer32", CLSID_ROOT, CP_GUID);
    let (inproc_key, _) = hkcr
        .create_subkey_with_flags(&inproc_path, KEY_WRITE)
        .map_err(|e| CustomResult::error(Some(format!("写 InprocServer32 失败: {}", e)), None))?;
    let dll_full = system32_dir().join(DLL_NAME).to_string_lossy().into_owned();
    inproc_key
        .set_value("", &dll_full)
        .map_err(|e| CustomResult::error(Some(format!("写 DLL 路径失败: {}", e)), None))?;
    inproc_key
        .set_value("ThreadingModel", &"Apartment")
        .map_err(|e| CustomResult::error(Some(format!("写 ThreadingModel 失败: {}", e)), None))?;

    // 4. 写入应用注册表配置（HKLM\SOFTWARE\facewinunlock-tauri）
    let app_reg_path = r"SOFTWARE\facewinunlock-tauri";
    let (app_key, _) = hklm
        .create_subkey_with_flags(app_reg_path, KEY_WRITE)
        .map_err(|e| CustomResult::error(Some(format!("创建应用注册表键失败: {}", e)), None))?;

    let log_dir = ROOT_DIR.join("logs");
    let _ = fs::create_dir_all(&log_dir);
    let root_dir_value = ROOT_DIR
        .to_str()
        .unwrap_or(r"C:\Program Files\facewinunlock-tauri");
    let log_dir_value = log_dir.to_str().unwrap_or(root_dir_value);

    // 默认配置（仅写入尚未存在的键，避免覆盖用户自定义设置）
    let defaults: &[(&str, &str)] = &[
        ("UNLOCK_SCENE", "1,2,4"),
        ("SHOW_TILE", "1"),
        ("CONNECT_TO_PIPE", "1"),
        ("RETRY_DELAY", "1.0"),
        ("UNLOCK_GRACE_PERIOD", "0.0"),
        ("CREDUI_ALLOW_GENERIC", "0"),
        ("CREDUI_ALLOW_BROKER", "1"),
        ("CREDUI_BROKER_FALLBACK_TIMEOUT", "5.0"),
        ("CREDUI_BROWSER_PASSWORD_FILL", "1"),
        ("DLL_LOG_PATH", log_dir_value),
    ];

    for &(name, value) in defaults {
        // 仅在键不存在时写入，避免覆盖已有配置
        if app_key.get_value::<String, _>(name).is_err() {
            app_key
                .set_value(name, &value)
                .map_err(|e| CustomResult::error(Some(format!("写 {name} 失败: {e}")), None))?;
        }
    }

    if let Ok(current) = app_key.get_value::<String, _>("DLL_LOG_PATH") {
        if current.trim_end_matches(['\\', '/']) == root_dir_value.trim_end_matches(['\\', '/']) {
            app_key
                .set_value("DLL_LOG_PATH", &log_dir_value)
                .map_err(|e| {
                    CustomResult::error(Some(format!("迁移 DLL_LOG_PATH 失败: {e}")), None)
                })?;
        }
    }

    if let Ok(current) = app_key.get_value::<String, _>("UNLOCK_GRACE_PERIOD") {
        if current.trim() == "5.0" {
            app_key
                .set_value("UNLOCK_GRACE_PERIOD", &"0.0")
                .map_err(|e| {
                    CustomResult::error(Some(format!("迁移 UNLOCK_GRACE_PERIOD 失败: {e}")), None)
                })?;
        }
    }

    if let Ok(current) = app_key.get_value::<String, _>("RETRY_DELAY") {
        if matches!(current.trim(), "10.0" | "10" | "2.0" | "2") {
            app_key.set_value("RETRY_DELAY", &"1.0").map_err(|e| {
                CustomResult::error(Some(format!("迁移 RETRY_DELAY 失败: {e}")), None)
            })?;
        }
    }

    if let Ok(current) = app_key.get_value::<String, _>("CREDUI_ALLOW_BROKER") {
        if current.trim() == "0" {
            app_key
                .set_value("CREDUI_ALLOW_BROKER", &"1")
                .map_err(|e| {
                    CustomResult::error(Some(format!("迁移 CREDUI_ALLOW_BROKER 失败: {e}")), None)
                })?;
        }
    }

    // Remove obsolete experiment switches so upgrades cannot retain conflicting
    // semantics. WebAuthn activity guarding is mandatory and has no off switch.
    for obsolete in [
        "CREDUI_UIA_DETECT",
        "CREDUI_BROKER_TRY_FACE_UNKNOWN",
        "CREDUI_BROWSER_TITLE_FALLBACK",
        "PASSKEY_TAKEOVER_ENABLED",
    ] {
        let _ = app_key.delete_value(obsolete);
    }

    // 5. 自动创建 Unlock EXE 的定时任务（BootTrigger + SessionUnlock）
    //    用户安装后无需手动去 Options 页点"同步"，就能让面容识别自动可用
    //    add_scheduled_task 内部会把相对路径解析为 ROOT_DIR 下的绝对路径
    if let Err(e) = crate::utils::api::add_scheduled_task(
        "FaceWinUnlock-Server.exe".to_string(),
        "FaceWinUnlockServer".to_string(),
        true,  // is_server: SYSTEM 账户运行
        false, // silent
        true,  // run_on_system_start: BootTrigger
        true,  // run_immediately: 部署完立即启动一次
    ) {
        // 任务创建失败不阻断部署，仅日志警告——用户仍可去 Options 手动创建
        log::warn!(
            "deploy_core_components: 创建定时任务失败（不影响 DLL 部署）: {:?}",
            e.msg
        );
    } else {
        log::info!("deploy_core_components: 定时任务 FaceWinUnlockServer 已创建并启动");
    }

    Ok(CustomResult::success(None, None))
}

// ──────────────────────────────────────────────────────────────────────────────
// 卸载核心组件（删除 DLL + 清理注册表）
// ──────────────────────────────────────────────────────────────────────────────
#[tauri::command]
pub fn uninstall_init() -> Result<CustomResult, CustomResult> {
    if !is_elevated() {
        return Err(CustomResult::error(
            Some("需要管理员权限才能卸载核心组件".to_string()),
            None,
        ));
    }

    // 1. 结束后台服务进程，避免 DLL/EXE 被占用
    let _ = run_hidden("taskkill", &["/F", "/IM", "FaceWinUnlock-Server.exe"]);

    // 2. 删除计划任务（UI 自启 + 服务自启）
    for tn in ["FaceWinUnlockAutoStart", "FaceWinUnlockServer"] {
        let _ = run_hidden("schtasks", &["/Delete", "/TN", tn, "/F"]);
    }

    // 3. 卸载官方 Passkey 插件。卸载是完整清理；只有更新流程会保留插件密钥。
    crate::modules::passkey_plugin::uninstall_passkey_plugin_for_core_uninstall()
        .map_err(|e| CustomResult::error(Some(format!("卸载 Passkey 插件失败: {e}")), None))?;

    // 4. 删除注册表：CP 列表项（磁贴来源）、CLSID、应用设置键
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let _ = hklm.delete_subkey_all(format!(r"{}\{}", CP_REG_PATH, CP_GUID));
    let _ = hklm.delete_subkey_all(r"SOFTWARE\facewinunlock-tauri");
    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
    let _ = hkcr.delete_subkey_all(format!(r"{}\{}", CLSID_ROOT, CP_GUID));

    // 5. 删除 System32 文件（主 DLL + 已废弃的 UIA-Helper），best-effort 不因占用而中断
    for f in [DLL_NAME, "FaceWinUnlock-UIA-Helper.exe"] {
        let p = system32_dir().join(f);
        if p.exists() {
            let _ = fs::remove_file(&p);
        }
    }

    // 6. 删除 WebView2 缓存（%ProgramData%\facewinunlock-tauri）
    if let Ok(pd) = std::env::var("ProgramData") {
        let cache = Path::new(&pd).join("facewinunlock-tauri");
        if cache.exists() {
            let _ = fs::remove_dir_all(&cache);
        }
    }

    Ok(CustomResult::success(None, None))
}

/// 隐藏窗口执行外部命令（best-effort，用于卸载时调用 taskkill / schtasks）
fn run_hidden(program: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    std::process::Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
}
