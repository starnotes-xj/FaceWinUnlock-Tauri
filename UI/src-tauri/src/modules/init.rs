use std::path::Path;

use opencv::videoio::{VideoCapture, VideoCaptureTrait, VideoCaptureTraitConst};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use winreg::enums::{HKEY_CLASSES_ROOT, HKEY_LOCAL_MACHINE, KEY_WRITE};
use winreg::RegKey;

use crate::utils::custom_result::CustomResult;
use crate::ROOT_DIR;

/// DLL 文件名（不含路径）
const DLL_NAME: &str = "FaceWinUnlock-Tauri.dll";
/// System32 完整路径
const SYSTEM32: &str = r"C:\Windows\System32";
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

    // 1. 复制 DLL 到 System32
    let src = ROOT_DIR.join("resources").join(DLL_NAME);
    let dst = Path::new(SYSTEM32).join(DLL_NAME);

    if !src.exists() {
        return Err(CustomResult::error(
            Some(format!("找不到 DLL 源文件: {}", src.display())),
            None,
        ));
    }

    std::fs::copy(&src, &dst).map_err(|e| {
        CustomResult::error(
            Some(format!("复制 DLL 失败: {} → {}: {}", src.display(), dst.display(), e)),
            None,
        )
    })?;

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
    let dll_full = format!(r"{}\{}", SYSTEM32, DLL_NAME);
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

    // 默认配置（仅写入尚未存在的键，避免覆盖用户自定义设置）
    let defaults: &[(&str, &str)] = &[
        ("UNLOCK_SCENE", "1,2,4"),
        ("SHOW_TILE", "1"),
        ("CONNECT_TO_PIPE", "1"),
        ("RETRY_DELAY", "10.0"),
        ("UNLOCK_GRACE_PERIOD", "5.0"),
        ("CREDUI_ALLOW_GENERIC", "0"),
        ("DLL_LOG_PATH", ROOT_DIR.to_str().unwrap_or(r"C:\Program Files\facewinunlock-tauri")),
        // 动画 UI（阶段 B/C）— 默认启用以便 VM 测试
        ("ANIMATION_UI_ENABLED", "1"),
    ];

    for &(name, value) in defaults {
        // 仅在键不存在时写入，避免覆盖已有配置
        if app_key.get_value::<String, _>(name).is_err() {
            app_key
                .set_value(name, &value)
                .map_err(|e| CustomResult::error(Some(format!("写 {name} 失败: {e}")), None))?;
        }
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

    // 1. 删除注册表项
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cp_path = format!(r"{}\{}", CP_REG_PATH, CP_GUID);
    let _ = hklm.delete_subkey_all(&cp_path);

    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
    let clsid_path = format!(r"{}\{}", CLSID_ROOT, CP_GUID);
    let _ = hkcr.delete_subkey_all(&clsid_path);

    // 2. 删除 DLL
    let dst = Path::new(SYSTEM32).join(DLL_NAME);
    if dst.exists() {
        std::fs::remove_file(&dst).map_err(|e| {
            CustomResult::error(
                Some(format!("删除 DLL 失败: {}", e)),
                None,
            )
        })?;
    }

    Ok(CustomResult::success(None, None))
}
