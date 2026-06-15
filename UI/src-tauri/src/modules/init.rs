use std::path::{Path, PathBuf};
use std::fs;

use opencv::videoio::{VideoCapture, VideoCaptureTrait, VideoCaptureTraitConst};
use tauri_plugin_log::log;
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

    // 1. 复制核心文件到 System32
    let copy_to_system32 = |name: &str| -> Result<(), CustomResult> {
        let src = ROOT_DIR.join("resources").join(name);
        let dst = Path::new(SYSTEM32).join(name);
        if !src.exists() {
            log::info!("deploy: {} 不存在，跳过", src.display());
            return Ok(());
        }
        std::fs::copy(&src, &dst).map_err(|e| {
            CustomResult::error(
                Some(format!("复制 {} 失败: {} → {}: {}", name, src.display(), dst.display(), e)),
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

    let log_dir = ROOT_DIR.join("logs");
    let _ = fs::create_dir_all(&log_dir);
    let root_dir_value = ROOT_DIR.to_str().unwrap_or(r"C:\Program Files\facewinunlock-tauri");
    let log_dir_value = log_dir.to_str().unwrap_or(root_dir_value);
    let animation_frames_path = ROOT_DIR.join("resources").join("animation_frames.bin");
    let animation_frames_value = animation_frames_path.to_str().unwrap_or("");

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
        ("CREDUI_UIA_DETECT", "0"),
        ("DLL_LOG_PATH", log_dir_value),
        ("ANIMATION_FRAMES_PATH", animation_frames_value),
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

    if let Ok(current) = app_key.get_value::<String, _>("DLL_LOG_PATH") {
        if current.trim_end_matches(['\\', '/']) == root_dir_value.trim_end_matches(['\\', '/']) {
            app_key
                .set_value("DLL_LOG_PATH", &log_dir_value)
                .map_err(|e| CustomResult::error(Some(format!("迁移 DLL_LOG_PATH 失败: {e}")), None))?;
        }
    }

    if let Ok(current) = app_key.get_value::<String, _>("UNLOCK_GRACE_PERIOD") {
        if current.trim() == "5.0" {
            app_key
                .set_value("UNLOCK_GRACE_PERIOD", &"0.0")
                .map_err(|e| CustomResult::error(Some(format!("迁移 UNLOCK_GRACE_PERIOD 失败: {e}")), None))?;
        }
    }

    if let Ok(current) = app_key.get_value::<String, _>("RETRY_DELAY") {
        if matches!(current.trim(), "10.0" | "10" | "2.0" | "2") {
            app_key
                .set_value("RETRY_DELAY", &"1.0")
                .map_err(|e| CustomResult::error(Some(format!("迁移 RETRY_DELAY 失败: {e}")), None))?;
        }
    }

    if let Ok(current) = app_key.get_value::<String, _>("CREDUI_ALLOW_BROKER") {
        if current.trim() == "0" {
            app_key
                .set_value("CREDUI_ALLOW_BROKER", &"1")
                .map_err(|e| CustomResult::error(Some(format!("迁移 CREDUI_ALLOW_BROKER 失败: {e}")), None))?;
        }
    }

    if !animation_frames_value.is_empty() {
        app_key
            .set_value("ANIMATION_FRAMES_PATH", &animation_frames_value)
            .map_err(|e| CustomResult::error(Some(format!("写 ANIMATION_FRAMES_PATH 失败: {e}")), None))?;
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

    // 3. 删除注册表：CP 列表项（磁贴来源）、CLSID、应用设置键
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let _ = hklm.delete_subkey_all(format!(r"{}\{}", CP_REG_PATH, CP_GUID));
    let _ = hklm.delete_subkey_all(r"SOFTWARE\facewinunlock-tauri");
    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
    let _ = hkcr.delete_subkey_all(format!(r"{}\{}", CLSID_ROOT, CP_GUID));

    // 4. 删除 System32 文件（主 DLL + 已废弃的 UIA-Helper），best-effort 不因占用而中断
    for f in [DLL_NAME, "FaceWinUnlock-UIA-Helper.exe"] {
        let p = Path::new(SYSTEM32).join(f);
        if p.exists() {
            let _ = fs::remove_file(&p);
        }
    }

    // 5. 删除 WebView2 缓存（%ProgramData%\facewinunlock-tauri）
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

/// 从 pin_store 数据库自动解密存储的 Windows Hello PIN
fn try_load_pin_from_db() -> Option<String> {
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPT_INTEGER_BLOB,
        CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
    };

    let db_path = ROOT_DIR.join("database.db");
    let conn = rusqlite::Connection::open(&db_path).ok()?;

    let mut stmt = conn
        .prepare("SELECT pin_blob, pin_entropy FROM pin_store WHERE enabled = 1 LIMIT 1")
        .ok()?;

    let (blob_b64, entropy_b64): (String, String) = stmt
        .query_row([], |row| Ok((row.get(0)?, row.get(1)?)))
        .ok()?;

    use base64::Engine;
    let blob = base64::engine::general_purpose::STANDARD.decode(&blob_b64).ok()?;
    let entropy = base64::engine::general_purpose::STANDARD.decode(&entropy_b64).ok()?;

    let data_in = CRYPT_INTEGER_BLOB { cbData: blob.len() as u32, pbData: blob.as_ptr() as _ };
    let ent = CRYPT_INTEGER_BLOB { cbData: entropy.len() as u32, pbData: entropy.as_ptr() as _ };
    let mut data_out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };

    unsafe {
        let r = CryptUnprotectData(
            &data_in, None, Some(&ent as *const _), None, None,
            CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
            &mut data_out,
        );
        if r.is_err() || data_out.pbData.is_null() { return None; }
        let pin = String::from_utf8(std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec()).ok()?;
        let _ = windows::Win32::Foundation::LocalFree(Some(
            windows::Win32::Foundation::HLOCAL(data_out.pbData as *mut std::ffi::c_void)
        ));
        Some(pin)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Passkey 密钥自动提取（通过 SYSTEM 计划任务运行 ngc_crack.exe）
// ──────────────────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn extract_passkey_keys(pin: Option<String>) -> Result<CustomResult, CustomResult> {

    // 1. 确认管理员权限
    if !is_elevated() {
        return Err(CustomResult::error(Some("需要管理员权限才能提取 passkey 密钥".to_string()), None));
    }

    // 2. 获取 PIN：优先用传入的，为空则从 pin_store 数据库自动解密
    let pin = match pin.filter(|p| !p.is_empty()) {
        Some(p) => p,
        None => match try_load_pin_from_db() {
            Some(p) => {
                log::info!("extract_passkey_keys: 从 pin_store 自动加载 PIN");
                p
            }
            None => return Err(CustomResult::error(
                Some("未提供 PIN 且数据库中没有存储的 PIN，请先在设置页预存 Windows Hello PIN".to_string()),
                None,
            )),
        },
    };

    // 3. 获取当前用户 SID
    let sid = match get_current_sid() {
        Ok(s) => s,
        Err(e) => return Err(CustomResult::error(Some(format!("获取 SID 失败: {e}")), None)),
    };

    // 4. 找到 ngc_crack.exe（安装目录下）
    let ngc_crack = ROOT_DIR.join("ngc_crack.exe");
    if !ngc_crack.exists() {
        return Err(CustomResult::error(
            Some(format!("未找到 ngc_crack.exe: {}", ngc_crack.display())),
            None,
        ));
    }

    let out_dir = r"C:\FaceWinUnlock\captured_keys";
    if let Err(e) = fs::create_dir_all(out_dir) {
        return Err(CustomResult::error(
            Some(format!("无法创建输出目录 {out_dir}: {e}")),
            None,
        ));
    }

    let task_name = "FaceWinUnlockNgcCrack";
    let ngc_exe = ngc_crack.to_string_lossy().to_string();

    // 4. 通过 SYSTEM 计划任务运行 ngc_crack
    log::info!("创建 SYSTEM 计划任务: {} --sid {} <PIN>", ngc_exe, sid);

    let create_args = [
        "/Create", "/TN", task_name,
        "/TR", &format!("\"{}\" --sid \"{}\" \"{}\"", ngc_exe, sid, pin),
        "/SC", "ONCE", "/ST", "23:59",
        "/RU", "SYSTEM", "/F",
    ];
    let _ = run_hidden("schtasks", &create_args);

    // 5. 立即运行
    let run_args = ["/Run", "/TN", task_name];
    let _ = run_hidden("schtasks", &run_args);

    // 6. 轮询等待完成（最多 2 分钟）
    let max_wait = 120;
    let mut waited = 0;
    let mut found_keys = false;

    while waited < max_wait {
        std::thread::sleep(std::time::Duration::from_secs(2));
        waited += 2;

        // 检查是否有生成的 .bin 文件
        if let Ok(entries) = fs::read_dir(out_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with("_18_no_entropy.bin") && entry.path().metadata().map(|m| m.len() > 0).unwrap_or(false) {
                    found_keys = true;
                    break;
                }
            }
        }
        if found_keys { break; }

        // 检查任务状态
        let query = run_hidden("schtasks", &["/Query", "/TN", task_name]).ok();
        let running = query.map(|o| String::from_utf8_lossy(&o.stdout).contains("Running")).unwrap_or(false);
        if !running && waited > 10 && !found_keys {
            break; // 任务已结束
        }
    }

    // 7. 删除计划任务
    let _ = run_hidden("schtasks", &["/Delete", "/TN", task_name, "/F"]);

    // 8. 生成 passkey_keys.json
    if found_keys {
        match generate_passkey_keys_json(out_dir) {
            Ok(json_path) => {
                log::info!("passkey_keys.json 已生成: {}", json_path.display());
                Ok(CustomResult::success(
                    Some(format!("密钥提取成功！配置文件: {}", json_path.display()).into()),
                    None,
                ))
            }
            Err(e) => Err(CustomResult::error(
                Some(format!("密钥提取成功，但生成配置文件失败: {e}")), None,
            )),
        }
    } else {
        Err(CustomResult::error(
            Some(format!("密钥提取失败：超时未生成密钥文件。请确认 PIN 正确且已注册过 passkey。输出目录: {out_dir}")), None,
        ))
    }
}

/// 获取当前用户 SID（复用 pin_commands 的可靠实现）
fn get_current_sid() -> Result<String, String> {
    let username = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".to_string());
    crate::modules::pin_commands::get_user_sid(username)
}

/// 从 ngc_crack 输出的映射文件生成 passkey_keys.json
/// ngc_crack 现在会在 OUT_DIR 写入 passkey_keys.json（从 7.dat CBOR 解析的真实凭据 ID）
fn generate_passkey_keys_json(out_dir: &str) -> Result<PathBuf, String> {
    // 优先使用 ngc_crack 生成的映射文件
    let mapping_file = Path::new(out_dir).join("passkey_keys.json");
    if mapping_file.exists() {
        let mapping = fs::read_to_string(&mapping_file)
            .map_err(|e| format!("读取映射文件: {e}"))?;
        // 验证是有效 JSON
        let _: serde_json::Value = serde_json::from_str(&mapping)
            .map_err(|e| format!("映射文件 JSON 无效: {e}"))?;
        let json_path = ROOT_DIR.join("passkey_keys.json");
        fs::write(&json_path, mapping.as_bytes())
            .map_err(|e| format!("写入: {e}"))?;
        return Ok(json_path);
    }

    // 回退：手动扫描 .bin 文件
    let mut entries: Vec<serde_json::Value> = Vec::new();
    if let Ok(dir) = fs::read_dir(out_dir) {
        for entry in dir.flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            if fname.ends_with("_18_no_entropy.bin") && entry.path().metadata().map(|m| m.len() == 32).unwrap_or(false) {
                entries.push(serde_json::json!({
                    "credential_id": "",
                    "rp_id": "",
                    "key_file": entry.path().to_string_lossy().to_string(),
                    "_comment": "请编辑填写实际的 credential_id 和 rp_id"
                }));
            }
        }
    }
    if entries.is_empty() {
        return Err("未找到有效的密钥文件".into());
    }
    let json_path = ROOT_DIR.join("passkey_keys.json");
    let json_str = serde_json::to_string_pretty(&entries)
        .map_err(|e| format!("序列化: {e}"))?;
    fs::write(&json_path, json_str.as_bytes())
        .map_err(|e| format!("写入: {e}"))?;
    Ok(json_path)
}
