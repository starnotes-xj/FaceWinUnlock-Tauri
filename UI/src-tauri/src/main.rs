// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use std::{env, fs, os::windows::ffi::OsStrExt, path::PathBuf};
use tauri_plugin_log::log::{info, warn};
use windows::{
    core::{w, PCWSTR},
    Win32::{
        Foundation::{LocalFree, WIN32_ERROR},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
                SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        },
    },
};

// 设置目录权限，给所有用户完全控制权
fn set_dir_permissions(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        let mut security_descriptor = PSECURITY_DESCRIPTOR::default();
        // 将字符串格式 安全描述符 转换为有效的功能安全描述符
        // 文档：https://learn.microsoft.com/zh-cn/windows/win32/api/sddl/nf-sddl-convertstringsecuritydescriptortosecuritydescriptorw
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            w!("D:(A;OICI;FA;;;WD)"), // 安全描述符的字符串
            SDDL_REVISION_1,          // 固定值
            &mut security_descriptor, // 接收的变量
            None,                     // 安全描述符大小，咱们不需要这个
        )
        .map_err(|e| format!("安全描述符转换失败：{}", e))?;

        // 提取DACL
        let mut dacl_present: windows::Win32::Foundation::BOOL =
            windows::Win32::Foundation::BOOL::from(false);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut dacl_defaulted: windows::Win32::Foundation::BOOL =
            windows::Win32::Foundation::BOOL::from(false);

        GetSecurityDescriptorDacl(
            security_descriptor, // DACL指针
            &mut dacl_present,   // 指向是否存在DACL的指针
            &mut dacl,           // 接收ACL
            &mut dacl_defaulted,
        )
        .map_err(|e| format!("提取DACL失败：{}", e))?;

        if !dacl_present.as_bool() || dacl.is_null() {
            // 释放内存
            LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                security_descriptor.0,
            )));
            return Err("安全描述符中未找到有效DACL".into());
        }

        // 将路径转换为Windows宽字符
        let path_wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let path_pcwstr = PCWSTR(path_wide.as_ptr());

        // 在指定对象的 安全描述符 中设置指定的安全信息
        let set_security_result = SetNamedSecurityInfoW(
            path_pcwstr,
            SE_FILE_OBJECT, // 目录
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl), // ACL
            None,
        );

        LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            security_descriptor.0,
        )));

        if set_security_result != WIN32_ERROR(0) {
            return Err(format!(
                "设置目录权限失败，错误码: {} (0x{:08X})，说明: {}",
                set_security_result.0,
                set_security_result.0,
                match set_security_result.0 {
                    5 => "拒绝访问（请确保程序以管理员权限运行）",
                    87 => "参数错误",
                    123 => "文件名、目录名或卷标语法不正确",
                    _ => "未知错误",
                }
            )
            .into());
        }
    }
    info!("成功设置 {} 的权限（所有用户可读写）", path.display());
    Ok(())
}

fn main() {
    // 设置 WebView2 数据文件夹的环境变量
    // 代码来源：[@Xiao-yu233](https://github.com/Xiao-yu233)
    let exe_dir = match env::current_exe() {
        Ok(exe_path) => exe_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".")), // 如果获取失败，使用当前工作目录
        Err(_) => PathBuf::from("."), // 如果获取可执行文件路径失败，使用当前工作目录
    };

    // 构建默认的 cache 文件夹路径（运行目录下的 cache 文件夹）
    let default_cache_dir = exe_dir.join("cache");

    // 尝试创建 cache 文件夹
    let webview_data_dir = match fs::create_dir_all(&default_cache_dir) {
        // 创建成功，使用当前目录下的 cache 文件夹
        Ok(_) => {
            if let Err(e) = set_dir_permissions(&default_cache_dir) {
                warn!(
                    "设置cache目录权限失败: {}, 可能导致WebView2访问异常: {}",
                    e,
                    default_cache_dir.display()
                );
            }
            default_cache_dir
        }

        // 创建失败，回退到 ProgramData 路径
        Err(e) => {
            warn!("创建默认 cache 目录失败: {}, 将使用 ProgramData 路径", e);
            let app_data =
                env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
            let fallback_dir = format!("{}\\facewinunlock-tauri", app_data);

            // 确保回退目录存在
            let _ = fs::create_dir_all(&fallback_dir);
            PathBuf::from(fallback_dir)
        }
    };

    std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", webview_data_dir);

    // OpenCL kernel tuning 缓存目录（issue #3）：不设此目录，OpenCV 的 ocl4dnn 每次 forward 都会
    // 对卷积层重新做 OpenCL kernel 编译 + auto-tuning —— GPU(OpenCL/FP16) 后端首次推理极慢
    // 且每次重复（录入预览/一致性检查黑屏卡顿）。指向持久可写目录后只首次慢、后续从缓存秒加载。
    // 必须在加载 OpenCV 模型前设置。UI 以用户身份运行，用 LOCALAPPDATA（用户可写且持久）。
    {
        let ocl_cache = env::var("LOCALAPPDATA")
            .map(|p| PathBuf::from(p).join("facewinunlock-tauri").join("ocl_cache"))
            .unwrap_or_else(|_| exe_dir.join("cache").join("ocl_cache"));
        if fs::create_dir_all(&ocl_cache).is_ok() {
            std::env::set_var("OPENCV_OCL4DNN_CONFIG_PATH", &ocl_cache);
        }
    }

    // MSMF 摄像头打开慢（issue #3）：同 Unlock 服务，关掉 MSMF 硬件帧变换让摄像头打开恢复速度，
    // 修复面容管理里"抓拍摄像头启动比 0.3.5 慢很多"。必须在打开摄像头前设置。
    std::env::set_var("OPENCV_VIDEOIO_MSMF_ENABLE_HW_TRANSFORMS", "0");

    facewinunlock_tauri_lib::run()
}
