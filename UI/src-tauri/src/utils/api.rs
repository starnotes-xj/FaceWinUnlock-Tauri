use std::{
    os::windows::process::CommandExt,
    process::Command,
    thread,
    time::Duration,
};

use crate::{
    utils::custom_result::CustomResult,
    OpenCVResource, APP_STATE, GLOBAL_TRAY, ROOT_DIR,
};
use tauri_plugin_log::log::info;
use opencv::{
    core::{Mat, MatTraitConst, Size},
    objdetect::{FaceDetectorYN, FaceRecognizerSF},
    prelude::NetTrait,
    videoio::{self, VideoCapture, VideoCaptureTrait, VideoCaptureTraitConst},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tauri::{AppHandle, Manager};
use windows::{
    core::PWSTR,
    Win32::{
        Foundation::HWND,
        System::{
            RemoteDesktop::WTSUnRegisterSessionNotification,
            WindowsProgramming::GetUserNameW,
        },
    },
};

use super::pipe::Client;

#[derive(Debug, Clone, Serialize)]
struct ValidCameraInfo {
    camera_name: String,
    capture_index: String,
    is_valid: bool,
}

// 定义摄像头后端类型枚举
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CameraBackend {
    Any,   // CAP_ANY
    DShow, // CAP_DSHOW
    MSMF,  // CAP_MSMF
    VFW,   // CAP_VFW
}

impl From<CameraBackend> for i32 {
    fn from(backend: CameraBackend) -> Self {
        match backend {
            CameraBackend::Any => videoio::CAP_ANY,
            CameraBackend::DShow => videoio::CAP_DSHOW,
            CameraBackend::MSMF => videoio::CAP_MSMF,
            CameraBackend::VFW => videoio::CAP_VFW,
        }
    }
}

// 获取安装根目录（database.db、faces\、logs\ 都在这里，
// 不是 Tauri resourceDir()——后者是 resources\ 子目录）
#[tauri::command]
pub fn get_install_dir() -> Result<CustomResult, CustomResult> {
    let dir = ROOT_DIR
        .to_str()
        .ok_or_else(|| CustomResult::error(Some("ROOT_DIR 不是有效 UTF-8".to_string()), None))?;
    Ok(CustomResult::success(None, Some(json!(dir))))
}

// 获取当前用户名
#[tauri::command]
pub fn get_now_username() -> Result<CustomResult, CustomResult> {
    // 因发现市面上有人在盗卖本项目，更有甚者改个软件名字，就当成自己软件在卖，多次举报无果。所以从2026年3月1日开始，本项目闭源。
    // 如果你对程序某一块功能感兴趣，可以提交 issues，我看到后会给你提供一些支持。
    unsafe {
        let mut size = 0u32;
        let _ = GetUserNameW(None, &mut size);
        if size == 0 {
            return Err(CustomResult::error(Some("获取用户名失败".to_string()), None));
        }
        let mut buf: Vec<u16> = vec![0u16; size as usize];
        match GetUserNameW(Some(PWSTR(buf.as_mut_ptr())), &mut size) {
            Ok(_) => {
                let name = String::from_utf16_lossy(&buf[..size as usize - 1]);
                Ok(CustomResult::success(
                    Some("获取用户名成功".to_string()),
                    Some(serde_json::json!({"username": name})),
                ))
            }
            Err(e) => Err(CustomResult::error(
                Some(format!("获取用户名失败: {e}")),
                None,
            )),
        }
    }
}

// 测试 WinLogon：写凭据到 block/test_creds.tmp，然后锁屏
// Unlock.exe 会在锁屏后读取此文件并通过管道推送凭据完成自动登录
#[tauri::command]
pub fn test_win_logon(user_name: String, password: String) -> Result<CustomResult, CustomResult> {
    // 创建 block 目录
    let block_dir = ROOT_DIR.join("block");
    std::fs::create_dir_all(&block_dir).map_err(|e| {
        CustomResult::error(Some(format!("创建 block 目录失败: {}", e)), None)
    })?;

    // 写入凭据 JSON
    let creds = serde_json::json!({
        "user_name": user_name,
        "user_pwd": password,
        "domain": "."
    });
    let creds_path = block_dir.join("test_creds.tmp");
    std::fs::write(&creds_path, creds.to_string()).map_err(|e| {
        CustomResult::error(Some(format!("写凭据文件失败: {}", e)), None)
    })?;

    // 锁屏
    unsafe {
        use windows::Win32::System::Shutdown::LockWorkStation;
        LockWorkStation()
            .map_err(|e| CustomResult::error(Some(format!("锁屏失败: {}", e)), None))?;
    }

    Ok(CustomResult::success(None, None))
}

// 初始化模型
#[tauri::command]
pub fn init_model() -> Result<CustomResult, CustomResult> {
    // 加载模型
    let resource_path = ROOT_DIR
        .join("resources")
        .join("face_detection_yunet_2023mar.onnx");

    // 这个不用检查文件是否存在，不存在opencv会报错
    let _ = FaceDetectorYN::create(
        resource_path.to_str().unwrap_or(""),
        "",
        Size::new(320, 320), // 初始尺寸，后面会动态更新
        0.9,
        0.3,
        5000,
        0,
        0,
    )
    .map_err(|e| CustomResult::error(Some(format!("初始化检测器模型失败: {:?}", e)), None))?;

    let resource_path = ROOT_DIR
        .join("resources")
        .join("face_recognition_sface_2021dec.onnx");
    let _ = FaceRecognizerSF::create(resource_path.to_str().unwrap_or(""), "", 0, 0)
        .map_err(|e| CustomResult::error(Some(format!("初始化识别器模型失败: {:?}", e)), None))?;

    // 加载活体检测模型
    let _ = opencv::dnn::read_net_from_onnx(ROOT_DIR.join("resources").join("face_liveness.onnx").to_str().unwrap())
            .map_err(|e| CustomResult::error(Some(format!("初始化活体检测模型失败: {:?}", e)), None))?;

    Ok(CustomResult::success(None, None))
}

// 获取windows所有摄像头
#[tauri::command]
pub fn get_camera() -> Result<CustomResult, CustomResult> {
    // 因发现市面上有人在盗卖本项目，更有甚者改个软件名字，就当成自己软件在卖，多次举报无果。所以从2026年3月1日开始，本项目闭源。
    // 如果你对程序某一块功能感兴趣，可以提交 issues，我看到后会给你提供一些支持。

    match get_windows_video_devices() {
        Ok(devices) => {
            let valid_cameras: Vec<ValidCameraInfo> = devices
                .into_iter()
                .map(|(name, index)| {
                    let is_valid = is_camera_index_valid(index).unwrap_or(false);
                    ValidCameraInfo {
                        camera_name: name,
                        capture_index: index.to_string(),
                        is_valid,
                    }
                })
                .collect();
            Ok(CustomResult::success(None, Some(json!(valid_cameras))))
        }
        Err(e) => Err(CustomResult::error(
            Some(format!("获取摄像头列表失败: {e}")),
            None,
        )),
    }
}

// 打开摄像头
#[tauri::command]
pub fn open_camera(
    backend: Option<CameraBackend>,
    camear_index: i32,
) -> Result<CustomResult, CustomResult> {
    // 按指定后端或依次尝试 MSMF → DShow → Any
    let backends_to_try: Vec<CameraBackend> = match backend {
        Some(b) => vec![b],
        None => vec![CameraBackend::MSMF, CameraBackend::DShow, CameraBackend::Any],
    };

    let mut last_err = String::from("无可用摄像头后端");
    for b in backends_to_try {
        match try_open_camera_with_backend(b, camear_index) {
            Ok(cam) => {
                let mut state = APP_STATE.lock().map_err(|e| {
                    CustomResult::error(Some(format!("获取 app 状态失败: {}", e)), None)
                })?;
                state.camera = Some(OpenCVResource { inner: cam });
                return Ok(CustomResult::success(None, None));
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }
    }

    Err(CustomResult::error(Some(last_err), None))
}

// 关闭摄像头
#[tauri::command]
pub fn stop_camera() -> Result<CustomResult, CustomResult> {
    let mut app_state = APP_STATE
        .lock()
        .map_err(|e| CustomResult::error(Some(format!("获取app状态失败 {}", e)), None))?;
    app_state.camera = None;
    Ok(CustomResult::success(None, None))
}

// 打开指定目录用资源管理器
#[tauri::command]
pub fn open_directory(path: String) -> Result<CustomResult, CustomResult> {
    let path = std::path::Path::new(&path);
    if !path.exists() {
        return Err(CustomResult::error(
            Some(format!("路径不存在 {}", path.display())),
            None,
        ));
    }

    std::process::Command::new("explorer")
        .arg(path)
        .status()
        .map_err(|e| {
            CustomResult::error(
                Some(format!(
                    "打开文件夹失败：{}<br>请手动打开文件夹：{:?}",
                    e,
                    path.to_str()
                )),
                None,
            )
        })?;

    Ok(CustomResult::success(None, None))
}

// 自启代码由 Google Gemini 3 生成
// 我写不了出来了，注册表不管用 哭**
const CREATE_NO_WINDOW: u32 = 0x08000000;
/// 通用计划任务创建函数
/// 参数说明：
/// - path: 程序绝对路径
/// - task_name: 任务名称
/// - is_server: 是否为无GUI（SYSTEM账户）模式
/// - silent: 是否附加 --silent 参数
/// - run_on_system_start: BootTrigger（true）or LogonTrigger（false），true 时强制 SYSTEM 账户
/// - run_immediately: 创建后立即运行
#[tauri::command]
pub fn add_scheduled_task(
    path: String,
    task_name: String,
    is_server: bool,
    silent: bool,
    run_on_system_start: bool,
    run_immediately: bool,
) -> Result<CustomResult, CustomResult> {
    let use_system = is_server || run_on_system_start;

    // 开机面容识别：同时使用 BootTrigger（延迟 15 秒）+ LogonTrigger（兜底）
    // BootTrigger 有延迟是因为系统启动时任务计划程序可能在驱动/服务就绪前就触发任务，
    // 导致 Unlock EXE 启动失败（OpenCV 模型加载、摄像头驱动等依赖未就绪）。
    // LogonTrigger 作为兜底：如果 BootTrigger 因故未触发，用户登录后仍可启动后台服务，
    // 配合 SessionUnlock 触发器保证后续锁屏解锁可用。
    // TimeTrigger 每1分钟周期性检查，在 Unlock.exe 静默崩溃后快速自动重启。
    // 配合 MultipleInstancesPolicy:IgnoreNew，已有实例运行时不会重复创建。
    let trigger_xml = if run_on_system_start {
        "<BootTrigger><Enabled>true</Enabled><Delay>PT15S</Delay></BootTrigger>\n    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>\n    <TimeTrigger>\n      <StartBoundary>2024-01-01T00:00:00</StartBoundary>\n      <Repetition>\n        <Interval>PT1M</Interval>\n        <StopAtDurationEnd>false</StopAtDurationEnd>\n      </Repetition>\n      <Enabled>true</Enabled>\n    </TimeTrigger>"
    } else {
        "<LogonTrigger><Enabled>true</Enabled></LogonTrigger>\n    <TimeTrigger>\n      <StartBoundary>2024-01-01T00:00:00</StartBoundary>\n      <Repetition>\n        <Interval>PT1M</Interval>\n        <StopAtDurationEnd>false</StopAtDurationEnd>\n      </Repetition>\n      <Enabled>true</Enabled>\n    </TimeTrigger>"
    };

    let principal_xml = if use_system {
        r#"<Principal id="Author">
          <UserId>S-1-5-18</UserId>
          <RunLevel>HighestAvailable</RunLevel>
        </Principal>"#
    } else {
        r#"<Principal id="Author">
          <RunLevel>HighestAvailable</RunLevel>
        </Principal>"#
    };

    let args_xml = if silent {
        "<Arguments>--silent</Arguments>"
    } else {
        ""
    };

    // 相对路径解析为绝对路径（基于 ROOT_DIR），避免 SYSTEM 账户 CWD=System32 找不到 exe
    let path_obj = std::path::Path::new(&path);
    let abs_path = if path_obj.is_absolute() {
        path_obj.to_path_buf()
    } else {
        ROOT_DIR.join(path_obj)
    };
    let abs_path_str = abs_path
        .to_str()
        .ok_or_else(|| CustomResult::error(Some("无法转换 exe 路径为 UTF-8".to_string()), None))?
        .to_string();
    let working_dir = ROOT_DIR
        .to_str()
        .unwrap_or(r"C:\Program Files\facewinunlock-tauri");

    let exe_path = quote_exe_path_with_args(&abs_path_str, None);
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    {trigger}
    <SessionStateChangeTrigger>
      <StateChange>SessionUnlock</StateChange>
    </SessionStateChangeTrigger>
  </Triggers>
  <Principals>
    {principal}
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions>
    <Exec>
      <Command>{exe}</Command>
      {args}
      <WorkingDirectory>{wd}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"#,
        trigger = trigger_xml,
        principal = principal_xml,
        exe = exe_path,
        args = args_xml,
        wd = working_dir,
    );

    // 写 XML 到临时文件
    let temp_path = std::env::temp_dir().join(format!("fwu_task_{}.xml", uuid::Uuid::new_v4()));
    // schtasks /Create /XML 需要 UTF-16 LE 编码
    let utf16: Vec<u8> = std::iter::once(0xFFu8)   // BOM
        .chain(std::iter::once(0xFEu8))
        .chain(
            xml.encode_utf16()
                .flat_map(|c| c.to_le_bytes())
        )
        .collect();
    std::fs::write(&temp_path, &utf16).map_err(|e| {
        CustomResult::error(Some(format!("写临时 XML 失败: {}", e)), None)
    })?;

    let output = Command::new("schtasks")
        .args(&[
            "/Create",
            "/TN", &task_name,
            "/XML", temp_path.to_str().unwrap_or(""),
            "/F",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| CustomResult::error(Some(format!("执行 schtasks 失败: {}", e)), None))?;

    let _ = std::fs::remove_file(&temp_path);

    if !output.status.success() {
        let err = fix_gbk_encoding(&output.stderr);
        return Err(CustomResult::error(
            Some(format!("创建计划任务失败: {}", err)),
            None,
        ));
    }

    if run_immediately {
        let _ = Command::new("schtasks")
            .args(&["/Run", "/TN", &task_name])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }

    Ok(CustomResult::success(None, None))
}

// 禁用全用户自启动
#[tauri::command]
pub fn disable_scheduled_task(task_name: String) -> Result<CustomResult, CustomResult> {
    let output = Command::new("schtasks")
        .args(&["/Delete", "/TN", &task_name, "/F"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| CustomResult::error(Some(format!("执行系统命令失败: {}", e)), None))?;

    if output.status.success() {
        Ok(CustomResult::success(None, None))
    } else {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        // 如果任务本身不存在，删除会报错，这里可以根据需要判断是否视为成功
        Err(CustomResult::error(
            Some(format!("删除计划任务失败: {}", err_msg)),
            None,
        ))
    }
}

// 检查是否已开启全用户自启动
#[tauri::command]
pub fn check_scheduled_task(task_name: String) -> Result<CustomResult, CustomResult> {
    // /Query 检查任务是否存在
    let output = Command::new("schtasks")
        .args(&["/Query", "/TN", &task_name])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| CustomResult::error(Some(format!("查询系统命令失败: {}", e)), None))?;

    // 如果状态码为 0，说明任务存在
    let is_enabled = output.status.success();

    Ok(CustomResult::success(
        None,
        Some(json!({"enable": is_enabled})),
    ))
}

#[tauri::command]
pub fn check_process_running() -> Result<CustomResult, CustomResult> {
    let client = match Client::new(r"\\.\pipe\MansonWindowsUnlockRustUnlock") {
        Ok(c) => c,
        Err(e) => {
            return Err(CustomResult::error(
                Some(format!("pipe错误: {}", e)),
                None,
            ));
        }
    };

    if let Err(e) = crate::utils::pipe::write(client.handle, String::from("hello server")) {
        return Err(CustomResult::error(
            Some(format!("向客户端写入数据失败: {:?}", e)),
            None,
        ));
    }

    Ok(CustomResult::success(None, None))
}

#[tauri::command]
pub fn delete_process_running() -> Result<CustomResult, CustomResult> {
    let client = match Client::new(r"\\.\pipe\MansonWindowsUnlockRustUnlock") {
        Ok(c) => c,
        Err(e) => {
            return Err(CustomResult::error(
                Some(format!("pipe错误: {}", e)),
                None,
            ));
        }
    };

    if let Err(e) = crate::utils::pipe::write(client.handle, String::from("exit")) {
        return Err(CustomResult::error(
            Some(format!("向客户端写入数据失败: {:?}", e)),
            None,
        ));
    }

    Ok(CustomResult::success(None, None))
}

// 检查当前服务启动状态
#[tauri::command]
pub fn check_trigger_via_xml(task_name: &str) -> Result<String, String> {
    let output = Command::new("schtasks")
        .args(&["/Query", "/TN", task_name, "/XML"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("执行系统命令失败: {}", e))?;

    if !output.status.success() {
        let err_msg = fix_gbk_encoding(&output.stderr);
        return Err(format!("查询计划任务失败: {}", err_msg));
    }

    let xml_content = decode_schtasks_xml(&output.stdout);

    if xml_content.contains("BootTrigger") {
        Ok("OnStart".to_string())
    } else if xml_content.contains("LogonTrigger") {
        Ok("OnLogon".to_string())
    } else {
        Ok("Unknown".to_string())
    }
}

// 关闭软件
#[tauri::command]
pub fn close_app(app_handle: AppHandle) -> Result<CustomResult, CustomResult> {
    let window = app_handle.get_webview_window("main").unwrap();
    let hwnd = window.hwnd().unwrap();
    unsafe {
        // 注销 WTS 通知
        let _ = WTSUnRegisterSessionNotification(HWND(hwnd.0));
    }

    // 关闭系统托盘
    let mut guard = GLOBAL_TRAY
        .lock()
        .map_err(|e| CustomResult::error(Some(format!("锁定托盘全局变量失败: {}", e)), None))?;
    if let Some(tray_any) = guard.as_mut() {
        tray_any
            .set_visible(false)
            .map_err(|e| CustomResult::error(Some(format!("隐藏托盘图标失败: {}", e)), None))?;
    }

    app_handle.exit(0);

    Ok(CustomResult::success(None, None))
}
#[tauri::command]
// 加载opencv模型，backend/target 对应 OpenCV DNN 后端 ID:
//   (0,0)=CPU  (3,1)=OpenCL  (3,2)=OpenCL_FP16  (2,9)=Intel NPU(OpenVINO)
pub fn load_opencv_model(backend: Option<i32>, target: Option<i32>) -> Result<(), String> {
    let backend_id = backend.unwrap_or(0);
    let target_id  = target.unwrap_or(0);

    let mut app_state = APP_STATE
        .lock()
        .map_err(|e| format!("获取app状态失败 {}", e))?;

    if app_state.detector.is_none() {
        let resource_path = ROOT_DIR
            .join("resources")
            .join("face_detection_yunet_2023mar.onnx");

        let detector = FaceDetectorYN::create(
            resource_path.to_str().unwrap_or(""),
            "",
            Size::new(320, 320),
            0.9,
            0.3,
            5000,
            backend_id,
            target_id,
        )
        .map_err(|e| format!("初始化检测器模型失败: {:?}", e))?;

        app_state.detector = Some(OpenCVResource { inner: detector });
    }

    if app_state.recognizer.is_none() {
        let resource_path = ROOT_DIR
            .join("resources")
            .join("face_recognition_sface_2021dec.onnx");
        let recognizer = FaceRecognizerSF::create(
            resource_path.to_str().unwrap_or(""),
            "",
            backend_id,
            target_id,
        )
        .map_err(|e| format!("初始化识别器模型失败: {:?}", e))?;

        app_state.recognizer = Some(OpenCVResource { inner: recognizer });
    }

    if app_state.liveness.is_none() {
        let resource_path = ROOT_DIR
            .join("resources")
            .join("face_liveness.onnx");
        let mut liveness = opencv::dnn::read_net_from_onnx(resource_path.to_str().unwrap_or(""))
            .map_err(|e| format!("初始化活体检测模型失败: {:?}", e))?;
        liveness
            .set_preferable_backend(backend_id)
            .map_err(|e| format!("设置推理后端失败: {:?}", e))?;
        liveness
            .set_preferable_target(target_id)
            .map_err(|e| format!("设置推理目标失败: {:?}", e))?;

        app_state.liveness = Some(OpenCVResource { inner: liveness });
    }

    Ok(())
}

#[tauri::command]
// 卸载模型
pub fn unload_model() -> Result<(), String> {
    let mut app_state = APP_STATE
        .lock()
        .map_err(|e| format!("获取app状态失败 {}", e))?;

    if app_state.detector.is_some() {
        app_state.detector = None;
    }

    if app_state.recognizer.is_some() {
        app_state.recognizer = None;
    }

    if app_state.liveness.is_some() {
        app_state.liveness = None;
    }
    Ok(())
}

#[tauri::command]
// 获取uuid v4
pub fn get_uuid_v4() -> Result<String, String> {
    let uuid = uuid::Uuid::new_v4();
    Ok(uuid.to_string())
}

#[tauri::command]
// 获取软件的缓存目录
pub fn get_cache_dir() -> Result<String, String> {
    let app_data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    let webview_data_dir = format!("{}\\facewinunlock-tauri\\EBWebView", app_data);
    Ok(webview_data_dir)
}

#[tauri::command]
// 执行计划任务
pub fn run_scheduled_task(task_name: &str) -> Result<(), String> {
    // 执行 schtasks /Run 命令
    let run_output = Command::new("schtasks")
        .args(&["/Run", "/TN", task_name])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("执行任务命令失败: {}", e))?;

    if !run_output.status.success() {
        let err_msg = fix_gbk_encoding(&run_output.stderr);
        return Err(format!("任务启动失败: {}", err_msg));
    }

    Ok(())
}

/// 处理带参数的路径，确保引号只包裹可执行文件路径，参数在外部
fn quote_exe_path_with_args(exe_path: &str, args: Option<&str>) -> String {
    // 只给可执行文件路径加引号（如果有空格），参数保持在引号外
    let quoted_exe = if exe_path.contains(' ') && !exe_path.starts_with('"') {
        format!("\"{}\"", exe_path)
    } else {
        exe_path.to_string()
    };

    // 拼接参数（如果有）
    match args {
        Some(arg) => format!("{} {}", quoted_exe, arg),
        None => quoted_exe,
    }
}

fn fix_gbk_encoding(bytes: &[u8]) -> String {
    let (s, _, _) = encoding_rs::GBK.decode(bytes);
    s.trim().to_string()
}

fn decode_schtasks_xml(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16_bytes(&bytes[2..], true);
    }

    if bytes.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16_bytes(&bytes[2..], false);
    }

    let sample_len = bytes.len().min(200);
    if sample_len >= 4 {
        let sample = &bytes[..sample_len];
        let le_zeroes = sample
            .chunks_exact(2)
            .filter(|chunk| chunk[1] == 0)
            .count();
        let be_zeroes = sample
            .chunks_exact(2)
            .filter(|chunk| chunk[0] == 0)
            .count();
        let units = sample_len / 2;

        if le_zeroes > units / 2 {
            return decode_utf16_bytes(bytes, true);
        }
        if be_zeroes > units / 2 {
            return decode_utf16_bytes(bytes, false);
        }
    }

    String::from_utf8_lossy(bytes).to_string()
}

fn decode_utf16_bytes(bytes: &[u8], little_endian: bool) -> String {
    let units = bytes.chunks_exact(2).map(|chunk| {
        if little_endian {
            u16::from_le_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], chunk[1]])
        }
    });

    std::char::decode_utf16(units)
        .map(|result| result.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect::<String>()
}

// 使用指定后端尝试打开摄像头并验证读取帧
fn try_open_camera_with_backend(
    backend: CameraBackend,
    camear_index: i32,
) -> Result<VideoCapture, Box<dyn std::error::Error>> {
    let mut cam = VideoCapture::new(camear_index, backend.into())?;

    if !cam.is_opened()? {
        return Err(format!("后端 {:?} 打开摄像头后状态为未激活", backend).into());
    }

    // 设置默认帧尺寸（虚拟摄像头如 NVIDIA Broadcast 可能输出异常分辨率 #94）
    let _ = cam.set(opencv::videoio::CAP_PROP_FRAME_WIDTH, 640.0);
    let _ = cam.set(opencv::videoio::CAP_PROP_FRAME_HEIGHT, 480.0);

    // 预热：丢弃前几帧，让虚拟摄像头初始化完成（#94）
    let mut frame = Mat::default();
    for _ in 0..10 {
        let _ = cam.read(&mut frame);
    }

    // 验证最终帧是否有效
    let read_result = cam.read(&mut frame);

    match read_result {
        Ok(_) => {
            if frame.empty() {
                return Err(format!("后端 {:?} 读取到空帧", backend).into());
            }
        }
        Err(e) => {
            return Err(format!("后端 {:?} 读取帧失败: {}", backend, e).into());
        }
    }

    Ok(cam)
}
// 枚举系统摄像头：逐索引探测，收集所有可用设备
fn get_windows_video_devices() -> windows::core::Result<Vec<(String, u32)>> {
    let mut devices = Vec::new();
    for index in 0u32..8 {
        if is_camera_index_valid(index).unwrap_or(false) {
            devices.push((format!("Camera {}", index), index));
        }
    }
    Ok(devices)
}

// 验证摄像头有效性
fn is_camera_index_valid(index: u32) -> opencv::Result<bool> {
    let mut capture = VideoCapture::new(index as i32, opencv::videoio::CAP_ANY)?;
    let is_valid = capture.is_opened()?;

    // 立即释放资源，避免占用摄像头
    if is_valid {
        capture.release()?;
    }

    Ok(is_valid)
}

/// 重新启动 Unlock 核心服务（计划任务 + 健康检查确认）
#[tauri::command]
pub fn restart_unlock_service(task_name: String) -> Result<CustomResult, CustomResult> {
    info!("正在重启 Unlock 核心服务，任务名: {}", task_name);

    // 先检查 Unlock EXE 是否已经在运行
    if check_process_running().is_ok() {
        info!("Unlock 核心服务已在运行，无需重启");
        return Ok(CustomResult::success(Some("already_running".to_string()), None));
    }

    // 执行 schtasks /Run 启动任务
    let run_output = Command::new("schtasks")
        .args(&["/Run", "/TN", &task_name])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| CustomResult::error(Some(format!("执行 schtasks 失败: {}", e)), None))?;

    if !run_output.status.success() {
        let err_msg = fix_gbk_encoding(&run_output.stderr);
        return Err(CustomResult::error(
            Some(format!("启动计划任务失败: {}", err_msg)),
            None,
        ));
    }

    // 等待 Unlock EXE 启动（最多 8 秒）
    for i in 1..=8 {
        thread::sleep(Duration::from_secs(1));
        if check_process_running().is_ok() {
            info!("Unlock 核心服务已成功重启（耗时{}秒）", i);
            return Ok(CustomResult::success(Some("restarted".to_string()), None));
        }
    }

    Err(CustomResult::error(
        Some("Unlock 核心服务启动超时，请检查计划任务配置".to_string()),
        None,
    ))
}

/// 向 Unlock EXE 的管道发送凭据（null 分隔格式）
pub fn unlock(user_name: String, password: String) -> windows::core::Result<()> {
    let creds = format!("{}\0{}\0.\0", user_name, password);
    match super::pipe::Client::new(r"\\.\pipe\MansonWindowsUnlockRustUnlock") {
        Ok(client) => {
            let _ = super::pipe::write(client.handle, creds);
        }
        Err(_) => {
            // Unlock EXE 未运行时静默失败
        }
    }
    Ok(())
}
