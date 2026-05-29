use std::{
    env,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
use tauri::{tray::TrayIcon, Manager, Wry};
use windows::Win32::{
    Foundation::HWND,
    System::RemoteDesktop::{WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION},
    UI::Shell::SetWindowSubclass,
};

pub mod modules;
pub mod proc;
pub mod utils;
use modules::faces::{
    check_face_from_camera, check_face_from_img, save_face_registration, verify_face,
};
use modules::init::{
    check_admin_privileges, check_camera_status, deploy_core_components, uninstall_init,
};
use modules::options::write_to_registry;
use opencv::{
    core::Ptr,
    objdetect::{FaceDetectorYN, FaceRecognizerSF},
    videoio::VideoCapture,
};
use proc::wnd_proc_subclass;
use tauri_plugin_log::{Target, TargetKind};
use utils::api::{
    add_scheduled_task, check_process_running, check_scheduled_task, close_app,
    delete_process_running, disable_scheduled_task, get_camera, get_install_dir,
    get_now_username, init_model, load_opencv_model, open_camera, open_directory,
    restart_unlock_service, stop_camera, test_win_logon, unload_model, get_uuid_v4,
    get_cache_dir, run_scheduled_task, check_trigger_via_xml
};
mod tray;
use tray::create_system_tray;

pub struct OpenCVResource<T> {
    pub inner: T,
}
unsafe impl<T> Send for OpenCVResource<T> {}
unsafe impl<T> Sync for OpenCVResource<T> {}
// 持久存储模型
pub struct AppState {
    pub detector: Option<OpenCVResource<Ptr<FaceDetectorYN>>>,
    pub recognizer: Option<OpenCVResource<Ptr<FaceRecognizerSF>>>,
    pub liveness: Option<OpenCVResource<opencv::dnn::Net>>,
    pub camera: Option<OpenCVResource<VideoCapture>>,
}

lazy_static::lazy_static! {
    // 系统托盘
    static ref GLOBAL_TRAY: Mutex<Option<Arc<TrayIcon<Wry>>>> = Mutex::new(None);
    static ref TRAY_IS_READY: Mutex<bool> = Mutex::new(false);
    // 不在使用状态管理，因为proc获取不到
    static ref APP_STATE: Mutex<AppState> = Mutex::new(AppState {
        detector: None,
        recognizer: None,
        liveness: None,
        camera: None,
    });

    // 全局只读软件根目录
    pub static ref ROOT_DIR: &'static Path = {
        let exe_path = match env::current_exe() {
            Ok(path) => path,
            // 失败时回退到当前工作目录
            Err(_) => env::current_dir().unwrap(),
        };
        let root_dir: PathBuf = match exe_path.parent() {
            Some(parent) => parent.to_path_buf(),
            None => {
                let current_dir = env::current_dir().unwrap();
                current_dir
            }
        };
        Box::leak(Box::new(root_dir)).as_path()
    };
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // 获取软件安装目录，用于将日志放到软件安装目录下
    let log_path = ROOT_DIR.join("logs");
    let mut builder = tauri::Builder::default();

    #[cfg(desktop)]
    {
        builder = builder
            .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
                let main = app.get_webview_window("main").expect("no main window");
                if !main.is_visible().unwrap() {
                    main.show().unwrap();
                }
                main.set_focus().unwrap();
            }))
            .plugin(tauri_plugin_fs::init())
            // 对话框
            .plugin(tauri_plugin_dialog::init())
            // 注册状态管理
            // .manage(AppState {
            //     detector: RwLock::new(None),
            //     recognizer: RwLock::new(None),
            //     camera: RwLock::new(None),
            // })
            // 文件系统插件
            .plugin(tauri_plugin_opener::init())
            .plugin(tauri_plugin_sql::Builder::default().build())
            // 注册日志插件
            .plugin(
                tauri_plugin_log::Builder::new()
                    .targets([
                        Target::new(TargetKind::Stdout),
                        Target::new(TargetKind::Webview),
                        Target::new(TargetKind::Folder {
                            path: log_path,
                            file_name: Some("app".to_string()),
                        }),
                    ])
                    .timezone_strategy(tauri_plugin_log::TimezoneStrategy::UseLocal)
                    .build(),
            )
            .setup(|app| {
                let _ = create_system_tray(app.app_handle());
                let window = app.get_webview_window("main").unwrap();
                #[cfg(debug_assertions)] // 仅在调试(debug)版本中包含此代码
                {
                    window.open_devtools();
                    window.close_devtools();
                }

                #[cfg(windows)]
                {
                    let window = app.get_webview_window("main").unwrap();
                    let hwnd = window.hwnd().unwrap();
                    unsafe {
                        // 注册 WTS 通知
                        let _ =
                            WTSRegisterSessionNotification(HWND(hwnd.0), NOTIFY_FOR_THIS_SESSION);

                        // 注入子类化回调来捕获 WM_WTSSESSION_CHANGE
                        // on_window_event 收不到这个消息
                        let _ = SetWindowSubclass(HWND(hwnd.0), Some(wnd_proc_subclass), 0, 0);
                    }
                }

                let args: Vec<String> = env::args().collect();
                let is_silent = args
                    .iter()
                    .any(|arg| arg == "-s" || arg == "--silent" || arg == "--s");
                if !is_silent {
                    // 只有不是静默启动时才显示
                    window.show().unwrap();
                }
                Ok(())
            })
            .on_window_event(|window, event| {
                if window.label() == "main" {
                    match event {
                        tauri::WindowEvent::CloseRequested { api, .. } => {
                            api.prevent_close();
                            let _ = window.hide();
                        }
                        _ => {}
                    }
                }
            })
            .invoke_handler(tauri::generate_handler![
                // init 初始化模块
                check_admin_privileges,
                check_camera_status,
                deploy_core_components,
                uninstall_init,
                // 面容模块
                check_face_from_img,
                check_face_from_camera,
                verify_face,
                save_face_registration,
                // 配置模块
                write_to_registry,
                // 通用api
                get_install_dir,
                get_now_username,
                test_win_logon,
                init_model,
                open_camera,
                stop_camera,
                get_camera,
                open_directory,
                close_app,
                check_process_running,
                delete_process_running,
                load_opencv_model,
                add_scheduled_task,
                disable_scheduled_task,
                check_scheduled_task,
                unload_model,
                get_uuid_v4,
                get_cache_dir,
                run_scheduled_task,
                check_trigger_via_xml,
                restart_unlock_service
            ]);
    }
    builder
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
