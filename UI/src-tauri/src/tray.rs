use std::sync::{Arc};
use std::thread;
use std::time::Duration;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, Wry,
};
use tauri_plugin_log::log::{error, info, warn};
use windows::Win32::{
    Foundation::HWND,
    UI::Shell::{SHAppBarMessage, ABM_GETTASKBARPOS, APPBARDATA},
};

use crate::TRAY_IS_READY;
use crate::{utils::api::close_app, GLOBAL_TRAY};

/// 检测 Windows 托盘（任务栏）服务是否就绪
fn is_tray_service_ready() -> bool {
    unsafe {
        // 通过 SHAppBarMessage 获取任务栏位置，判断托盘服务是否加载
        let mut appbar_data = APPBARDATA {
            cbSize: std::mem::size_of::<APPBARDATA>() as u32,
            hWnd: HWND::default(),
            uCallbackMessage: 0,
            uEdge: 0,
            rc: Default::default(),
            lParam: windows::Win32::Foundation::LPARAM(0),
        };
        // ABM_GETTASKBARPOS 成功返回非0，说明任务栏就绪
        SHAppBarMessage(ABM_GETTASKBARPOS, &mut appbar_data) != 0
    }
}

/// 尝试创建托盘
fn try_create_tray(app: &AppHandle<Wry>) -> Result<Arc<TrayIcon<Wry>>, Box<dyn std::error::Error>> {
    let menu = create_tray_menu(app)?;
    let tray = Arc::new(
        TrayIconBuilder::new()
            .icon(app.default_window_icon().unwrap().clone())
            .menu(&menu)
            .show_menu_on_left_click(false)
            .tooltip("facewinunlock-tauri")
            .build(app)?,
    );

    // 绑定托盘事件
    let window = app.get_webview_window("main").unwrap().clone();
    let tray_clone = tray.clone();
    
    tray.on_menu_event(move |app, event| match event.id.as_ref() {
        "show-window" => {
            let _ = window.show();
            let _ = window.set_focus();
        }
        "quit" => {
            let _ = close_app(app.clone());
        }
        _ => {
            let _ = window.emit("menu-event", format!("unknow id {:?}", event.id().as_ref()));
        }
    });

    tray.on_tray_icon_event(move |tray, event| match event {
        TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        } => {
            let app = tray.app_handle();
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }
        _ => {}
    });

    // 标记托盘创建成功
    *TRAY_IS_READY.lock().unwrap() = true;
    *GLOBAL_TRAY.lock().unwrap() = Some(tray_clone);

    Ok(tray)
}

/// 启动托盘重试线程
fn start_tray_retry_thread(app: AppHandle<Wry>) {
    thread::spawn(move || {
        let mut retry_count = 0;
        const MAX_RETRY: u32 = 30; // 最多重试30次（约30秒）
        const RETRY_INTERVAL: u64 = 1000; // 每次重试间隔1秒

        while retry_count < MAX_RETRY {
            // 检查托盘是否已就绪，就绪则退出循环
            if *TRAY_IS_READY.lock().unwrap() {
                break;
            }

            // 检测托盘服务是否就绪，未就绪则等待
            if !is_tray_service_ready() {
                thread::sleep(Duration::from_millis(RETRY_INTERVAL));
                retry_count += 1;
                continue;
            }

            // 尝试重建托盘
            match try_create_tray(&app) {
                Ok(_) => {
                    info!("托盘重建成功（重试第{}次）", retry_count + 1);
                    break;
                }
                Err(e) => {
                    warn!("托盘重建失败（重试第{}次）：{}", retry_count + 1, e);
                    // 销毁可能存在的无效托盘
                    if let Ok(mut global_tray) = GLOBAL_TRAY.lock() {
                        *global_tray = None;
                    }
                    thread::sleep(Duration::from_millis(RETRY_INTERVAL));
                    retry_count += 1;
                }
            }
        }

        // 最终检查，仍失败则记录错误
        if !*TRAY_IS_READY.lock().unwrap() {
            error!("托盘重试{}次仍失败，可能无法显示托盘图标", MAX_RETRY);
        }
    });
}

// 创建托盘菜单
pub fn create_tray_menu(
    app: &AppHandle<Wry>,
) -> Result<Menu<Wry>, Box<dyn std::error::Error>> {
    let show_window = MenuItem::with_id(app, "show-window", "显示窗口", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;

    let menu = Menu::new(app)?;
    menu.append_items(&[&show_window, &quit])?;

    Ok(menu)
}

pub fn create_system_tray(
    app: &AppHandle<Wry>,
) -> Result<Arc<TrayIcon<Wry>>, Box<dyn std::error::Error>> {
    // 先等待托盘服务就绪
    let mut wait_count = 0;
    while !is_tray_service_ready() && wait_count < 5 {
        thread::sleep(Duration::from_secs(1));
        wait_count += 1;
    }

    // 首次尝试创建托盘
    match try_create_tray(app) {
        Ok(tray) => {
            info!("托盘首次创建成功");
            // 启动监控线程
            start_tray_monitor_thread(app.clone());
            Ok(tray)
        }
        Err(e) => {
            warn!("托盘首次创建失败：{}，启动重试线程", e);
            // 启动重试线程
            start_tray_retry_thread(app.clone());
            // 返回错误，但不终止程序
            Err(e)
        }
    }
}

/// 启动托盘监控线程
fn start_tray_monitor_thread(app: AppHandle<Wry>) {
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(5)); // 每5秒检测一次

            // 检查托盘是否有效
            let global_tray = GLOBAL_TRAY.lock().unwrap();
            let tray_exists = global_tray.is_some();
            drop(global_tray);

            // 托盘不存在且未标记就绪，触发重建
            if !tray_exists && !*TRAY_IS_READY.lock().unwrap() {
                warn!("检测到托盘消失，触发重建");
                let _ = try_create_tray(&app);
            }
        }
    });
}