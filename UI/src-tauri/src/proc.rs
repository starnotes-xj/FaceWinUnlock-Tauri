use std::sync::OnceLock;

use tauri::{AppHandle, Emitter};
use tauri_plugin_log::log::error;
use windows::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, WPARAM},
    UI::{
        Shell::DefSubclassProc,
        WindowsAndMessaging::{WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK, WTS_SESSION_UNLOCK},
    },
};

use crate::utils::api::stop_camera;

static APP_HANDLE: OnceLock<AppHandle> = OnceLock::new();

pub fn register_app_handle(app_handle: AppHandle) {
    let _ = APP_HANDLE.set(app_handle);
}

// windows回调
pub unsafe extern "system" fn wnd_proc_subclass(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    if msg == WM_WTSSESSION_CHANGE {
        let event_type = wparam.0 as u32;
        let _session_id = lparam.0 as u32;

        match event_type {
            WTS_SESSION_LOCK => {
                // 屏幕锁屏，关闭摄像头，因为不确定用户是否开启了摄像头
                if let Err(e) = stop_camera() {
                    error!("关闭摄像头失败: {}", e.to_string());
                }
            }
            WTS_SESSION_UNLOCK => {
                if let Some(app_handle) = APP_HANDLE.get() {
                    if let Err(e) = app_handle.emit("session-unlocked", ()) {
                        error!("发送会话解锁事件失败: {}", e);
                    }
                }
            }
            _ => {}
        }
    }
    DefSubclassProc(hwnd, msg, wparam, lparam)
}
