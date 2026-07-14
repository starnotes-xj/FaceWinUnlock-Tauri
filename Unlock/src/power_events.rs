use std::{
    ffi::c_void,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};

use windows::Win32::{
    Foundation::{ERROR_INVALID_PARAMETER, ERROR_SUCCESS, HANDLE},
    System::Power::{
        PowerRegisterSuspendResumeNotification, PowerSettingRegisterNotification,
        PowerSettingUnregisterNotification, PowerUnregisterSuspendResumeNotification,
        DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS, HPOWERNOTIFY, POWERBROADCAST_SETTING,
    },
    System::SystemServices::{
        GUID_CONSOLE_DISPLAY_STATE, PowerMonitorOn,
    },
    UI::WindowsAndMessaging::{
        DEVICE_NOTIFY_CALLBACK, PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMECRITICAL,
        PBT_APMRESUMESUSPEND, PBT_APMSUSPEND,
    },
};

#[derive(Default)]
pub struct PowerLifecycle {
    suspended: AtomicBool,
    display_inactive: AtomicBool,
    camera_blocked: AtomicBool,
    generation: AtomicU64,
}

impl PowerLifecycle {
    pub fn is_suspended(&self) -> bool {
        self.suspended.load(Ordering::SeqCst)
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    pub fn is_display_inactive(&self) -> bool {
        self.display_inactive.load(Ordering::SeqCst)
    }

    pub fn is_camera_blocked(&self) -> bool {
        self.camera_blocked.load(Ordering::SeqCst)
    }

    fn refresh_camera_blocked(&self) {
        let blocked = self.suspended.load(Ordering::SeqCst)
            || self.display_inactive.load(Ordering::SeqCst);
        if self.camera_blocked.swap(blocked, Ordering::SeqCst) != blocked {
            self.generation.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub fn inhibit_camera(&self) {
        self.suspended.store(true, Ordering::SeqCst);
        self.refresh_camera_blocked();
    }

    fn apply_event(&self, event_type: u32) {
        match event_type {
            PBT_APMSUSPEND => {
                self.suspended.store(true, Ordering::SeqCst);
                self.refresh_camera_blocked();
            }
            PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMECRITICAL | PBT_APMRESUMESUSPEND => {
                self.suspended.store(false, Ordering::SeqCst);
                self.refresh_camera_blocked();
            }
            _ => {}
        }
    }

    fn apply_display_state(&self, display_state: u32) {
        self.display_inactive
            .store(display_state != PowerMonitorOn.0 as u32, Ordering::SeqCst);
        self.refresh_camera_blocked();
    }
}

unsafe extern "system" fn power_callback(
    context: *const c_void,
    event_type: u32,
    setting: *const c_void,
) -> u32 {
    if let Some(lifecycle) = (context as *const PowerLifecycle).as_ref() {
        if let Some(power_setting) = (setting as *const POWERBROADCAST_SETTING).as_ref() {
            if power_setting.PowerSetting == GUID_CONSOLE_DISPLAY_STATE {
                if power_setting.DataLength != std::mem::size_of::<u32>() as u32 {
                    return ERROR_INVALID_PARAMETER.0;
                }
                let display_state = std::ptr::read_unaligned(power_setting.Data.as_ptr().cast());
                lifecycle.apply_display_state(display_state);
                return ERROR_SUCCESS.0;
            }
        }
        lifecycle.apply_event(event_type);
    }
    ERROR_SUCCESS.0
}

pub struct SuspendResumeRegistration {
    suspend_handle: HPOWERNOTIFY,
    display_handle: HPOWERNOTIFY,
    _parameters: Box<DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS>,
    _lifecycle: Arc<PowerLifecycle>,
}

impl Drop for SuspendResumeRegistration {
    fn drop(&mut self) {
        unsafe {
            let _ = PowerSettingUnregisterNotification(self.display_handle);
            let _ = PowerUnregisterSuspendResumeNotification(self.suspend_handle);
        }
    }
}

pub fn register(lifecycle: Arc<PowerLifecycle>) -> Result<SuspendResumeRegistration, String> {
    let mut parameters = Box::new(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
        Callback: Some(power_callback),
        Context: Arc::as_ptr(&lifecycle) as *mut c_void,
    });
    let recipient = HANDLE((&mut *parameters as *mut DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS).cast());
    let mut raw_suspend_handle = std::ptr::null_mut();
    let suspend_status = unsafe {
        PowerRegisterSuspendResumeNotification(
            DEVICE_NOTIFY_CALLBACK,
            recipient,
            &mut raw_suspend_handle,
        )
    };
    if suspend_status != ERROR_SUCCESS {
        return Err(format!(
            "PowerRegisterSuspendResumeNotification failed: {}",
            suspend_status.0
        ));
    }

    let suspend_handle = HPOWERNOTIFY(raw_suspend_handle as isize);
    let mut raw_display_handle = std::ptr::null_mut();
    let display_status = unsafe {
        PowerSettingRegisterNotification(
            &GUID_CONSOLE_DISPLAY_STATE,
            DEVICE_NOTIFY_CALLBACK,
            recipient,
            &mut raw_display_handle,
        )
    };
    if display_status != ERROR_SUCCESS {
        unsafe {
            let _ = PowerUnregisterSuspendResumeNotification(suspend_handle);
        }
        return Err(format!(
            "PowerSettingRegisterNotification(GUID_CONSOLE_DISPLAY_STATE) failed: {}",
            display_status.0
        ));
    }

    Ok(SuspendResumeRegistration {
        suspend_handle,
        display_handle: HPOWERNOTIFY(raw_display_handle as isize),
        _parameters: parameters,
        _lifecycle: lifecycle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct DisplaySetting {
        power_setting: windows_core::GUID,
        data_length: u32,
        data: u32,
    }

    #[test]
    fn suspend_and_resume_advance_generation() {
        let lifecycle = PowerLifecycle::default();
        assert!(!lifecycle.is_suspended());
        assert_eq!(lifecycle.generation(), 0);

        lifecycle.apply_event(PBT_APMSUSPEND);
        assert!(lifecycle.is_suspended());
        assert_eq!(lifecycle.generation(), 1);

        lifecycle.apply_event(PBT_APMRESUMEAUTOMATIC);
        assert!(!lifecycle.is_suspended());
        assert_eq!(lifecycle.generation(), 2);

        lifecycle.apply_event(PBT_APMRESUMESUSPEND);
        assert_eq!(lifecycle.generation(), 2);
    }

    #[test]
    fn display_off_blocks_camera_without_marking_system_suspended() {
        let lifecycle = PowerLifecycle::default();
        lifecycle.apply_display_state(0);
        assert!(!lifecycle.is_suspended());
        assert!(lifecycle.is_display_inactive());
        assert!(lifecycle.is_camera_blocked());
        assert_eq!(lifecycle.generation(), 1);

        lifecycle.apply_display_state(PowerMonitorOn.0 as u32);
        assert!(!lifecycle.is_display_inactive());
        assert!(!lifecycle.is_camera_blocked());
        assert_eq!(lifecycle.generation(), 2);
    }

    #[test]
    fn display_on_does_not_override_a_real_suspend() {
        let lifecycle = PowerLifecycle::default();
        lifecycle.apply_event(PBT_APMSUSPEND);
        lifecycle.apply_display_state(PowerMonitorOn.0 as u32);
        assert!(lifecycle.is_camera_blocked());
        assert_eq!(lifecycle.generation(), 1);

        lifecycle.apply_event(PBT_APMRESUMEAUTOMATIC);
        assert!(!lifecycle.is_camera_blocked());
        assert_eq!(lifecycle.generation(), 2);
    }

    #[test]
    fn callback_parses_console_display_notifications() {
        let lifecycle = PowerLifecycle::default();
        let off = DisplaySetting {
            power_setting: GUID_CONSOLE_DISPLAY_STATE,
            data_length: std::mem::size_of::<u32>() as u32,
            data: 0,
        };
        let status = unsafe {
            power_callback(
                &lifecycle as *const PowerLifecycle as *const c_void,
                0,
                &off as *const DisplaySetting as *const c_void,
            )
        };
        assert_eq!(status, ERROR_SUCCESS.0);
        assert!(lifecycle.is_camera_blocked());

        let invalid = DisplaySetting {
            data_length: 1,
            ..off
        };
        let status = unsafe {
            power_callback(
                &lifecycle as *const PowerLifecycle as *const c_void,
                0,
                &invalid as *const DisplaySetting as *const c_void,
            )
        };
        assert_eq!(status, ERROR_INVALID_PARAMETER.0);
    }

    #[test]
    fn unrelated_power_event_does_not_change_state() {
        let lifecycle = PowerLifecycle::default();
        lifecycle.apply_event(0xFFFF_FFFF);
        assert!(!lifecycle.is_suspended());
        assert_eq!(lifecycle.generation(), 0);
    }

    #[test]
    fn registration_failure_can_inhibit_all_camera_paths() {
        let lifecycle = PowerLifecycle::default();
        lifecycle.inhibit_camera();
        assert!(lifecycle.is_suspended());
        assert_eq!(lifecycle.generation(), 1);

        lifecycle.inhibit_camera();
        assert_eq!(lifecycle.generation(), 1);
    }

    #[test]
    fn callback_registration_succeeds_on_supported_windows() {
        let lifecycle = Arc::new(PowerLifecycle::default());
        let registration = register(lifecycle).expect("power callback registration should succeed");
        drop(registration);
    }
}
