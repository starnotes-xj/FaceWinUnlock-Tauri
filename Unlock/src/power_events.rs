use std::{
    ffi::c_void,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
        Arc,
    },
};

use windows::Win32::{
    Foundation::{ERROR_SUCCESS, HANDLE},
    System::Power::{
        PowerRegisterSuspendResumeNotification, PowerUnregisterSuspendResumeNotification,
        DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS, HPOWERNOTIFY,
    },
    UI::WindowsAndMessaging::{
        DEVICE_NOTIFY_CALLBACK, PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMECRITICAL,
        PBT_APMRESUMESUSPEND, PBT_APMSUSPEND,
    },
};

#[derive(Default)]
pub struct PowerLifecycle {
    suspended: AtomicBool,
    generation: AtomicU64,
    last_event: AtomicU8,
}

impl PowerLifecycle {
    pub fn is_suspended(&self) -> bool {
        self.suspended.load(Ordering::SeqCst)
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    pub fn inhibit_camera(&self) {
        self.suspended.store(true, Ordering::SeqCst);
        if self.last_event.swap(1, Ordering::SeqCst) != 1 {
            self.generation.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn apply_event(&self, event_type: u32) {
        match event_type {
            PBT_APMSUSPEND => {
                self.suspended.store(true, Ordering::SeqCst);
                if self.last_event.swap(1, Ordering::SeqCst) != 1 {
                    self.generation.fetch_add(1, Ordering::SeqCst);
                }
            }
            PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMECRITICAL | PBT_APMRESUMESUSPEND => {
                self.suspended.store(false, Ordering::SeqCst);
                if self.last_event.swap(2, Ordering::SeqCst) != 2 {
                    self.generation.fetch_add(1, Ordering::SeqCst);
                }
            }
            _ => {}
        }
    }
}

unsafe extern "system" fn power_callback(
    context: *const c_void,
    event_type: u32,
    _setting: *const c_void,
) -> u32 {
    if let Some(lifecycle) = (context as *const PowerLifecycle).as_ref() {
        lifecycle.apply_event(event_type);
    }
    ERROR_SUCCESS.0
}

pub struct SuspendResumeRegistration {
    handle: HPOWERNOTIFY,
    _parameters: Box<DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS>,
    _lifecycle: Arc<PowerLifecycle>,
}

impl Drop for SuspendResumeRegistration {
    fn drop(&mut self) {
        unsafe {
            let _ = PowerUnregisterSuspendResumeNotification(self.handle);
        }
    }
}

pub fn register(lifecycle: Arc<PowerLifecycle>) -> Result<SuspendResumeRegistration, String> {
    let mut parameters = Box::new(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
        Callback: Some(power_callback),
        Context: Arc::as_ptr(&lifecycle) as *mut c_void,
    });
    let recipient = HANDLE((&mut *parameters as *mut DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS).cast());
    let mut raw_handle = std::ptr::null_mut();
    let status = unsafe {
        PowerRegisterSuspendResumeNotification(DEVICE_NOTIFY_CALLBACK, recipient, &mut raw_handle)
    };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "PowerRegisterSuspendResumeNotification failed: {}",
            status.0
        ));
    }

    Ok(SuspendResumeRegistration {
        handle: HPOWERNOTIFY(raw_handle as isize),
        _parameters: parameters,
        _lifecycle: lifecycle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
