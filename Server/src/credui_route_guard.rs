//! Cross-process arbitration for Passkey face authorization versus generic
//! browser credential serialization. Unlock owns creation and holds the mutex
//! during its Passkey face decision; the Credential Provider only tries it at
//! the final serialization boundary.

use std::{ffi::OsStr, os::windows::ffi::OsStrExt};

use windows::Win32::{
    Foundation::{
        CloseHandle, GetLastError, HANDLE, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    System::Threading::{
        OpenMutexW, ReleaseMutex, WaitForSingleObject, MUTEX_MODIFY_STATE,
        SYNCHRONIZATION_ACCESS_RIGHTS, SYNCHRONIZATION_SYNCHRONIZE,
    },
};
use windows_core::PCWSTR;

const ROUTE_MUTEX_NAME: &str = r"Global\FaceWinUnlockTauriBrokerRouteMutex";

pub struct BrokerRouteGuard(HANDLE);

pub fn try_acquire() -> Result<BrokerRouteGuard, String> {
    try_acquire_named(ROUTE_MUTEX_NAME)
}

fn try_acquire_named(mutex_name: &str) -> Result<BrokerRouteGuard, String> {
    let name = wide(mutex_name);
    let rights =
        SYNCHRONIZATION_ACCESS_RIGHTS(MUTEX_MODIFY_STATE.0 | SYNCHRONIZATION_SYNCHRONIZE.0);
    let mutex = unsafe { OpenMutexW(rights, false, PCWSTR::from_raw(name.as_ptr())) }
        .map_err(|error| format!("open route mutex failed: {error:?}"))?;

    match unsafe { WaitForSingleObject(mutex, 0) } {
        WAIT_OBJECT_0 => Ok(BrokerRouteGuard(mutex)),
        WAIT_TIMEOUT => {
            unsafe {
                let _ = CloseHandle(mutex);
            }
            Err("Passkey route is active".to_string())
        }
        WAIT_ABANDONED => {
            // An abandoned auth route must fail closed once. WaitForSingleObject
            // grants ownership even for WAIT_ABANDONED, so release it here.
            unsafe {
                let _ = ReleaseMutex(mutex);
                let _ = CloseHandle(mutex);
            }
            Err("route mutex was abandoned".to_string())
        }
        WAIT_FAILED => {
            let error = unsafe { GetLastError() };
            unsafe {
                let _ = CloseHandle(mutex);
            }
            Err(format!("route mutex wait failed: {error:?}"))
        }
        other => {
            unsafe {
                let _ = CloseHandle(mutex);
            }
            Err(format!("unexpected route mutex wait result: {other:?}"))
        }
    }
}

impl Drop for BrokerRouteGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.0);
            let _ = CloseHandle(self.0);
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::try_acquire_named;
    use std::{os::windows::ffi::OsStrExt, sync::mpsc, thread, time::Duration};
    use windows::Win32::{Foundation::CloseHandle, System::Threading::CreateMutexW};
    use windows_core::PCWSTR;

    #[test]
    fn provider_lock_never_waits_behind_an_active_passkey_owner() {
        let name = format!(
            "Local\\FaceWinUnlockProviderRouteTest_{}",
            std::process::id()
        );
        let wide_name: Vec<u16> = std::ffi::OsStr::new(&name)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let owner_mutex =
            unsafe { CreateMutexW(None, false, PCWSTR::from_raw(wide_name.as_ptr())) }.unwrap();
        let _owner_guard = try_acquire_named(&name).unwrap();

        let (tx, rx) = mpsc::channel();
        let competing_name = name.clone();
        let competing = thread::spawn(move || {
            tx.send(try_acquire_named(&competing_name).is_err())
                .unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_secs(1)).unwrap());
        competing.join().unwrap();
        drop(_owner_guard);
        assert!(try_acquire_named(&name).is_ok());
        unsafe {
            let _ = CloseHandle(owner_mutex);
        }
    }
}
