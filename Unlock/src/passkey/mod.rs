//! Face gate for the official Windows passkey provider.
//!
//! The provider owns the WebAuthn credential keys. Unlock.exe only exposes a
//! local named-pipe gate so the provider can request one face-recognition based
//! user-verification decision before it signs with its own non-exportable key.

use std::{
    ffi::OsStr,
    marker::PhantomData,
    mem::size_of,
    os::windows::ffi::OsStrExt,
    rc::Rc,
    sync::{Condvar, Mutex},
    time::{Duration, Instant},
};

use windows::Win32::{
    Foundation::{
        CloseHandle, GetLastError, LocalFree, BOOL, HANDLE, HLOCAL, WAIT_ABANDONED, WAIT_FAILED,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    },
    System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject},
};
use windows_core::PCWSTR;

const ROUTE_MUTEX_NAME: &str = r"Global\FaceWinUnlockTauriBrokerRouteMutex";

/// Cross-process linearization point between FaceWinUnlock passkey authorization
/// and generic browser-credential serialization. The mutex is owned by a thread
/// only for the duration of the corresponding authorization/serialization.
pub(crate) struct RouteMutex(HANDLE);

unsafe impl Send for RouteMutex {}
unsafe impl Sync for RouteMutex {}

impl RouteMutex {
    pub(crate) fn create() -> Result<Self, String> {
        Self::create_named(ROUTE_MUTEX_NAME)
    }

    fn create_named(name: &str) -> Result<Self, String> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let sddl = wide("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100001;;;WD)");
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR::from_raw(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|error| format!("route-mutex SDDL failed: {error:?}"))?;

        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0.cast(),
            bInheritHandle: BOOL(0),
        };
        let name = wide(name);
        let mutex =
            unsafe { CreateMutexW(Some(&attributes), false, PCWSTR::from_raw(name.as_ptr())) };
        if !descriptor.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(descriptor.0)));
            }
        }
        mutex
            .map(Self)
            .map_err(|error| format!("create passkey route mutex failed: {error:?}"))
    }

    /// Serialize a passkey authorization request. A timeout fails closed so a
    /// stale/blocked broker serialization cannot hang the Passkey Provider.
    pub(crate) fn acquire_for_passkey(
        &self,
        timeout: Duration,
    ) -> Result<RouteMutexGuard<'_>, String> {
        let millis = timeout.as_millis().min(u32::MAX as u128) as u32;
        match unsafe { WaitForSingleObject(self.0, millis) } {
            WAIT_OBJECT_0 => Ok(RouteMutexGuard {
                mutex: self,
                _not_send: PhantomData,
            }),
            WAIT_ABANDONED => {
                // The previous owner died while inside an authentication route.
                // Clear the abandoned state but reject this request once.
                unsafe {
                    let _ = ReleaseMutex(self.0);
                }
                Err("passkey route mutex was abandoned".to_string())
            }
            WAIT_TIMEOUT => Err("passkey route mutex is busy".to_string()),
            WAIT_FAILED => Err(format!(
                "waiting for passkey route mutex failed: {:?}",
                unsafe { GetLastError() }
            )),
            other => Err(format!(
                "unexpected passkey route mutex wait result: {other:?}"
            )),
        }
    }
}

impl Drop for RouteMutex {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub(crate) struct RouteMutexGuard<'a> {
    mutex: &'a RouteMutex,
    _not_send: PhantomData<Rc<()>>,
}

impl Drop for RouteMutexGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.mutex.0);
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FaceAuthorizationResult {
    Authorized,
    Rejected,
    TimedOut,
}

#[derive(Debug)]
struct ActiveFaceRequest {
    id: u64,
    result: Option<bool>,
}

#[derive(Debug, Default)]
struct FaceAuthorizationState {
    next_id: u64,
    active: Option<ActiveFaceRequest>,
}

/// Serializes passkey signing requests and grants a single assertion only after
/// the face-recognition loop authorizes the matching request ID.
#[derive(Debug, Default)]
pub(crate) struct FaceAuthorizationGate {
    request_lock: Mutex<()>,
    state: Mutex<FaceAuthorizationState>,
    changed: Condvar,
}

impl FaceAuthorizationGate {
    pub(crate) fn request_and_wait(&self, timeout: Duration) -> FaceAuthorizationResult {
        let _request_guard = self.request_lock.lock().unwrap();
        let deadline = Instant::now() + timeout;

        let request_id = {
            let mut state = self.state.lock().unwrap();
            state.next_id = state.next_id.wrapping_add(1).max(1);
            let request_id = state.next_id;
            state.active = Some(ActiveFaceRequest {
                id: request_id,
                result: None,
            });
            self.changed.notify_all();
            request_id
        };

        let mut state = self.state.lock().unwrap();
        loop {
            let result = state
                .active
                .as_ref()
                .and_then(|active| (active.id == request_id).then_some(active.result).flatten());
            if let Some(authorized) = result {
                state.active = None;
                return if authorized {
                    FaceAuthorizationResult::Authorized
                } else {
                    FaceAuthorizationResult::Rejected
                };
            }

            let now = Instant::now();
            if now >= deadline {
                if state
                    .active
                    .as_ref()
                    .is_some_and(|active| active.id == request_id)
                {
                    state.active = None;
                }
                return FaceAuthorizationResult::TimedOut;
            }

            let wait = deadline.saturating_duration_since(now);
            let (next_state, _) = self.changed.wait_timeout(state, wait).unwrap();
            state = next_state;
        }
    }

    pub(crate) fn pending_request_id(&self) -> Option<u64> {
        self.state
            .lock()
            .unwrap()
            .active
            .as_ref()
            .filter(|active| active.result.is_none())
            .map(|active| active.id)
    }

    pub(crate) fn authorize(&self, request_id: u64) -> bool {
        self.complete(request_id, true)
    }

    pub(crate) fn reject(&self, request_id: u64) -> bool {
        self.complete(request_id, false)
    }

    pub(crate) fn reject_pending(&self) {
        let mut state = self.state.lock().unwrap();
        if let Some(active) = state.active.as_mut() {
            if active.result.is_none() {
                active.result = Some(false);
                self.changed.notify_all();
            }
        }
    }

    fn complete(&self, request_id: u64, authorized: bool) -> bool {
        let mut state = self.state.lock().unwrap();
        let Some(active) = state.active.as_mut() else {
            return false;
        };
        if active.id != request_id || active.result.is_some() {
            return false;
        }
        active.result = Some(authorized);
        self.changed.notify_all();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{FaceAuthorizationGate, FaceAuthorizationResult, RouteMutex};
    use std::{
        sync::Arc,
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn authorization_unblocks_only_the_active_request() {
        let gate = Arc::new(FaceAuthorizationGate::default());
        let waiter = gate.clone();
        let handle = thread::spawn(move || waiter.request_and_wait(Duration::from_secs(1)));

        let request_id = wait_for_pending(&gate);
        assert!(gate.authorize(request_id));
        assert_eq!(handle.join().unwrap(), FaceAuthorizationResult::Authorized);
        assert_eq!(gate.pending_request_id(), None);
        assert!(!gate.authorize(request_id));
    }

    #[test]
    fn timed_out_authorization_cannot_be_reused() {
        let gate = FaceAuthorizationGate::default();
        assert_eq!(
            gate.request_and_wait(Duration::from_millis(20)),
            FaceAuthorizationResult::TimedOut
        );
        assert_eq!(gate.pending_request_id(), None);
        assert!(!gate.authorize(1));
    }

    #[test]
    fn route_mutex_serializes_passkey_ownership_against_other_threads() {
        let name = format!(
            "Local\\FaceWinUnlockRouteMutexTest_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let mutex = Arc::new(RouteMutex::create_named(&name).unwrap());
        let name_wide = super::wide(&name);
        let provider_handle = unsafe {
            windows::Win32::System::Threading::OpenMutexW(
                windows::Win32::System::Threading::SYNCHRONIZATION_ACCESS_RIGHTS(0x0010_0001),
                false,
                windows_core::PCWSTR::from_raw(name_wide.as_ptr()),
            )
        }
        .unwrap();
        assert_eq!(
            unsafe { windows::Win32::System::Threading::WaitForSingleObject(provider_handle, 0) },
            windows::Win32::Foundation::WAIT_OBJECT_0
        );
        unsafe {
            let _ = windows::Win32::System::Threading::ReleaseMutex(provider_handle);
            let _ = windows::Win32::Foundation::CloseHandle(provider_handle);
        }
        let (owned_tx, owned_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let other_thread_mutex = mutex.clone();
        let owner = thread::spawn(move || {
            let _guard = other_thread_mutex
                .acquire_for_passkey(Duration::from_secs(1))
                .unwrap();
            owned_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });

        owned_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(mutex
            .acquire_for_passkey(Duration::from_millis(20))
            .is_err());
        release_tx.send(()).unwrap();
        owner.join().unwrap();
        assert!(mutex
            .acquire_for_passkey(Duration::from_millis(100))
            .is_ok());
    }

    #[test]
    fn rejecting_pending_request_wakes_waiter() {
        let gate = Arc::new(FaceAuthorizationGate::default());
        let waiter = gate.clone();
        let started = Instant::now();
        let handle = thread::spawn(move || waiter.request_and_wait(Duration::from_secs(5)));

        wait_for_pending(&gate);
        gate.reject_pending();
        assert_eq!(handle.join().unwrap(), FaceAuthorizationResult::Rejected);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    fn wait_for_pending(gate: &FaceAuthorizationGate) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(request_id) = gate.pending_request_id() {
                return request_id;
            }
            assert!(Instant::now() < deadline, "request did not become pending");
            thread::sleep(Duration::from_millis(1));
        }
    }
}
