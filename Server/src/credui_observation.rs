//! Opt-in metadata sampling for the intent bridge's window-correlation gate.
//!
//! This is not an authorization source: HWND reuse inside one process cannot
//! be ruled out by a snapshot. No ticket, IPC request, or camera action is made.

use std::sync::atomic::{AtomicU64, Ordering};
use windows::Win32::{
    Foundation::{CloseHandle, FILETIME, HWND},
    System::{
        RemoteDesktop::ProcessIdToSessionId,
        Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    },
    UI::{
        Shell::ICredentialProviderCredentialEvents,
        WindowsAndMessaging::{
            GetAncestor, GetWindow, GetWindowThreadProcessId, IsWindow, GA_ROOTOWNER, GW_OWNER,
        },
    },
};

const MAX_OWNER_WINDOWS: usize = 8;
static NEXT_OBSERVATION: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq)]
struct WindowIdentity {
    hwnd: usize,
    thread_id: u32,
    process_id: u32,
    process_created: u64,
    session_id: u32,
}

#[derive(Debug, PartialEq, Eq)]
struct WindowSnapshot {
    owners: Vec<WindowIdentity>,
    root_owner: WindowIdentity,
}

#[derive(Debug, PartialEq, Eq)]
enum Unavailable {
    MissingWindow,
    ProcessIdentity,
    OwnerCycleOrLimit,
    ChangedWindow,
}

pub(crate) struct HostObservation {
    generation: u64,
}

fn observation_enabled(mode: Option<&str>) -> bool {
    // Even an explicit "auto" value cannot activate this experimental sampler.
    mode == Some("observe")
}

fn filetime_value(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

fn window_identity(hwnd: HWND) -> Result<WindowIdentity, Unavailable> {
    if hwnd.0.is_null() || !unsafe { IsWindow(Some(hwnd)) }.as_bool() {
        return Err(Unavailable::MissingWindow);
    }
    let mut process_id = 0;
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut process_id)) };
    if thread_id == 0 || process_id == 0 {
        return Err(Unavailable::MissingWindow);
    }

    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }
        .map_err(|_| Unavailable::ProcessIdentity)?;
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let times =
        unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) };
    unsafe {
        let _ = CloseHandle(process);
    }
    times.map_err(|_| Unavailable::ProcessIdentity)?;
    let mut session_id = 0;
    unsafe { ProcessIdToSessionId(process_id, &mut session_id) }
        .map_err(|_| Unavailable::ProcessIdentity)?;

    let mut second_process_id = 0;
    let second_thread_id = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut second_process_id)) };
    if second_process_id != process_id || second_thread_id != thread_id {
        return Err(Unavailable::ChangedWindow);
    }
    Ok(WindowIdentity {
        hwnd: hwnd.0 as usize,
        thread_id,
        process_id,
        process_created: filetime_value(created),
        session_id,
    })
}

fn snapshot_once(host: HWND) -> Result<WindowSnapshot, Unavailable> {
    let mut owners: Vec<WindowIdentity> = Vec::new();
    let mut current = host;
    while !current.0.is_null() {
        if owners.len() == MAX_OWNER_WINDOWS
            || owners.iter().any(|owner| owner.hwnd == current.0 as usize)
        {
            return Err(Unavailable::OwnerCycleOrLimit);
        }
        owners.push(window_identity(current)?);
        // GetWindow returns NULL for the normal ownerless case, and the
        // generated wrapper represents NULL as Err without a reliable way to
        // distinguish another failure. This sampler is metadata-only and never
        // treats the collapsed result as authorization evidence.
        current = unsafe { GetWindow(current, GW_OWNER) }.unwrap_or_default();
    }
    let root_owner = window_identity(unsafe { GetAncestor(host, GA_ROOTOWNER) })?;
    Ok(WindowSnapshot { owners, root_owner })
}

fn stable_snapshot(host: HWND) -> Result<WindowSnapshot, Unavailable> {
    let first = snapshot_once(host)?;
    if snapshot_once(host)? != first {
        return Err(Unavailable::ChangedWindow);
    }
    Ok(first)
}

fn log_window(generation: u64, role: &str, index: usize, window: &WindowIdentity) {
    info!(
        "CredUIHostObserve - generation={}, role={}, index={}, hwnd={:#x}, pid={}, created={}, session={}, tid={}",
        generation, role, index, window.hwnd, window.process_id,
        window.process_created, window.session_id, window.thread_id
    );
}

pub(crate) fn observe_after_advise(
    events: &ICredentialProviderCredentialEvents,
) -> Option<HostObservation> {
    let mode = crate::read_facewinunlock_registry("CREDUI_INTENT_MODE").ok();
    if !observation_enabled(mode.as_deref()) {
        return None;
    }
    let generation = NEXT_OBSERVATION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .ok()?
        .checked_add(1)?;
    // The credential's Advise has stored this official callback already. No
    // credential/provider mutex is held across this external COM call.
    let host = match unsafe { events.OnCreatingWindow() } {
        Ok(host) => host,
        Err(_) => {
            info!(
                "CredUIHostObserve - generation={}, unavailable=callback",
                generation
            );
            return None;
        }
    };
    let snapshot = match stable_snapshot(host) {
        Ok(snapshot) => snapshot,
        Err(reason) => {
            info!(
                "CredUIHostObserve - generation={}, unavailable={:?}",
                generation, reason
            );
            return None;
        }
    };
    for (index, window) in snapshot.owners.iter().enumerate() {
        log_window(generation, "host_or_owner", index, window);
    }
    log_window(generation, "root_owner", 0, &snapshot.root_owner);
    Some(HostObservation { generation })
}

impl HostObservation {
    pub(crate) fn end(self, reason: &str) {
        info!(
            "CredUIHostObserve - generation={}, end={}",
            self.generation, reason
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::w;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, WINDOW_EX_STYLE, WINDOW_STYLE,
    };

    #[test]
    fn only_observe_enables_sampling() {
        assert!(observation_enabled(Some("observe")));
        for mode in [None, Some("off"), Some("auto"), Some("OBSERVE"), Some("1")] {
            assert!(!observation_enabled(mode));
        }
    }

    #[test]
    fn null_host_is_unavailable() {
        assert_eq!(
            stable_snapshot(HWND::default()),
            Err(Unavailable::MissingWindow)
        );
    }

    #[test]
    fn creation_time_preserves_both_halves() {
        assert_eq!(
            filetime_value(FILETIME {
                dwLowDateTime: 3,
                dwHighDateTime: 2
            }),
            (2u64 << 32) | 3
        );
    }

    #[test]
    fn own_hidden_window_has_identity_and_destroyed_window_is_rejected() {
        // This creates only the test's own invisible STATIC window. It never
        // selects, enumerates, or reads an authentication dialog.
        let host = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                w!("STATIC"),
                w!(""),
                WINDOW_STYLE::default(),
                0,
                0,
                1,
                1,
                None,
                None,
                None,
                None,
            )
        }
        .unwrap();
        let snapshot = stable_snapshot(host);
        unsafe { DestroyWindow(host) }.unwrap();
        let snapshot = snapshot.unwrap();
        assert_eq!(snapshot.owners[0].hwnd, host.0 as usize);
        assert_eq!(snapshot.owners[0].process_id, std::process::id());
        assert!(snapshot.owners[0].process_created > 0);
        assert_eq!(snapshot.root_owner, snapshot.owners[0]);
        assert!(stable_snapshot(host).is_err());
    }
}
