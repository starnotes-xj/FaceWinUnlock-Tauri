//! Face gate for the official Windows passkey provider.
//!
//! The provider owns the WebAuthn credential keys. Unlock.exe only exposes a
//! local named-pipe gate so the provider can request one face-recognition based
//! user-verification decision before it signs with its own non-exportable key.

use std::{
    sync::{Condvar, Mutex},
    time::{Duration, Instant},
};

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
            let result = state.active.as_ref().and_then(|active| {
                (active.id == request_id).then_some(active.result).flatten()
            });
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
                if state.active.as_ref().is_some_and(|active| active.id == request_id) {
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
    use super::{FaceAuthorizationGate, FaceAuthorizationResult};
    use std::{
        sync::Arc,
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn authorization_unblocks_only_the_active_request() {
        let gate = Arc::new(FaceAuthorizationGate::default());
        let waiter = gate.clone();
        let handle = thread::spawn(move || {
            waiter.request_and_wait(Duration::from_secs(1))
        });

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
    fn rejecting_pending_request_wakes_waiter() {
        let gate = Arc::new(FaceAuthorizationGate::default());
        let waiter = gate.clone();
        let started = Instant::now();
        let handle = thread::spawn(move || {
            waiter.request_and_wait(Duration::from_secs(5))
        });

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
