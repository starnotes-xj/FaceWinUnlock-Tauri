//! Conservative, offline CredUI intent and recognition ownership model.
//!
//! This module does not hook APIs, authenticate IPC, inspect windows, or run a
//! camera. An adapter must obtain peer identity, window lifetimes and policy
//! evidence independently; none of these facts may come from client assertions.
//! Times are milliseconds from one server-owned monotonic clock. Every mutation
//! takes `&mut self`, so an adapter must serialize cancellation and output checks.
//! No prompt text, credential, PIN or WebAuthn payload is accepted or retained.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClientCallId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RequestId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProcessInstance {
    pub pid: u32,
    pub creation_time: u64,
    pub session_id: u32,
}

/// `lifetime` is allocated by the trusted window observer, never by a client.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WindowIdentity {
    pub hwnd: u64,
    pub lifetime: u64,
    pub process: ProcessInstance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRole {
    VerifiedBrowser,
    VerifiedCredentialHost,
    VerifiedPasskeyHost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyMode {
    Off,
    Observe,
    Auto,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AutoPrerequisites {
    pub probe_transparency_verified: bool,
    pub host_association_verified: bool,
    pub privacy_evidence_verified: bool,
    pub recognition_ownership_verified: bool,
}

impl AutoPrerequisites {
    fn complete(self) -> bool {
        self.probe_transparency_verified
            && self.host_association_verified
            && self.privacy_evidence_verified
            && self.recognition_ownership_verified
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WebAuthnMonitor {
    pub ready: bool,
    pub active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyState {
    Normal,
    Private,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptPurpose {
    VerifiedDistinctPasswordFill,
    OtherPasswordOperation,
    Ambiguous,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiFlags(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderFlags(pub u32);

/// A mapping established by P0 for this browser/Windows combination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedFlagMapping {
    pub api: ApiFlags,
    pub provider: ProviderFlags,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntentEvidence {
    pub browser_image_verified: bool,
    pub purpose: PromptPurpose,
    pub retry_semantics_verified: bool,
    pub privacy: PrivacyState,
    pub api_flags: ApiFlags,
    pub auth_error: u32,
    pub passkey_signal: bool,
    pub pin_setup_signal: bool,
    pub uac_signal: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BeginCall {
    pub connection: ConnectionId,
    pub call: ClientCallId,
    pub parent: WindowIdentity,
    pub evidence: IntentEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestHandle {
    pub request: RequestId,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BeginAck {
    pub handle: RequestHandle,
    pub arm_deadline_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialInstance {
    pub connection: ConnectionId,
    pub provider_instance: u64,
    pub credential_instance: u64,
    pub generation: u64,
}

/// The fixed host comes from credential Advise + OnCreatingWindow. Adapters
/// revalidate this same anchor; changing foreground windows cannot replace it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialContext {
    pub credential: CredentialInstance,
    pub host: WindowIdentity,
    pub parent: WindowIdentity,
    pub owner_relationship_verified: bool,
    pub provider_flags: ProviderFlags,
    pub verified_flag_mapping: Option<VerifiedFlagMapping>,
    pub selected: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecognitionRoute {
    PrimaryLogon,
    GenericBroker,
    Passkey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecognitionOwner {
    pub route: RecognitionRoute,
    pub connection: ConnectionId,
    pub request: RequestId,
    pub generation: u64,
    pub session_id: u32,
}

/// Fields are private: only a successful Claim can create a ticket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ticket {
    handle: RequestHandle,
    credential: CredentialInstance,
}

impl Ticket {
    pub fn handle(self) -> RequestHandle {
        self.handle
    }

    pub fn credential(self) -> CredentialInstance {
        self.credential
    }
}

/// Permission to send a result now, not a credential or reusable authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputPermit {
    pub owner: RecognitionOwner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestState {
    Pending,
    Observed,
    Claimed,
    Recognizing,
    Completed,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevokeReason {
    ApiReturned,
    ApiCancelled,
    ApiError,
    RetryError,
    ExplicitCancel,
    Deselected,
    Unadvised,
    Ambiguous,
    ConnectionClosed,
    WindowInvalid,
    ProcessExited,
    MonitorUnavailable,
    PolicyChanged,
    Timeout,
    ProviderReused,
    ServiceRestarted,
    EvidenceLost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndStatus {
    ReturnedSuccess,
    Cancelled,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentError {
    InvalidConfiguration,
    InvalidIdentity,
    CapacityExceeded,
    CounterExhausted,
    ClockWentBackwards,
    UnknownConnection,
    ConnectionClosed,
    WrongPeerRole,
    Duplicate,
    UnknownWindow,
    WindowReused,
    UnknownRequest,
    WrongConnection,
    StaleGeneration,
    Terminal,
    NotArmed,
    AlreadyClaimed,
    Ambiguous,
    AssociationUnverified,
    FlagsUnverified,
    AutoDisabled,
    PrerequisitesMissing,
    MonitorNotReady,
    WebAuthnActive,
    IntentUnverified,
    PrivacyNotNormal,
    ExplicitVeto,
    ManualRequired,
    CredentialChanged,
    NotSelected,
    CameraBusy,
    WrongOwner,
    ResultNotReady,
}

#[derive(Clone, Copy, Debug)]
pub struct IntentLimits {
    pub arm_lease_ms: u64,
    pub recognition_lease_ms: u64,
    pub max_requests: usize,
    pub max_connections: usize,
    pub max_windows: usize,
}

impl Default for IntentLimits {
    fn default() -> Self {
        Self {
            arm_lease_ms: 1_000,
            recognition_lease_ms: 15_000,
            max_requests: 1_024,
            max_connections: 128,
            max_windows: 256,
        }
    }
}

#[derive(Clone, Copy)]
struct Peer {
    process: ProcessInstance,
    role: PeerRole,
    connected: bool,
}

#[derive(Clone, Copy)]
struct TrackedWindow {
    identity: WindowIdentity,
    alive: bool,
}

struct Request {
    handle: RequestHandle,
    begin: BeginCall,
    state: RequestState,
    deadline_ms: u64,
    context: Option<CredentialContext>,
    owner: Option<RecognitionOwner>,
    result_ready: bool,
    ended: bool,
    reason: Option<RevokeReason>,
}

impl Request {
    fn active(&self) -> bool {
        !self.ended && !matches!(self.state, RequestState::Completed | RequestState::Revoked)
    }
}

pub struct IntentBridge {
    limits: IntentLimits,
    mode: PolicyMode,
    monitor: WebAuthnMonitor,
    last_time_ms: u64,
    next_request: u64,
    next_generation: u64,
    exhausted: bool,
    peers: BTreeMap<ConnectionId, Peer>,
    windows: BTreeMap<(u32, u64), TrackedWindow>,
    calls: BTreeMap<(ConnectionId, ClientCallId), RequestId>,
    requests: BTreeMap<RequestId, Request>,
    manual_required: BTreeSet<WindowIdentity>,
    recognition_owner: Option<RecognitionOwner>,
    manual_owner_deadline_ms: Option<u64>,
}

impl IntentBridge {
    pub fn new(limits: IntentLimits) -> Result<Self, IntentError> {
        if limits.arm_lease_ms == 0
            || limits.recognition_lease_ms == 0
            || limits.max_requests == 0
            || limits.max_connections == 0
            || limits.max_windows == 0
        {
            return Err(IntentError::InvalidConfiguration);
        }
        Ok(Self {
            limits,
            mode: PolicyMode::Off,
            monitor: WebAuthnMonitor::default(),
            last_time_ms: 0,
            next_request: 0,
            next_generation: 0,
            exhausted: false,
            peers: BTreeMap::new(),
            windows: BTreeMap::new(),
            calls: BTreeMap::new(),
            requests: BTreeMap::new(),
            manual_required: BTreeSet::new(),
            recognition_owner: None,
            manual_owner_deadline_ms: None,
        })
    }

    pub fn mode(&self) -> PolicyMode {
        self.mode
    }

    pub fn current_owner(&self) -> Option<RecognitionOwner> {
        self.recognition_owner
    }

    pub fn state(&self, request: RequestId) -> Option<RequestState> {
        self.requests.get(&request).map(|r| r.state)
    }

    pub fn is_manual_required(&self, parent: WindowIdentity) -> bool {
        self.manual_required.contains(&parent)
    }

    /// Only a trusted IPC adapter may register an authenticated peer. Connection
    /// identifiers cannot be reused, even after disconnect, within this model.
    pub fn connect(
        &mut self,
        connection: ConnectionId,
        process: ProcessInstance,
        role: PeerRole,
    ) -> Result<(), IntentError> {
        if connection.0 == 0 || process.pid == 0 || process.creation_time == 0 {
            return Err(IntentError::InvalidIdentity);
        }
        if self.peers.contains_key(&connection) {
            return Err(IntentError::Duplicate);
        }
        if self.peers.len() >= self.limits.max_connections {
            return Err(IntentError::CapacityExceeded);
        }
        self.peers.insert(
            connection,
            Peer {
                process,
                role,
                connected: true,
            },
        );
        Ok(())
    }

    /// Lifecycle changes are authoritative server observations. A new lifetime
    /// cannot replace a live HWND; dead window records are pruned after the
    /// trusted observer has supplied a newer lifetime or a different HWND.
    pub fn register_window(&mut self, window: WindowIdentity) -> Result<(), IntentError> {
        if window.hwnd == 0 || window.lifetime == 0 || window.process.pid == 0 {
            return Err(IntentError::InvalidIdentity);
        }
        let key = (window.process.session_id, window.hwnd);
        if let Some(old) = self.windows.get(&key) {
            if old.alive {
                return if old.identity == window {
                    Ok(())
                } else {
                    Err(IntentError::WindowReused)
                };
            }
            if window.lifetime <= old.identity.lifetime {
                return Err(IntentError::WindowReused);
            }
        }
        let live_count = self
            .windows
            .values()
            .filter(|tracked| tracked.alive)
            .count();
        if live_count >= self.limits.max_windows {
            return Err(IntentError::CapacityExceeded);
        }
        self.windows.retain(|_, tracked| tracked.alive);
        self.windows.insert(
            key,
            TrackedWindow {
                identity: window,
                alive: true,
            },
        );
        Ok(())
    }

    pub fn set_observation_mode(&mut self, now_ms: u64) -> Result<(), IntentError> {
        self.advance(now_ms)?;
        self.revoke_auto_requests(RevokeReason::PolicyChanged, true)?;
        self.release_generic_broker_owner();
        self.mode = PolicyMode::Observe;
        Ok(())
    }

    pub fn disable(&mut self, now_ms: u64) -> Result<(), IntentError> {
        self.advance(now_ms)?;
        self.mode = PolicyMode::Off;
        self.revoke_auto_requests(RevokeReason::PolicyChanged, true)?;
        self.release_generic_broker_owner();
        Ok(())
    }

    /// Explicit activation is not persisted. Switching modes invalidates old
    /// observations, so enabling Auto cannot adopt an already open old prompt.
    pub fn enable_auto(
        &mut self,
        prerequisites: AutoPrerequisites,
        now_ms: u64,
    ) -> Result<(), IntentError> {
        self.advance(now_ms)?;
        if !prerequisites.complete() {
            return Err(IntentError::PrerequisitesMissing);
        }
        if self.exhausted {
            return Err(IntentError::CounterExhausted);
        }
        self.revoke_auto_requests(RevokeReason::PolicyChanged, true)?;
        self.release_generic_broker_owner();
        self.mode = PolicyMode::Auto;
        Ok(())
    }

    pub fn set_monitor(
        &mut self,
        monitor: WebAuthnMonitor,
        now_ms: u64,
    ) -> Result<(), IntentError> {
        self.advance(now_ms)?;
        self.monitor = monitor;
        if !monitor.ready || monitor.active {
            self.revoke_auto_requests(RevokeReason::MonitorUnavailable, true)?;
            self.release_generic_broker_owner();
        }
        Ok(())
    }

    pub fn begin(&mut self, call: BeginCall, now_ms: u64) -> Result<BeginAck, IntentError> {
        self.advance(now_ms)?;
        if self.mode == PolicyMode::Off {
            return Err(IntentError::AutoDisabled);
        }
        let peer = self.peer(call.connection)?;
        if peer.role != PeerRole::VerifiedBrowser {
            return Err(IntentError::WrongPeerRole);
        }
        if peer.process != call.parent.process || call.call.0 == 0 {
            return Err(IntentError::InvalidIdentity);
        }
        self.check_window(call.parent)?;
        if self.manual_required.contains(&call.parent) {
            return Err(IntentError::ManualRequired);
        }
        if self.calls.contains_key(&(call.connection, call.call)) {
            return Err(IntentError::Duplicate);
        }
        if call.evidence.auth_error != 0 {
            self.manual_required.insert(call.parent);
            self.revoke_parent(call.parent, RevokeReason::RetryError)?;
            return Err(IntentError::ManualRequired);
        }
        if self.requests.len() >= self.limits.max_requests {
            return Err(IntentError::CapacityExceeded);
        }
        let overlapping: Vec<_> = self
            .requests
            .iter()
            .filter(|(_, r)| r.active() && r.begin.parent == call.parent)
            .map(|(id, _)| *id)
            .collect();
        if !overlapping.is_empty() {
            for id in overlapping {
                self.revoke(id, RevokeReason::Ambiguous, true)?;
            }
            self.manual_required.insert(call.parent);
            return Err(IntentError::Ambiguous);
        }
        let Some(deadline) = now_ms.checked_add(self.limits.arm_lease_ms) else {
            self.fail_closed_on_exhaustion();
            return Err(IntentError::CounterExhausted);
        };
        let handle = self.allocate_handle()?;
        self.calls
            .insert((call.connection, call.call), handle.request);
        self.requests.insert(
            handle.request,
            Request {
                handle,
                begin: call,
                state: RequestState::Pending,
                deadline_ms: deadline,
                context: None,
                owner: None,
                result_ready: false,
                ended: false,
                reason: None,
            },
        );
        Ok(BeginAck {
            handle,
            arm_deadline_ms: deadline,
        })
    }

    /// A Begin ACK alone never makes a request claimable. The probe calls Arm
    /// only after receiving its ACK within its own bounded waiting budget.
    pub fn arm(
        &mut self,
        connection: ConnectionId,
        handle: RequestHandle,
        now_ms: u64,
    ) -> Result<(), IntentError> {
        self.advance(now_ms)?;
        self.peer(connection)?;
        let request = self.request_for_handle(handle)?;
        if request.begin.connection != connection {
            return Err(IntentError::WrongConnection);
        }
        if request.state != RequestState::Pending {
            return Err(IntentError::Duplicate);
        }
        self.requests.get_mut(&handle.request).unwrap().state = RequestState::Observed;
        Ok(())
    }

    pub fn claim(
        &mut self,
        context: CredentialContext,
        now_ms: u64,
    ) -> Result<Ticket, IntentError> {
        self.advance(now_ms)?;
        self.check_host(context)?;
        let candidates: Vec<_> = self
            .requests
            .iter()
            .filter(|(_, r)| r.active() && r.begin.parent == context.parent)
            .map(|(id, _)| *id)
            .collect();
        if candidates.len() > 1 {
            for id in candidates {
                self.revoke(id, RevokeReason::Ambiguous, true)?;
            }
            return Err(IntentError::Ambiguous);
        }
        let id = *candidates.first().ok_or(IntentError::UnknownRequest)?;
        let request = &self.requests[&id];
        if request.state == RequestState::Pending {
            return Err(IntentError::NotArmed);
        }
        if request.state != RequestState::Observed {
            return Err(IntentError::AlreadyClaimed);
        }
        if !context.selected {
            self.revoke(id, RevokeReason::Deselected, true)?;
            return Err(IntentError::NotSelected);
        }
        if let Err(error) = self.check_auto(request, context) {
            self.revoke(id, RevokeReason::EvidenceLost, true)?;
            return Err(error);
        }
        let Some(deadline) = now_ms.checked_add(self.limits.recognition_lease_ms) else {
            self.fail_closed_on_exhaustion();
            return Err(IntentError::CounterExhausted);
        };
        let request = self.requests.get_mut(&id).unwrap();
        request.state = RequestState::Claimed;
        request.context = Some(context);
        request.deadline_ms = deadline;
        Ok(Ticket {
            handle: request.handle,
            credential: context.credential,
        })
    }

    pub fn validate(
        &mut self,
        ticket: Ticket,
        context: CredentialContext,
        now_ms: u64,
    ) -> Result<(), IntentError> {
        self.advance(now_ms)?;
        let outcome = self.check_ticket(ticket, context);
        if let Err(error) = outcome {
            if self
                .requests
                .get(&ticket.handle.request)
                .is_some_and(|r| r.active())
            {
                let reason = if error == IntentError::NotSelected {
                    RevokeReason::Deselected
                } else {
                    RevokeReason::EvidenceLost
                };
                self.revoke(ticket.handle.request, reason, true)?;
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn start(
        &mut self,
        ticket: Ticket,
        context: CredentialContext,
        now_ms: u64,
    ) -> Result<RecognitionOwner, IntentError> {
        self.validate(ticket, context, now_ms)?;
        let request = &self.requests[&ticket.handle.request];
        if request.state != RequestState::Claimed {
            return Err(IntentError::Duplicate);
        }
        if !context.selected {
            return Err(IntentError::NotSelected);
        }
        if self.recognition_owner.is_some() {
            self.revoke(ticket.handle.request, RevokeReason::Ambiguous, true)?;
            return Err(IntentError::CameraBusy);
        }
        let owner = RecognitionOwner {
            route: RecognitionRoute::GenericBroker,
            connection: ticket.credential.connection,
            request: ticket.handle.request,
            generation: ticket.handle.generation,
            session_id: context.host.process.session_id,
        };
        let request = self.requests.get_mut(&ticket.handle.request).unwrap();
        request.state = RequestState::Recognizing;
        request.owner = Some(owner);
        self.recognition_owner = Some(owner);
        Ok(owner)
    }

    /// Marks a result available without storing its contents. The camera lease
    /// stays owned until output or cancellation, preventing cross-client reuse.
    pub fn receive_result(
        &mut self,
        owner: RecognitionOwner,
        context: CredentialContext,
        now_ms: u64,
    ) -> Result<(), IntentError> {
        let ticket = Ticket {
            handle: RequestHandle {
                request: owner.request,
                generation: owner.generation,
            },
            credential: context.credential,
        };
        self.validate(ticket, context, now_ms)?;
        if !context.selected {
            return Err(IntentError::NotSelected);
        }
        if self.recognition_owner != Some(owner) {
            return Err(IntentError::WrongOwner);
        }
        let request = self
            .requests
            .get_mut(&owner.request)
            .ok_or(IntentError::UnknownRequest)?;
        if request.state != RequestState::Recognizing || request.owner != Some(owner) {
            return Err(IntentError::WrongOwner);
        }
        if request.result_ready {
            return Err(IntentError::Duplicate);
        }
        request.result_ready = true;
        Ok(())
    }

    /// This is the final, single-use output gate. An adapter must send the result
    /// immediately in the same serialized operation; permits cannot revoke data
    /// already given to Windows and must not be cached for later submission.
    pub fn take_output(
        &mut self,
        ticket: Ticket,
        context: CredentialContext,
        now_ms: u64,
    ) -> Result<OutputPermit, IntentError> {
        self.validate(ticket, context, now_ms)?;
        if !context.selected {
            return Err(IntentError::NotSelected);
        }
        let request = self.requests.get_mut(&ticket.handle.request).unwrap();
        if !request.result_ready {
            return Err(IntentError::ResultNotReady);
        }
        let owner = request.owner.ok_or(IntentError::WrongOwner)?;
        if self.recognition_owner != Some(owner) {
            return Err(IntentError::WrongOwner);
        }
        request.state = RequestState::Completed;
        request.result_ready = false;
        self.recognition_owner = None;
        Ok(OutputPermit { owner })
    }

    pub fn cancel(
        &mut self,
        ticket: Ticket,
        reason: RevokeReason,
        now_ms: u64,
    ) -> Result<(), IntentError> {
        self.advance(now_ms)?;
        let request = self.request_for_handle(ticket.handle)?;
        if request.context.map(|c| c.credential) != Some(ticket.credential) {
            return Err(IntentError::CredentialChanged);
        }
        self.revoke(ticket.handle.request, reason, true)
    }

    pub fn end(
        &mut self,
        connection: ConnectionId,
        call: ClientCallId,
        status: EndStatus,
        now_ms: u64,
    ) -> Result<(), IntentError> {
        self.advance(now_ms)?;
        self.peer(connection)?;
        let id = *self
            .calls
            .get(&(connection, call))
            .ok_or(IntentError::UnknownRequest)?;
        let request = &self.requests[&id];
        if request.ended {
            return Err(IntentError::Duplicate);
        }
        let parent = request.begin.parent;
        let reason = match status {
            EndStatus::ReturnedSuccess => RevokeReason::ApiReturned,
            EndStatus::Cancelled => RevokeReason::ApiCancelled,
            EndStatus::Error => RevokeReason::ApiError,
        };
        if status != EndStatus::ReturnedSuccess {
            self.manual_required.insert(parent);
            self.revoke_parent(parent, reason)?;
        } else {
            self.revoke(id, reason, false)?;
        }
        self.requests.get_mut(&id).unwrap().ended = true;
        Ok(())
    }

    pub fn disconnect(&mut self, connection: ConnectionId, now_ms: u64) -> Result<(), IntentError> {
        self.advance(now_ms)?;
        self.peer(connection)?;
        self.peers.get_mut(&connection).unwrap().connected = false;
        let ids: Vec<_> = self
            .requests
            .iter()
            .filter(|(_, r)| {
                r.active()
                    && (r.begin.connection == connection
                        || r.context
                            .is_some_and(|c| c.credential.connection == connection))
            })
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.revoke(id, RevokeReason::ConnectionClosed, true)?;
        }
        if self
            .recognition_owner
            .is_some_and(|o| o.connection == connection)
        {
            self.recognition_owner = None;
            self.manual_owner_deadline_ms = None;
        }
        Ok(())
    }

    pub fn window_destroyed(
        &mut self,
        window: WindowIdentity,
        now_ms: u64,
    ) -> Result<(), IntentError> {
        self.advance(now_ms)?;
        self.check_window(window)?;
        self.windows
            .get_mut(&(window.process.session_id, window.hwnd))
            .unwrap()
            .alive = false;
        let ids: Vec<_> = self
            .requests
            .iter()
            .filter(|(_, r)| {
                r.active()
                    && (r.begin.parent == window || r.context.is_some_and(|c| c.host == window))
            })
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.revoke(id, RevokeReason::WindowInvalid, true)?;
        }
        Ok(())
    }

    pub fn process_exited(
        &mut self,
        process: ProcessInstance,
        now_ms: u64,
    ) -> Result<(), IntentError> {
        self.advance(now_ms)?;
        let connections: Vec<_> = self
            .peers
            .iter()
            .filter(|(_, p)| p.connected && p.process == process)
            .map(|(id, _)| *id)
            .collect();
        for connection in connections {
            self.disconnect(connection, now_ms)?;
        }
        for window in self
            .windows
            .values_mut()
            .filter(|w| w.identity.process == process)
        {
            window.alive = false;
        }
        Ok(())
    }

    pub fn credential_invalidated(
        &mut self,
        credential: CredentialInstance,
        reason: RevokeReason,
        now_ms: u64,
    ) -> Result<(), IntentError> {
        self.advance(now_ms)?;
        let ids: Vec<_> = self
            .requests
            .iter()
            .filter(|(_, r)| r.active() && r.context.is_some_and(|c| c.credential == credential))
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.revoke(id, reason, true)?;
        }
        Ok(())
    }

    /// Manual and legacy routes must reserve the same exclusive owner. This
    /// model supplies fresh IDs; callers cannot install a self-chosen owner.
    pub fn reserve_manual(
        &mut self,
        connection: ConnectionId,
        route: RecognitionRoute,
        now_ms: u64,
    ) -> Result<RecognitionOwner, IntentError> {
        self.advance(now_ms)?;
        let peer = self.peer(connection)?;
        let allowed = match route {
            RecognitionRoute::PrimaryLogon | RecognitionRoute::GenericBroker => {
                peer.role == PeerRole::VerifiedCredentialHost
            }
            RecognitionRoute::Passkey => peer.role == PeerRole::VerifiedPasskeyHost,
        };
        if !allowed {
            return Err(IntentError::WrongPeerRole);
        }
        if route == RecognitionRoute::GenericBroker {
            self.check_monitor()?;
        }
        if self.recognition_owner.is_some() {
            return Err(IntentError::CameraBusy);
        }
        let Some(deadline) = now_ms.checked_add(self.limits.recognition_lease_ms) else {
            self.fail_closed_on_exhaustion();
            return Err(IntentError::CounterExhausted);
        };
        let handle = self.allocate_handle()?;
        let owner = RecognitionOwner {
            route,
            connection,
            request: handle.request,
            generation: handle.generation,
            session_id: peer.process.session_id,
        };
        self.recognition_owner = Some(owner);
        self.manual_owner_deadline_ms = Some(deadline);
        Ok(owner)
    }

    /// A stale/cross-route cancellation cannot stop someone else's task.
    pub fn release_manual(
        &mut self,
        owner: RecognitionOwner,
        now_ms: u64,
    ) -> Result<(), IntentError> {
        self.advance(now_ms)?;
        if self.requests.contains_key(&owner.request) || self.recognition_owner != Some(owner) {
            return Err(IntentError::WrongOwner);
        }
        self.recognition_owner = None;
        self.manual_owner_deadline_ms = None;
        Ok(())
    }

    pub fn tick(&mut self, now_ms: u64) -> Result<(), IntentError> {
        self.advance(now_ms)
    }

    /// Restart drops peers and evidence but never resets counters. Auto is
    /// disabled; the adapter must re-establish prerequisites before activation.
    pub fn restart(&mut self, now_ms: u64) -> Result<(), IntentError> {
        self.advance(now_ms)?;
        self.mode = if self.mode == PolicyMode::Off {
            PolicyMode::Off
        } else {
            PolicyMode::Observe
        };
        self.revoke_all(RevokeReason::ServiceRestarted)?;
        self.recognition_owner = None;
        self.manual_owner_deadline_ms = None;
        self.peers.clear();
        self.windows.clear();
        self.calls.clear();
        self.requests.clear();
        self.manual_required.clear();
        self.monitor = WebAuthnMonitor::default();
        Ok(())
    }

    fn peer(&self, connection: ConnectionId) -> Result<Peer, IntentError> {
        let peer = *self
            .peers
            .get(&connection)
            .ok_or(IntentError::UnknownConnection)?;
        if !peer.connected {
            return Err(IntentError::ConnectionClosed);
        }
        Ok(peer)
    }

    fn check_window(&self, window: WindowIdentity) -> Result<(), IntentError> {
        match self.windows.get(&(window.process.session_id, window.hwnd)) {
            Some(tracked) if tracked.alive && tracked.identity == window => Ok(()),
            Some(_) => Err(IntentError::WindowReused),
            None => Err(IntentError::UnknownWindow),
        }
    }

    fn check_host(&self, context: CredentialContext) -> Result<(), IntentError> {
        let peer = self.peer(context.credential.connection)?;
        if peer.role != PeerRole::VerifiedCredentialHost {
            return Err(IntentError::WrongPeerRole);
        }
        if peer.process != context.host.process
            || context.credential.provider_instance == 0
            || context.credential.credential_instance == 0
            || context.credential.generation == 0
            || context.host.process.session_id != context.parent.process.session_id
        {
            return Err(IntentError::InvalidIdentity);
        }
        self.check_window(context.host)?;
        self.check_window(context.parent)?;
        if !context.owner_relationship_verified {
            return Err(IntentError::AssociationUnverified);
        }
        Ok(())
    }

    fn check_monitor(&self) -> Result<(), IntentError> {
        if !self.monitor.ready {
            return Err(IntentError::MonitorNotReady);
        }
        if self.monitor.active {
            return Err(IntentError::WebAuthnActive);
        }
        Ok(())
    }

    fn check_auto(&self, request: &Request, context: CredentialContext) -> Result<(), IntentError> {
        if self.mode != PolicyMode::Auto {
            return Err(IntentError::AutoDisabled);
        }
        self.peer(request.begin.connection)?;
        self.check_monitor()?;
        if self.manual_required.contains(&request.begin.parent) {
            return Err(IntentError::ManualRequired);
        }
        let evidence = request.begin.evidence;
        if evidence.passkey_signal || evidence.pin_setup_signal || evidence.uac_signal {
            return Err(IntentError::ExplicitVeto);
        }
        if evidence.privacy != PrivacyState::Normal {
            return Err(IntentError::PrivacyNotNormal);
        }
        if !evidence.browser_image_verified
            || !evidence.retry_semantics_verified
            || evidence.purpose != PromptPurpose::VerifiedDistinctPasswordFill
            || evidence.auth_error != 0
        {
            return Err(IntentError::IntentUnverified);
        }
        match context.verified_flag_mapping {
            Some(mapping)
                if mapping.api == evidence.api_flags
                    && mapping.provider == context.provider_flags => {}
            _ => return Err(IntentError::FlagsUnverified),
        }
        Ok(())
    }

    fn request_for_handle(&self, handle: RequestHandle) -> Result<&Request, IntentError> {
        let request = self
            .requests
            .get(&handle.request)
            .ok_or(IntentError::UnknownRequest)?;
        if !request.active() {
            return Err(IntentError::Terminal);
        }
        if request.handle != handle {
            return Err(IntentError::StaleGeneration);
        }
        Ok(request)
    }

    fn check_ticket(&self, ticket: Ticket, context: CredentialContext) -> Result<(), IntentError> {
        let request = self.request_for_handle(ticket.handle)?;
        if request.context.map(|c| c.credential) != Some(ticket.credential)
            || ticket.credential != context.credential
        {
            return Err(IntentError::CredentialChanged);
        }
        let old = request.context.ok_or(IntentError::NotArmed)?;
        if old.host != context.host
            || old.parent != context.parent
            || old.provider_flags != context.provider_flags
            || old.verified_flag_mapping != context.verified_flag_mapping
        {
            return Err(IntentError::CredentialChanged);
        }
        self.check_host(context)?;
        if !context.selected {
            return Err(IntentError::NotSelected);
        }
        let count = self
            .requests
            .values()
            .filter(|r| r.active() && r.begin.parent == context.parent)
            .count();
        if count != 1 {
            return Err(IntentError::Ambiguous);
        }
        self.check_auto(request, context)
    }

    fn allocate_handle(&mut self) -> Result<RequestHandle, IntentError> {
        if self.exhausted {
            return Err(IntentError::CounterExhausted);
        }
        let (Some(request), Some(generation)) = (
            self.next_request.checked_add(1),
            self.next_generation.checked_add(1),
        ) else {
            self.fail_closed_on_exhaustion();
            return Err(IntentError::CounterExhausted);
        };
        self.next_request = request;
        self.next_generation = generation;
        Ok(RequestHandle {
            request: RequestId(request),
            generation,
        })
    }

    fn advance(&mut self, now_ms: u64) -> Result<(), IntentError> {
        if now_ms < self.last_time_ms {
            return Err(IntentError::ClockWentBackwards);
        }
        self.last_time_ms = now_ms;
        let expired: Vec<_> = self
            .requests
            .iter()
            .filter(|(_, r)| r.active() && now_ms >= r.deadline_ms)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.revoke(id, RevokeReason::Timeout, true)?;
        }
        if self
            .manual_owner_deadline_ms
            .is_some_and(|deadline| now_ms >= deadline)
            && self
                .recognition_owner
                .is_some_and(|owner| !self.requests.contains_key(&owner.request))
        {
            self.recognition_owner = None;
            self.manual_owner_deadline_ms = None;
        }
        Ok(())
    }

    fn revoke_parent(
        &mut self,
        parent: WindowIdentity,
        reason: RevokeReason,
    ) -> Result<(), IntentError> {
        let ids: Vec<_> = self
            .requests
            .iter()
            .filter(|(_, r)| r.active() && r.begin.parent == parent)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.revoke(id, reason, true)?;
        }
        Ok(())
    }

    fn revoke_auto_requests(
        &mut self,
        reason: RevokeReason,
        suppress: bool,
    ) -> Result<(), IntentError> {
        let ids: Vec<_> = self
            .requests
            .iter()
            .filter(|(_, r)| r.active())
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.revoke(id, reason, suppress)?;
        }
        Ok(())
    }

    fn release_generic_broker_owner(&mut self) {
        if self
            .recognition_owner
            .is_some_and(|owner| owner.route == RecognitionRoute::GenericBroker)
        {
            self.recognition_owner = None;
            self.manual_owner_deadline_ms = None;
        }
    }

    fn revoke_all(&mut self, reason: RevokeReason) -> Result<(), IntentError> {
        let ids: Vec<_> = self
            .requests
            .iter()
            .filter(|(_, r)| r.active())
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.revoke(id, reason, false)?;
        }
        Ok(())
    }

    fn revoke(
        &mut self,
        id: RequestId,
        reason: RevokeReason,
        suppress: bool,
    ) -> Result<(), IntentError> {
        let request = self.requests.get(&id).ok_or(IntentError::UnknownRequest)?;
        let parent = request.begin.parent;
        let owner = request.owner;
        if suppress {
            self.manual_required.insert(parent);
        }
        if !request.active() {
            return Ok(());
        }
        let Some(generation) = self.next_generation.checked_add(1) else {
            self.fail_closed_on_exhaustion();
            return Err(IntentError::CounterExhausted);
        };
        self.next_generation = generation;
        if self.recognition_owner == owner && owner.is_some() {
            self.recognition_owner = None;
            self.manual_owner_deadline_ms = None;
        }
        let request = self.requests.get_mut(&id).unwrap();
        request.state = RequestState::Revoked;
        request.result_ready = false;
        request.owner = None;
        request.reason = Some(reason);
        request.handle.generation = generation;
        Ok(())
    }

    fn fail_closed_on_exhaustion(&mut self) {
        self.exhausted = true;
        self.mode = PolicyMode::Off;
        self.recognition_owner = None;
        self.manual_owner_deadline_ms = None;
        for request in self.requests.values_mut() {
            if request.active() {
                request.state = RequestState::Revoked;
                request.result_ready = false;
                request.owner = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BROWSER: ConnectionId = ConnectionId(1);
    const CREDENTIAL_HOST: ConnectionId = ConnectionId(2);
    const PASSKEY_HOST: ConnectionId = ConnectionId(3);

    fn process(pid: u32, creation_time: u64) -> ProcessInstance {
        ProcessInstance {
            pid,
            creation_time,
            session_id: 7,
        }
    }

    fn window(hwnd: u64, lifetime: u64, process: ProcessInstance) -> WindowIdentity {
        WindowIdentity {
            hwnd,
            lifetime,
            process,
        }
    }

    fn setup_with_limits(
        limits: IntentLimits,
    ) -> (
        IntentBridge,
        WindowIdentity,
        WindowIdentity,
        CredentialContext,
    ) {
        let browser_process = process(100, 10_000);
        let credential_process = process(200, 20_000);
        let passkey_process = process(300, 30_000);
        let parent = window(0x1000, 1, browser_process);
        let host = window(0x2000, 1, credential_process);
        let mut bridge = IntentBridge::new(limits).unwrap();
        bridge
            .connect(BROWSER, browser_process, PeerRole::VerifiedBrowser)
            .unwrap();
        bridge
            .connect(
                CREDENTIAL_HOST,
                credential_process,
                PeerRole::VerifiedCredentialHost,
            )
            .unwrap();
        bridge
            .connect(PASSKEY_HOST, passkey_process, PeerRole::VerifiedPasskeyHost)
            .unwrap();
        bridge.register_window(parent).unwrap();
        bridge.register_window(host).unwrap();
        bridge
            .set_monitor(
                WebAuthnMonitor {
                    ready: true,
                    active: false,
                },
                0,
            )
            .unwrap();
        bridge
            .enable_auto(
                AutoPrerequisites {
                    probe_transparency_verified: true,
                    host_association_verified: true,
                    privacy_evidence_verified: true,
                    recognition_ownership_verified: true,
                },
                0,
            )
            .unwrap();
        let context = CredentialContext {
            credential: CredentialInstance {
                connection: CREDENTIAL_HOST,
                provider_instance: 10,
                credential_instance: 20,
                generation: 1,
            },
            host,
            parent,
            owner_relationship_verified: true,
            provider_flags: ProviderFlags(0x12),
            verified_flag_mapping: Some(VerifiedFlagMapping {
                api: ApiFlags(0x200),
                provider: ProviderFlags(0x12),
            }),
            selected: true,
        };
        (bridge, parent, host, context)
    }

    fn setup() -> (
        IntentBridge,
        WindowIdentity,
        WindowIdentity,
        CredentialContext,
    ) {
        setup_with_limits(IntentLimits::default())
    }

    fn begin_call(parent: WindowIdentity, call: u64, auth_error: u32) -> BeginCall {
        BeginCall {
            connection: BROWSER,
            call: ClientCallId(call),
            parent,
            evidence: IntentEvidence {
                browser_image_verified: true,
                purpose: PromptPurpose::VerifiedDistinctPasswordFill,
                retry_semantics_verified: true,
                privacy: PrivacyState::Normal,
                api_flags: ApiFlags(0x200),
                auth_error,
                passkey_signal: false,
                pin_setup_signal: false,
                uac_signal: false,
            },
        }
    }

    fn observed_request(
        bridge: &mut IntentBridge,
        parent: WindowIdentity,
        call: u64,
    ) -> RequestHandle {
        let ack = bridge.begin(begin_call(parent, call, 0), 1).unwrap();
        bridge.arm(BROWSER, ack.handle, 2).unwrap();
        ack.handle
    }

    #[test]
    fn default_mode_is_off_and_begin_cannot_start_recognition() {
        let mut default_bridge = IntentBridge::new(IntentLimits::default()).unwrap();
        assert_eq!(default_bridge.mode(), PolicyMode::Off);
        assert_eq!(
            default_bridge.begin(begin_call(window(0x1000, 1, process(100, 10_000)), 1, 0), 0),
            Err(IntentError::AutoDisabled)
        );

        let (mut bridge, parent, _, _) = setup();
        bridge.disable(1).unwrap();
        assert_eq!(bridge.mode(), PolicyMode::Off);
        assert_eq!(
            bridge.begin(begin_call(parent, 1, 0), 2),
            Err(IntentError::AutoDisabled)
        );
        assert_eq!(bridge.current_owner(), None);
    }

    #[test]
    fn distinct_password_fill_requires_claim_and_single_use_output() {
        let (mut bridge, parent, _, context) = setup();
        let ticket_handle = observed_request(&mut bridge, parent, 1);
        let ticket = bridge.claim(context, 3).unwrap();
        assert_eq!(ticket.handle(), ticket_handle);
        assert_eq!(
            bridge.state(ticket_handle.request),
            Some(RequestState::Claimed)
        );

        let owner = bridge.start(ticket, context, 4).unwrap();
        assert_eq!(owner.route, RecognitionRoute::GenericBroker);
        assert_eq!(bridge.current_owner(), Some(owner));
        bridge.receive_result(owner, context, 5).unwrap();
        let permit = bridge.take_output(ticket, context, 6).unwrap();
        assert_eq!(permit.owner, owner);
        assert_eq!(bridge.current_owner(), None);
        assert_eq!(
            bridge.state(ticket_handle.request),
            Some(RequestState::Completed)
        );
        assert_eq!(
            bridge.take_output(ticket, context, 7),
            Err(IntentError::Terminal)
        );
    }

    #[test]
    fn wrong_pin_retry_revokes_inflight_attempt_and_requires_manual_route() {
        let (mut bridge, parent, _, _) = setup();
        let first = observed_request(&mut bridge, parent, 1);
        let retry = begin_call(parent, 2, 1326);
        assert_eq!(bridge.begin(retry, 3), Err(IntentError::ManualRequired));
        assert_eq!(bridge.state(first.request), Some(RequestState::Revoked));
        assert!(bridge.is_manual_required(parent));
        assert_eq!(bridge.arm(BROWSER, first, 4), Err(IntentError::Terminal));
        assert_eq!(bridge.current_owner(), None);
    }

    #[test]
    fn closing_cred_ui_revokes_request_and_blocks_automatic_reopen() {
        let (mut bridge, parent, _, _) = setup();
        let handle = bridge.begin(begin_call(parent, 1, 0), 1).unwrap().handle;
        bridge
            .end(BROWSER, ClientCallId(1), EndStatus::Cancelled, 2)
            .unwrap();
        assert_eq!(bridge.state(handle.request), Some(RequestState::Revoked));
        assert!(bridge.is_manual_required(parent));
        assert_eq!(
            bridge.begin(begin_call(parent, 2, 0), 3),
            Err(IntentError::ManualRequired)
        );
    }

    #[test]
    fn overlapping_prompt_is_ambiguous_and_neither_request_can_win() {
        let (mut bridge, parent, _, _) = setup();
        let first = bridge.begin(begin_call(parent, 1, 0), 1).unwrap().handle;
        assert_eq!(
            bridge.begin(begin_call(parent, 2, 0), 2),
            Err(IntentError::Ambiguous)
        );
        assert_eq!(bridge.state(first.request), Some(RequestState::Revoked));
        assert!(bridge.is_manual_required(parent));
    }

    #[test]
    fn unselected_credential_is_revoked_before_it_can_be_claimed() {
        let (mut bridge, parent, _, mut context) = setup();
        let handle = observed_request(&mut bridge, parent, 1);
        context.selected = false;
        assert_eq!(bridge.claim(context, 3), Err(IntentError::NotSelected));
        assert_eq!(bridge.state(handle.request), Some(RequestState::Revoked));
        assert!(bridge.is_manual_required(parent));
    }

    #[test]
    fn active_webauthn_releases_generic_broker_owner_but_preserves_passkey_owner() {
        let (mut bridge, _, _, _) = setup();
        let generic = bridge
            .reserve_manual(CREDENTIAL_HOST, RecognitionRoute::GenericBroker, 1)
            .unwrap();
        bridge
            .set_monitor(
                WebAuthnMonitor {
                    ready: true,
                    active: true,
                },
                2,
            )
            .unwrap();
        assert_eq!(bridge.current_owner(), None);
        assert_eq!(
            bridge.release_manual(generic, 3),
            Err(IntentError::WrongOwner)
        );

        let passkey = bridge
            .reserve_manual(PASSKEY_HOST, RecognitionRoute::Passkey, 4)
            .unwrap();
        bridge
            .set_monitor(
                WebAuthnMonitor {
                    ready: true,
                    active: true,
                },
                5,
            )
            .unwrap();
        assert_eq!(bridge.current_owner(), Some(passkey));
        bridge.release_manual(passkey, 6).unwrap();
    }

    #[test]
    fn active_webauthn_racing_recognition_revokes_the_output_ticket() {
        let (mut bridge, parent, _, context) = setup();
        let handle = observed_request(&mut bridge, parent, 1);
        let ticket = bridge.claim(context, 3).unwrap();
        let owner = bridge.start(ticket, context, 4).unwrap();
        bridge.receive_result(owner, context, 5).unwrap();
        bridge
            .set_monitor(
                WebAuthnMonitor {
                    ready: true,
                    active: true,
                },
                6,
            )
            .unwrap();
        assert_eq!(bridge.current_owner(), None);
        assert_eq!(
            bridge.take_output(ticket, context, 7),
            Err(IntentError::Terminal)
        );
        assert_eq!(bridge.state(handle.request), Some(RequestState::Revoked));
        assert!(bridge.is_manual_required(parent));
    }

    #[test]
    fn a_busy_camera_revokes_instead_of_queueing_a_broker_attempt() {
        let (mut bridge, parent, _, context) = setup();
        let handle = observed_request(&mut bridge, parent, 1);
        let ticket = bridge.claim(context, 3).unwrap();
        let primary = bridge
            .reserve_manual(CREDENTIAL_HOST, RecognitionRoute::PrimaryLogon, 4)
            .unwrap();
        assert_eq!(
            bridge.start(ticket, context, 5),
            Err(IntentError::CameraBusy)
        );
        assert_eq!(bridge.state(handle.request), Some(RequestState::Revoked));
        assert!(bridge.is_manual_required(parent));
        assert_eq!(bridge.current_owner(), Some(primary));
        bridge.release_manual(primary, 6).unwrap();
    }

    #[test]
    fn failed_intent_evidence_fails_closed_on_claim() {
        let (mut bridge, parent, _, context) = setup();
        let mut call = begin_call(parent, 1, 0);
        call.evidence.passkey_signal = true;
        let handle = bridge.begin(call, 1).unwrap().handle;
        bridge.arm(BROWSER, handle, 2).unwrap();
        assert_eq!(bridge.claim(context, 3), Err(IntentError::ExplicitVeto));
        assert_eq!(bridge.state(handle.request), Some(RequestState::Revoked));
        assert!(bridge.is_manual_required(parent));
    }

    #[test]
    fn manual_owner_has_a_bounded_lease() {
        let mut limits = IntentLimits::default();
        limits.recognition_lease_ms = 10;
        let (mut bridge, _, _, _) = setup_with_limits(limits);
        let owner = bridge
            .reserve_manual(CREDENTIAL_HOST, RecognitionRoute::PrimaryLogon, 1)
            .unwrap();
        assert_eq!(bridge.current_owner(), Some(owner));
        bridge.tick(11).unwrap();
        assert_eq!(bridge.current_owner(), None);
    }

    #[test]
    fn unclaimed_request_timeout_blocks_same_window_retries() {
        let mut limits = IntentLimits::default();
        limits.arm_lease_ms = 10;
        let (mut bridge, parent, _, _) = setup_with_limits(limits);
        let handle = bridge.begin(begin_call(parent, 1, 0), 1).unwrap().handle;
        bridge.tick(11).unwrap();
        assert_eq!(bridge.state(handle.request), Some(RequestState::Revoked));
        assert!(bridge.is_manual_required(parent));
        assert_eq!(
            bridge.begin(begin_call(parent, 2, 0), 12),
            Err(IntentError::ManualRequired)
        );
    }

    #[test]
    fn provider_window_destruction_suppresses_the_still_open_parent_attempt() {
        let (mut bridge, parent, host, context) = setup();
        let handle = observed_request(&mut bridge, parent, 1);
        bridge.claim(context, 3).unwrap();
        bridge.window_destroyed(host, 4).unwrap();
        assert_eq!(bridge.state(handle.request), Some(RequestState::Revoked));
        assert!(bridge.is_manual_required(parent));
    }

    #[test]
    fn destroyed_handle_requires_a_new_lifetime_and_does_not_consume_window_capacity() {
        let mut limits = IntentLimits::default();
        limits.max_windows = 2;
        let (mut bridge, parent, host, _) = setup_with_limits(limits);
        let request = bridge.begin(begin_call(parent, 1, 0), 1).unwrap().handle;
        bridge.window_destroyed(parent, 2).unwrap();
        assert_eq!(bridge.state(request.request), Some(RequestState::Revoked));
        assert_eq!(
            bridge.register_window(window(parent.hwnd, parent.lifetime, parent.process)),
            Err(IntentError::WindowReused)
        );
        let new_parent = window(parent.hwnd, parent.lifetime + 1, parent.process);
        bridge.register_window(new_parent).unwrap();
        assert_eq!(bridge.check_window(host), Ok(()));
        assert_eq!(bridge.check_window(new_parent), Ok(()));
        assert!(bridge.is_manual_required(parent));
        assert!(!bridge.is_manual_required(new_parent));
    }
}
