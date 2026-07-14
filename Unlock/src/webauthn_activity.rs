//! Tracks active WebAuthn operations without inspecting credential-dialog UI.
//!
//! The Windows WebAuthn provider emits top-level transaction start/completion
//! events before CredentialUIBroker loads credential providers. This module
//! projects that state into read-only named events so the credential provider
//! can conservatively opt out of passkey and security-key operations.

use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    mem::size_of,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    slice,
    sync::{atomic::Ordering, Arc},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use windows::Win32::{
    Foundation::{
        CloseHandle, GetLastError, LocalFree, BOOL, ERROR_NO_MORE_ITEMS, HANDLE, HLOCAL,
        WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    },
    System::{
        EventLog::{
            EventMetadataEventID, EvtChannelConfigEnabled, EvtClose, EvtCreateRenderContext,
            EvtGetChannelConfigProperty, EvtGetEventMetadataProperty, EvtNext,
            EvtNextEventMetadata, EvtOpenChannelConfig, EvtOpenEventMetadataEnum,
            EvtOpenPublisherMetadata, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection,
            EvtRender, EvtRenderContextValues, EvtRenderEventValues, EvtSubscribe,
            EvtSubscribeToFutureEvents, EvtVarTypeBoolean, EvtVarTypeFileTime, EvtVarTypeGuid,
            EvtVarTypeString, EvtVarTypeSysTime, EvtVarTypeUInt16, EvtVarTypeUInt32,
            EVT_HANDLE, EVT_VARIANT, EVT_VARIANT_TYPE_MASK,
        },
        Threading::{CreateEventW, ResetEvent, SetEvent, WaitForSingleObject},
    },
};
use windows_core::{w, PCWSTR};

use crate::{log_service, State};

pub(crate) const READY_EVENT_NAME: &str = "Global\\FaceWinUnlockTauriWebAuthnReady";
pub(crate) const ACTIVE_EVENT_NAME: &str = "Global\\FaceWinUnlockTauriWebAuthnActive";

const CHANNEL: &str = "Microsoft-Windows-WebAuthN/Operational";
const PROVIDER: &str = "Microsoft-Windows-WebAuthN";
const TRANSACTION_TTL: Duration = Duration::from_secs(10 * 60);
/// 凭据枚举事件（2250/2251）是 CTAP 事务前最早的 WebAuthn 信号。
/// 枚举在弹窗出现前约 1-2s 发生。保留 5s 足够覆盖正常弹窗延迟，同时避免
/// passkey 取消后立刻触发密码填充被误判（Chrome 条件 UI 枚举到后续密码填充
/// 通常间隔 >30s，不会被 5s TTL 影响）。
const ENUM_TTL: Duration = Duration::from_secs(5);
const CTAP_EVENT_IDS: &str = "1000 or 1001 or 1002 or 1003 or 1004 or 1005 or 1006 or 1007 or 1008";
const EVENT_QUERY: &str =
    "*[System[(EventID=2250 or EventID=2251 or EventID=1000 or EventID=1001 or EventID=1002 or EventID=1003 or EventID=1004 or EventID=1005 or EventID=1006 or EventID=1007 or EventID=1008)]]";
const REQUIRED_EVENT_IDS: [u32; 11] =
    [1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 2250, 2251];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventPhase {
    Started,
    Completed,
}

fn event_phase(event_id: u32) -> Option<EventPhase> {
    match event_id {
        1000 | 1003 | 1006 | 2250 => Some(EventPhase::Started),
        1001 | 1002 | 1004 | 1005 | 1007 | 1008 | 2251 => Some(EventPhase::Completed),
        _ => None,
    }
}
/// 返回 true 表示该事件 ID 属于凭据枚举阶段（弹窗出现之前即发生）。
fn is_enumeration_event(event_id: u32) -> bool {
    event_id == 2250 || event_id == 2251
}

#[derive(Debug, Clone)]
struct ActivityEvent {
    event_id: u32,
    transaction_id: String,
    observed_at: SystemTime,
}

#[derive(Debug, Clone)]
struct TransactionState {
    active: bool,
    observed_at: SystemTime,
}

#[derive(Debug, Default)]
struct ActivityTracker {
    transactions: HashMap<String, TransactionState>,
    /// 最近一次凭据枚举开始的时刻。None 表示未观察到或无近期枚举。
    last_enumeration_started: Option<SystemTime>,
}

impl ActivityTracker {
    fn apply(&mut self, event: ActivityEvent) {
        let Some(phase) = event_phase(event.event_id) else {
            return;
        };
        if is_enumeration_event(event.event_id) {
            // 枚举事件不需要完整的事务配对；记录最近一次枚举开始时刻即可。
            if phase == EventPhase::Started {
                self.last_enumeration_started = Some(event.observed_at);
            }
            return;
        }
        if self
            .transactions
            .get(&event.transaction_id)
            .is_some_and(|current| current.observed_at > event.observed_at)
        {
            return;
        }
        self.transactions.insert(
            event.transaction_id,
            TransactionState {
                active: phase == EventPhase::Started,
                observed_at: event.observed_at,
            },
        );
    }

    fn active_count(&mut self, now: SystemTime) -> usize {
        self.transactions.retain(|_, state| {
            now.duration_since(state.observed_at).unwrap_or_default() <= TRANSACTION_TTL
        });
        let ctap_active = self
            .transactions
            .values()
            .filter(|state| state.active)
            .count();
        // 近期有凭据枚举（弹窗出现前的早期信号）时也视同 active。
        let enum_recent = self
            .last_enumeration_started
            .is_some_and(|t| now.duration_since(t).unwrap_or_default() <= ENUM_TTL);
        if enum_recent { ctap_active.max(1) } else { ctap_active }
    }
}

struct KernelHandle(HANDLE);

impl Drop for KernelHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct EvtHandle(EVT_HANDLE);

impl Drop for EvtHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = EvtClose(self.0);
        }
    }
}

pub(crate) fn run(state: Arc<State>, exe_dir: PathBuf) {
    let (ready_event, active_event) = match create_status_events() {
        Ok(events) => events,
        Err(error) => {
            log_service(
                &exe_dir,
                "ERROR",
                &format!("WebAuthn monitor status events unavailable: {error}"),
            );
            return;
        }
    };

    let mut retry_delay = Duration::from_secs(1);
    while !state.should_exit.load(Ordering::SeqCst) {
        reset_status_events(ready_event.0, active_event.0);
        match monitor_once(&state, &exe_dir, ready_event.0, active_event.0) {
            Ok(()) => break,
            Err(error) => {
                reset_status_events(ready_event.0, active_event.0);
                log_service(
                    &exe_dir,
                    "WARN",
                    &format!("WebAuthn monitor unavailable: {error}; retrying"),
                );
            }
        }
        sleep_until_exit(&state, retry_delay);
        retry_delay = (retry_delay * 2).min(Duration::from_secs(30));
    }

    reset_status_events(ready_event.0, active_event.0);
}

fn monitor_once(
    state: &Arc<State>,
    exe_dir: &Path,
    ready_event: HANDLE,
    active_event: HANDLE,
) -> Result<(), String> {
    validate_provider_contract()?;

    let render_context = EvtHandle(create_render_context()?);
    let signal = unsafe { CreateEventW(None, true, false, None) }
        .map(KernelHandle)
        .map_err(|error| format!("create subscription signal failed: {error:?}"))?;
    let mut tracker = ActivityTracker::default();

    // Subscribe first, then replay. Timestamp ordering in ActivityTracker makes
    // duplicate or out-of-order subscription/replay delivery harmless. Pull mode
    // keeps all event processing on this thread and needs no callback raw pointer.
    let channel = wide(CHANNEL);
    let query = wide(EVENT_QUERY);
    let subscription = unsafe {
        EvtSubscribe(
            None,
            Some(signal.0),
            PCWSTR::from_raw(channel.as_ptr()),
            PCWSTR::from_raw(query.as_ptr()),
            None,
            None,
            None,
            EvtSubscribeToFutureEvents.0,
        )
    }
    .map(EvtHandle)
    .map_err(|error| format!("EvtSubscribe failed: {error:?}"))?;

    replay_recent(&mut tracker, render_context.0, active_event)?;
    sync_active_event(&mut tracker, active_event);
    unsafe {
        SetEvent(ready_event).map_err(|error| format!("SetEvent(Ready) failed: {error:?}"))?;
    }
    log_service(exe_dir, "INFO", "WebAuthn monitor ready");

    while !state.should_exit.load(Ordering::SeqCst) {
        match unsafe { WaitForSingleObject(signal.0, 500) } {
            WAIT_OBJECT_0 => {
                drain_events(
                    subscription.0,
                    render_context.0,
                    &mut tracker,
                    active_event,
                    Some(exe_dir),
                    "subscription",
                )?;
                unsafe {
                    ResetEvent(signal.0)
                        .map_err(|error| format!("ResetEvent(subscription) failed: {error:?}"))?;
                }
            }
            WAIT_TIMEOUT => sync_active_event(&mut tracker, active_event),
            WAIT_FAILED => {
                return Err(format!(
                    "waiting for WebAuthn subscription failed: {:?}",
                    unsafe { GetLastError() }
                ));
            }
            other => return Err(format!("unexpected WebAuthn subscription wait result: {other:?}")),
        }
    }

    reset_status_events(ready_event, active_event);
    Ok(())
}

fn replay_recent(
    tracker: &mut ActivityTracker,
    render_context: EVT_HANDLE,
    active_event: HANDLE,
) -> Result<(), String> {
    let channel = wide(CHANNEL);
    // 回放时也要查询枚举事件，启动后立即恢复近期 WebAuthn 活动状态。
    let query_str = format!(
        "*[System[(EventID=2250 or EventID=2251 or {CTAP_EVENT_IDS}) and TimeCreated[timediff(@SystemTime) <= 600000]]]"
    );
    let query = wide(&query_str);
    let result_set = unsafe {
        EvtQuery(
            None,
            PCWSTR::from_raw(channel.as_ptr()),
            PCWSTR::from_raw(query.as_ptr()),
            EvtQueryChannelPath.0 | EvtQueryForwardDirection.0,
        )
    }
    .map(EvtHandle)
    .map_err(|error| format!("recent event query failed: {error:?}"))?;

    drain_events(result_set.0, render_context, tracker, active_event, None, "replay")
}

fn drain_events(
    result_set: EVT_HANDLE,
    render_context: EVT_HANDLE,
    tracker: &mut ActivityTracker,
    active_event: HANDLE,
    log_dir: Option<&Path>,
    operation: &str,
) -> Result<(), String> {
    loop {
        let mut raw_events = [0isize; 16];
        let mut returned = 0u32;
        let result = unsafe { EvtNext(result_set, &mut raw_events, 0, 0, &mut returned) };
        if let Err(error) = result {
            if unsafe { GetLastError() } == ERROR_NO_MORE_ITEMS {
                break;
            }
            return Err(format!("EvtNext {operation} failed: {error:?}"));
        }
        if returned == 0 {
            break;
        }
        // Wrap the full batch before parsing so every event handle is closed even
        // when one malformed event aborts this subscription attempt.
        let events: Vec<EvtHandle> = raw_events
            .into_iter()
            .take(returned as usize)
            .map(|raw| EvtHandle(EVT_HANDLE(raw)))
            .collect();
        for event in &events {
            let activity = unsafe { render_activity_event(render_context, event.0) }?;
            let event_id = activity.event_id;
            tracker.apply(activity);
            let active_count = tracker.active_count(SystemTime::now());
            update_active_event(active_event, active_count > 0);
            if let Some(exe_dir) = log_dir {
                log_service(
                    exe_dir,
                    "INFO",
                    &format!("WebAuthn monitor event {event_id}: active_transactions={active_count}"),
                );
            }
        }
    }
    Ok(())
}

fn create_render_context() -> Result<EVT_HANDLE, String> {
    let paths = [
        w!("Event/System/EventID"),
        w!("Event/EventData/Data[@Name='TransactionId']"),
        w!("Event/System/TimeCreated/@SystemTime"),
    ];
    unsafe { EvtCreateRenderContext(Some(&paths), EvtRenderContextValues.0) }
        .map_err(|error| format!("EvtCreateRenderContext failed: {error:?}"))
}

unsafe fn render_activity_event(
    render_context: EVT_HANDLE,
    event: EVT_HANDLE,
) -> Result<ActivityEvent, String> {
    let mut bytes_used = 0u32;
    let mut property_count = 0u32;
    let _ = EvtRender(
        Some(render_context),
        event,
        EvtRenderEventValues.0,
        0,
        None,
        &mut bytes_used,
        &mut property_count,
    );
    if bytes_used == 0 {
        return Err("EvtRender returned an empty value buffer".to_string());
    }

    let mut storage = vec![0u64; (bytes_used as usize).div_ceil(size_of::<u64>())];
    EvtRender(
        Some(render_context),
        event,
        EvtRenderEventValues.0,
        bytes_used,
        Some(storage.as_mut_ptr().cast()),
        &mut bytes_used,
        &mut property_count,
    )
    .map_err(|error| format!("EvtRender values failed: {error:?}"))?;
    if property_count < 3 {
        return Err(format!(
            "expected 3 event values, received {property_count}"
        ));
    }

    let values = slice::from_raw_parts(
        storage.as_ptr().cast::<EVT_VARIANT>(),
        property_count as usize,
    );
    let event_id = variant_u32(&values[0])?;
    let transaction_id = variant_string(&values[1])?;
    let observed_at = variant_system_time(&values[2]).unwrap_or_else(SystemTime::now);
    if transaction_id.is_empty() {
        return Err(format!("event {event_id} has no transaction ID"));
    }
    Ok(ActivityEvent {
        event_id,
        transaction_id,
        observed_at,
    })
}

unsafe fn variant_u32(value: &EVT_VARIANT) -> Result<u32, String> {
    match value.Type & EVT_VARIANT_TYPE_MASK {
        kind if kind == EvtVarTypeUInt16.0 as u32 => Ok(value.Anonymous.UInt16Val as u32),
        kind if kind == EvtVarTypeUInt32.0 as u32 => Ok(value.Anonymous.UInt32Val),
        kind => Err(format!("unexpected integer variant type {kind}")),
    }
}

unsafe fn variant_string(value: &EVT_VARIANT) -> Result<String, String> {
    let kind = value.Type & EVT_VARIANT_TYPE_MASK;
    if kind == EvtVarTypeString.0 as u32 {
        return value
            .Anonymous
            .StringVal
            .to_string()
            .map_err(|error| format!("invalid event string: {error:?}"));
    }
    // 根因修复：Microsoft-Windows-WebAuthN 的 CTAP 事件（1000-1008 MakeCredential /
    // GetAssertion / SendCommand）把 TransactionId 渲染为 GUID 变体（EvtVarTypeGuid=15），
    // 而非字符串。旧实现只认 String → 每次收到真实 passkey 事件就报
    // "unexpected string variant type 15" → 回调标记 unhealthy → Ready 事件被 Reset →
    // 浏览器填密码场景读到 webauthn_ready=false → 一律回退 PIN、走不了人脸。
    // 这里把 GUID 规范化为稳定字符串作事务键（手写格式，保证 started/completed 同一
    // 事务产生完全一致的键，供 HashMap 配对）。
    if kind == EvtVarTypeGuid.0 as u32 {
        let guid_ptr = value.Anonymous.GuidVal;
        if guid_ptr.is_null() {
            return Err("null GUID transaction id".to_string());
        }
        let guid = *guid_ptr;
        return Ok(format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            guid.data1,
            guid.data2,
            guid.data3,
            guid.data4[0],
            guid.data4[1],
            guid.data4[2],
            guid.data4[3],
            guid.data4[4],
            guid.data4[5],
            guid.data4[6],
            guid.data4[7],
        ));
    }
    Err(format!("unexpected transaction-id variant type {kind}"))
}

unsafe fn variant_system_time(value: &EVT_VARIANT) -> Option<SystemTime> {
    let kind = value.Type & EVT_VARIANT_TYPE_MASK;
    // TimeCreated/@SystemTime 通常渲染为 FILETIME（100ns tick，1601 纪元）。
    if kind == EvtVarTypeFileTime.0 as u32 {
        const WINDOWS_TO_UNIX_100NS: u64 = 116_444_736_000_000_000;
        let ticks = value.Anonymous.FileTimeVal;
        let unix_ticks = ticks.checked_sub(WINDOWS_TO_UNIX_100NS)?;
        return Some(UNIX_EPOCH + Duration::from_nanos(unix_ticks.saturating_mul(100)));
    }
    // 少数渲染路径会返回 SYSTEMTIME 变体；也解析它，避免回退 now() 削弱乱序保护。
    if kind == EvtVarTypeSysTime.0 as u32 {
        let st_ptr = value.Anonymous.SysTimeVal;
        if st_ptr.is_null() {
            return None;
        }
        let st = *st_ptr;
        // Howard Hinnant days_from_civil：把公历日期换算成 Unix 纪元天数（无第三方依赖）。
        let (y, m, d) = (st.wYear as i64, st.wMonth as i64, st.wDay as i64);
        if !(1..=12).contains(&m) {
            return None;
        }
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let mp = if m > 2 { m - 3 } else { m + 9 };
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        let secs = days * 86_400
            + st.wHour as i64 * 3_600
            + st.wMinute as i64 * 60
            + st.wSecond as i64;
        if secs < 0 {
            return None;
        }
        return Some(
            UNIX_EPOCH
                + Duration::from_secs(secs as u64)
                + Duration::from_millis(st.wMilliseconds as u64),
        );
    }
    None
}

fn validate_provider_contract() -> Result<(), String> {
    validate_channel_enabled()?;
    validate_event_metadata()
}

fn validate_channel_enabled() -> Result<(), String> {
    let channel = wide(CHANNEL);
    let config = unsafe { EvtOpenChannelConfig(None, PCWSTR::from_raw(channel.as_ptr()), 0) }
        .map(EvtHandle)
        .map_err(|error| format!("WebAuthn channel unavailable: {error:?}"))?;
    let mut value = EVT_VARIANT::default();
    let mut used = 0u32;
    unsafe {
        EvtGetChannelConfigProperty(
            config.0,
            EvtChannelConfigEnabled,
            0,
            size_of::<EVT_VARIANT>() as u32,
            Some(&mut value),
            &mut used,
        )
    }
    .map_err(|error| format!("cannot read WebAuthn channel state: {error:?}"))?;
    let kind = value.Type & EVT_VARIANT_TYPE_MASK;
    if kind != EvtVarTypeBoolean.0 as u32 || unsafe { value.Anonymous.BooleanVal } == BOOL(0) {
        return Err("WebAuthn Operational channel is disabled".to_string());
    }
    Ok(())
}

fn validate_event_metadata() -> Result<(), String> {
    let provider = wide(PROVIDER);
    let metadata = unsafe {
        EvtOpenPublisherMetadata(
            None,
            PCWSTR::from_raw(provider.as_ptr()),
            PCWSTR::null(),
            0,
            0,
        )
    }
    .map(EvtHandle)
    .map_err(|error| format!("WebAuthn publisher metadata unavailable: {error:?}"))?;
    let enumeration = unsafe { EvtOpenEventMetadataEnum(metadata.0, 0) }
        .map(EvtHandle)
        .map_err(|error| format!("cannot enumerate WebAuthn event metadata: {error:?}"))?;

    let mut available = HashSet::new();
    loop {
        let event_metadata = match unsafe { EvtNextEventMetadata(enumeration.0, 0) } {
            Ok(handle) => EvtHandle(handle),
            Err(_error) if unsafe { GetLastError() } == ERROR_NO_MORE_ITEMS => break,
            Err(error) => return Err(format!("event metadata enumeration failed: {error:?}")),
        };
        let mut value = EVT_VARIANT::default();
        let mut used = 0u32;
        unsafe {
            EvtGetEventMetadataProperty(
                event_metadata.0,
                EventMetadataEventID,
                0,
                size_of::<EVT_VARIANT>() as u32,
                Some(&mut value),
                &mut used,
            )
        }
        .map_err(|error| format!("cannot read event metadata ID: {error:?}"))?;
        if let Ok(event_id) = unsafe { variant_u32(&value) } {
            available.insert(event_id);
        }
    }

    let missing: Vec<u32> = REQUIRED_EVENT_IDS
        .iter()
        .copied()
        .filter(|event_id| !available.contains(event_id))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "WebAuthn event contract mismatch; missing IDs {missing:?}"
        ))
    }
}

fn create_status_events() -> Result<(KernelHandle, KernelHandle), String> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let sddl = wide("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x00100000;;;WD)");
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR::from_raw(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|error| format!("status-event SDDL failed: {error:?}"))?;

    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.cast(),
        bInheritHandle: BOOL(0),
    };
    let ready_name = wide(READY_EVENT_NAME);
    let active_name = wide(ACTIVE_EVENT_NAME);
    let ready = unsafe {
        CreateEventW(
            Some(&attributes),
            true,
            false,
            PCWSTR::from_raw(ready_name.as_ptr()),
        )
    }
    .map(KernelHandle);
    let active = unsafe {
        CreateEventW(
            Some(&attributes),
            true,
            false,
            PCWSTR::from_raw(active_name.as_ptr()),
        )
    }
    .map(KernelHandle);
    if !descriptor.0.is_null() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
    }
    Ok((
        ready.map_err(|error| format!("create Ready event failed: {error:?}"))?,
        active.map_err(|error| format!("create Active event failed: {error:?}"))?,
    ))
}

fn sync_active_event(tracker: &mut ActivityTracker, active_event: HANDLE) {
    let active_count = tracker.active_count(SystemTime::now());
    update_active_event(active_event, active_count > 0);
}

fn update_active_event(event: HANDLE, active: bool) {
    unsafe {
        if active {
            let _ = SetEvent(event);
        } else {
            let _ = ResetEvent(event);
        }
    }
}

fn reset_status_events(ready_event: HANDLE, active_event: HANDLE) {
    unsafe {
        let _ = ResetEvent(ready_event);
        let _ = ResetEvent(active_event);
    }
}

fn sleep_until_exit(state: &Arc<State>, duration: Duration) {
    let deadline = std::time::Instant::now() + duration;
    while !state.should_exit.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        reset_status_events, ActivityEvent, ActivityTracker, KernelHandle, TRANSACTION_TTL,
    };
    use std::time::{Duration, SystemTime};
    use windows::Win32::{
        Foundation::WAIT_TIMEOUT,
        System::Threading::{CreateEventW, WaitForSingleObject},
    };

    fn event(event_id: u32, transaction_id: &str, observed_at: SystemTime) -> ActivityEvent {
        ActivityEvent {
            event_id,
            transaction_id: transaction_id.to_string(),
            observed_at,
        }
    }

    #[test]
    fn start_and_completion_toggle_activity() {
        let now = SystemTime::now();
        let mut tracker = ActivityTracker::default();
        tracker.apply(event(1003, "a", now));
        assert_eq!(tracker.active_count(now), 1);
        tracker.apply(event(1005, "a", now + Duration::from_secs(1)));
        assert_eq!(tracker.active_count(now + Duration::from_secs(1)), 0);
    }

    #[test]
    fn concurrent_transactions_remain_active_until_all_complete() {
        let now = SystemTime::now();
        let mut tracker = ActivityTracker::default();
        tracker.apply(event(1000, "a", now));
        tracker.apply(event(1006, "b", now));
        tracker.apply(event(1001, "a", now + Duration::from_secs(1)));
        assert_eq!(tracker.active_count(now + Duration::from_secs(1)), 1);
        tracker.apply(event(1008, "b", now + Duration::from_secs(2)));
        assert_eq!(tracker.active_count(now + Duration::from_secs(2)), 0);
    }

    #[test]
    fn duplicate_events_are_idempotent() {
        let now = SystemTime::now();
        let mut tracker = ActivityTracker::default();
        tracker.apply(event(1003, "a", now));
        tracker.apply(event(1003, "a", now));
        assert_eq!(tracker.active_count(now), 1);

        let completed_at = now + Duration::from_secs(1);
        tracker.apply(event(1005, "a", completed_at));
        tracker.apply(event(1005, "a", completed_at));
        assert_eq!(tracker.active_count(completed_at), 0);
    }

    #[test]
    fn startup_replay_restores_only_unfinished_transactions() {
        let now = SystemTime::now();
        let mut tracker = ActivityTracker::default();
        for replayed in [
            event(1000, "finished", now - Duration::from_secs(4)),
            event(1002, "finished", now - Duration::from_secs(3)),
            event(1003, "active", now - Duration::from_secs(2)),
        ] {
            tracker.apply(replayed);
        }

        assert_eq!(tracker.active_count(now), 1);
    }

    #[test]
    fn older_replay_cannot_overwrite_newer_completion() {
        let now = SystemTime::now();
        let mut tracker = ActivityTracker::default();
        tracker.apply(event(1005, "a", now));
        tracker.apply(event(1003, "a", now - Duration::from_secs(1)));
        assert_eq!(tracker.active_count(now), 0);
    }

    #[test]
    fn missing_completion_expires_safely() {
        let now = SystemTime::now();
        let mut tracker = ActivityTracker::default();
        tracker.apply(event(1003, "a", now));
        assert_eq!(tracker.active_count(now), 1);
        assert_eq!(
            tracker.active_count(now + TRANSACTION_TTL + Duration::from_secs(1)),
            0
        );
    }

    #[test]
    fn monitor_reset_clears_ready_and_active_state() {
        let ready = KernelHandle(unsafe { CreateEventW(None, true, true, None) }.unwrap());
        let active = KernelHandle(unsafe { CreateEventW(None, true, true, None) }.unwrap());

        reset_status_events(ready.0, active.0);

        assert_eq!(unsafe { WaitForSingleObject(ready.0, 0) }, WAIT_TIMEOUT);
        assert_eq!(unsafe { WaitForSingleObject(active.0, 0) }, WAIT_TIMEOUT);
    }

    // 根因回归：真实 WebAuthn CTAP 事件（1000-1008）的 TransactionId 是 GUID 变体
    // （EvtVarTypeGuid=15），不是字符串。variant_string 必须能把它解析成规范 GUID
    // 字符串，否则监视器收到第一个 passkey 事件即崩溃、Ready 被清、浏览器填密码
    // 永远回退 PIN。GUID 取自实测 unlock 日志的一条真实 TransactionId。
    #[test]
    fn transaction_id_guid_variant_parses_to_canonical_string() {
        use super::variant_string;
        use windows::Win32::System::EventLog::{EvtVarTypeGuid, EVT_VARIANT, EVT_VARIANT_0};
        use windows_core::GUID;

        let mut guid = GUID {
            data1: 0x4966_465a,
            data2: 0x2683,
            data3: 0x428f,
            data4: [0xbf, 0x19, 0x20, 0x35, 0x11, 0xd5, 0xe2, 0x46],
        };
        let variant = EVT_VARIANT {
            Anonymous: EVT_VARIANT_0 {
                GuidVal: &mut guid as *mut GUID,
            },
            Count: 0,
            Type: EvtVarTypeGuid.0 as u32,
        };
        let parsed = unsafe { variant_string(&variant) }.expect("guid transaction id parses");
        assert_eq!(parsed, "4966465a-2683-428f-bf19-203511d5e246");
    }
}
