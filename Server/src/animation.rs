//! 动画 UI 管线（阶段 C · 状态机）
//!
//! DComp topmost 层叠加在 LogonUI 凭据磁贴上方，60 FPS GPU 动画。
//! 状态机：Idle → Scanning → Success|Failure → (2s) → Idle
//!
//! 架构：
//!   LogonUI 父 HWND
//!     ├── [DComp Topmost] ← Visual { Offset = 磁贴位置 }
//!     │       └── Surface (128×128) ← D2D 状态机动画
//!     └── [Child Windows] ← LogonUI 凭据磁贴
//!
//!   AnimationSlot = Arc<Mutex<Option<AnimationContext>>>
//!     - CSampleCredential: 创建并存入 AnimationContext
//!     - CPipeListener: 通过 set_state() 驱动状态变更
//!     - RenderThread: 读取状态并渲染对应动画

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows::Foundation::Numerics::Matrix3x2;
use windows::Win32::{
    Foundation::{BOOL, HMODULE, HWND, LPARAM, POINT, RECT},
    Graphics::{
        Direct2D::{
            Common::{
                D2D1_ALPHA_MODE_PREMULTIPLIED, D2D1_COLOR_F, D2D1_FIGURE_BEGIN_FILLED,
                D2D1_FIGURE_BEGIN_HOLLOW, D2D1_FIGURE_END_OPEN, D2D1_PIXEL_FORMAT,
                D2D_POINT_2F, D2D_SIZE_F, D2D_RECT_F,
            },
            D2D1CreateFactory, ID2D1Bitmap1, ID2D1DeviceContext, ID2D1Factory1,
            ID2D1PathGeometry1, ID2D1StrokeStyle, D2D1_ARC_SEGMENT,
            D2D1_ARC_SIZE_SMALL, D2D1_BITMAP_OPTIONS_CANNOT_DRAW, D2D1_BITMAP_OPTIONS_TARGET,
            D2D1_BITMAP_PROPERTIES1, D2D1_DEVICE_CONTEXT_OPTIONS_NONE, D2D1_ELLIPSE,
            D2D1_FACTORY_TYPE_SINGLE_THREADED, D2D1_SWEEP_DIRECTION_CLOCKWISE,
            ID2D1Brush, ID2D1Geometry,
        },
        Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL},
        Direct3D11::{
            D3D11CreateDevice, ID3D11Device, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION,
        },
        DirectComposition::{
            DCompositionCreateDevice2, IDCompositionDesktopDevice, IDCompositionVisual2,
        },
        Dxgi::{Common::DXGI_FORMAT_B8G8R8A8_UNORM, IDXGIDevice, IDXGISurface},
        Gdi::{
            EnumDisplaySettingsW, GetMonitorInfoW, MonitorFromWindow,
            DEVMODEW, ENUM_CURRENT_SETTINGS, MONITORINFOEXW, MONITOR_DEFAULTTOPRIMARY,
        },
    },
    UI::WindowsAndMessaging::{
        EnumChildWindows, GetClassNameW, GetClientRect, GetDlgCtrlID, GetWindowLongW,
        GetWindowRect, GetWindowTextW, IsWindowVisible, GWL_STYLE,
    },
};
use windows_core::Interface;

use crate::read_facewinunlock_registry;

// ── 常量 ──────────────────────────────────────────────────────

const ANIM_WIDTH: u32 = 128;
const ANIM_HEIGHT: u32 = 128;

const RING_RADIUS: f32 = 48.0;
const RING_CENTER_X: f32 = 64.0;
const RING_CENTER_Y: f32 = 64.0;
const ARC_SPAN_DEG: f32 = 120.0;
const BG_STROKE_WIDTH: f32 = 2.0;
const ARC_STROKE_WIDTH: f32 = 3.0;
const ROTATION_SPEED: f32 = 180.0;
const DEFAULT_FPS: u32 = 60;

/// Success/Failure 动画持续后自动退回 Idle 的时间
const OUTCOME_TIMEOUT_SECS: f32 = 2.0;

const TILE_FIND_RETRY_MS: u64 = 200;
const TILE_FIND_MAX_RETRIES: u32 = 15;
const TILE_MIN_SIZE: i32 = 64;
const TILE_MAX_SIZE: i32 = 512;

// ── 帧率检测 ─────────────────────────────────────────────────

/// 查询 `hwnd` 所在显示器的刷新率（Hz）。
/// 失败时返回 `DEFAULT_FPS`。
fn query_monitor_refresh_rate(hwnd: HWND) -> u32 {
    unsafe {
        let hmon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTOPRIMARY);
        let mut mi = MONITORINFOEXW::default();
        mi.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;

        if !GetMonitorInfoW(hmon, &mut mi as *mut MONITORINFOEXW as *mut _).as_bool() {
            log::warn!("[anim] GetMonitorInfoW failed, fallback {DEFAULT_FPS} Hz");
            return DEFAULT_FPS;
        }

        let mut dm = DEVMODEW::default();
        dm.dmSize = std::mem::size_of::<DEVMODEW>() as u16;

        if !EnumDisplaySettingsW(
            windows_core::PCWSTR::from_raw(mi.szDevice.as_ptr()),
            ENUM_CURRENT_SETTINGS,
            &mut dm,
        ).as_bool() {
            log::warn!("[anim] EnumDisplaySettingsW failed, fallback {DEFAULT_FPS} Hz");
            return DEFAULT_FPS;
        }

        let hz = dm.dmDisplayFrequency;
        if hz == 0 || hz == 1 {
            // 0/1 = 驱动未报告有效值
            log::warn!("[anim] driver reported {hz} Hz, fallback {DEFAULT_FPS} Hz");
            return DEFAULT_FPS;
        }
        hz
    }
}

// ── 动画状态 ──────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum AnimState {
    Idle,
    Scanning,
    Success,
    Failure,
}

/// 状态 + 进入时间（渲染线程原子读取）
struct AnimStateData {
    state: AnimState,
    entered_at: Instant,
}

// ── 共享状态 ──────────────────────────────────────────────────

struct RenderState {
    stop: AtomicBool,
    /// 动画状态 + 状态进入时间（Mutex 保护）
    anim: Mutex<AnimStateData>,
}

// ── AnimationContext（主线程控制器）───────────────────────────

pub struct AnimationContext {
    parent_hwnd: HWND,
    render_state: Arc<RenderState>,
    render_thread: Option<JoinHandle<()>>,
}

unsafe impl Send for AnimationContext {}

impl AnimationContext {
    pub fn new(parent_hwnd: HWND, tile_search_text: &str) -> windows_core::Result<Self> {
        let hwnd_raw = parent_hwnd.0 as isize;
        let search_utf16: Vec<u16> = tile_search_text.encode_utf16().collect();

        let render_state = Arc::new(RenderState {
            stop: AtomicBool::new(false),
            anim: Mutex::new(AnimStateData {
                state: AnimState::Scanning,
                entered_at: Instant::now(),
            }),
        });

        let thread_state = render_state.clone();
        let thread = std::thread::spawn(move || {
            let hwnd = HWND(hwnd_raw as *mut std::ffi::c_void);
            if let Err(_e) = run_render_loop(hwnd, &search_utf16, thread_state) {
                // 渲染失败不影响登录
            }
        });

        Ok(Self {
            parent_hwnd,
            render_state,
            render_thread: Some(thread),
        })
    }

    /// 切换动画状态（由 CPipeListener 从管道线程调用）
    pub fn set_state(&self, new_state: AnimState) {
        if let Ok(mut a) = self.render_state.anim.lock() {
            if a.state != new_state {
                log::info!("[anim] state transition {:?} → {new_state:?}", a.state);
                a.state = new_state;
                a.entered_at = Instant::now();
            }
        }
    }

    #[allow(dead_code)]
    pub fn parent_hwnd(&self) -> HWND {
        self.parent_hwnd
    }
}

impl Drop for AnimationContext {
    fn drop(&mut self) {
        self.render_state.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.render_thread.take() {
            let _ = t.join();
        }
    }
}

// ── 公开槽位类型（Arc 共享版本）───────────────────────────────

/// Arc-wrapped animation slot，可跨组件共享
pub type AnimationSlot = Arc<Mutex<Option<AnimationContext>>>;

pub fn make_slot() -> AnimationSlot {
    Arc::new(Mutex::new(None))
}

// ── Matrix3x2 辅助 ────────────────────────────────────────────

fn mat_identity() -> Matrix3x2 {
    Matrix3x2 { M11: 1.0, M12: 0.0, M21: 0.0, M22: 1.0, M31: 0.0, M32: 0.0 }
}

fn mat_rotation(angle_deg: f32, cx: f32, cy: f32) -> Matrix3x2 {
    let a = angle_deg.to_radians();
    let (s, c) = a.sin_cos();
    Matrix3x2 {
        M11: c,  M12: s,
        M21: -s, M22: c,
        M31: cx * (1.0 - c) + cy * s,
        M32: cy * (1.0 - c) - cx * s,
    }
}

fn mat_scale(sx: f32, sy: f32, cx: f32, cy: f32) -> Matrix3x2 {
    Matrix3x2 {
        M11: sx,  M12: 0.0,
        M21: 0.0, M22: sy,
        M31: cx * (1.0 - sx),
        M32: cy * (1.0 - sy),
    }
}

fn mat_mul(a: &Matrix3x2, b: &Matrix3x2) -> Matrix3x2 {
    Matrix3x2 {
        M11: a.M11 * b.M11 + a.M12 * b.M21,
        M12: a.M11 * b.M12 + a.M12 * b.M22,
        M21: a.M21 * b.M11 + a.M22 * b.M21,
        M22: a.M21 * b.M12 + a.M22 * b.M22,
        M31: a.M31 * b.M11 + a.M32 * b.M21 + b.M31,
        M32: a.M31 * b.M12 + a.M32 * b.M22 + b.M32,
    }
}

// ── 磁贴定位（多层策略 + 自诊断）─────────────────────────────

unsafe fn dump_child_windows(parent: HWND) {
    struct Ctx;
    unsafe extern "system" fn callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let mut cls = vec![0u16; 128];
        let cls_len = GetClassNameW(hwnd, &mut cls);
        let mut text = vec![0u16; 128];
        let text_len = GetWindowTextW(hwnd, &mut text);
        let mut rect = RECT::default();
        let _ = GetWindowRect(hwnd, &mut rect);
        let w = rect.right - rect.left;
        let h = rect.bottom - rect.top;
        let visible = IsWindowVisible(hwnd).as_bool();
        let ctrl_id = GetDlgCtrlID(hwnd);
        let style = GetWindowLongW(hwnd, GWL_STYLE);
        let _ctx = &*(lparam.0 as *const Ctx);
        log::info!(
            "[anim-dump] cls=\"{}\" text=\"{}\" rect=({},{})-{}x{} vis={visible} ctrl_id=0x{ctrl_id:X} style=0x{style:X}",
            String::from_utf16_lossy(&cls[..cls_len as usize]),
            String::from_utf16_lossy(&text[..text_len as usize]),
            rect.left, rect.top, w, h,
        );
        BOOL(1)
    }
    log::info!("[anim-dump] === begin (parent={parent:?}) ===");
    let _ = EnumChildWindows(Some(parent), Some(callback), LPARAM(0));
    log::info!("[anim-dump] === end ===");
}

unsafe fn screen_to_parent_rect(parent: HWND, child: HWND) -> Option<RECT> {
    let mut cr = RECT::default();
    let mut pr = RECT::default();
    if GetWindowRect(child, &mut cr).is_err() || GetWindowRect(parent, &mut pr).is_err() {
        return None;
    }
    Some(RECT { left: cr.left - pr.left, top: cr.top - pr.top, right: cr.right - pr.left, bottom: cr.bottom - pr.top })
}

unsafe fn find_by_text(parent: HWND, search: &[u16]) -> Option<RECT> {
    struct Ctx { search: Vec<u16>, parent: HWND, result: Option<RECT> }
    unsafe extern "system" fn cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let ctx = &mut *(lparam.0 as *mut Ctx);
        let mut buf = vec![0u16; 256];
        let len = GetWindowTextW(hwnd, &mut buf);
        if len > 0 && buf[..len as usize].windows(ctx.search.len()).any(|w| w == ctx.search) {
            ctx.result = screen_to_parent_rect(ctx.parent, hwnd);
            return BOOL(0);
        }
        BOOL(1)
    }
    let mut ctx = Ctx { search: search.to_vec(), parent, result: None };
    let _ = EnumChildWindows(Some(parent), Some(cb), LPARAM(&mut ctx as *mut _ as isize));
    ctx.result
}

unsafe fn find_by_size_heuristic(parent: HWND) -> Option<RECT> {
    struct Candidate { rect: RECT, score: i32 }
    struct Ctx { parent: HWND, candidates: Vec<Candidate> }
    unsafe extern "system" fn cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let ctx = &mut *(lparam.0 as *mut Ctx);
        if !IsWindowVisible(hwnd).as_bool() { return BOOL(1); }
        let rect = match screen_to_parent_rect(ctx.parent, hwnd) { Some(r) => r, None => return BOOL(1) };
        let w = rect.right - rect.left;
        let h = rect.bottom - rect.top;
        if w < TILE_MIN_SIZE || w > TILE_MAX_SIZE || h < TILE_MIN_SIZE || h > TILE_MAX_SIZE { return BOOL(1); }
        if (w - h).abs() > w / 2 { return BOOL(1); }
        let size_score = 100 - ((w - 192).abs() + (h - 192).abs()) / 4;
        let parent_h = { let mut pr = RECT::default(); if GetWindowRect(ctx.parent, &mut pr).is_err() { return BOOL(1); } pr.bottom - pr.top };
        // 凭据磁贴图像区在父窗口上半部；偏向选择上方窗口
        let pos_score = if rect.top < parent_h / 2 { 50 } else { 0 };
        ctx.candidates.push(Candidate { rect, score: size_score + pos_score });
        BOOL(1)
    }
    let mut ctx = Ctx { parent, candidates: Vec::new() };
    let _ = EnumChildWindows(Some(parent), Some(cb), LPARAM(&mut ctx as *mut _ as isize));
    ctx.candidates.sort_by_key(|c| -c.score);
    ctx.candidates.first().map(|c| c.rect)
}

unsafe fn find_by_registry_offset(_parent: HWND) -> Option<RECT> {
    let ox = crate::read_facewinunlock_registry("ANIMATION_OFFSET_X").ok().and_then(|v| v.trim().parse::<i32>().ok());
    let oy = crate::read_facewinunlock_registry("ANIMATION_OFFSET_Y").ok().and_then(|v| v.trim().parse::<i32>().ok());
    match (ox, oy) {
        (Some(x), Some(y)) => Some(RECT { left: x, top: y, right: x + ANIM_WIDTH as i32, bottom: y + ANIM_HEIGHT as i32 }),
        _ => None,
    }
}

unsafe fn fallback_position(parent: HWND) -> RECT {
    let mut cr = RECT::default();
    let _ = GetClientRect(parent, &mut cr);
    let cx = (cr.right - cr.left) / 2;
    // 凭据磁贴图像区在父窗口上方约 1/4 处
    // VM 实测：2/3 → PIN 输入区；1/3 → 与用户头像重合；1/4 → 头像上方
    let cy = (cr.bottom - cr.top) / 4;
    RECT { left: cx - ANIM_WIDTH as i32 / 2, top: cy - ANIM_HEIGHT as i32 / 2, right: cx + ANIM_WIDTH as i32 / 2, bottom: cy + ANIM_HEIGHT as i32 / 2 }
}

unsafe fn find_tile_position(parent: HWND, search_text: &[u16]) -> (RECT, &'static str) {
    dump_child_windows(parent);
    for _ in 0..TILE_FIND_MAX_RETRIES {
        if let Some(r) = find_by_text(parent, search_text) { return (r, "text_match"); }
        if let Some(r) = find_by_size_heuristic(parent) { return (r, "size_heuristic"); }
        std::thread::sleep(Duration::from_millis(TILE_FIND_RETRY_MS));
    }
    if let Some(r) = find_by_registry_offset(parent) { return (r, "registry_offset"); }
    (fallback_position(parent), "fallback")
}

// ── 几何体预创建 ──────────────────────────────────────────────

struct PrebuiltGeo {
    arc: ID2D1Geometry,
    check: ID2D1PathGeometry1,
    cross: ID2D1PathGeometry1,
}

/// 预创建弧、对号、叉号几何体
unsafe fn create_all_geometries(factory: &ID2D1Factory1) -> windows_core::Result<PrebuiltGeo> {
    // ── 弧（120°）─
    let arc = create_arc_geometry(factory, RING_RADIUS, ARC_SPAN_DEG)?;
    let arc_geom: ID2D1Geometry = arc.cast()?;

    // ── 对号 ─
    let check = factory.CreatePathGeometry()?;
    {
        let sink = check.Open()?;
        sink.BeginFigure(
            D2D_POINT_2F { x: RING_CENTER_X - 16.0, y: RING_CENTER_Y + 2.0 },
            D2D1_FIGURE_BEGIN_FILLED,
        );
        sink.AddLine(D2D_POINT_2F { x: RING_CENTER_X - 4.0, y: RING_CENTER_Y + 14.0 });
        sink.AddLine(D2D_POINT_2F { x: RING_CENTER_X + 18.0, y: RING_CENTER_Y - 14.0 });
        sink.EndFigure(D2D1_FIGURE_END_OPEN);
        sink.Close()?;
    }

    // ── 叉号 ─
    let cross = factory.CreatePathGeometry()?;
    {
        let sink = cross.Open()?;
        let d = 14.0;
        sink.BeginFigure(
            D2D_POINT_2F { x: RING_CENTER_X - d, y: RING_CENTER_Y - d },
            D2D1_FIGURE_BEGIN_FILLED,
        );
        sink.AddLine(D2D_POINT_2F { x: RING_CENTER_X + d, y: RING_CENTER_Y + d });
        sink.EndFigure(D2D1_FIGURE_END_OPEN);
        // 第二段
        sink.BeginFigure(
            D2D_POINT_2F { x: RING_CENTER_X + d, y: RING_CENTER_Y - d },
            D2D1_FIGURE_BEGIN_FILLED,
        );
        sink.AddLine(D2D_POINT_2F { x: RING_CENTER_X - d, y: RING_CENTER_Y + d });
        sink.EndFigure(D2D1_FIGURE_END_OPEN);
        sink.Close()?;
    }

    Ok(PrebuiltGeo { arc: arc_geom, check, cross })
}

// ── D2D 几何体辅助创建 ────────────────────────────────────────

unsafe fn create_arc_geometry(
    factory: &ID2D1Factory1,
    radius: f32,
    span_deg: f32,
) -> windows_core::Result<ID2D1PathGeometry1> {
    let geometry = factory.CreatePathGeometry()?;
    let sink = geometry.Open()?;
    let half_rad = (span_deg / 2.0).to_radians();
    // Arc 起止点相对于圆心 (RING_CENTER_X, RING_CENTER_Y)，确保始终在 128×128 曲面内
    // 起点：圆心右上方 half_span 角处；终点：圆心右下方 half_span 角处（顺时针）
    sink.BeginFigure(
        D2D_POINT_2F {
            x: RING_CENTER_X + radius * half_rad.cos(),
            y: RING_CENTER_Y - radius * half_rad.sin(),
        },
        D2D1_FIGURE_BEGIN_HOLLOW,
    );
    sink.AddArc(&D2D1_ARC_SEGMENT {
        point: D2D_POINT_2F {
            x: RING_CENTER_X + radius * half_rad.cos(),
            y: RING_CENTER_Y + radius * half_rad.sin(),
        },
        size: D2D_SIZE_F { width: radius, height: radius },
        rotationAngle: 0.0,
        sweepDirection: D2D1_SWEEP_DIRECTION_CLOCKWISE,
        arcSize: D2D1_ARC_SIZE_SMALL, // 120° < 180°，使用 SMALL
    });
    sink.EndFigure(D2D1_FIGURE_END_OPEN);
    sink.Close()?;
    Ok(geometry)
}

// ── 渲染线程 ──────────────────────────────────────────────────

fn run_render_loop(
    parent_hwnd: HWND,
    tile_search_text: &[u16],
    state: Arc<RenderState>,
) -> windows_core::Result<()> {
    unsafe {
        let mut d3d_device: Option<ID3D11Device> = None;
        let mut feature_level = D3D_FEATURE_LEVEL::default();
        D3D11CreateDevice(None, D3D_DRIVER_TYPE_HARDWARE, HMODULE::default(), D3D11_CREATE_DEVICE_BGRA_SUPPORT, None, D3D11_SDK_VERSION, Some(&mut d3d_device), Some(&mut feature_level), None)?;
        let d3d_device = d3d_device.ok_or_else(|| windows::core::Error::new(windows::Win32::Foundation::E_FAIL, "D3D11 设备为空"))?;

        let dxgi_device: IDXGIDevice = d3d_device.cast()?;
        let dcomp_device: IDCompositionDesktopDevice = DCompositionCreateDevice2(&dxgi_device)?;
        let dcomp_target = dcomp_device.CreateTargetForHwnd(parent_hwnd, true)?;
        let dcomp_visual: IDCompositionVisual2 = dcomp_device.CreateVisual()?.cast()?;
        dcomp_target.SetRoot(&dcomp_visual)?;

        let (tile_rect, strategy) = find_tile_position(parent_hwnd, tile_search_text);
        log::info!("[anim] tile strategy={strategy} rect=({},{})-({},{})", tile_rect.left, tile_rect.top, tile_rect.right, tile_rect.bottom);
        let tile_cx = (tile_rect.left + tile_rect.right) / 2;
        let tile_cy = (tile_rect.top + tile_rect.bottom) / 2;
        dcomp_visual.SetOffsetX2((tile_cx - ANIM_WIDTH as i32 / 2) as f32)?;
        dcomp_visual.SetOffsetY2((tile_cy - ANIM_HEIGHT as i32 / 2) as f32)?;

        let dcomp_surface = dcomp_device.CreateVirtualSurface(ANIM_WIDTH, ANIM_HEIGHT, DXGI_FORMAT_B8G8R8A8_UNORM, windows::Win32::Graphics::Dxgi::Common::DXGI_ALPHA_MODE_PREMULTIPLIED)?;
        dcomp_visual.SetContent(&dcomp_surface)?;
        dcomp_device.Commit()?;

        let d2d_factory: ID2D1Factory1 = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, None)?;
        let d2d_device = d2d_factory.CreateDevice(&dxgi_device)?;
        let d2d_context = d2d_device.CreateDeviceContext(D2D1_DEVICE_CONTEXT_OPTIONS_NONE)?;

        let bg_brush: ID2D1Brush = d2d_context.CreateSolidColorBrush(&D2D1_COLOR_F { r: 0.4, g: 0.4, b: 0.45, a: 0.35 }, None)?.cast()?;
        let arc_brush: ID2D1Brush = d2d_context.CreateSolidColorBrush(&D2D1_COLOR_F { r: 0.2, g: 0.6, b: 0.95, a: 1.0 }, None)?.cast()?;
        let success_bg: ID2D1Brush = d2d_context.CreateSolidColorBrush(&D2D1_COLOR_F { r: 0.15, g: 0.75, b: 0.35, a: 1.0 }, None)?.cast()?;
        let failure_bg: ID2D1Brush = d2d_context.CreateSolidColorBrush(&D2D1_COLOR_F { r: 0.9, g: 0.2, b: 0.2, a: 1.0 }, None)?.cast()?;
        let white_brush: ID2D1Brush = d2d_context.CreateSolidColorBrush(&D2D1_COLOR_F { r: 1.0, g: 1.0, b: 1.0, a: 1.0 }, None)?.cast()?;

        let geo = create_all_geometries(&d2d_factory)?;
        let check_geom: ID2D1Geometry = geo.check.cast().unwrap();
        let cross_geom: ID2D1Geometry = geo.cross.cast().unwrap();

        // 帧率：注册表 ANIMATION_FPS 覆盖 > 显示器刷新率 > 默认 60
        let monitor_hz = query_monitor_refresh_rate(parent_hwnd);
        let target_fps = read_facewinunlock_registry("ANIMATION_FPS")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(monitor_hz)
            .clamp(10, 240);
        let frame_dur = Duration::from_micros(1_000_000 / target_fps as u64);
        log::info!("[anim] monitor={monitor_hz} Hz, target FPS={target_fps} (frame_dur={frame_dur:?})");
        let app_start = Instant::now();

        loop {
            if state.stop.load(Ordering::SeqCst) { break; }

            let frame_start = Instant::now();
            let elapsed = app_start.elapsed().as_secs_f64();
            let angle = (elapsed * ROTATION_SPEED as f64) as f32 % 360.0;

            // 读取状态 + 进入时间
            let (current_state, state_age) = {
                let a = state.anim.lock().unwrap();
                (a.state, a.entered_at.elapsed())
            };

            // Success/Failure 超时自动退回 Idle
            let effective_state = match current_state {
                AnimState::Success | AnimState::Failure
                    if state_age > Duration::from_secs_f32(OUTCOME_TIMEOUT_SECS) =>
                {
                    // 自动过渡
                    drop(state.anim.lock()); // 避免死锁
                    if let Ok(mut a) = state.anim.lock() {
                        if matches!(a.state, AnimState::Success | AnimState::Failure) {
                            a.state = AnimState::Idle;
                            a.entered_at = Instant::now();
                        }
                    }
                    AnimState::Idle
                }
                other => other,
            };

            let mut offset = POINT::default();
            let update_rect = RECT { left: 0, top: 0, right: ANIM_WIDTH as i32, bottom: ANIM_HEIGHT as i32 };
            let dxgi_surface: IDXGISurface = dcomp_surface.BeginDraw(Some(&update_rect), &mut offset)?;

            let bitmap_props = D2D1_BITMAP_PROPERTIES1 {
                pixelFormat: D2D1_PIXEL_FORMAT { format: DXGI_FORMAT_B8G8R8A8_UNORM, alphaMode: D2D1_ALPHA_MODE_PREMULTIPLIED },
                dpiX: 96.0, dpiY: 96.0,
                bitmapOptions: D2D1_BITMAP_OPTIONS_TARGET | D2D1_BITMAP_OPTIONS_CANNOT_DRAW,
                colorContext: std::mem::ManuallyDrop::new(None),
            };
            let bitmap: ID2D1Bitmap1 = d2d_context.CreateBitmapFromDxgiSurface(&dxgi_surface, Some(&bitmap_props))?;

            d2d_context.SetTarget(&bitmap);
            d2d_context.BeginDraw();
            d2d_context.Clear(None);

            match effective_state {
                AnimState::Idle => render_idle(&d2d_context, &bg_brush, &arc_brush, &geo.arc, angle)?,
                AnimState::Scanning => render_scanning(&d2d_context, &bg_brush, &arc_brush, &geo.arc, angle)?,
                AnimState::Success => render_success(&d2d_context, &success_bg, &white_brush, &check_geom, &state_age)?,
                AnimState::Failure => render_failure(&d2d_context, &failure_bg, &white_brush, &cross_geom, &state_age)?,
            }

            d2d_context.EndDraw(None, None)?;
            d2d_context.SetTarget(None);
            let _bh = bitmap;
            dcomp_surface.EndDraw()?;
            dcomp_device.Commit()?;

            let ft = frame_start.elapsed();
            if ft < frame_dur { std::thread::sleep(frame_dur - ft); }
        }
        Ok(())
    }
}

// ── 绘制函数 ──────────────────────────────────────────────────

unsafe fn render_scanning(
    ctx: &ID2D1DeviceContext, bg: &ID2D1Brush, arc_brush: &ID2D1Brush,
    arc_geom: &ID2D1Geometry, angle: f32,
) -> windows_core::Result<()> {
    ctx.DrawEllipse(&D2D1_ELLIPSE { point: D2D_POINT_2F { x: RING_CENTER_X, y: RING_CENTER_Y }, radiusX: RING_RADIUS, radiusY: RING_RADIUS }, bg, BG_STROKE_WIDTH, None::<&ID2D1StrokeStyle>);
    let rot = mat_rotation(angle, RING_CENTER_X, RING_CENTER_Y);
    ctx.SetTransform(&rot);
    ctx.DrawGeometry(arc_geom, arc_brush, ARC_STROKE_WIDTH, None::<&ID2D1StrokeStyle>);
    ctx.SetTransform(&mat_identity());
    Ok(())
}

unsafe fn render_idle(
    ctx: &ID2D1DeviceContext, bg: &ID2D1Brush, arc_brush: &ID2D1Brush,
    arc_geom: &ID2D1Geometry, angle: f32,
) -> windows_core::Result<()> {
    let pulse = 0.925 + 0.075 * (angle.to_radians() * 4.0).sin();
    ctx.DrawEllipse(&D2D1_ELLIPSE { point: D2D_POINT_2F { x: RING_CENTER_X, y: RING_CENTER_Y }, radiusX: RING_RADIUS, radiusY: RING_RADIUS }, bg, BG_STROKE_WIDTH, None::<&ID2D1StrokeStyle>);
    let rot = mat_rotation(angle, RING_CENTER_X, RING_CENTER_Y);
    let scl = mat_scale(pulse, pulse, RING_CENTER_X, RING_CENTER_Y);
    let xform = mat_mul(&rot, &scl);
    ctx.SetTransform(&xform);
    ctx.DrawGeometry(arc_geom, arc_brush, ARC_STROKE_WIDTH, None::<&ID2D1StrokeStyle>);
    ctx.SetTransform(&mat_identity());
    Ok(())
}

/// Success: 绿色圆 + 白色对号，2 秒淡出
unsafe fn render_success(
    ctx: &ID2D1DeviceContext, bg: &ID2D1Brush, fg: &ID2D1Brush,
    check: &ID2D1Geometry, age: &Duration,
) -> windows_core::Result<()> {
    let progress = (age.as_secs_f32() / OUTCOME_TIMEOUT_SECS).clamp(0.0, 1.0);
    let alpha = 1.0 - progress;

    // 绿色填充圆
    ctx.DrawEllipse(&D2D1_ELLIPSE { point: D2D_POINT_2F { x: RING_CENTER_X, y: RING_CENTER_Y }, radiusX: RING_RADIUS, radiusY: RING_RADIUS }, bg, 3.0, None::<&ID2D1StrokeStyle>);
    // 对号
    ctx.DrawGeometry(check, fg, 4.0, None::<&ID2D1StrokeStyle>);

    // 全局透明度淡出（通过全表面覆盖半透明黑色）
    if alpha < 1.0 {
        let fade = 1.0 - alpha;
        let overlay = ctx.CreateSolidColorBrush(&D2D1_COLOR_F { r: 0.0, g: 0.0, b: 0.0, a: fade }, None)?;
        ctx.FillRectangle(&D2D_RECT_F { left: 0.0, top: 0.0, right: ANIM_WIDTH as f32, bottom: ANIM_HEIGHT as f32 }, &overlay);
    }
    Ok(())
}

/// Failure: 红色圆 + 叉号 + 水平抖动，2 秒淡出
unsafe fn render_failure(
    ctx: &ID2D1DeviceContext, bg: &ID2D1Brush, fg: &ID2D1Brush,
    cross: &ID2D1Geometry, age: &Duration,
) -> windows_core::Result<()> {
    let progress = (age.as_secs_f32() / OUTCOME_TIMEOUT_SECS).clamp(0.0, 1.0);
    let alpha = 1.0 - progress;
    // 水平抖动（前 0.5s 明显，之后衰减）
    let shake = (age.as_secs_f32() * 30.0).sin() * 8.0 * (1.0 - progress).powi(2);

    let xform = mat_mul(&mat_identity(), &Matrix3x2 { M11: 1.0, M12: 0.0, M21: 0.0, M22: 1.0, M31: shake, M32: 0.0 });
    ctx.SetTransform(&xform);

    ctx.DrawEllipse(&D2D1_ELLIPSE { point: D2D_POINT_2F { x: RING_CENTER_X, y: RING_CENTER_Y }, radiusX: RING_RADIUS, radiusY: RING_RADIUS }, bg, 3.0, None::<&ID2D1StrokeStyle>);
    ctx.DrawGeometry(cross, fg, 3.5, None::<&ID2D1StrokeStyle>);
    ctx.SetTransform(&mat_identity());

    // 淡出遮罩
    if alpha < 1.0 {
        let fade = 1.0 - alpha;
        let overlay = ctx.CreateSolidColorBrush(&D2D1_COLOR_F { r: 0.0, g: 0.0, b: 0.0, a: fade }, None)?;
        ctx.FillRectangle(&D2D_RECT_F { left: 0.0, top: 0.0, right: ANIM_WIDTH as f32, bottom: ANIM_HEIGHT as f32 }, &overlay);
    }
    Ok(())
}
