//! 动画 UI 管线（阶段 E · 预渲染帧 + 文字叠加）
//!
//! DComp topmost 层叠加在 LogonUI 凭据磁贴上方，60 FPS GPU 动画。
//! 状态机：Idle → Scanning → Success|Failure → (2s) → Idle
//!
//! 动画设计来源：https://uiverse.io/StealthWorm/pink-duck-62
//!
//! 架构：浏览器预渲染帧序列 + DWrite 动态文字叠加
//!   构建时：Puppeteer 渲染 HTML/CSS → 导出 BGRA8 帧序列 (animation_frames.bin)
//!   运行时：加载帧 → ID2D1Bitmap1 Vec → 每帧 DrawImage + 文字 + 状态特效

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows::core::w;
use windows::Foundation::Numerics::Matrix3x2;
use windows::Win32::{
    Foundation::{BOOL, HMODULE, HWND, LPARAM, POINT, RECT},
    Graphics::{
        Direct2D::{
            Common::{
                D2D1_ALPHA_MODE_PREMULTIPLIED, D2D1_COLOR_F, D2D1_FIGURE_BEGIN_FILLED,
                D2D1_FIGURE_END_OPEN, D2D1_PIXEL_FORMAT,
                D2D_POINT_2F, D2D_RECT_F, D2D_SIZE_U,
                D2D1_COMPOSITE_MODE_SOURCE_OVER,
            },
            D2D1CreateFactory, ID2D1Bitmap1, ID2D1DeviceContext, ID2D1Factory1,
            ID2D1PathGeometry1, ID2D1StrokeStyle, ID2D1RenderTarget,
            D2D1_BITMAP_OPTIONS_CANNOT_DRAW, D2D1_BITMAP_OPTIONS_TARGET,
            D2D1_BITMAP_PROPERTIES1, D2D1_DEVICE_CONTEXT_OPTIONS_NONE, D2D1_ELLIPSE,
            D2D1_FACTORY_TYPE_SINGLE_THREADED,
            ID2D1Geometry, ID2D1SolidColorBrush,
            D2D1_INTERPOLATION_MODE_LINEAR,
            D2D1_DRAW_TEXT_OPTIONS_NONE,
        },
        Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL},
        Direct3D11::{
            D3D11CreateDevice, ID3D11Device, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION,
        },
        DirectComposition::{
            DCompositionCreateDevice2, IDCompositionDesktopDevice, IDCompositionVisual2,
        },
        DirectWrite::{
            DWriteCreateFactory, IDWriteFactory, IDWriteTextFormat,
            DWRITE_FACTORY_TYPE_SHARED, DWRITE_TEXT_ALIGNMENT_CENTER,
            DWRITE_PARAGRAPH_ALIGNMENT_CENTER, DWRITE_FONT_WEIGHT_BOLD,
            DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL,
            DWRITE_MEASURING_MODE_NATURAL,
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

// CRITICAL: ANIM_WIDTH/HEIGHT 必须与以下两处保持一致，create_frames() 会 assert：
//   - UI/resources/capture_frames.js WIDTH / HEIGHT
//   - UI/resources/animation_render.html body { width / height }
const ANIM_WIDTH: u32 = 200;
const ANIM_HEIGHT: u32 = 200;

const CX: f32 = 100.0;
const CY: f32 = 100.0;

// 文字
const TEXT_RADIUS: f32 = 84.0;
const TEXT_FONT_SIZE: f32 = 14.0;
const TEXT_ARC_DEG: f32 = 260.0;
const TEXT_START_DEG: f32 = 230.0;

const TEXT_PERIOD_IDLE: f32 = 8.0;
const TEXT_PERIOD_SCAN: f32 = 3.0;

// 预渲染帧参数（须与 capture_frames.js 一致）
const FRAME_PERIOD: f64 = 6.0;

const DEFAULT_FPS: u32 = 60;
const OUTCOME_TIMEOUT_SECS: f32 = 2.0;
const TILE_FIND_RETRY_MS: u64 = 200;
const TILE_FIND_MAX_RETRIES: u32 = 15;
const TILE_MIN_SIZE: i32 = 64;
const TILE_MAX_SIZE: i32 = 512;

// ── 帧率检测 ─────────────────────────────────────────────────

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
            log::warn!("[anim] driver reported {hz} Hz, fallback {DEFAULT_FPS} Hz");
            return DEFAULT_FPS;
        }
        hz
    }
}

// ── 动画状态（公共接口不变）──────────────────────────────────

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum AnimState {
    Idle,
    Scanning,
    Success,
    Failure,
}

struct AnimStateData {
    state: AnimState,
    entered_at: Instant,
}

struct RenderState {
    stop: AtomicBool,
    anim: Mutex<AnimStateData>,
}

// ── AnimationContext（公共接口不变）───────────────────────────

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
            if let Err(e) = run_render_loop(hwnd, &search_utf16, thread_state) {
                log::error!("[anim] render loop failed: {:?}", e);
            }
        });

        Ok(Self {
            parent_hwnd,
            render_state,
            render_thread: Some(thread),
        })
    }

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

fn mat_translate(tx: f32, ty: f32) -> Matrix3x2 {
    Matrix3x2 { M11: 1.0, M12: 0.0, M21: 0.0, M22: 1.0, M31: tx, M32: ty }
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

// ── 颜色工具 ──────────────────────────────────────────────────

fn color(r: f32, g: f32, b: f32, a: f32) -> D2D1_COLOR_F {
    D2D1_COLOR_F { r, g, b, a }
}

// ── 预构建资源 ────────────────────────────────────────────────

struct BlackHoleRes {
    // 预渲染帧
    frames: Vec<ID2D1Bitmap1>,
    total_frames: u32,

    // 纯色笔刷
    white_brush: ID2D1SolidColorBrush,
    green_brush: ID2D1SolidColorBrush,
    red_brush: ID2D1SolidColorBrush,
    black_brush: ID2D1SolidColorBrush,

    // 文字
    text_format: IDWriteTextFormat,

    // 几何体
    check: ID2D1PathGeometry1,
    cross: ID2D1PathGeometry1,
}

/// 查找帧数据文件，返回原始字节
fn load_frames_raw() -> Result<Vec<u8>, String> {
    // 1. 注册表自定义路径（最高优先级，供高级用户覆盖）
    if let Ok(custom) = read_facewinunlock_registry("ANIMATION_FRAMES_PATH") {
        let path = custom.trim();
        if !path.is_empty() {
            log::info!("[anim] trying registry override path: {path}");
            if let Ok(data) = std::fs::read(path) {
                log::info!("[anim] loaded frames from registry override: {path}");
                return Ok(data);
            }
            log::warn!("[anim] registry override path not found: {path}");
        }
    }

    // 2. 安装目录（DLL_LOG_PATH 由 UI 安装时写入，指向 ROOT_DIR）
    if let Ok(raw) = read_facewinunlock_registry("DLL_LOG_PATH") {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            log::warn!("[anim] DLL_LOG_PATH is empty in registry, skipping install-dir lookup");
        } else {
            let stripped = if let Some(rest) = trimmed.strip_prefix("\\\\?\\") {
                rest
            } else {
                trimmed
            };
            let install_dir = stripped.trim_end_matches('\\');
            for rel in &["resources\\animation_frames.bin", "animation_frames.bin"] {
                let p = format!("{}\\{}", install_dir, rel);
                match std::fs::read(&p) {
                    Ok(data) => {
                        log::info!("[anim] loaded frames from install dir: {p}");
                        return Ok(data);
                    }
                    Err(e) => log::info!("[anim] tried {}: {}", p, e),
                }
            }
        }
    }

    // 3. DLL 自身所在目录（开发/测试场景 DLL 未注册到 System32 时）
    match get_dll_directory() {
        Ok(dll_dir) => {
            for rel in &["resources\\animation_frames.bin", "animation_frames.bin"] {
                let p = format!("{}\\{}", dll_dir, rel);
                match std::fs::read(&p) {
                    Ok(data) => {
                        log::info!("[anim] loaded frames from DLL dir: {p}");
                        return Ok(data);
                    }
                    Err(e) => log::info!("[anim] tried {}: {}", p, e),
                }
            }
        }
        Err(_) => log::warn!("[anim] get_dll_directory failed, cannot try DLL-relative fallback"),
    }

    Err("animation_frames.bin not found. Set ANIMATION_FRAMES_PATH registry key or reinstall.".to_string())
}

/// 本函数地址用于 GetModuleHandleExW 反查 DLL 模块
extern "C" fn addr_for_module_handle() {}

/// 获取 DLL 所在目录（通过函数地址反查，不依赖文件名拼写）
fn get_dll_directory() -> Result<String, ()> {
    unsafe {
        use windows::Win32::System::LibraryLoader::{
            GetModuleHandleExW, GetModuleFileNameW,
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        };
        let mut hmod = HMODULE::default();
        let addr = windows_core::PCWSTR::from_raw(
            addr_for_module_handle as *const u16,
        );
        let flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
        GetModuleHandleExW(flags, addr, &mut hmod)
            .map_err(|_| log::warn!("[anim] GetModuleHandleExW failed"))?;
        let mut buf = vec![0u16; 512];
        let len = GetModuleFileNameW(Some(hmod), &mut buf) as usize;
        if len == 0 { return Err(()); }
        let full_path = String::from_utf16_lossy(&buf[..len]);
        log::info!("[anim] DLL full path: {}", full_path);
        std::path::Path::new(&full_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .ok_or(())
    }
}

unsafe fn create_frames(
    ctx: &ID2D1DeviceContext,
    raw: &[u8],
) -> windows_core::Result<(Vec<ID2D1Bitmap1>, u32)> {
    if raw.len() < 12 {
        return Err(windows::core::Error::new(
            windows::Win32::Foundation::E_FAIL,
            "frames file too small",
        ));
    }

    let total_frames = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let fw = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let fh = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);

    log::info!("[anim] loading {total_frames} frames ({fw}x{fh})");

    // 校验文件帧尺寸与编译时常量一致（capture_frames.js WIDTH/HEIGHT 必须与
    // ANIM_WIDTH/ANIM_HEIGHT 同步，否则 stride 错位导致花屏）
    if fw != ANIM_WIDTH || fh != ANIM_HEIGHT {
        return Err(windows::core::Error::new(
            windows::Win32::Foundation::E_FAIL,
            format!(
                "frame size mismatch: file is {}x{}, code expects {}x{}",
                fw, fh, ANIM_WIDTH, ANIM_HEIGHT
            )
            .as_str(),
        ));
    }
    if total_frames == 0 {
        return Err(windows::core::Error::new(
            windows::Win32::Foundation::E_FAIL,
            "frames file declares zero frames",
        ));
    }

    let frame_size = (fw * fh * 4) as usize;
    if raw.len() < 12 + total_frames as usize * frame_size {
        return Err(windows::core::Error::new(
            windows::Win32::Foundation::E_FAIL,
            "frames file truncated",
        ));
    }

    let bmp_props = D2D1_BITMAP_PROPERTIES1 {
        pixelFormat: D2D1_PIXEL_FORMAT {
            format: DXGI_FORMAT_B8G8R8A8_UNORM,
            alphaMode: D2D1_ALPHA_MODE_PREMULTIPLIED,
        },
        dpiX: 96.0,
        dpiY: 96.0,
        bitmapOptions: D2D1_BITMAP_OPTIONS_TARGET,
        colorContext: std::mem::ManuallyDrop::new(None),
    };

    let mut frames = Vec::with_capacity(total_frames as usize);
    for i in 0..total_frames as usize {
        let offset = 12 + i * frame_size;
        let bmp = ctx.CreateBitmap(
            D2D_SIZE_U { width: fw, height: fh },
            Some(raw[offset..].as_ptr() as *const _),
            fw * 4,
            &bmp_props,
        )?;
        frames.push(bmp);
    }

    Ok((frames, total_frames))
}

unsafe fn create_all_resources(
    d2d_factory: &ID2D1Factory1,
    ctx: &ID2D1DeviceContext,
    rt: &ID2D1RenderTarget,
) -> windows_core::Result<BlackHoleRes> {
    // ── 加载预渲染帧 ──

    let raw = load_frames_raw().map_err(|e| {
        log::error!("[anim] {e}");
        windows::core::Error::new(windows::Win32::Foundation::E_FAIL, e)
    })?;
    let (frames, total_frames) = create_frames(ctx, &raw)?;

    // ── 纯色笔刷 ──

    let white_brush = rt.CreateSolidColorBrush(
        &D2D1_COLOR_F { r: 1.0, g: 1.0, b: 1.0, a: 1.0 },
        None,
    )?;
    let green_brush = rt.CreateSolidColorBrush(&color(0.2, 0.85, 0.4, 1.0), None)?;
    let red_brush = rt.CreateSolidColorBrush(&color(0.9, 0.2, 0.2, 1.0), None)?;
    let black_brush = rt.CreateSolidColorBrush(&color(0.0, 0.0, 0.0, 0.65), None)?;

    // ── DWrite ──

    let dwrite_factory: IDWriteFactory = DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED)?;
    let text_format: IDWriteTextFormat = dwrite_factory.CreateTextFormat(
        w!("Segoe UI"),
        None,
        DWRITE_FONT_WEIGHT_BOLD,
        DWRITE_FONT_STYLE_NORMAL,
        DWRITE_FONT_STRETCH_NORMAL,
        TEXT_FONT_SIZE,
        w!("en-US"),
    )?;
    let _ = text_format.SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
    let _ = text_format.SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    // ── 几何体 ──

    let check = d2d_factory.CreatePathGeometry()?;
    {
        let sink = check.Open()?;
        sink.BeginFigure(D2D_POINT_2F { x: CX - 18.0, y: CY + 3.0 }, D2D1_FIGURE_BEGIN_FILLED);
        sink.AddLine(D2D_POINT_2F { x: CX - 5.0, y: CY + 16.0 });
        sink.AddLine(D2D_POINT_2F { x: CX + 20.0, y: CY - 16.0 });
        sink.EndFigure(D2D1_FIGURE_END_OPEN);
        sink.Close()?;
    }

    let cross = d2d_factory.CreatePathGeometry()?;
    {
        let sink = cross.Open()?;
        let d = 16.0;
        sink.BeginFigure(D2D_POINT_2F { x: CX - d, y: CY - d }, D2D1_FIGURE_BEGIN_FILLED);
        sink.AddLine(D2D_POINT_2F { x: CX + d, y: CY + d });
        sink.EndFigure(D2D1_FIGURE_END_OPEN);
        sink.BeginFigure(D2D_POINT_2F { x: CX + d, y: CY - d }, D2D1_FIGURE_BEGIN_FILLED);
        sink.AddLine(D2D_POINT_2F { x: CX - d, y: CY + d });
        sink.EndFigure(D2D1_FIGURE_END_OPEN);
        sink.Close()?;
    }

    Ok(BlackHoleRes {
        frames,
        total_frames,
        white_brush,
        green_brush,
        red_brush,
        black_brush,
        text_format,
        check,
        cross,
    })
}

// ── 弧线文字渲染（带 drop-shadow）────────────────────────────

unsafe fn render_arc_text(
    ctx: &ID2D1DeviceContext,
    res: &BlackHoleRes,
    text: &str,
    rotation_deg: f32,
) -> windows_core::Result<()> {
    let chars: Vec<char> = text.chars().collect();
    if chars.is_empty() {
        return Ok(());
    }
    let n = chars.len();

    for (i, &ch) in chars.iter().enumerate() {
        let frac = if n > 1 { i as f32 / (n - 1) as f32 } else { 0.5 };
        let angle_deg = TEXT_START_DEG + frac * TEXT_ARC_DEG + rotation_deg;
        let angle_rad = angle_deg.to_radians();
        let px = CX + TEXT_RADIUS * angle_rad.cos();
        let py = CY + TEXT_RADIUS * angle_rad.sin();
        let tangent_deg = angle_deg + 90.0;

        let rotate_mat = mat_rotation(tangent_deg, 0.0, 0.0);
        let mut wbuf = [0u16; 2];
        let ch_str = ch.encode_utf16(&mut wbuf);
        let char_rect = D2D_RECT_F { left: -18.0, top: -10.0, right: 18.0, bottom: 10.0 };

        // 阴影
        let sxform = mat_mul(&rotate_mat, &mat_translate(px + 1.0, py + 2.0));
        ctx.SetTransform(&sxform);
        let _ = ctx.DrawText(ch_str, &res.text_format, std::ptr::from_ref(&char_rect), &res.black_brush, D2D1_DRAW_TEXT_OPTIONS_NONE, DWRITE_MEASURING_MODE_NATURAL);

        // 主体
        let mxform = mat_mul(&rotate_mat, &mat_translate(px, py));
        ctx.SetTransform(&mxform);
        let _ = ctx.DrawText(ch_str, &res.text_format, std::ptr::from_ref(&char_rect), &res.white_brush, D2D1_DRAW_TEXT_OPTIONS_NONE, DWRITE_MEASURING_MODE_NATURAL);
    }
    ctx.SetTransform(&mat_identity());
    Ok(())
}

// ── 帧索引计算 ────────────────────────────────────────────────

fn get_frame_idx(elapsed_secs: f64, total_frames: u32) -> u32 {
    let phase = (elapsed_secs % FRAME_PERIOD) / FRAME_PERIOD;
    (phase * total_frames as f64) as u32 % total_frames
}

// ── 各状态渲染（完整管理 BeginDraw/EndDraw）─────────────────

unsafe fn render_base(
    ctx: &ID2D1DeviceContext,
    res: &BlackHoleRes,
    elapsed_secs: f64,
    tint: Option<&ID2D1SolidColorBrush>,
    text: &str,
    text_period: f32,
    geo: Option<(&ID2D1Geometry, &ID2D1SolidColorBrush, f32)>,
    shake: f32,
    fade_progress: f32,
    main_bitmap: &ID2D1Bitmap1,
) -> windows_core::Result<()> {
    let frame_idx = get_frame_idx(elapsed_secs, res.total_frames);

    ctx.SetTarget(main_bitmap);
    ctx.BeginDraw();
    ctx.Clear(None);

    // 抖动变换（Failure）
    if shake != 0.0 {
        ctx.SetTransform(&mat_translate(shake, 0.0));
    }

    // 1. 预渲染帧
    ctx.DrawImage(
        &res.frames[frame_idx as usize],
        None,
        None,
        D2D1_INTERPOLATION_MODE_LINEAR,
        D2D1_COMPOSITE_MODE_SOURCE_OVER,
    );

    // 2. 状态色调叠加
    if let Some(tint) = tint {
        ctx.DrawEllipse(
            &D2D1_ELLIPSE { point: D2D_POINT_2F { x: CX, y: CY }, radiusX: 44.0, radiusY: 44.0 },
            tint, 2.0, None::<&ID2D1StrokeStyle>,
        );
    }

    // 3. 弧线文字（空字符串时跳过，配合 falcon 设计不显示文字）
    if !text.is_empty() {
        let text_rot = (elapsed_secs as f32 / text_period * 360.0) % 360.0;
        render_arc_text(ctx, res, text, text_rot)?;
    }

    // 4. 几何体（对号/叉号）
    if let Some((geo, brush, width)) = geo {
        ctx.DrawGeometry(geo, brush, width, None::<&ID2D1StrokeStyle>);
    }

    // 5. 淡出遮罩
    if fade_progress > 0.0 {
        let fade_overlay = ctx.CreateSolidColorBrush(&color(0.0, 0.0, 0.0, fade_progress * 0.7), None)?;
        ctx.FillRectangle(&D2D_RECT_F { left: 0.0, top: 0.0, right: ANIM_WIDTH as f32, bottom: ANIM_HEIGHT as f32 }, &fade_overlay);
    }

    if shake != 0.0 {
        ctx.SetTransform(&mat_identity());
    }

    ctx.EndDraw(None, None)?;
    Ok(())
}

unsafe fn render_idle(
    ctx: &ID2D1DeviceContext, res: &BlackHoleRes, elapsed_secs: f64, main_bitmap: &ID2D1Bitmap1,
) -> windows_core::Result<()> {
    render_base(ctx, res, elapsed_secs, None, "", TEXT_PERIOD_IDLE, None, 0.0, 0.0, main_bitmap)
}

unsafe fn render_scanning(
    ctx: &ID2D1DeviceContext, res: &BlackHoleRes, elapsed_secs: f64, main_bitmap: &ID2D1Bitmap1,
) -> windows_core::Result<()> {
    render_base(ctx, res, elapsed_secs, None, "", TEXT_PERIOD_SCAN, None, 0.0, 0.0, main_bitmap)
}

unsafe fn render_success(
    ctx: &ID2D1DeviceContext, res: &BlackHoleRes, elapsed_secs: f64, state_age: &Duration, main_bitmap: &ID2D1Bitmap1,
) -> windows_core::Result<()> {
    let progress = (state_age.as_secs_f32() / OUTCOME_TIMEOUT_SECS).clamp(0.0, 1.0);
    let check_geo: ID2D1Geometry = res.check.cast()?;
    render_base(ctx, res, elapsed_secs, Some(&res.green_brush), "", TEXT_PERIOD_IDLE, Some((&check_geo, &res.green_brush, 4.0)), 0.0, progress, main_bitmap)
}

unsafe fn render_failure(
    ctx: &ID2D1DeviceContext, res: &BlackHoleRes, elapsed_secs: f64, state_age: &Duration, main_bitmap: &ID2D1Bitmap1,
) -> windows_core::Result<()> {
    let progress = (state_age.as_secs_f32() / OUTCOME_TIMEOUT_SECS).clamp(0.0, 1.0);
    let shake = (state_age.as_secs_f32() * 30.0).sin() * 10.0 * (1.0 - progress).powi(2);
    let cross_geo: ID2D1Geometry = res.cross.cast()?;
    render_base(ctx, res, elapsed_secs, Some(&res.red_brush), "", TEXT_PERIOD_IDLE, Some((&cross_geo, &res.red_brush, 3.5)), shake, progress, main_bitmap)
}

// ── 磁贴定位（未改动）─────────────────────────────────────────

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
    let cy = (cr.bottom - cr.top) / 4;
    RECT { left: cx - ANIM_WIDTH as i32 / 2, top: cy - ANIM_HEIGHT as i32 / 2, right: cx + ANIM_WIDTH as i32 / 2, bottom: cy + ANIM_HEIGHT as i32 / 2 }
}

unsafe fn find_tile_position(parent: HWND, search_text: &[u16], stop: &AtomicBool) -> (RECT, &'static str) {
    dump_child_windows(parent);
    for _ in 0..TILE_FIND_MAX_RETRIES {
        if stop.load(Ordering::SeqCst) { return (fallback_position(parent), "stopped"); }
        if let Some(r) = find_by_text(parent, search_text) { return (r, "text_match"); }
        if let Some(r) = find_by_size_heuristic(parent) { return (r, "size_heuristic"); }
        // 拆分 sleep 为短轮询，便于 AnimationContext::drop 时快速响应
        let deadline = Instant::now() + Duration::from_millis(TILE_FIND_RETRY_MS);
        while Instant::now() < deadline {
            if stop.load(Ordering::SeqCst) { return (fallback_position(parent), "stopped"); }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    if let Some(r) = find_by_registry_offset(parent) { return (r, "registry_offset"); }
    (fallback_position(parent), "fallback")
}

// ── 渲染主循环 ────────────────────────────────────────────────

fn run_render_loop(
    parent_hwnd: HWND,
    tile_search_text: &[u16],
    state: Arc<RenderState>,
) -> windows_core::Result<()> {
    unsafe {
        // 各 init 步骤之间检查 stop_flag，避免长初始化（资源加载、磁贴搜索）
        // 期间用户关闭对话框时 AnimationContext::drop 的 join() 卡住
        macro_rules! check_stop { () => {
            if state.stop.load(Ordering::SeqCst) {
                log::info!("[anim] stop requested during init, aborting");
                return Ok(());
            }
        }; }

        log::info!("[anim] initializing D3D11 device...");
        let mut d3d_device: Option<ID3D11Device> = None;
        let mut feature_level = D3D_FEATURE_LEVEL::default();
        D3D11CreateDevice(None, D3D_DRIVER_TYPE_HARDWARE, HMODULE::default(), D3D11_CREATE_DEVICE_BGRA_SUPPORT, None, D3D11_SDK_VERSION, Some(&mut d3d_device), Some(&mut feature_level), None)?;
        let d3d_device = d3d_device.ok_or_else(|| windows::core::Error::new(windows::Win32::Foundation::E_FAIL, "D3D11 设备为空"))?;
        log::info!("[anim] D3D11 device created");
        check_stop!();

        let dxgi_device: IDXGIDevice = d3d_device.cast()?;
        let dcomp_device: IDCompositionDesktopDevice = DCompositionCreateDevice2(&dxgi_device)?;
        let dcomp_target = dcomp_device.CreateTargetForHwnd(parent_hwnd, true)?;
        let dcomp_visual: IDCompositionVisual2 = dcomp_device.CreateVisual()?.cast()?;
        dcomp_target.SetRoot(&dcomp_visual)?;
        log::info!("[anim] DComp target created");
        check_stop!();

        let (tile_rect, strategy) = find_tile_position(parent_hwnd, tile_search_text, &state.stop);
        check_stop!();
        log::info!("[anim] tile strategy={strategy} rect=({},{})-({},{})", tile_rect.left, tile_rect.top, tile_rect.right, tile_rect.bottom);
        let tile_cx = (tile_rect.left + tile_rect.right) / 2;
        let tile_cy = (tile_rect.top + tile_rect.bottom) / 2;

        // Y 偏移：falcon 风格的按钮比黑洞更实，需要往上让出用户头像区域。
        // 注册表 ANIMATION_Y_OFFSET（默认 -80）允许 VM 测试时微调而无需重建。
        let y_offset: i32 = read_facewinunlock_registry("ANIMATION_Y_OFFSET")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(-80);
        let x_offset: i32 = read_facewinunlock_registry("ANIMATION_X_OFFSET")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        log::info!("[anim] offset=({x_offset},{y_offset})");

        dcomp_visual.SetOffsetX2((tile_cx - ANIM_WIDTH as i32 / 2 + x_offset) as f32)?;
        dcomp_visual.SetOffsetY2((tile_cy - ANIM_HEIGHT as i32 / 2 + y_offset) as f32)?;

        let dcomp_surface = dcomp_device.CreateVirtualSurface(ANIM_WIDTH, ANIM_HEIGHT, DXGI_FORMAT_B8G8R8A8_UNORM, windows::Win32::Graphics::Dxgi::Common::DXGI_ALPHA_MODE_PREMULTIPLIED)?;
        dcomp_visual.SetContent(&dcomp_surface)?;
        dcomp_device.Commit()?;
        check_stop!();

        let d2d_factory: ID2D1Factory1 = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, None)?;
        let d2d_device = d2d_factory.CreateDevice(&dxgi_device)?;
        let d2d_context = d2d_device.CreateDeviceContext(D2D1_DEVICE_CONTEXT_OPTIONS_NONE)?;
        check_stop!();

        let rt: ID2D1RenderTarget = d2d_context.cast()?;
        log::info!("[anim] loading resources...");
        let res = create_all_resources(&d2d_factory, &d2d_context, &rt)?;
        log::info!("[anim] resources loaded, entering render loop");
        check_stop!();

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

            let (current_state, state_age) = {
                let a = state.anim.lock().unwrap();
                (a.state, a.entered_at.elapsed())
            };

            let effective_state = match current_state {
                AnimState::Success | AnimState::Failure
                    if state_age > Duration::from_secs_f32(OUTCOME_TIMEOUT_SECS) =>
                {
                    drop(state.anim.lock());
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

            match effective_state {
                AnimState::Idle => render_idle(&d2d_context, &res, elapsed, &bitmap)?,
                AnimState::Scanning => render_scanning(&d2d_context, &res, elapsed, &bitmap)?,
                AnimState::Success => render_success(&d2d_context, &res, elapsed, &state_age, &bitmap)?,
                AnimState::Failure => render_failure(&d2d_context, &res, elapsed, &state_age, &bitmap)?,
            }

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
