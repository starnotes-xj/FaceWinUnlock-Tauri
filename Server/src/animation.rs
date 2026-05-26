//! 动画 UI 子窗口管线（阶段 A）
//!
//! 用 DirectComposition + Direct2D 在 LogonUI 进程内创建自定义子窗口，
//! 用于绘制 Windows Hello 风格的解锁动画。
//!
//! 管线层次:
//!   Win32 子窗口 (CreateWindowExW)
//!     ↓ 绑定
//!   DComp Target ← DCompositionDevice2 ← IDXGIDevice ← ID3D11Device
//!     ↓ SetRoot
//!   DComp Visual
//!     ↓ SetContent
//!   DComp Surface ← BeginDraw → IDXGISurface
//!     ↓ CreateBitmapFromDxgiSurface
//!   D2D Bitmap (ID2D1Bitmap1) ← D2D DeviceContext ← D2D Device ← D2D Factory
//!
//! 当前阶段 A 仅实现 PoC（纯色填充），动画在 B 阶段加入。

use std::sync::{Mutex, Once};

use windows::Win32::{
    Foundation::{HMODULE, HWND, LPARAM, LRESULT, POINT, WPARAM},
    Graphics::{
        Direct2D::{
            Common::{
                D2D1_ALPHA_MODE_PREMULTIPLIED, D2D1_COLOR_F,
                D2D1_PIXEL_FORMAT,
            },
            D2D1CreateFactory, ID2D1Bitmap1, ID2D1Device, ID2D1DeviceContext, ID2D1Factory1,
            D2D1_BITMAP_OPTIONS_CANNOT_DRAW, D2D1_BITMAP_OPTIONS_TARGET, D2D1_BITMAP_PROPERTIES1,
            D2D1_DEVICE_CONTEXT_OPTIONS_NONE, D2D1_FACTORY_TYPE_SINGLE_THREADED,
        },
        Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL},
        Direct3D11::{
            D3D11CreateDevice, ID3D11Device, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION,
        },
        DirectComposition::{
            DCompositionCreateDevice2, IDCompositionDesktopDevice, IDCompositionTarget,
            IDCompositionVirtualSurface, IDCompositionVisual2,
        },
        Dxgi::{Common::DXGI_FORMAT_B8G8R8A8_UNORM, IDXGIDevice, IDXGISurface},
    },
    System::LibraryLoader::GetModuleHandleW,
    UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, RegisterClassExW, ShowWindow, CS_HREDRAW,
        CS_VREDRAW, HCURSOR, HICON, HMENU, SW_SHOW, WINDOW_EX_STYLE, WNDCLASSEXW, WS_CHILD,
        WS_VISIBLE,
    },
};
use windows_core::{Interface, PCWSTR};

/// 子窗口默认尺寸（沿用磁贴尺寸，后期可调）
const ANIM_WIDTH: u32 = 128;
const ANIM_HEIGHT: u32 = 128;

/// 自定义窗口类名（全局唯一）
const WND_CLASS_NAME: &str = "FaceWinUnlockAnimationWindow\0";

static WND_CLASS_REGISTERED: Once = Once::new();

/// 注册自定义窗口类（只在首次调用时执行）
fn register_window_class(hinstance: HMODULE) -> windows_core::Result<()> {
    let mut result: windows_core::Result<()> = Ok(());
    WND_CLASS_REGISTERED.call_once(|| unsafe {
        let class_name_utf16: Vec<u16> = WND_CLASS_NAME.encode_utf16().collect();
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance.into(),
            hIcon: HICON::default(),
            hCursor: HCURSOR::default(),
            hbrBackground: windows::Win32::Graphics::Gdi::HBRUSH::default(),
            lpszMenuName: PCWSTR::null(),
            lpszClassName: PCWSTR(class_name_utf16.as_ptr()),
            hIconSm: HICON::default(),
        };
        let atom = RegisterClassExW(&wc);
        if atom == 0 {
            let err = windows::core::Error::from_win32();
            // 0x582 = ERROR_CLASS_ALREADY_EXISTS, 视为成功
            if err.code().0 as u32 != 0x582 {
                result = Err(err);
            }
        }
    });
    result
}

/// 默认窗口过程：直接转交给 DefWindowProcW（不需要处理消息，让 DComp 接管渲染）
unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

/// 渲染上下文 — 持有所有 COM 对象，Drop 时自动释放
pub struct AnimationContext {
    /// LogonUI 父窗口 HWND（不拥有，仅引用）
    parent_hwnd: HWND,
    /// 我们创建的子窗口 HWND（拥有，Drop 时 DestroyWindow）
    child_hwnd: HWND,
    /// COM 对象（按 Drop 顺序排列：从依赖底到底层）
    d2d_bitmap: Option<ID2D1Bitmap1>,
    d2d_context: ID2D1DeviceContext,
    #[allow(dead_code)]
    d2d_device: ID2D1Device,
    #[allow(dead_code)]
    d2d_factory: ID2D1Factory1,
    dcomp_surface: IDCompositionVirtualSurface,
    #[allow(dead_code)]
    dcomp_visual: IDCompositionVisual2,
    #[allow(dead_code)]
    dcomp_target: IDCompositionTarget,
    dcomp_device: IDCompositionDesktopDevice,
    #[allow(dead_code)]
    d3d_device: ID3D11Device,
}

// HWND/COM 对象在 windows-rs 中没实现 Send。Animation 仅在 LogonUI 的 UI 线程创建/使用，
// 但 Mutex 包装需要 Send。这里用 unsafe impl 标记安全（实际访问点都在 CredentialEvents 调用链中，
// 由 LogonUI 串行化）。
unsafe impl Send for AnimationContext {}

impl AnimationContext {
    /// 创建动画上下文：注册窗口类、创建子窗口、初始化 D3D/DComp/D2D 管线
    pub fn new(parent_hwnd: HWND) -> windows_core::Result<Self> {
        unsafe {
            let hinstance = GetModuleHandleW(PCWSTR::null())?;
            register_window_class(hinstance)?;

            // ── 1. 创建子窗口（贴在父窗口左上角，后期再做位置调整）─────────────
            let class_name_utf16: Vec<u16> = WND_CLASS_NAME.encode_utf16().collect();
            let child_hwnd = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(class_name_utf16.as_ptr()),
                PCWSTR::null(),
                WS_CHILD | WS_VISIBLE,
                0,
                0,
                ANIM_WIDTH as i32,
                ANIM_HEIGHT as i32,
                Some(parent_hwnd),
                Some(HMENU::default()),
                Some(hinstance.into()),
                None,
            )?;

            let _ = ShowWindow(child_hwnd, SW_SHOW);

            // ── 2. D3D11 设备（BGRA 支持是 D2D 互操作的前提）──────────────────
            let mut d3d_device: Option<ID3D11Device> = None;
            let mut feature_level = D3D_FEATURE_LEVEL::default();
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                None,
                D3D11_SDK_VERSION,
                Some(&mut d3d_device),
                Some(&mut feature_level),
                None,
            )?;
            let d3d_device = d3d_device.ok_or_else(|| {
                windows::core::Error::new(
                    windows::Win32::Foundation::E_FAIL,
                    "D3D11CreateDevice 未返回设备",
                )
            })?;

            // ── 3. DXGI Device（DComp/D2D 通用底层接口）─────────────────────
            let dxgi_device: IDXGIDevice = d3d_device.cast()?;

            // ── 4. DComp Desktop Device + Target ───────────────────────────
            let dcomp_device: IDCompositionDesktopDevice = DCompositionCreateDevice2(&dxgi_device)?;
            let dcomp_target = dcomp_device.CreateTargetForHwnd(child_hwnd, true)?;

            // ── 5. Root Visual ─────────────────────────────────────────────
            let dcomp_visual: IDCompositionVisual2 = dcomp_device.CreateVisual()?.cast()?;
            dcomp_target.SetRoot(&dcomp_visual)?;

            // ── 6. Virtual Surface（128×128 BGRA Premultiplied）────────────
            let dcomp_surface = dcomp_device.CreateVirtualSurface(
                ANIM_WIDTH,
                ANIM_HEIGHT,
                DXGI_FORMAT_B8G8R8A8_UNORM,
                windows::Win32::Graphics::Dxgi::Common::DXGI_ALPHA_MODE_PREMULTIPLIED,
            )?;
            dcomp_visual.SetContent(&dcomp_surface)?;

            // ── 7. D2D Factory + Device + DeviceContext ───────────────────
            let d2d_factory: ID2D1Factory1 = D2D1CreateFactory(
                D2D1_FACTORY_TYPE_SINGLE_THREADED,
                None,
            )?;
            let d2d_device = d2d_factory.CreateDevice(&dxgi_device)?;
            let d2d_context = d2d_device.CreateDeviceContext(D2D1_DEVICE_CONTEXT_OPTIONS_NONE)?;

            Ok(Self {
                parent_hwnd,
                child_hwnd,
                d2d_bitmap: None,
                d2d_context,
                d2d_device,
                d2d_factory,
                dcomp_surface,
                dcomp_visual,
                dcomp_target,
                dcomp_device,
                d3d_device,
            })
        }
    }

    /// 渲染一帧纯色填充（阶段 A6 验证管线）
    /// color: BGRA 浮点 0.0-1.0
    pub fn render_solid_color(&mut self, r: f32, g: f32, b: f32, a: f32) -> windows_core::Result<()> {
        unsafe {
            // BeginDraw 返回 IDXGISurface（在 update_rect 内）
            let mut offset = POINT::default();
            let update_rect = windows::Win32::Foundation::RECT {
                left: 0,
                top: 0,
                right: ANIM_WIDTH as i32,
                bottom: ANIM_HEIGHT as i32,
            };
            let dxgi_surface: IDXGISurface =
                self.dcomp_surface.BeginDraw(Some(&update_rect), &mut offset)?;

            // 把 DXGI Surface 转成 D2D Bitmap
            let bitmap_props = D2D1_BITMAP_PROPERTIES1 {
                pixelFormat: D2D1_PIXEL_FORMAT {
                    format: DXGI_FORMAT_B8G8R8A8_UNORM,
                    alphaMode: D2D1_ALPHA_MODE_PREMULTIPLIED,
                },
                dpiX: 96.0,
                dpiY: 96.0,
                bitmapOptions: D2D1_BITMAP_OPTIONS_TARGET | D2D1_BITMAP_OPTIONS_CANNOT_DRAW,
                colorContext: std::mem::ManuallyDrop::new(None),
            };
            let bitmap: ID2D1Bitmap1 = self
                .d2d_context
                .CreateBitmapFromDxgiSurface(&dxgi_surface, Some(&bitmap_props))?;

            // 设置渲染目标（DComp BeginDraw 已通过 offset 告知偏移，PoC 阶段 offset=0,0 无需变换）
            self.d2d_context.SetTarget(&bitmap);
            self.d2d_context.BeginDraw();
            self.d2d_context.Clear(Some(&D2D1_COLOR_F { r, g, b, a }));
            self.d2d_context.EndDraw(None, None)?;

            // 释放 bitmap target，避免后续 EndDraw 时仍持有引用
            self.d2d_context.SetTarget(None);
            self.d2d_bitmap = Some(bitmap);

            self.dcomp_surface.EndDraw()?;
            self.dcomp_device.Commit()?;
        }
        Ok(())
    }

    /// 父窗口 HWND（供外部查询，不允许修改）
    #[allow(dead_code)]
    pub fn parent_hwnd(&self) -> HWND {
        self.parent_hwnd
    }
}

impl Drop for AnimationContext {
    fn drop(&mut self) {
        unsafe {
            // 销毁子窗口（COM 对象由 Rust drop 顺序自动 Release）
            if !self.child_hwnd.is_invalid() {
                let _ = DestroyWindow(self.child_hwnd);
            }
        }
    }
}

/// 全局动画上下文（每个 SampleCredential 实例最多一个），由 Mutex 保护跨线程访问
pub type AnimationSlot = Mutex<Option<AnimationContext>>;

/// 创建一个空的动画槽位
pub fn make_slot() -> AnimationSlot {
    Mutex::new(None)
}
