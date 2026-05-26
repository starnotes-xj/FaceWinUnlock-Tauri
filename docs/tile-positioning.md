# LogonUI 凭据磁贴定位方案

> 本文档分析如何在 LogonUI 窗口层次中可靠定位我们的凭据磁贴，
> 以便 DComp 动画能精确覆盖到用户头像位置。

---

## 一、问题

`EnumChildWindows` + `GetWindowTextW` 文本匹配 `"FaceWinUnlock"` 在
现代 LogonUI（Win10+ DComp/XAML 渲染）中大概率失败，因为：

- 凭据字段文本是 LogonUI 内部运行时数据，不一定会设到窗口标题
- DComp/XAML 渲染的窗口对 `GetWindowTextW` 通常返回空字符串

代码目前会走重试 15 次 → 回退到默认位置的路径。

---

## 二、信息来源

定位凭据磁贴只依赖 `OnCreatingWindow` 返回的**一个**父 HWND。
从它出发，可用手段：

| 手段 | 说明 |
|---|---|
| `EnumChildWindows` | 枚举所有后代窗口 |
| `GetWindowTextW` | 窗口标题（现代 LogonUI 通常为空） |
| `GetClassName` | 窗口类名 |
| `GetWindowRect` | 窗口屏幕坐标 |
| `GetWindowLongW(GWL_STYLE/GWL_EXSTYLE)` | 窗口样式/扩展样式 |
| `GetWindowLongW(GWL_ID)` / `GetDlgCtrlID` | 控件 ID |
| `IsWindowVisible` | 可见性 |
| `FindWindowEx` | 按类名/标题搜索子窗口 |

**不可用**：UI Automation（`IUIAutomation`）— 它在 Winlogon 桌面上的
COM 初始化可能受限，且引入额外依赖（`uiautomationcore.dll`）。

---

## 三、定位策略（按优先级）

### 策略 1：窗口类名 + 特征过滤

在 VM 中用 Spy++ / 脚本抓取 LogonUI 窗口树，找到凭据磁贴的类名规律。

预期发现：
- 磁贴容器类名可能包含 `CredProv` 或类似前缀
- 在类名匹配的窗口中筛选尺寸 ~128×128 ~ 256×256 的可见窗口

```rust
fn is_likely_tile(class_name: &str, rect: &RECT) -> bool {
    let w = rect.right - rect.left;
    let h = rect.bottom - rect.top;
    // 磁贴尺寸通常在 128-384 像素范围
    class_name_contains_any(class_name, &["CredProv", "Tile"])
        && w >= 100 && w <= 400
        && h >= 100 && h <= 400
        && (w - h).abs() < 50  // 近似正方形
}
```

### 策略 2：控件 ID 特征

某些 LogonUI 版本会给凭据磁贴分配一致的控件 ID（如 `0x3E8` 或特定范围）。
先抓取确认是否存在此规律。

### 策略 3：位置启发式

如果以上均失败，按布局规律回退：

| 场景 | 磁贴位置 |
|---|---|
| Win10 锁屏（多用户） | 屏幕中偏下，左侧排列 |
| Win11 锁屏 | 屏幕垂直居中，水平居中 |
| CredUI（UAC） | 对话框中心 |

常用回退：在父窗口 client 区域的**水平居中、垂直 2/3 处**放置。

### 策略 4：注册表可配置偏移量

作为所有自动检测的保底方案，支持注册表手动微调：

```
ANIMATION_OFFSET_X  = 0    // 水平偏移
ANIMATION_OFFSET_Y  = 0    // 垂直偏移
ANIMATION_SIZE_W    = 128  // 覆盖宽度
ANIMATION_SIZE_H    = 128  // 覆盖高度
```

---

## 四、实施步骤

1. **抓窗口树**：用本文第六章的 PowerShell 脚本在 VM 锁屏时抓取
2. **分析特征**：在 Win10 和 Win11 上各确认一次
3. **实现策略 1**：按类名 + 尺寸过滤
4. **实现策略 3**：作为回退
5. **实现策略 4**：注册表偏移
6. **VM 验证**：两个 Windows 版本各验证

---

## 五、代码结构设计

```rust
// animation.rs

/// 多层定位策略（按优先级尝试，成功即返回）
fn find_tile_position(parent: HWND) -> TilePosition {
    // 策略 1: 窗口类名 + 尺寸特征
    if let Some(pos) = find_by_class_pattern(parent) {
        return pos;
    }
    // 策略 2: 控件 ID 特征
    if let Some(pos) = find_by_control_id(parent) {
        return pos;
    }
    // 策略 3: 位置启发式回退
    heuristic_fallback(parent)
}

struct TilePosition {
    /// 磁贴左上角相对父窗口 client 区域的坐标
    rect: RECT,
    /// 使用的策略（调试用）
    strategy: &'static str,
}
```

---

## 六、窗口树抓取脚本

### 6.1 PowerShell 脚本（在锁屏进程外运行）

```powershell
# dump_logonui_windows.ps1
# 用法：管理员权限运行，锁屏后执行
# 输出：LogonUI 窗口层次结构

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class WinDump {
    [DllImport("user32.dll")] public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr hWndParent, EnumChildProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll")] public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern uint GetWindowLong(IntPtr hWnd, int nIndex);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    public delegate bool EnumChildProc(IntPtr hWnd, IntPtr lParam);
    public const int GWL_STYLE = -16;
    public const int GWL_EXSTYLE = -20;
    public const uint WS_CHILD = 0x40000000;
    public static string GetStyleStr(uint style) {
        var sb = new StringBuilder();
        if ((style & 0x10000000) != 0) sb.Append("VISIBLE|");
        if ((style & 0x40000000) != 0) sb.Append("CHILD|");
        if ((style & 0x80000000) != 0) sb.Append("POPUP|");
        if ((style & 0x00C00000) != 0) sb.Append("CAPTION|");
        if ((style & 0x00080000) != 0) sb.Append("DLGFRAME|");
        if ((style & 0x00010000) != 0) sb.Append("TABSTOP|");
        return sb.ToString().TrimEnd('|');
    }
}
"@

function Get-WindowTree {
    param([IntPtr]$hwnd, [int]$depth = 0)
    $indent = "  " * $depth
    $sb = [System.Text.StringBuilder]::new(256)
    [WinDump]::GetClassName($hwnd, $sb, 256) | Out-Null; $cls = $sb.ToString()
    $sb.Clear()
    [WinDump]::GetWindowText($hwnd, $sb, 256) | Out-Null; $title = $sb.ToString()
    $rect = New-Object WinDump+RECT
    [WinDump]::GetWindowRect($hwnd, [ref]$rect) | Out-Null
    $visible = [WinDump]::IsWindowVisible($hwnd)
    $id = [WinDump]::GetDlgCtrlID($hwnd)
    $style = [WinDump]::GetWindowLong($hwnd, -16)
    $w = $rect.Right - $rect.Left
    $h = $rect.Bottom - $rect.Top

    Write-Host ("{0}HWND=0x{1:X8} cls=`"{2}`" title=`"{3}`" rect=({4},{5})-({6}x{7}) vis={8} id={9} style=0x{10:X8}[{11}]" -f
        $indent, $hwnd, $cls, ($title.Substring(0,[Math]::Min(40,$title.Length))), $rect.Left, $rect.Top, $w, $h, $visible, $id, $style, [WinDump]::GetStyleStr($style))

    $children = [System.Collections.Generic.List[IntPtr]]::new()
    $callback = { param($h, $p) $children.Add($h); return $true }
    [WinDump]::EnumChildWindows($hwnd, $callback, [IntPtr]::Zero) | Out-Null
    foreach ($c in $children) { Get-WindowTree $c ($depth + 1) }
}

# 主入口
Write-Host "=== LogonUI Window Tree ===" -ForegroundColor Cyan
$logonUI = [WinDump]::FindWindow("LogonUI", $null)
if ($logonUI -eq [IntPtr]::Zero) {
    Write-Host "LogonUI not found. Lock the screen first." -ForegroundColor Red
    return
}
Get-WindowTree $logonUI
```

> **限制**：此脚本在普通桌面运行，无法从锁屏桌面枚举窗口。
> 需在锁屏桌面进程内运行（即从 DLL 内抓取并写日志），或通过
> `psexec -s -d cmd /c powershell ...` 以 SYSTEM 权限运行。

### 6.2 DLL 内置自诊断（推荐）

在 `animation.rs` 中增加一个调试函数，在动画管线初始化时自动 dump
子窗口信息到日志文件，用于收集真实数据：

```rust
/// 调试用：dump 父窗口下所有可见子窗口信息到 info! 日志
#[allow(dead_code)]
unsafe fn dump_child_windows(parent: HWND) {
    struct DumpCtx { parent: HWND }
    unsafe extern "system" fn callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let _ctx = &*(lparam.0 as *const DumpCtx);
        let mut cls = vec![0u16; 128];
        let cls_len = GetClassNameW(hwnd, &mut cls);
        let cls_str = String::from_utf16_lossy(&cls[..cls_len as usize]);

        let mut text = vec![0u16; 128];
        let text_len = GetWindowTextW(hwnd, &mut text);
        let text_str = String::from_utf16_lossy(&text[..text_len as usize]);

        let mut rect = RECT::default();
        let _ = GetWindowRect(hwnd, &mut rect);

        let w = rect.right - rect.left;
        let h = rect.bottom - rect.top;
        let visible = IsWindowVisible(hwnd).as_bool();
        let ctrl_id = GetDlgCtrlID(hwnd);

        info!("[anim-dump] cls=\"{cls_str}\" text=\"{text_str}\" \
               rect=({},{})-{}x{} vis={visible} ctrl_id={ctrl_id}",
              rect.left, rect.top, w, h);

        BOOL(1) // continue
    }
    info!("[anim-dump] === 开始 dump 子窗口 (parent={parent:?}) ===");
    EnumChildWindows(Some(parent), Some(callback), LPARAM(0));
    info!("[anim-dump] === dump 结束 ===");
}
```

使用时在 `run_render_loop` 开头调用 `dump_child_windows(parent_hwnd)`，
日志会写入 `facewinunlock.log`。

---

## 七、定位流程（最终）

```
run_render_loop(parent_hwnd)
│
├── dump_child_windows()         → 日志输出窗口树（调试期）
│
├── find_tile_position()
│   ├── [1] 类名模式匹配        → 找到 → 返回 RECT
│   ├── [2] 尺寸+可见性启发式    → 找到 → 返回 RECT
│   ├── [3] 注册表偏移配置      → 读取 ANIMATION_OFFSET_*
│   └── [4] 兜底：父窗口 2/3 处  → 返回默认 RECT
│
├── SetOffsetX2 / SetOffsetY2    → 放置 Visual
│
└── 60 FPS 渲染循环
```

---

**版本**：v1.0
**日期**：2026-05-26
**状态**：待 VM 实测数据后实现策略 1 和策略 2
