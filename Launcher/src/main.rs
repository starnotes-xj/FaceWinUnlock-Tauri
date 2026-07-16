// FaceWinUnlock-Launcher.exe —— 原生启动器（不依赖 opencv）
//
// 为什么需要独立启动器：
//   facewinunlock-tauri.exe 和 FaceWinUnlock-Server.exe 都动态链接 opencv_world4120.dll。
//   一旦 DLL 被安全软件删除（火绒/Defender 云查杀），Windows PE 加载器解析导入表失败，
//   直接弹出"由于找不到 opencv_world4120.dll，无法继续执行代码"系统错误，进程甚至
//   到不了 main()。Rust 代码无法自愈——因为根本没机会运行。
//
//   本启动器不依赖 opencv，在启动主程序前检查 DLL 存在性；缺失时自动调用
//   resilience.ps1 从备份恢复，全部失败才显示用户友好错误提示。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::ffi::OsString;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

use windows::core::PCWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK, MB_SYSTEMMODAL};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MAIN_EXE_NAME: &str = "facewinunlock-tauri.exe";
const HEAL_SCRIPT_REL: &str = "nsis\\resilience.ps1";
const CRITICAL_DLL: &str = "opencv_world4120.dll";
const SERVER_EXE: &str = "FaceWinUnlock-Server.exe";

fn main() {
    let exe_dir = match std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
    {
        Some(d) => d,
        None => {
            fatal("无法获取启动器所在目录，程序无法继续。");
            return;
        }
    };

    // 收集命令行参数（转发给主程序，--silent 等）
    let forwarded_args: Vec<OsString> = std::env::args_os().skip(1).collect();

    let dll_path = exe_dir.join(CRITICAL_DLL);

    // ── 第 1 步：检查 DLL 是否存在 ──
    if !dll_path.exists() {
        // 等待一小段时间（杀软可能正在写入/占用文件）
        thread::sleep(Duration::from_millis(500));

        if !try_heal(&exe_dir) {
            let msg = format!(
                "关键文件丢失，程序无法启动。\n\n缺失文件: {}\n安装目录: {}\n\n可能原因: 安全软件（火绒/Defender 等）误删了该文件。\n\n解决方法:\n1. 将安装目录添加到安全软件的信任区（白名单）\n2. 重新运行安装程序",
                CRITICAL_DLL,
                exe_dir.display()
            );
            msgbox_error(&msg, "FaceWinUnlock - 启动失败");
            return;
        }

        // 自愈脚本已执行，再次检查
        if !dll_path.exists() {
            fatal("自愈脚本已执行，但关键 DLL 仍未恢复。请重新安装程序。");
            return;
        }
    }

    // ── 第 2 步：检查核心服务 EXE（best-effort，不影响 UI 启动）──
    let server_exe = exe_dir.join(SERVER_EXE);
    if !server_exe.exists() {
        let _ = try_heal(&exe_dir);
    }

    // ── 第 3 步：检查主程序是否已在运行 ──
    if is_process_running(MAIN_EXE_NAME) {
        return;
    }

    // ── 第 4 步：启动主程序 ──
    let main_exe = exe_dir.join(MAIN_EXE_NAME);
    if !main_exe.exists() {
        fatal("找不到主程序 facewinunlock-tauri.exe，请重新安装。");
        return;
    }

    let mut cmd = Command::new(&main_exe);
    cmd.creation_flags(CREATE_NO_WINDOW);
    if !forwarded_args.is_empty() {
        cmd.args(&forwarded_args);
    }

    if let Err(e) = cmd.spawn() {
        let msg = format!(
            "启动主程序失败: {}\n\n路径: {}\n\n请尝试重新安装程序。",
            e,
            main_exe.display()
        );
        msgbox_error(&msg, "FaceWinUnlock - 启动失败");
    }
}

/// 调用 resilience.ps1 -Mode Heal 从备份 zip 恢复被删文件。
fn try_heal(exe_dir: &PathBuf) -> bool {
    let heal_script = exe_dir.join(HEAL_SCRIPT_REL);
    if !heal_script.exists() {
        return false;
    }

    let script_path = match heal_script.to_str() {
        Some(s) => s,
        None => return false,
    };
    let dir_path = match exe_dir.to_str() {
        Some(s) => s,
        None => return false,
    };

    match Command::new("powershell.exe")
        .args(&[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            script_path,
            "-Mode",
            "Heal",
            "-InstallDir",
            dir_path,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
    {
        Ok(s) => s.success(),
        Err(_) => false,
    }
}

/// 检查指定进程名是否正在运行（精确匹配 .exe 后缀）。
fn is_process_running(exe_name: &str) -> bool {
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let mut pe = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let current_pid = GetCurrentProcessId();

        if Process32FirstW(snapshot, &mut pe).is_ok() {
            loop {
                let name = wide_slice_to_string(&pe.szExeFile);
                if name.eq_ignore_ascii_case(exe_name) && pe.th32ProcessID != current_pid {
                    let _ = CloseHandle(snapshot);
                    return true;
                }
                if Process32NextW(snapshot, &mut pe).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }
    false
}

fn wide_slice_to_string(slice: &[u16]) -> String {
    let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    String::from_utf16_lossy(&slice[..end])
}

fn msgbox_error(text: &str, title: &str) {
    let text_wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let title_wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        MessageBoxW(
            None,
            PCWSTR(text_wide.as_ptr()),
            PCWSTR(title_wide.as_ptr()),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL,
        );
    }
}

fn fatal(msg: &str) {
    msgbox_error(msg, "FaceWinUnlock - 启动失败");
    std::process::exit(1);
}
