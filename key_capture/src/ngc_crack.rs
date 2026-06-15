//! ngc_crack.exe — 25H2 NGC 二进制格式离线解密
//!
//! 用法（管理员 PowerShell，以 SYSTEM 运行）:
//!   PsExec -accepteula -s ngc_crack.exe <SID> <PIN>
//!
//! 流程:
//!   1. 扫描 Ngc 目录找到含匹配 SID 的容器
//!   2. dump 所有 .dat 文件 hex（分析 25H2 二进制格式）
//!   3. 对每个疑似密钥 blob 尝试 DPAPI 解密 × 9 种 PIN 编码

use std::fs;
use std::path::{Path, PathBuf};
use windows::Win32::Security::Cryptography::{
    CryptUnprotectData, CRYPT_INTEGER_BLOB,
    CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
};
use windows::Win32::Foundation::LocalFree;

const NGC_ROOT: &str = r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc";
const OUT_DIR: &str = r"C:\FaceWinUnlock\captured_keys";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("用法: ngc_crack.exe --sid <SID> <PIN>");
        eprintln!("      ngc_crack.exe --dump                    # 仅 dump 文件结构");
        std::process::exit(1);
    }

    let _ = fs::create_dir_all(OUT_DIR);

    if args[1] == "--dump" {
        dump_all_containers();
        return;
    }

    if args[1] == "--sid" && args.len() >= 4 {
        let sid = &args[2];
        let pin = &args[3];
        println!("=== NGC 25H2 OFFLINE DECRYPT ===");
        println!("SID: {}", sid);
        println!("PIN: {}", pin);
        scan_and_crack(sid, pin);
    } else {
        eprintln!("用法: ngc_crack.exe --sid <SID> <PIN>");
    }
}

// ─── 容器扫描 ────────────────────────────────────────────────────────────

fn dump_all_containers() {
    let root = Path::new(NGC_ROOT);
    if !root.is_dir() {
        eprintln!("NGC root not found: {}", NGC_ROOT);
        return;
    }
    for entry in fs::read_dir(root).unwrap() {
        let e = entry.unwrap();
        let p = e.path();
        if p.is_dir() && p.file_name().unwrap().to_str().unwrap_or("").starts_with("{") {
            println!("\n========================================");
            println!("CONTAINER: {}", p.display());
            dump_dir(&p, 0);
        }
    }
}

fn dump_dir(dir: &Path, depth: usize) {
    let prefix = "  ".repeat(depth);
    let mut entries: Vec<_> = fs::read_dir(dir).unwrap()
        .filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in &entries {
        let p = entry.path();
        let fname = entry.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            println!("{}{}/", prefix, fname);
            dump_dir(&p, depth + 1);
        } else {
            let len = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            if let Ok(data) = fs::read(&p) {
                let hex: String = data.iter().take(64).map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                let ascii: String = data.iter().take(64).map(|&b| if b >= 32 && b < 127 { b as char } else { '.' }).collect();
                println!("{}{}: {}B | {} | {}",
                    prefix, fname, len,
                    if data.len() > 64 { format!("{}...", &hex) } else { hex },
                    ascii);
            } else {
                println!("{}{}: {}B (cannot read)", prefix, fname, len);
            }
        }
    }
}

// ─── 破解流程 ────────────────────────────────────────────────────────────

fn scan_and_crack(sid: &str, pin: &str) {
    let root = Path::new(NGC_ROOT);
    if !root.is_dir() {
        eprintln!("NGC root not found");
        return;
    }

    let mut containers: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let e = entry.unwrap();
        let p = e.path();
        if !p.is_dir() { continue; }
        let fname = e.file_name().to_string_lossy().to_string();
        if fname == "PregenPool" || !fname.starts_with("{") { continue; }

        // 读 1.dat — 25H2 存储 UTF-16LE SID
        let sid_file = p.join("1.dat");
        if let Ok(data) = fs::read(&sid_file) {
            // 去掉 UTF-16LE 里的 null bytes
            let utf16: Vec<u16> = data.chunks_exact(2)
                .filter_map(|c| Some(u16::from_le_bytes([c[0], c[1]])))
                .collect();
            let sid_str = String::from_utf16_lossy(&utf16);
            let sid_clean = sid_str.replace('\0', "").trim().to_string();
            // 移除空格（旧的 1.dat 格式有空格）
            let sid_nospace = sid_clean.replace(' ', "");
            let sid_ref = sid.replace(' ', "");
            if sid_nospace.contains(&sid_ref) || sid_ref.contains(&sid_nospace) || sid_ref == sid_nospace {
                println!("\nMATCH container: {} (SID: {})", fname, sid_clean);
                containers.push(p.clone());
            } else {
                println!("SKIP container: {} (SID: {} != {})", fname, sid_clean, sid);
            }
        }
    }

    if containers.is_empty() {
        eprintln!("ERROR: No matching NGC containers");
        return;
    }

    // 对每个容器，尝试破解
    for container in &containers {
        println!("\n====== CRACKING CONTAINER: {} ======", container.file_name().unwrap().to_string_lossy());
        crack_container(container, pin);
    }

    // 生成正确的密钥映射（从 7.dat CBOR 解析 credential_id + rp_id）
    generate_key_mapping(&containers);
}

fn crack_container(container: &Path, pin: &str) {
    // 第一步：DPAPI 解密所有 .dat 文件，收集 AES 密钥
    let blobs = collect_dat_blobs(container);
    println!("Found {} .dat blobs", blobs.len());

    // 收集 DPAPI 解密出的密钥（来自 18.dat）
    let mut aes_keys: Vec<(PathBuf, Vec<u8>, String)> = Vec::new();

    // PIN 编码
    let pin_variants: Vec<(&str, Vec<u8>)> = vec![
        ("hex_upper_utf16", pin_to_hex_upper_utf16(pin)),
        ("hex_lower_utf16", pin_to_hex_lower_utf16(pin)),
        ("raw_utf16", pin_to_utf16le(pin)),
        ("raw_bytes", pin.as_bytes().to_vec()),
        ("hex_upper_ascii", pin_to_hex_upper_ascii(pin)),
        ("sha256_pin", sha256(pin.as_bytes()).to_vec()),
    ];

    for (fpath, data) in &blobs {
        let fname = fpath.file_name().unwrap().to_string_lossy();
        if data.len() < 16 || data.len() > 4096 { continue; }

        // 无 entropy
        if let Ok(pt) = dpapi_unprotect(data, &[]) {
            let parent_dir = fpath.parent().and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy()).unwrap_or_default();
            println!("  {fname} ({size}B) in {parent_dir}: DPAPI[none] → {pt_len}B | {hex8}",
                size = data.len(), pt_len = pt.len(),
                hex8 = hex::encode(&pt.iter().take(8).copied().collect::<Vec<_>>()));
            if pt.len() == 32 {
                aes_keys.push((fpath.clone(), pt.clone(), "none".into()));
            }
            save_decrypted(fpath, &pt, "no_entropy");
        }

        // 带 PIN entropy
        for (vname, entropy) in &pin_variants {
            if let Ok(pt) = dpapi_unprotect(data, entropy) {
                println!("  {fname}: DPAPI[{vname}] → {len}B", len = pt.len());
                if pt.len() == 32 {
                    aes_keys.push((fpath.clone(), pt.clone(), vname.to_string()));
                }
                save_decrypted(fpath, &pt, vname);
            }
        }
    }

    // 第二步：用 AES 密钥解密所有 .dat 文件（跨目录）
    if !aes_keys.is_empty() {
        println!("\n=== 第二步: AES 解密 ({} 个密钥) ===", aes_keys.len());

        // 收集所有加密候选
        let all_blobs = collect_dat_blobs(container);
        // dump raw 18.dat hex for analysis
        for (key_path, aes_key, variant) in &aes_keys {
            println!("\n  密钥来自: {:?} [{}]", key_path.file_name().unwrap(), variant);
            println!("  AES key: {}", hex::encode(&aes_key[..16]));

            // Dump raw 18.dat first 64 bytes for header analysis
            if let Ok(raw) = fs::read(key_path) {
                println!("  raw 18.dat[0..64]: {}", hex::encode(&raw.iter().take(64).copied().collect::<Vec<_>>()));
            }

            // 从 raw 18.dat 解析 NgcIsoHeader
            let mut gcm_nonces: Vec<(&str, Vec<u8>)> = Vec::new();
            let mut cbc_ivs: Vec<(&str, Vec<u8>)> = Vec::new();

            if let Ok(raw) = fs::read(key_path) {
                if raw.len() >= 40 {
                    // 偏移 24 (4+16+4): 16 字节 IV（四个文件完全相同）
                    let header_iv = raw[24..40].to_vec();
                    gcm_nonces.push(("hdr_iv12", header_iv[..12].to_vec()));
                    cbc_ivs.push(("hdr_iv16", header_iv.clone()));
                    println!("  Header IV: {}", hex::encode(&header_iv));
                }
                // 回退方案
                gcm_nonces.push(("zero12", vec![0u8; 12]));
                gcm_nonces.push(("raw18_0_12", raw[..12.min(raw.len())].to_vec()));
                cbc_ivs.push(("zero16", vec![0u8; 16]));
            }

            // 对每个 .dat blob 尝试解密
            for (fpath, edata) in &all_blobs {
                if fpath == key_path { continue; } // 跳过 18.dat 自己
                if edata.len() < 16 { continue; }
                let dfname = format!("{}/{}",
                    fpath.parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy()).unwrap_or_default(),
                    fpath.file_name().unwrap().to_string_lossy());

                // AES-GCM
                for (nname, nonce) in &gcm_nonces {
                    if let Ok(pt) = aes_gcm_decrypt(aes_key, nonce, edata) {
                        let hex8 = hex::encode(&pt.iter().take(8).copied().collect::<Vec<_>>());
                        println!("    ✅ {dfname} ({len}B) GCM[{nname}] → {ptlen}B | {hex8}",
                            len = edata.len(), ptlen = pt.len());
                        find_ecdsa_key(&pt, &dfname);
                    }
                }

                // AES-CBC
                if edata.len() % 16 == 0 {
                    for (iname, iv) in &cbc_ivs {
                        if let Ok(pt) = aes_cbc_decrypt(aes_key, iv, edata) {
                            println!("    ✅ {dfname} ({len}B) CBC[{iname}] → {ptlen}B",
                                len = edata.len(), ptlen = pt.len());
                            find_ecdsa_key(&pt, &dfname);
                        }
                    }
                }
            }
        }
    }
}

fn collect_dat_blobs(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    walk_dir(dir, &mut out);
    // 按大小排序，大的（可能是加密 blob）先试
    out.sort_by_key(|(_, d)| -(d.len() as i64));
    out
}

fn walk_dir(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() { walk_dir(&p, out); }
            else if p.extension().map(|e| e == "dat").unwrap_or(false) {
                if let Ok(data) = fs::read(&p) {
                    out.push((p, data));
                }
            }
        }
    }
}

fn save_decrypted(file_path: &Path, data: &[u8], variant: &str) {
    let fname = file_path.file_stem().unwrap().to_string_lossy();
    let parent = file_path.parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy()).unwrap_or_default();
    let out = format!("{}/ngc_{}_{}_{}.bin", OUT_DIR, parent, fname, variant);
    let _ = fs::write(&out, data);
    // 查 ECDSA 密钥
    find_ecdsa_key(data, &out);
}

fn find_ecdsa_key(data: &[u8], _fname: &str) {
    // 搜 BCRYPT_ECCPRIVATE_BLOB magic
    let magic = 0x32434345u32.to_le_bytes();
    let mut i = 0;
    while i + 104 <= data.len() {
        if data[i] == magic[0] && data[i+1] == magic[1] && data[i+2] == magic[2] && data[i+3] == magic[3] {
            let cb = u32::from_le_bytes([data[i+4], data[i+5], data[i+6], data[i+7]]);
            if cb == 32 {
                let blob = &data[i..i+104];
                let x = &blob[8..40];
                let y = &blob[40..72];
                let d = &blob[72..104];
                if verify_ecdsa(x, y, d) {
                    println!("    ★★★ ECDSA_P256 PRIVATE KEY FOUND! offset={i} ★★★");
                    println!("    X: {}...", hex::encode(&x[..8]));
                    println!("    COSE: {}", cose_pk(x, y));
                    let _ = fs::write(format!("{}/ECDSA_KEY_offset_{}.bin", OUT_DIR, i), blob);
                }
            }
        }
        i += 4;
    }
}

fn verify_ecdsa(x: &[u8], y: &[u8], d: &[u8]) -> bool {
    use p256::SecretKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    if let Ok(sk) = SecretKey::from_bytes(d.into()) {
        let pk = sk.public_key();
        let pt = pk.to_encoded_point(false);
        pt.x().map(|dx| dx.as_slice() == x).unwrap_or(false)
            && pt.y().map(|dy| dy.as_slice() == y).unwrap_or(false)
    } else { false }
}

fn cose_pk(x: &[u8], y: &[u8]) -> String {
    let mut c = vec![0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    c.extend_from_slice(x);
    c.extend_from_slice(&[0x22, 0x58, 0x20]);
    c.extend_from_slice(y);
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&c)
}

// ─── DPAPI ────────────────────────────────────────────────────────────────

fn dpapi_unprotect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
    let data_in = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as _ };
    let ent = if entropy.is_empty() { None } else {
        Some(CRYPT_INTEGER_BLOB { cbData: entropy.len() as u32, pbData: entropy.as_ptr() as _ })
    };
    let mut data_out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    let r = unsafe {
        CryptUnprotectData(&data_in, None, ent.as_ref().map(|e| e as *const _), None, None,
            CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, &mut data_out)
    };
    if r.is_err() || data_out.pbData.is_null() {
        return Err("DPAPI failed".into());
    }
    let pt = unsafe {
        std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec()
    };
    unsafe { let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(data_out.pbData as _))); }
    Ok(pt)
}

// ─── PIN 编码 ─────────────────────────────────────────────────────────────

fn pin_to_hex_upper_utf16(pin: &str) -> Vec<u8> {
    let hex: String = pin.as_bytes().iter().map(|b| format!("{:02X}", b)).collect();
    hex.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

fn pin_to_hex_lower_utf16(pin: &str) -> Vec<u8> {
    let hex: String = pin.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
    hex.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

fn pin_to_utf16le(pin: &str) -> Vec<u8> {
    pin.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

fn pin_to_hex_upper_ascii(pin: &str) -> Vec<u8> {
    pin.as_bytes().iter().map(|b| format!("{:02X}", b)).collect::<String>().into_bytes()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn aes_gcm_decrypt(key: &[u8], nonce12: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    if key.len() != 32 || nonce12.len() < 12 || ct.len() < 16 {
        return Err("bad params".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "init")?;
    cipher.decrypt(Nonce::from_slice(&nonce12[..12]), ct).map_err(|_| "decrypt failed".into())
}

fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
    use aes::cipher::KeyIvInit;
    use aes::cipher::BlockDecryptMut;
    if key.len() != 32 || iv.len() != 16 || ct.len() < 16 || ct.len() % 16 != 0 {
        return Err("bad params".into());
    }
    type Aes256Cbc = cbc::Decryptor<aes::Aes256>;
    let mut dec = Aes256Cbc::new_from_slices(key, iv).map_err(|_| "init")?;
    let mut buf = ct.to_vec();
    for chunk in buf.chunks_exact_mut(16) {
        dec.decrypt_block_mut(aes::cipher::Block::<aes::Aes256>::from_mut_slice(chunk));
    }
    // Remove PKCS7 padding
    let pad = *buf.last().unwrap() as usize;
    if pad == 0 || pad > 16 || pad > buf.len() { return Err("bad padding".into()); }
    buf.truncate(buf.len() - pad);
    Ok(buf)
}

/// 从 7.dat CBOR 解析 credential_id 和 rp_id
fn parse_7dat_credential(seven_dat: &[u8]) -> Option<(String, String)> {
    // 7.dat 是 CBOR map(3): {1:2, 2:map{"bid":rp_id, "dname":..}, 3:map{"bid":cred_id, "dname":..}}
    // 简单解析：找 "bid" 字符串后跟着的 UTF-8 字符串值
    let mut rp_id = String::new();
    let mut cred_id = String::new();
    let mut i = 0;
    // 编码: 62 69 64 = text(2) "bid" → 后跟 text(N) value
    while i + 3 < seven_dat.len() {
        if seven_dat[i] == 0x62 && seven_dat[i+1] == 0x69 && seven_dat[i+2] == 0x64 {
            // found "bid", next byte is text(N) where N = next byte value
            i += 3;
            if i < seven_dat.len() {
                let len = seven_dat[i] as usize;
                i += 1;
                if i + len <= seven_dat.len() {
                    let val = String::from_utf8_lossy(&seven_dat[i..i+len]).to_string();
                    if rp_id.is_empty() {
                        rp_id = val;
                    } else {
                        cred_id = val;
                    }
                    i += len;
                    continue;
                }
            }
        }
        i += 1;
    }
    if cred_id.is_empty() && rp_id.is_empty() { None }
    else if cred_id.is_empty() { Some((rp_id.clone(), rp_id)) }
    else { Some((cred_id, rp_id)) }
}

/// 扫描输出目录的 .bin 文件，匹配 NGC 容器 7.dat，生成 passkey_keys.json
fn generate_key_mapping(containers: &[PathBuf]) {
    let out_dir = Path::new(OUT_DIR);
    if !out_dir.is_dir() { return; }

    let mut entries: Vec<serde_json::Value> = Vec::new();

    for entry in fs::read_dir(out_dir).unwrap().flatten() {
        let fname = entry.file_name().to_string_lossy().to_string();
        if !fname.starts_with("ngc_") || !fname.ends_with("_18_no_entropy.bin") {
            continue;
        }
        // ngc_{hash}_18_no_entropy.bin → 提取 hash
        let hash = fname.strip_prefix("ngc_").and_then(|s| s.strip_suffix("_18_no_entropy.bin")).unwrap_or("");
        let key_file = entry.path();

        // 在 NGC 容器中搜索对应的 7.dat
        let mut rp_id = String::new();
        let mut cred_id = hash.to_string();
        for c in containers {
            if let Ok(dirs) = fs::read_dir(c) {
                for d in dirs.flatten() {
                    let dpath = d.path();
                    if !dpath.is_dir() { continue; }
                    let sub = dpath.join(hash).join("7.dat");
                    if sub.exists() {
                        if let Ok(data) = fs::read(&sub) {
                            if let Some((cid, rp)) = parse_7dat_credential(&data) {
                                cred_id = cid;
                                rp_id = rp;
                            }
                        }
                    }
                }
            }
        }

        entries.push(serde_json::json!({
            "credential_id": cred_id,
            "rp_id": rp_id,
            "key_file": key_file.to_string_lossy().to_string(),
        }));
    }

    if !entries.is_empty() {
        let mapping_path = out_dir.join("passkey_keys.json");
        let json = serde_json::to_string_pretty(&entries).unwrap_or_default();
        let _ = fs::write(&mapping_path, &json);
        println!("\n✅ 密钥映射已生成: {} ({} 个凭据)", mapping_path.display(), entries.len());
        for e in &entries {
            println!("  {} @ {}",
                e.get("credential_id").and_then(|v| v.as_str()).unwrap_or("?"),
                e.get("rp_id").and_then(|v| v.as_str()).unwrap_or("?"));
        }
    }
}

fn pbkdf2_sha256(pass: &[u8], salt: &[u8], rounds: u32, len: usize) -> Vec<u8> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    let mut out = vec![0u8; len];
    pbkdf2_hmac::<Sha256>(pass, salt, rounds, &mut out);
    out
}
