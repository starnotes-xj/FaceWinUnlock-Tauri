//! NGC FIDO2 ECDSA P-256 offline decryption tool
//!
//! Must run as SYSTEM (e.g. PsExec -s).
//!
//! Usage: ngc_decrypt.exe <username> <pin>
//!
//! Decryption chain:
//!   PIN -> PIN encoding -> KDF -> entropy
//!   -> CryptUnprotectData(srk_blob, entropy, LOCAL_MACHINE)
//!   -> SRK (AES-256 key)
//!   -> AES-GCM decrypt(key encryptedCbor)
//!   -> ECDSA P-256 private key
//!
//! Tries 9 PIN encodings x 5 KDF methods = 45 combinations,
//! plus multiple entropy variants for each.

use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use pbkdf2::pbkdf2_hmac;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256, Sha512};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE,
    CRYPTPROTECT_UI_FORBIDDEN,
};

// ─── Constants ─────────────────────────────────────────────────────────────────

const NGC_ROOT: &str =
    r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc";
const FIXED_ENTROPY_PREFIX: &[u8] = b"xT5rZW5qVVbrvpuA\0";

// BCRYPT_ECCPRIVATE_BLOB magic: "ECC2" = 0x32454343
const ECC_PRIVATE_MAGIC: u32 = 0x32454343;

// ─── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (username, pin, sid_override) = if args.len() >= 4 && args[1] == "--sid" {
        ("<by-sid>", args[3].clone(), Some(args[2].clone()))
    } else if args.len() >= 3 {
        (args[1].as_str(), args[2].clone(), None)
    } else {
        eprintln!("Usage: {} <username> <pin>", args[0]);
        eprintln!("       {} --sid <SID> <pin>", args[0]);
        std::process::exit(1);
    };
    let pin = &pin;

    println!("=== NGC FIDO2 ECDSA P-256 Offline Decryption ===");
    println!("Target user: {}", username);
    println!("PIN: {}", pin);
    check_system_context();

    let sid = if let Some(s) = sid_override {
        println!("Using explicit SID: {}", s);
        s
    } else {
        match find_sid_by_username(username) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("ERROR: Cannot find SID for '{}': {}", username, e);
                std::process::exit(1);
            }
        }
    };
    println!("SID: {}", sid);

    let containers = match scan_containers(&sid) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: Cannot scan NGC containers: {}", e);
            std::process::exit(1);
        }
    };

    if containers.is_empty() {
        eprintln!("ERROR: No NGC containers found for user '{}'", username);
        std::process::exit(1);
    }

    println!("Found {} NGC container(s)", containers.len());
    for (ci, c) in containers.iter().enumerate() {
        println!(
            "\n═══ Container [{}]: {} ═══",
            ci,
            c.guid
        );
        println!("  Salt: {} bytes, Rounds: {}", c.salt.len(), c.rounds);
        match &c.srk_blob {
            Some(b) => println!("  SRK blob: {} bytes", b.len()),
            None => println!("  SRK blob: NOT FOUND (will try alternative protector blobs)"),
        }
        println!("  Keys: {}", c.keys.len());

        for (ki, key) in c.keys.iter().enumerate() {
            println!(
                "\n--- Key [{}]: {} ---",
                ki, key.filename
            );
            println!("  Alg: {}, Bits: {}", key.alg, key.bits);
            println!("  IV (first 12B): {:02X?}", &key.iv[..key.iv.len().min(12)]);
            println!("  Payload: {} bytes", key.payload.len());

            let mut found = false;

            // Determine protector blob to DPAPI-decrypt.
            let protector_blobs: Vec<(&str, &[u8])> = {
                let mut blobs: Vec<(&str, &[u8])> = Vec::new();
                if let Some(srk) = &c.srk_blob {
                    blobs.push(("srk", srk.as_slice()));
                }
                if let Some(alt) = &c.srk_alt {
                    blobs.push(("Container.encryptedCbor", alt.as_slice()));
                }
                if let Some(alt2) = &c.protectors_encrypted_cbor {
                    blobs.push(("Protectors.encryptedCbor", alt2.as_slice()));
                }
                blobs
            };

            if protector_blobs.is_empty() {
                println!("  WARNING: No protector blob found to DPAPI-decrypt");
                println!("  Trying alternative: direct AES with PBKDF2-derived keys...");
                // Fall back to trying PBKDF2 entropy directly as AES key
                if try_direct_aes_no_srk(pin, &c.salt, c.rounds, &key.iv, &key.payload, &key.filename, c.guid.as_str(), &key.alg, key.bits) {
                    found = true;
                }
                if !found {
                    println!("  -> No combination worked for this key");
                }
                continue;
            }

            for (protector_name, protector_blob) in &protector_blobs {
                if found {
                    break;
                }
                println!("  Trying protector: {} ({} bytes)", protector_name, protector_blob.len());
                found = try_decrypt_key(
                    pin,
                    protector_blob,
                    &c.salt,
                    c.rounds,
                    &key.iv,
                    &key.payload,
                    protector_name,
                    &key.filename,
                    c.guid.as_str(),
                    &key.alg,
                    key.bits,
                );
            }

            if found {
                println!("  -> Key decrypted successfully!");
            } else {
                println!("  -> No combination worked for this key");
            }
        }
    }
}

// ─── Context checks ────────────────────────────────────────────────────────────

fn check_system_context() {
    // Quick admin check via registry write attempt
    use windows::Win32::System::Registry::*;
    use windows_core::PCWSTR;
    unsafe {
        let key: Vec<u16> = r"SOFTWARE\facewinunlock-tauri_test".encode_utf16().chain(Some(0)).collect();
        let mut hkey = std::mem::zeroed();
        let result = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(key.as_ptr()),
            None,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE | KEY_READ,
            None,
            &mut hkey,
            None,
        );
        if result.is_ok() {
            println!("[OK] Running with elevated/System privileges (HKLM write OK)");
            let _ = RegCloseKey(hkey);
            let _ = RegDeleteKeyW(HKEY_LOCAL_MACHINE, PCWSTR::from_raw(key.as_ptr()));
        } else {
            println!("[WARN] Cannot write to HKLM -- may not be SYSTEM");
        }
    }
}

// ─── SID lookup (copied from Unlock/src/ngc/mod.rs) ────────────────────────────

fn find_sid_by_username(username: &str) -> Result<String, String> {
    use windows::Win32::Security::LookupAccountNameW;
    use windows::Win32::Security::SID_NAME_USE;
    use windows::Win32::Security::PSID;
    use windows_core::PCWSTR;

    let name_wide: Vec<u16> = username.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let mut sid_size = 0u32;
        let mut domain_size = 0u32;
        let mut sid_type = SID_NAME_USE::default();

        let _ = LookupAccountNameW(
            None,
            PCWSTR::from_raw(name_wide.as_ptr()),
            None,
            &mut sid_size,
            None,
            &mut domain_size,
            &mut sid_type,
        );

        if sid_size == 0 {
            return Err(format!(
                "LookupAccountNameW query size failed (user: {})",
                username
            ));
        }

        let mut sid_buf = vec![0u8; sid_size as usize];
        let mut domain_buf = vec![0u16; domain_size as usize];

        if LookupAccountNameW(
            None,
            PCWSTR::from_raw(name_wide.as_ptr()),
            Some(PSID(sid_buf.as_mut_ptr() as *mut std::ffi::c_void)),
            &mut sid_size,
            Some(windows_core::PWSTR(domain_buf.as_mut_ptr())),
            &mut domain_size,
            &mut sid_type,
        )
        .is_err()
        {
            return Err(format!("LookupAccountNameW failed for '{}'", username));
        }

        Ok(sid_to_string(&sid_buf[..sid_size as usize])?)
    }
}

fn sid_to_string(sid: &[u8]) -> Result<String, String> {
    if sid.len() < 8 {
        return Err("SID too short".to_string());
    }
    let revision = sid[0];
    let sub_count = sid[1] as usize;
    let id_auth = ((sid[2] as u64) << 40)
        | ((sid[3] as u64) << 32)
        | ((sid[4] as u64) << 24)
        | ((sid[5] as u64) << 16)
        | ((sid[6] as u64) << 8)
        | (sid[7] as u64);

    if sid.len() < 8 + sub_count * 4 {
        return Err("SID data incomplete".to_string());
    }

    let mut s = format!("S-{}-{}", revision, id_auth);
    for i in 0..sub_count {
        let offset = 8 + i * 4;
        let sub_auth = u32::from_le_bytes([
            sid[offset],
            sid[offset + 1],
            sid[offset + 2],
            sid[offset + 3],
        ]);
        s.push_str(&format!("-{}", sub_auth));
    }
    Ok(s)
}

// ─── NGC Container scanning ────────────────────────────────────────────────────

#[derive(Debug)]
struct ContainerInfo {
    guid: String,
    container_path: PathBuf,
    salt: Vec<u8>,
    rounds: u32,
    /// DPAPI-encrypted SRK blob from Container.json `srk` field (base64-decoded)
    srk_blob: Option<Vec<u8>>,
    /// Alternative protector: Container.json `encryptedCbor` (base64-decoded)
    srk_alt: Option<Vec<u8>>,
    /// For debugging: Protectors.json `encryptedCbor` (base64-decoded),
    /// NOT typically a DPAPI blob, but worth trying.
    protectors_encrypted_cbor: Option<Vec<u8>>,
    keys: Vec<KeyInfo>,
}

#[derive(Debug)]
struct KeyInfo {
    filename: String,
    alg: String,
    bits: u32,
    iv: Vec<u8>,
    payload: Vec<u8>,
}

fn scan_containers(sid: &str) -> Result<Vec<ContainerInfo>, String> {
    let ngc_root = Path::new(NGC_ROOT);
    if !ngc_root.is_dir() {
        return Err(format!("NGC root not found: {}", NGC_ROOT));
    }

    let mut containers = Vec::new();

    for entry in std::fs::read_dir(ngc_root).map_err(|e| format!("read_dir: {}", e))? {
        let entry = entry.map_err(|e| format!("entry: {}", e))?;
        let container_path = entry.path();
        if !container_path.is_dir() {
            continue;
        }

        let guid = container_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        if guid == "PregenPool" || guid.is_empty() {
            continue;
        }

        // Check if this container belongs to the user (via Container.json SID)
        let cj_path = container_path.join("Container.json");
        let belongs = if cj_path.is_file() {
            if let Ok(js) = std::fs::read_to_string(&cj_path) {
                js.contains(&format!("\"sid\":\"{}\"", sid))
                    || js.contains(&format!("\"sid\": \"{}\"", sid))
            } else {
                false
            }
        } else {
            false
        };
        if !belongs {
            continue;
        }

        println!("  Scanning container: {} (matches SID)", guid);

        // Parse Protectors.json for salt + rounds
        let (salt, rounds) = parse_protectors_salt_rounds(&container_path);
        let salt = salt.unwrap_or_else(|| vec![0u8; 32]);
        let rounds = rounds.unwrap_or(10_000);

        // Parse Container.json for SRK and other blobs
        let (srk_blob, srk_alt) = parse_container_srk(&container_path);

        // Also grab Protectors.json encryptedCbor as a fallback protector blob
        let protectors_encrypted_cbor = parse_protectors_encrypted_cbor(&container_path);

        // Scan Keys/ directory
        let keys = scan_keys(&container_path);

        if keys.is_empty() {
            println!("    No Keys/ files found in this container, skipping");
            continue;
        }

        containers.push(ContainerInfo {
            guid,
            container_path,
            salt,
            rounds,
            srk_blob,
            srk_alt,
            protectors_encrypted_cbor,
            keys,
        });
    }

    Ok(containers)
}

/// Parse Protectors.json to extract salt and rounds from the PIN protector.
/// Returns (salt, rounds) or (None, None) on failure.
fn parse_protectors_salt_rounds(container_path: &Path) -> (Option<Vec<u8>>, Option<u32>) {
    let pj = container_path.join("Protectors.json");
    if !pj.is_file() {
        return (None, None);
    }
    let json_str = match std::fs::read_to_string(&pj) {
        Ok(s) => s,
        Err(_) => return (None, None),
    };
    let root: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return (None, None),
    };

    let cbor_b64 = root
        .get("pin")
        .and_then(|p| p.get("secretStore"))
        .and_then(|s| s.get("encryptedCbor"))
        .and_then(|v| v.as_str());

    let cbor_b64 = match cbor_b64 {
        Some(s) => s,
        None => return (None, None),
    };

    let cbor_bytes = match base64::engine::general_purpose::STANDARD.decode(cbor_b64) {
        Ok(b) => b,
        Err(_) => return (None, None),
    };

    let hdr = match parse_ngciso_header(&cbor_bytes) {
        Ok(h) => h,
        Err(_) => return (None, None),
    };

    (Some(hdr.salt), Some(hdr.rounds))
}

/// Parse Container.json to extract the SRK DPAPI blob and alternative encryptedCbor.
fn parse_container_srk(container_path: &Path) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let cj = container_path.join("Container.json");
    if !cj.is_file() {
        return (None, None);
    }
    let json_str = match std::fs::read_to_string(&cj) {
        Ok(s) => s,
        Err(_) => return (None, None),
    };
    let root: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return (None, None),
    };

    let srk = root
        .get("srk")
        .and_then(|v| v.as_str())
        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok());

    let alt = root
        .get("encryptedCbor")
        .and_then(|v| v.as_str())
        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok());

    // Also check for "EncData" field used in some container formats
    let alt2 = root
        .get("EncData")
        .and_then(|v| v.as_str())
        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok());

    (srk, alt.or(alt2))
}

fn parse_protectors_encrypted_cbor(container_path: &Path) -> Option<Vec<u8>> {
    let pj = container_path.join("Protectors.json");
    if !pj.is_file() {
        return None;
    }
    let json_str = std::fs::read_to_string(&pj).ok()?;
    let root: serde_json::Value = serde_json::from_str(&json_str).ok()?;
    let cbor_b64 = root
        .get("pin")
        .and_then(|p| p.get("secretStore"))
        .and_then(|s| s.get("encryptedCbor"))
        .and_then(|v| v.as_str())?;
    base64::engine::general_purpose::STANDARD.decode(cbor_b64).ok()
}

fn scan_keys(container_path: &Path) -> Vec<KeyInfo> {
    let keys_dir = container_path.join("Keys");
    if !keys_dir.is_dir() {
        return Vec::new();
    }

    let mut keys = Vec::new();
    let entries = match std::fs::read_dir(&keys_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() || path.extension().map_or(true, |e| e != "json") {
            continue;
        }

        let fname = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();

        let json_str = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let root: serde_json::Value = match serde_json::from_str(&json_str) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let alg = root
            .get("alg")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let bits = root.get("bits").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        // Find encryptedCbor (may be under "encrypted" or at root level)
        let cbor_b64 = root
            .get("encrypted")
            .and_then(|e| e.get("encryptedCbor"))
            .and_then(|v| v.as_str())
            .or_else(|| root.get("encryptedCbor").and_then(|v| v.as_str()));

        let cbor_b64 = match cbor_b64 {
            Some(s) => s,
            None => continue,
        };

        let cbor_bytes = match base64::engine::general_purpose::STANDARD.decode(cbor_b64) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let hdr = match parse_ngciso_header(&cbor_bytes) {
            Ok(h) => h,
            Err(_) => continue,
        };

        let payload = cbor_bytes[hdr.payload_offset..].to_vec();

        println!(
            "    Key: {} alg={} bits={} iv={}B payload={}B",
            fname,
            alg,
            bits,
            hdr.iv.len(),
            payload.len()
        );

        keys.push(KeyInfo {
            filename: fname,
            alg,
            bits,
            iv: hdr.iv,
            payload,
        });
    }

    keys
}

// ─── NgcIsoHeader parsing (copied from Unlock/src/ngc/container.rs) ─────────────

#[derive(Debug)]
struct NgcIsoHeader {
    salt: Vec<u8>,
    rounds: u32,
    iv: Vec<u8>,
    payload_offset: usize,
}

fn parse_ngciso_header(data: &[u8]) -> Result<NgcIsoHeader, String> {
    if data.len() < 128 {
        return Err(format!(
            "encryptedCbor too short: {} bytes (need >= 128)",
            data.len()
        ));
    }
    let salt = data[0x1C..0x1C + 32].to_vec();
    let iv = data[0x3C..0x3C + 16].to_vec();
    // Find payload: scan past "NgcIsoHeader_<GUID>" to null or CBOR byte
    let mut payload_offset = 0x64;
    for i in 0x64..data.len().min(256) {
        if data[i] == 0 && i > 0x64 + 36 {
            payload_offset = i + 1;
            break;
        }
        if data[i] >= 0xA0 && i > 0x64 + 36 {
            payload_offset = i;
            break;
        }
    }
    Ok(NgcIsoHeader {
        salt,
        rounds: 10_000,
        iv,
        payload_offset,
    })
}

// ─── DPAPI unprotect (copied from Unlock/src/ngc/dpapi.rs) ──────────────────────

fn dpapi_unprotect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
    let data_in = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };

    let entropy_blob = if entropy.is_empty() {
        None
    } else {
        Some(CRYPT_INTEGER_BLOB {
            cbData: entropy.len() as u32,
            pbData: entropy.as_ptr() as *mut u8,
        })
    };

    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let result = unsafe {
        CryptUnprotectData(
            &data_in,
            None,
            entropy_blob.as_ref().map(|b| b as *const _),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
            &mut data_out,
        )
    };

    if result.is_err() {
        return Err("DPAPI decrypt failed".to_string());
    }

    let plaintext = unsafe {
        if data_out.pbData.is_null() || data_out.cbData == 0 {
            return Err("DPAPI returned empty data".to_string());
        }
        std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec()
    };

    unsafe {
        let _ = LocalFree(Some(HLOCAL(data_out.pbData as *mut _)));
    }

    Ok(plaintext)
}

// ─── AES-256-GCM decrypt (copied from Unlock/src/ngc/dpapi.rs) ──────────────────

fn aes256_gcm_decrypt(key: &[u8], nonce12: &[u8], ct_with_tag: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("GCM key len != 32: {}", key.len()));
    }
    if nonce12.len() < 12 {
        return Err(format!("GCM nonce < 12: {}", nonce12.len()));
    }
    if ct_with_tag.len() < 16 {
        return Err(format!("GCM ct too short: {}", ct_with_tag.len()));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "Aes256Gcm init failed".to_string())?;
    let nonce = Nonce::from_slice(&nonce12[..12]);

    cipher
        .decrypt(nonce, ct_with_tag)
        .map_err(|_| "AES-GCM decrypt failed (authentication failed)".to_string())
}

// ─── PIN encodings (9 variants) ─────────────────────────────────────────────────

fn encode_pin_hex_upper(pin: &str) -> Vec<u8> {
    pin.as_bytes()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>()
        .into_bytes()
}

fn encode_pin_hex_upper_utf16(pin: &str) -> Vec<u8> {
    let hex = encode_pin_hex_upper(pin);
    to_utf16le_bytes(&String::from_utf8_lossy(&hex))
}

fn encode_pin_hex_lower(pin: &str) -> Vec<u8> {
    pin.as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
        .into_bytes()
}

fn encode_pin_hex_lower_utf16(pin: &str) -> Vec<u8> {
    let hex = encode_pin_hex_lower(pin);
    to_utf16le_bytes(&String::from_utf8_lossy(&hex))
}

fn encode_pin_raw_utf16(pin: &str) -> Vec<u8> {
    to_utf16le_bytes(pin)
}

fn encode_pin_raw_bytes(pin: &str) -> Vec<u8> {
    pin.as_bytes().to_vec()
}

fn encode_pin_digits_int(pin: &str) -> Vec<u8> {
    // Parse as u64, then big-endian 4 bytes
    let val: u64 = pin.parse().unwrap_or(0);
    val.to_be_bytes().to_vec() // 8 bytes
}

fn encode_pin_digits_int_le(pin: &str) -> Vec<u8> {
    let val: u64 = pin.parse().unwrap_or(0);
    val.to_le_bytes().to_vec() // 8 bytes
}

fn encode_pin_digits_hex(pin: &str) -> Vec<u8> {
    // Each char byte interpreted as hex nibble value -> one byte per digit
    pin.chars()
        .filter_map(|c| c.to_digit(16))
        .map(|d| d as u8)
        .collect()
}

fn encode_pin_sha256(pin: &str) -> Vec<u8> {
    Sha256::digest(pin.as_bytes()).to_vec()
}

fn to_utf16le_bytes(s: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(s.len() * 2);
    for ch in s.chars() {
        let code = ch as u16;
        buf.extend_from_slice(&code.to_le_bytes());
    }
    buf
}

// ─── KDF methods (5 variants) ───────────────────────────────────────────────────

fn kdf_pbkdf2(pin_bytes: &[u8], salt: &[u8], rounds: u32) -> Vec<u8> {
    let mut derived = vec![0u8; 64];
    pbkdf2_hmac::<Sha256>(pin_bytes, salt, rounds, &mut derived);
    derived
}

fn kdf_sha512(pin_bytes: &[u8], salt: &[u8], _rounds: u32) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(pin_bytes);
    hasher.update(salt);
    hasher.finalize().to_vec() // 64 bytes
}

fn kdf_sha256_concat(pin_bytes: &[u8], salt: &[u8], _rounds: u32) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(pin_bytes);
    hasher.update(salt);
    hasher.update(pin_bytes);
    hasher.finalize().to_vec() // 32 bytes
}

fn kdf_empty(_pin_bytes: &[u8], _salt: &[u8], _rounds: u32) -> Vec<u8> {
    Vec::new() // 0 bytes
}

fn kdf_direct_wrapper(pin_bytes: &[u8], _salt: &[u8], _rounds: u32) -> Vec<u8> {
    if pin_bytes.len() == 32 {
        pin_bytes.to_vec()
    } else {
        Vec::new()
    }
}

// ─── Entropy variants from KDF output ──────────────────────────────────────────

fn derive_entropy_variants(kdf_bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut variants: Vec<(String, Vec<u8>)> = Vec::new();

    if !kdf_bytes.is_empty() {
        // V0: Raw KDF result directly
        variants.push(("raw".to_string(), kdf_bytes.to_vec()));

        // V1: Standard NGC post-processing:
        // hex(KDF) uppercase -> UTF-16LE -> SHA-512 -> prefix + hash = 82 bytes
        let hex_upper: String = kdf_bytes.iter().map(|b| format!("{:02X}", b)).collect();
        let hex_utf16le = to_utf16le_bytes(&hex_upper);
        let hash = Sha512::digest(&hex_utf16le);
        let mut std_entropy = FIXED_ENTROPY_PREFIX.to_vec();
        std_entropy.extend_from_slice(&hash);
        variants.push(("NGC_std".to_string(), std_entropy));

        // V1b: Same but lowercase hex
        let hex_lower: String = kdf_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let hex_lower_utf16le = to_utf16le_bytes(&hex_lower);
        let hash2 = Sha512::digest(&hex_lower_utf16le);
        let mut std_entropy_lower = FIXED_ENTROPY_PREFIX.to_vec();
        std_entropy_lower.extend_from_slice(&hash2);
        variants.push(("NGC_std_lower".to_string(), std_entropy_lower));

        // V2: SHA-512 of KDF bytes
        if kdf_bytes.len() >= 1 {
            let sha512_full = Sha512::digest(kdf_bytes);
            variants.push(("SHA512[..32]".to_string(), sha512_full[..32].to_vec()));
            variants.push(("SHA512[..64]".to_string(), sha512_full[..64].to_vec()));
            // SHA512 slices
            if sha512_full.len() >= 82 {
                variants.push(("SHA512[18..50]".to_string(), sha512_full[18..50].to_vec()));
            }
        }

        // V3: SHA-256 of KDF bytes
        let sha256_result = Sha256::digest(kdf_bytes);
        variants.push(("SHA256".to_string(), sha256_result.to_vec()));

        // V4: Various slices of kdf_bytes if long enough
        if kdf_bytes.len() >= 82 {
            variants.push(("raw[18..50]".to_string(), kdf_bytes[18..50].to_vec()));
            variants.push(("raw[..32]".to_string(), kdf_bytes[..32].to_vec()));
            variants.push(("raw[32..64]".to_string(), kdf_bytes[32..64].to_vec()));
        }
        if kdf_bytes.len() >= 64 {
            variants.push(("raw[..64]".to_string(), kdf_bytes[..64].to_vec()));
        }
        if kdf_bytes.len() >= 50 {
            variants.push(("raw[..50]".to_string(), kdf_bytes[..50].to_vec()));
        }
        if kdf_bytes.len() >= 128 {
            variants.push(("raw[..128]".to_string(), kdf_bytes[..128].to_vec()));
        }

        // V5: Double SHA-256
        let double_sha = Sha256::digest(&Sha256::digest(kdf_bytes));
        variants.push(("SHA256^2".to_string(), double_sha.to_vec()));

        // V6: skip HMAC variant to avoid compile issues with hmac 0.12 trait imports

        // V7: Just the first 32 bytes of kdf_bytes (most common AES key size)
        // Also try first 16, 24, 48 bytes
        if kdf_bytes.len() > 32 {
            variants.push(("raw[..32]".to_string(), kdf_bytes[..32].to_vec()));
        }
        if kdf_bytes.len() > 48 {
            variants.push(("raw[..48]".to_string(), kdf_bytes[..48].to_vec()));
        }
        if kdf_bytes.len() > 16 {
            variants.push(("raw[..16]".to_string(), kdf_bytes[..16].to_vec()));
        }
    }

    // Vx: Empty entropy (some DPAPI blobs have no entropy)
    variants.push(("empty".to_string(), vec![]));

    // Deduplicate by keeping first occurrence of each label
    let mut seen = std::collections::HashSet::new();
    variants.retain(|(label, _)| seen.insert(label.clone()));

    variants
}

// ─── ECDSA P-256 key handling ──────────────────────────────────────────────────

/// Try to parse decrypted key bytes as an ECDSA P-256 private key.
/// Returns (d, x, y) on success where all are 32-byte big-endian.
fn parse_ecdsa_key(key_bytes: &[u8]) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
    match key_bytes.len() {
        32 => {
            // Raw 32-byte scalar d (big-endian)
            let mut d = [0u8; 32];
            d.copy_from_slice(key_bytes);
            // Compute public key from d
            let secret = p256::SecretKey::from_slice(&d)
                .map_err(|e| format!("p256::SecretKey::from_slice: {}", e))?;
            let public = secret.public_key();
            let encoded = public.to_encoded_point(false);
            let x = encoded
                .x()
                .ok_or_else(|| "No X coordinate".to_string())?;
            let y = encoded
                .y()
                .ok_or_else(|| "No Y coordinate".to_string())?;
            let mut x_arr = [0u8; 32];
            let mut y_arr = [0u8; 32];
            x_arr.copy_from_slice(x);
            y_arr.copy_from_slice(y);
            Ok((d, x_arr, y_arr))
        }
        96 => {
            // X(32) || Y(32) || d(32)
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            let mut d = [0u8; 32];
            x.copy_from_slice(&key_bytes[0..32]);
            y.copy_from_slice(&key_bytes[32..64]);
            d.copy_from_slice(&key_bytes[64..96]);
            Ok((d, x, y))
        }
        104 => {
            // BCRYPT_ECCPRIVATE_BLOB format: magic(4) | cbKey(4) | padding(32) | X(32) | Y(32) | d(32)
            let magic = u32::from_le_bytes(key_bytes[0..4].try_into().unwrap());
            if magic != ECC_PRIVATE_MAGIC {
                return Err(format!(
                    "BCRYPT_ECCPRIVATE_BLOB bad magic: 0x{:08X}",
                    magic
                ));
            }
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            let mut d = [0u8; 32];
            x.copy_from_slice(&key_bytes[40..72]);
            y.copy_from_slice(&key_bytes[72..104]);
            // d is at the end
            let d_start = 8 + 32 + 32 + 32;
            if key_bytes.len() >= d_start + 32 {
                d.copy_from_slice(&key_bytes[d_start..d_start + 32]);
            }
            Ok((d, x, y))
        }
        _ => Err(format!(
            "Unexpected key data length: {} bytes (expected 32, 96, or 104)",
            key_bytes.len()
        )),
    }
}

/// Verify ECDSA key self-consistency: d * G should produce point (X, Y).
fn verify_ecdsa_key(d: &[u8; 32], x: &[u8; 32], y: &[u8; 32]) -> bool {
    let secret = match p256::SecretKey::from_slice(d) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let public = secret.public_key();
    let encoded = public.to_encoded_point(false);

    let computed_x = match encoded.x() {
        Some(x) => x,
        None => return false,
    };
    let computed_y = match encoded.y() {
        Some(y) => y,
        None => return false,
    };

    computed_x.as_slice() == x && computed_y.as_slice() == y
}

/// Build a 104-byte BCRYPT_ECCPRIVATE_BLOB.
fn make_bcrypt_ecc_blob(d: &[u8; 32], x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(104);
    blob.extend_from_slice(&ECC_PRIVATE_MAGIC.to_le_bytes()); // magic "ECC2"
    blob.extend_from_slice(&32u32.to_le_bytes()); // cbKey
    blob.extend_from_slice(&[0u8; 32]); // padding
    blob.extend_from_slice(x); // X
    blob.extend_from_slice(y); // Y
    blob.extend_from_slice(d); // d (private key scalar)
    blob
}

/// Compute COSE_PublicKey as base64url-encoded CBOR.
fn compute_cose_key(x: &[u8; 32], y: &[u8; 32]) -> String {
    // Manually construct COSE_Key CBOR:
    // {
    //   1: 2,      // kty: EC2
    //   3: -7,     // alg: ES256
    //   -1: 1,     // crv: P-256
    //   -2: x',    // x coordinate (32 bytes)
    //   -3: y',    // y coordinate (32 bytes)
    // }
    // CBOR map: 5 pairs -> 0xA5
    // key 1 (unsigned): 0x01
    // val 2 (unsigned): 0x02
    // key 3 (unsigned): 0x03
    // val -7 (negative): CBOR negative(-7) = 0x26 (1+6 = 7)
    // key -1 (negative): 0x20 (= 32 = -(1+31)? Actually for negative -1: 0x20)
    //   CBOR negative: major type 1, val = -(arg+1), so -1 = arg 0 = 0x20
    // val 1 (unsigned): 0x01
    // key -2 (negative): 0x21 = -(arg+1) where arg=1 -> -(1+1) = -2
    // val x (32 bytes): 0x58 0x20 <32 bytes>
    // key -3 (negative): 0x22 = -(arg+1) where arg=2 -> -(2+1) = -3
    // val y (32 bytes): 0x58 0x20 <32 bytes>

    let mut cbor = Vec::new();
    // map(5)
    cbor.push(0xA5);
    // 1: 2 (kty: EC2)
    cbor.push(0x01);
    cbor.push(0x02);
    // 3: -7 (alg: ES256)
    cbor.push(0x03);
    cbor.push(0x26); // negative(-7) = 0x26
    // -1: 1 (crv: P-256)
    cbor.push(0x20);
    cbor.push(0x01);
    // -2: h'<x>' (x coordinate)
    cbor.push(0x21);
    cbor.push(0x58);
    cbor.push(32);
    cbor.extend_from_slice(x);
    // -3: h'<y>' (y coordinate)
    cbor.push(0x22);
    cbor.push(0x58);
    cbor.push(32);
    cbor.extend_from_slice(y);

    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cbor)
}

// ─── Main decryption attempt ───────────────────────────────────────────────────

/// Try all PIN encoding x KDF method combinations to decrypt the protector blob,
/// then use the SRK to AES-GCM decrypt the key payload.
fn try_decrypt_key(
    pin: &str,
    protector_blob: &[u8],
    salt: &[u8],
    rounds: u32,
    key_iv: &[u8],
    key_payload: &[u8],
    protector_name: &str,
    key_filename: &str,
    container_guid: &str,
    _key_alg: &str,
    _key_bits: u32,
) -> bool {
    if protector_blob.len() < 32 {
        println!("    Protector blob too small ({} bytes), skipping", protector_blob.len());
        return false;
    }

    let encodings: Vec<(&str, fn(&str) -> Vec<u8>)> = vec![
        ("hex_upper", encode_pin_hex_upper),
        ("hex_upper_utf16", encode_pin_hex_upper_utf16),
        ("hex_lower", encode_pin_hex_lower),
        ("hex_lower_utf16", encode_pin_hex_lower_utf16),
        ("raw_utf16", encode_pin_raw_utf16),
        ("raw_bytes", encode_pin_raw_bytes),
        ("digits_int_be", encode_pin_digits_int),
        ("digits_int_le", encode_pin_digits_int_le),
        ("digits_hex", encode_pin_digits_hex),
        ("sha256_pin", encode_pin_sha256),
    ];

    // KDF methods: (name, fn, expects_pin_bytes, has_rounds_param)
    // All functions have signature fn(&[u8], &[u8], u32) -> Vec<u8>
    let kdf_fns: [(&str, fn(&[u8], &[u8], u32) -> Vec<u8>, bool, bool); 5] = [
        ("A", kdf_pbkdf2, true, true),
        ("B", kdf_sha512, true, false),
        ("C", kdf_sha256_concat, true, false),
        ("D_direct", kdf_direct_wrapper, true, false),
        ("E_empty", kdf_empty, false, false),
    ];
    let kdfs = &kdf_fns[..];

    let mut total_combos = 0u64;
    let mut checked_combos = 0u64;

    for (enc_name, enc_fn) in &encodings {
        let pin_bytes = enc_fn(pin);

        for (kdf_name, kdf_fn, needs_pin, has_rounds) in kdfs {
            if *needs_pin && pin_bytes.is_empty() {
                continue;
            }

            let kdf_result = if *has_rounds {
                kdf_fn(&pin_bytes, salt, rounds)
            } else {
                kdf_fn(&pin_bytes, salt, 0)
            };

            // Skip empty KDF results unless explicitly empty method
            if kdf_result.is_empty() && *kdf_name != "E_empty" {
                continue;
            }

            // Generate entropy variants from KDF result
            let entropy_variants = derive_entropy_variants(&kdf_result);

            for (ev_label, entropy) in &entropy_variants {
                total_combos += 1;

                // Attempt DPAPI unprotect
                let srk = match dpapi_unprotect(protector_blob, entropy) {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                if srk.len() < 32 {
                    continue;
                }
                let aes_key = &srk[..32];

                checked_combos += 1;

                // Verify SRK: it should have high entropy (not all zeros, not all same)
                let unique_bytes: std::collections::HashSet<u8> =
                    aes_key.iter().copied().collect();
                if unique_bytes.len() <= 2 {
                    // DPAPI "succeeded" but returned garbage
                    continue;
                }

                // Try AES-GCM decrypt the key payload
                let variant = format!(
                    "E{}_{}_K{}_{}",
                    &encodings
                        .iter()
                        .position(|(n, _)| *n == *enc_name)
                        .unwrap_or(0)
                        + 1,
                    enc_name,
                    kdf_name,
                    ev_label
                );
                match aes256_gcm_decrypt(aes_key, key_iv, key_payload) {
                    Ok(key_bytes) => {
                        // Try to parse as ECDSA P-256 key
                        match parse_ecdsa_key(&key_bytes) {
                            Ok((d, x, y)) => {
                                println!("\n  ✅ SUCCESS variant={}", variant);
                                println!(
                                    "     encoding={} kdf={} entropy={} protector={}",
                                    enc_name, kdf_name, ev_label, protector_name
                                );

                                // Verify key self-consistency
                                if verify_ecdsa_key(&d, &x, &y) {
                                    println!("     ✅ ECDSA key self-consistency VERIFIED");
                                } else {
                                    // Try with X and Y from the decrypted data (if longer format)
                                    println!("     ⚠️  Key self-consistency FAILED (but decrypted)");
                                }

                                // Compute COSE public key
                                let cose = compute_cose_key(&x, &y);
                                println!("     🔑 COSE_PublicKey (base64url): {}", cose);

                                // Save BCRYPT_ECCPRIVATE_BLOB
                                let blob = make_bcrypt_ecc_blob(&d, &x, &y);
                                let safe_key_name = key_filename.replace('.', "_");
                                let safe_guid = container_guid.trim_matches(|c| c == '{' || c == '}');
                                let out_path = format!(
                                    "ngc_key_{}_{}_{}.bin",
                                    safe_guid, safe_key_name, variant
                                );
                                if let Err(e) = std::fs::write(&out_path, &blob) {
                                    println!("     ❌ Failed to save key: {}", e);
                                } else {
                                    println!("     💾 Saved: {} ({} bytes)", out_path, blob.len());
                                }

                                // Also save raw d
                                let raw_path = format!(
                                    "ngc_key_{}_{}_d.bin",
                                    safe_guid, safe_key_name
                                );
                                if let Err(e) = std::fs::write(&raw_path, &d) {
                                    println!("     ❌ Failed to save raw d: {}", e);
                                } else {
                                    println!("     💾 Saved raw d: {} (32 bytes)", raw_path);
                                }

                                // Print hex of key data
                                println!(
                                    "     d = {}",
                                    hex::encode(d)
                                );
                                println!(
                                    "     x = {}",
                                    hex::encode(x)
                                );
                                println!(
                                    "     y = {}",
                                    hex::encode(y)
                                );

                                println!(
                                    "     SUCCESS variant={} encoding={} kdf={} entropy={} COSE={}",
                                    variant, enc_name, kdf_name, ev_label, cose
                                );

                                return true;
                            }
                            Err(parse_err) => {
                                // Decrypted but not a valid ECDSA key
                                println!(
                                    "     ⚠️  DPAPI+SRK OK but key parse failed: {} bytes -> {}",
                                    key_bytes.len(),
                                    parse_err
                                );
                                if key_bytes.len() <= 128 {
                                    println!(
                                        "        Decrypted hex: {}",
                                        hex::encode(&key_bytes)
                                    );
                                } else {
                                    println!(
                                        "        Decrypted hex (head): {}",
                                        hex::encode(&key_bytes[..64])
                                    );
                                }
                                // Still count as DPAPI success
                                println!(
                                    "     PROTECTOR_OK variant={} encoding={} kdf={} entropy={}",
                                    variant, enc_name, kdf_name, ev_label
                                );
                            }
                        }
                    }
                    Err(_) => {
                        // AES-GCM auth failed, decrypt was wrong key
                    }
                }
            }
        }
    }

    println!(
        "    Tried {} DPAPI calls, {} SRK candidates",
        total_combos, checked_combos
    );
    false
}

// ─── Fallback: try PBKDF2-derived keys directly as AES keys (no SRK DPAPI) ──────

fn try_direct_aes_no_srk(
    pin: &str,
    salt: &[u8],
    rounds: u32,
    key_iv: &[u8],
    key_payload: &[u8],
    key_filename: &str,
    container_guid: &str,
    _key_alg: &str,
    _key_bits: u32,
) -> bool {
    println!("    Trying direct AES decrypt (no SRK)...");

    let encodings: Vec<(&str, fn(&str) -> Vec<u8>)> = vec![
        ("hex_upper", encode_pin_hex_upper),
        ("hex_upper_utf16", encode_pin_hex_upper_utf16),
        ("hex_lower", encode_pin_hex_lower),
        ("hex_lower_utf16", encode_pin_hex_lower_utf16),
        ("raw_utf16", encode_pin_raw_utf16),
        ("raw_bytes", encode_pin_raw_bytes),
        ("digits_int_be", encode_pin_digits_int),
        ("digits_int_le", encode_pin_digits_int_le),
        ("digits_hex", encode_pin_digits_hex),
        ("sha256_pin", encode_pin_sha256),
    ];

    for (enc_name, enc_fn) in &encodings {
        let pin_bytes = enc_fn(pin);
        if pin_bytes.is_empty() {
            continue;
        }

        // PBKDF2 -> 64 bytes
        let mut pbkdf2_64 = vec![0u8; 64];
        pbkdf2_hmac::<Sha256>(&pin_bytes, salt, rounds, &mut pbkdf2_64);

        // Try various slices of PBKDF2 output as AES key
        let candidates: Vec<(String, Vec<u8>)> = {
            let mut c: Vec<(String, Vec<u8>)> = Vec::new();
            // Raw PBKDF2 slices
            for start in [0, 16, 32] {
                if start + 32 <= pbkdf2_64.len() {
                    c.push((
                        format!("PBKDF2[{}..{}]", start, start + 32),
                        pbkdf2_64[start..start + 32].to_vec(),
                    ));
                }
            }
            // Standard NGC format
            let hex_upper: String = pbkdf2_64[..32]
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect();
            let hex_utf16le = to_utf16le_bytes(&hex_upper);
            let hash = Sha512::digest(&hex_utf16le);
            let mut std_entropy = FIXED_ENTROPY_PREFIX.to_vec();
            std_entropy.extend_from_slice(&hash);
            if std_entropy.len() >= 32 {
                c.push(("NGC_std[..32]".to_string(), std_entropy[..32].to_vec()));
                c.push(("NGC_std[18..50]".to_string(), std_entropy[18..50].to_vec()));
            }
            // SHA-512 of PBKDF2 output
            let sha512 = Sha512::digest(&pbkdf2_64[..32]);
            c.push(("SHA512(PBKDF2)[..32]".to_string(), sha512[..32].to_vec()));
            // SHA-256 of PBKDF2 output
            c.push(("SHA256(PBKDF2)".to_string(), Sha256::digest(&pbkdf2_64[..32]).to_vec()));
            c
        };

        for (desc, aes_key) in &candidates {
            if aes_key.len() != 32 {
                continue;
            }
            if let Ok(key_bytes) = aes256_gcm_decrypt(aes_key, key_iv, key_payload) {
                if let Ok((d, x, y)) = parse_ecdsa_key(&key_bytes) {
                    println!(
                        "  ✅ SUCCESS no_srk encoding={} key={}",
                        enc_name, desc
                    );
                    if verify_ecdsa_key(&d, &x, &y) {
                        println!("     ✅ ECDSA key self-consistency VERIFIED");
                    }
                    let cose = compute_cose_key(&x, &y);
                    println!("     🔑 COSE_PublicKey (base64url): {}", cose);
                    let blob = make_bcrypt_ecc_blob(&d, &x, &y);
                    let safe_key_name = key_filename.replace('.', "_");
                    let safe_guid = container_guid.trim_matches(|c| c == '{' || c == '}');
                    let out_path =
                        format!("ngc_key_{}_{}_no_srk.bin", safe_guid, safe_key_name);
                    std::fs::write(&out_path, &blob).ok();
                    println!("     💾 Saved: {} ({} bytes)", out_path, blob.len());
                    return true;
                }
            }
        }
    }
    false
}
