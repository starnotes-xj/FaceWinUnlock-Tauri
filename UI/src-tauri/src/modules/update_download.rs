//! Signed differential-update manifest verification, download, and staging.

use minisign_verify::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use crate::ROOT_DIR;

const MANIFEST_URL: &str =
    "https://github.com/starnotes-xj/FaceWinUnlock-Tauri/releases/latest/download/update_manifest.json";
const MANIFEST_SIGNATURE_URL: &str =
    "https://github.com/starnotes-xj/FaceWinUnlock-Tauri/releases/latest/download/update_manifest.json.sig";
const USER_AGENT: &str = "FaceWinUnlock-Tauri-UpdateDownload";

/// New binaries embed this non-secret keyring at compile time. Missing or invalid
/// configuration is a hard failure for incremental updates.
const RELEASE_SIGNING_PUBLIC_KEYS: &str = include_str!("../../release-signing-public-keys.txt");

const MANIFEST_MAX_BYTES: u64 = 1024 * 1024;
const SIGNATURE_MAX_BYTES: u64 = 16 * 1024;
const METADATA_DIR: &str = ".update-metadata";
const STAGED_MANIFEST: &str = "manifest.json";
const STAGED_SIGNATURE: &str = "manifest.json.sig";
const STAGED_FILES: &str = "files.json";
const STAGED_READY: &str = "ready";

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(crate) struct ManifestFile {
    /// File name under the install root.
    pub(crate) path: String,
    /// Expected SHA-256, hexadecimal.
    pub(crate) sha256: String,
    /// Expected file size in bytes.
    pub(crate) size: u64,
    /// Immutable GitHub Release asset URL.
    pub(crate) url: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct UpdateManifest {
    pub(crate) version: String,
    pub(crate) files: Vec<ManifestFile>,
}

struct SignedManifest {
    manifest: UpdateManifest,
    raw_bytes: Vec<u8>,
    signature: Vec<u8>,
}

/// The verified, staged file names are passed to the replacement boundary only
/// after the manifest signature and every staged file have been checked.
#[derive(Debug)]
pub(crate) struct ValidatedStagedUpdate {
    pub(crate) files: Vec<String>,
}

#[derive(Serialize)]
pub struct DiffResult {
    pub version: String,
    pub files_to_update: Vec<String>,
    pub total_size_mb: f64,
    pub files_to_delete: Vec<String>,
}

#[tauri::command]
pub async fn fetch_update_diff() -> Result<DiffResult, String> {
    tauri::async_runtime::spawn_blocking(fetch_update_diff_internal)
        .await
        .map_err(|e| format!("更新检查任务失败: {e}"))?
}

pub(crate) fn fetch_update_diff_internal() -> Result<DiffResult, String> {
    let signed = download_manifest()?;
    compute_diff(&signed.manifest)
}

/// Downloads all changed files and stages them only after validating the signed
/// manifest. The application shutdown path performs the checks again immediately
/// before any component replacement.
#[tauri::command]
pub async fn apply_update() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(apply_update_inner)
        .await
        .map_err(|e| format!("更新下载任务失败: {e}"))?
}

fn apply_update_inner() -> Result<String, String> {
    let tmp_dir = ROOT_DIR.join("update_temp");
    clear_staged_update(&tmp_dir)?;

    let signed = download_manifest()?;
    let diff = compute_diff(&signed.manifest)?;
    if diff.files_to_update.is_empty() {
        return Err("当前版本已是最新版本".to_string());
    }

    stage_update_at(&ROOT_DIR, &signed, &diff.files_to_update, |file, dest| {
        download_file(&file.url, dest, file.size)
    })?;

    Ok(tmp_dir.to_string_lossy().to_string())
}

fn download_manifest() -> Result<SignedManifest, String> {
    let signature = download_bounded(MANIFEST_SIGNATURE_URL, SIGNATURE_MAX_BYTES)?;
    let raw_bytes = download_bounded(MANIFEST_URL, MANIFEST_MAX_BYTES)?;
    let manifest = parse_verified_manifest_with_compiled_keyring(&raw_bytes, &signature)?;
    Ok(SignedManifest {
        manifest,
        raw_bytes,
        signature,
    })
}

fn download_bounded(url: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
    let response = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .set("Accept", "application/octet-stream")
        .timeout(Duration::from_secs(8))
        .call()
        .map_err(|e| format!("下载更新元数据失败: {e}"))?;

    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| format!("读取更新元数据失败: {e}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("更新元数据超过大小限制: {url}"));
    }
    Ok(bytes)
}

fn parse_verified_manifest_with_compiled_keyring(
    raw: &[u8],
    signature: &[u8],
) -> Result<UpdateManifest, String> {
    parse_verified_manifest(raw, signature, RELEASE_SIGNING_PUBLIC_KEYS)
}

fn parse_verified_manifest(
    raw: &[u8],
    signature: &[u8],
    keyring: &str,
) -> Result<UpdateManifest, String> {
    verify_signature(raw, signature, keyring)?;
    let manifest: UpdateManifest =
        serde_json::from_slice(raw).map_err(|e| format!("已签名更新清单 JSON 无效: {e}"))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn verify_signature(raw: &[u8], signature: &[u8], keyring: &str) -> Result<(), String> {
    if signature.is_empty() {
        return Err("更新清单签名缺失".to_string());
    }
    let signature_text =
        std::str::from_utf8(signature).map_err(|_| "更新清单签名不是有效 UTF-8".to_string())?;
    let signature =
        Signature::decode(signature_text).map_err(|e| format!("更新清单签名格式无效: {e}"))?;

    let keys = keyring
        .split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
        .filter(|key| !key.is_empty())
        .collect::<Vec<_>>();
    if keys.is_empty() {
        return Err("客户端未内置发布签名公钥，拒绝增量更新".to_string());
    }
    if keys
        .iter()
        .any(|key| key.eq_ignore_ascii_case("UNCONFIGURED"))
    {
        return Err("发布签名公钥尚未配置，拒绝增量更新".to_string());
    }

    let mut parse_error = None;
    for encoded_key in keys {
        match PublicKey::from_base64(encoded_key) {
            Ok(public_key) if public_key.verify(raw, &signature, false).is_ok() => return Ok(()),
            Ok(_) => {}
            Err(error) => parse_error = Some(error),
        }
    }
    if let Some(error) = parse_error {
        return Err(format!("客户端内置发布签名公钥无效: {error}"));
    }
    Err("更新清单签名无效或签名密钥不受信任".to_string())
}

pub(crate) fn compute_diff(manifest: &UpdateManifest) -> Result<DiffResult, String> {
    compute_diff_at(&ROOT_DIR, manifest)
}

fn compute_diff_at(root: &Path, manifest: &UpdateManifest) -> Result<DiffResult, String> {
    let mut files_to_update = Vec::new();
    let mut total_size = 0u64;

    for file in &manifest.files {
        let relative = validated_manifest_path(&file.path)?;
        let local = root.join(relative);
        let need = if local.exists() {
            sha256_file(&local)? != file.sha256.to_lowercase()
        } else {
            true
        };
        if need {
            files_to_update.push(file.path.clone());
            total_size += file.size;
        }
    }

    Ok(DiffResult {
        version: manifest.version.clone(),
        files_to_update,
        total_size_mb: total_size as f64 / 1_048_576.0,
        // Files absent from the signed manifest are never removed from the install root.
        files_to_delete: Vec::new(),
    })
}

fn validate_manifest(manifest: &UpdateManifest) -> Result<(), String> {
    if manifest.version.trim().is_empty() {
        return Err("更新清单缺少版本号".to_string());
    }

    let mut seen = HashSet::new();
    for file in &manifest.files {
        validated_manifest_path(&file.path)?;
        if file.path.eq_ignore_ascii_case(METADATA_DIR) {
            return Err("更新清单使用了保留路径".to_string());
        }
        if !seen.insert(file.path.to_ascii_lowercase()) {
            return Err(format!("更新清单包含重复文件: {}", file.path));
        }
        if file.size == 0 || file.size > 512 * 1024 * 1024 {
            return Err(format!("更新文件大小异常: {} ({})", file.path, file.size));
        }
        if file.sha256.len() != 64 || !file.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("更新文件 SHA256 无效: {}", file.path));
        }
        if !file
            .url
            .starts_with("https://github.com/starnotes-xj/FaceWinUnlock-Tauri/releases/download/")
        {
            return Err(format!("更新文件来源不受信任: {}", file.path));
        }
    }
    Ok(())
}

fn validated_manifest_path(raw: &str) -> Result<PathBuf, String> {
    let path = Path::new(raw);
    let mut components = path.components();
    let is_single_file =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    if raw.trim().is_empty() || path.is_absolute() || !is_single_file {
        return Err(format!("更新清单包含不安全路径: {raw}"));
    }
    Ok(path.to_path_buf())
}

fn clear_staged_update(stage_dir: &Path) -> Result<(), String> {
    if stage_dir.exists() {
        std::fs::remove_dir_all(stage_dir).map_err(|e| format!("清理旧更新暂存目录失败: {e}"))?;
    }
    Ok(())
}

fn stage_update_at<F>(
    install_root: &Path,
    signed: &SignedManifest,
    names: &[String],
    mut download: F,
) -> Result<(), String>
where
    F: FnMut(&ManifestFile, &Path) -> Result<(), String>,
{
    let stage_dir = install_root.join("update_temp");
    clear_staged_update(&stage_dir)?;

    let result = (|| {
        if names.is_empty() {
            return Err("更新清单没有需要暂存的文件".to_string());
        }
        std::fs::create_dir_all(&stage_dir).map_err(|e| format!("创建临时目录失败: {e}"))?;
        let metadata_dir = stage_dir.join(METADATA_DIR);
        std::fs::create_dir_all(&metadata_dir)
            .map_err(|e| format!("创建更新元数据目录失败: {e}"))?;
        std::fs::write(metadata_dir.join(STAGED_MANIFEST), &signed.raw_bytes)
            .map_err(|e| format!("保存已签名更新清单失败: {e}"))?;
        std::fs::write(metadata_dir.join(STAGED_SIGNATURE), &signed.signature)
            .map_err(|e| format!("保存更新清单签名失败: {e}"))?;
        std::fs::write(
            metadata_dir.join(STAGED_FILES),
            serde_json::to_vec(names).map_err(|e| format!("序列化暂存文件列表失败: {e}"))?,
        )
        .map_err(|e| format!("保存暂存文件列表失败: {e}"))?;

        let mut seen = HashSet::new();
        for name in names {
            if !seen.insert(name.to_ascii_lowercase()) {
                return Err(format!("暂存文件列表包含重复文件: {name}"));
            }
            let file = signed
                .manifest
                .files
                .iter()
                .find(|file| &file.path == name)
                .ok_or_else(|| format!("签名清单中不存在文件: {name}"))?;
            let dest = stage_dir.join(validated_manifest_path(&file.path)?);
            download(file, &dest)?;
            verify_asset(&dest, file)?;
        }

        std::fs::write(
            metadata_dir.join(STAGED_READY),
            signed.manifest.version.as_bytes(),
        )
        .map_err(|e| format!("写入更新暂存完成标记失败: {e}"))?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_dir_all(&stage_dir);
    }
    result
}

fn verify_asset(path: &Path, expected: &ManifestFile) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| format!("读取下载文件 {} 失败: {e}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("更新文件不是普通文件: {}", path.display()));
    }
    if metadata.len() != expected.size {
        return Err(format!(
            "{} 下载大小不匹配：期望 {}，实际 {}",
            expected.path,
            expected.size,
            metadata.len()
        ));
    }
    let got = sha256_file(path)?;
    if got != expected.sha256.to_lowercase() {
        return Err(format!(
            "{} 哈希校验失败：期望 {}，实际 {}",
            expected.path, expected.sha256, got
        ));
    }
    Ok(())
}

/// Re-verifies the staged metadata and every file before crossing the component
/// replacement boundary. The callback (service stop) is not called on any failure.
pub(crate) fn apply_staged_update<F>(
    install_root: &Path,
    before_replace: F,
) -> Result<Vec<String>, String>
where
    F: FnOnce(&[String]),
{
    if !install_root.join("update_temp").exists() {
        return Ok(Vec::new());
    }
    apply_staged_update_with_keyring(install_root, RELEASE_SIGNING_PUBLIC_KEYS, before_replace)
}

fn apply_staged_update_with_keyring<F>(
    install_root: &Path,
    keyring: &str,
    before_replace: F,
) -> Result<Vec<String>, String>
where
    F: FnOnce(&[String]),
{
    let stage_dir = install_root.join("update_temp");
    let validated = match validate_staged_update_at(install_root, keyring) {
        Ok(Some(validated)) => validated,
        Ok(None) => return Ok(Vec::new()),
        Err(error) => {
            let _ = std::fs::remove_dir_all(&stage_dir);
            return Err(error);
        }
    };
    before_replace(&validated.files);

    for name in &validated.files {
        let src = stage_dir.join(validated_manifest_path(name)?);
        let dst = install_root.join(validated_manifest_path(name)?);
        if std::fs::copy(&src, &dst).is_err() {
            std::fs::copy(&src, install_root.join(format!("{name}.new")))
                .map_err(|e| format!("替换 {} 失败: {e}", dst.display()))?;
        }
    }

    let _ = std::fs::remove_dir_all(&stage_dir);
    Ok(validated.files)
}

fn validate_staged_update_at(
    install_root: &Path,
    keyring: &str,
) -> Result<Option<ValidatedStagedUpdate>, String> {
    let stage_dir = install_root.join("update_temp");
    if !stage_dir.exists() {
        return Ok(None);
    }
    let metadata_dir = stage_dir.join(METADATA_DIR);
    if !metadata_dir.join(STAGED_READY).is_file() {
        return Err("更新暂存未完成，拒绝替换组件".to_string());
    }

    let raw_manifest = read_bounded_file(&metadata_dir.join(STAGED_MANIFEST), MANIFEST_MAX_BYTES)?;
    let signature = read_bounded_file(&metadata_dir.join(STAGED_SIGNATURE), SIGNATURE_MAX_BYTES)?;
    let manifest = parse_verified_manifest(&raw_manifest, &signature, keyring)?;
    let file_list_bytes = read_bounded_file(&metadata_dir.join(STAGED_FILES), MANIFEST_MAX_BYTES)?;
    let files: Vec<String> =
        serde_json::from_slice(&file_list_bytes).map_err(|e| format!("暂存文件列表无效: {e}"))?;
    if files.is_empty() {
        return Err("更新暂存文件列表为空".to_string());
    }

    let manifest_files = manifest
        .files
        .iter()
        .map(|file| (file.path.to_ascii_lowercase(), file))
        .collect::<HashMap<_, _>>();
    let mut seen = HashSet::new();
    for name in &files {
        validated_manifest_path(name)?;
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err(format!("暂存文件列表包含重复文件: {name}"));
        }
        let expected = manifest_files
            .get(&name.to_ascii_lowercase())
            .ok_or_else(|| format!("签名清单中不存在暂存文件: {name}"))?;
        verify_asset(&stage_dir.join(validated_manifest_path(name)?), expected)?;
    }

    for entry in std::fs::read_dir(&stage_dir).map_err(|e| format!("读取更新暂存目录失败: {e}"))?
    {
        let entry = entry.map_err(|e| format!("读取更新暂存项失败: {e}"))?;
        let name = entry.file_name();
        if name == METADATA_DIR {
            continue;
        }
        let name = name
            .to_str()
            .ok_or_else(|| "更新暂存目录包含无效文件名".to_string())?;
        if !seen.contains(&name.to_ascii_lowercase())
            || !entry.file_type().map_err(|e| e.to_string())?.is_file()
        {
            return Err(format!("更新暂存目录包含未验证文件: {name}"));
        }
    }

    Ok(Some(ValidatedStagedUpdate { files }))
}

fn read_bounded_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let metadata =
        std::fs::metadata(path).map_err(|e| format!("读取 {} 失败: {e}", path.display()))?;
    if metadata.len() > max_bytes {
        return Err(format!("更新元数据超过大小限制: {}", path.display()));
    }
    std::fs::read(path).map_err(|e| format!("读取 {} 失败: {e}", path.display()))
}

fn download_file(url: &str, dest: &Path, expected_size: u64) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建目录失败: {e}"))?;
    }
    let response = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .timeout(Duration::from_secs(120))
        .call()
        .map_err(|e| format!("下载 {url} 失败: {e}"))?;

    let file_name = dest
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("无效目标路径: {}", dest.display()))?;
    let part_path = dest.with_file_name(format!("{file_name}.part"));
    let mut file = std::fs::File::create(&part_path)
        .map_err(|e| format!("创建 {} 失败: {e}", part_path.display()))?;
    let mut reader = response.into_reader().take(expected_size.saturating_add(1));
    let written =
        std::io::copy(&mut reader, &mut file).map_err(|e| format!("读取下载响应失败: {e}"))?;
    file.flush()
        .map_err(|e| format!("刷新 {} 失败: {e}", part_path.display()))?;
    if written != expected_size {
        let _ = std::fs::remove_file(&part_path);
        return Err(format!(
            "{} 下载大小不匹配：期望 {}，实际 {}",
            dest.display(),
            expected_size,
            written
        ));
    }
    std::fs::rename(&part_path, dest).map_err(|e| format!("写入 {} 失败: {e}", dest.display()))?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("读取 {} 失败: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| format!("读取 {} 失败: {e}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test-only Minisign key generated in a temporary directory. The private key
    // is not stored in the repository; only the public test vector and signatures
    // are kept here.
    const TEST_PUBLIC_KEY: &str = "RWQ3Ab4IDruH5XLPDrdnvM45EjovEZY2bjQfEjLuz644XBxXxNbpIKOH";
    const WRONG_PUBLIC_KEY: &str = "RWSYTAaM18fWWG01q0nEPxpAO+Y2IxI+eBZkGOIugld6ApKyOJobTtBq";
    const SIGNED_MANIFEST: &[u8] = br#"{"version":"9.9.9","files":[{"path":"FaceWinUnlock-Server.exe","sha256":"11507a0e2f5e69d5dfa40a62a1bd7b6ee57e6bcd85c67c9b8431b36fff21c437","size":3,"url":"https://github.com/starnotes-xj/FaceWinUnlock-Tauri/releases/download/v-test/FaceWinUnlock-Server.exe"}]}"#;
    const VALID_SIGNATURE: &str = r#"untrusted comment: signature from tauri secret key
RUQ3Ab4IDruH5Rs07JR9hKfNL9nBt+L8pHGAif4CDduNxjkM8YcDwG5vsRBYPCkX2OqpmHOJ1CApZpWI8ZX0WqUBMOyRxikDfgY=
trusted comment: timestamp:1791194277	file:manifest.json
BC6FipIJ8bWC8erjxGOSBMpZOkhW6OzK4YrzaMKAGwFy5G0uttxdVck9Oe8d1oEhTtn6JRcXX6tQOG2PqLAtCA==
"#;

    fn test_signed_manifest() -> SignedManifest {
        let signature = VALID_SIGNATURE.as_bytes().to_vec();
        let manifest =
            parse_verified_manifest(SIGNED_MANIFEST, &signature, TEST_PUBLIC_KEY).unwrap();
        SignedManifest {
            manifest,
            raw_bytes: SIGNED_MANIFEST.to_vec(),
            signature,
        }
    }

    fn test_root(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "facewinunlock-update-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn manifest_file(path: &str, content: &[u8]) -> ManifestFile {
        let mut hasher = Sha256::new();
        hasher.update(content);
        ManifestFile {
            path: path.to_string(),
            sha256: hex::encode(hasher.finalize()),
            size: content.len() as u64,
            url: format!(
                "https://github.com/starnotes-xj/FaceWinUnlock-Tauri/releases/download/v-test/{path}"
            ),
        }
    }

    fn write_stage_metadata(root: &Path, manifest: &[u8], signature: &[u8], files: &[&str]) {
        let metadata = root.join("update_temp").join(METADATA_DIR);
        std::fs::create_dir_all(&metadata).unwrap();
        std::fs::write(metadata.join(STAGED_MANIFEST), manifest).unwrap();
        std::fs::write(metadata.join(STAGED_SIGNATURE), signature).unwrap();
        std::fs::write(
            metadata.join(STAGED_FILES),
            serde_json::to_vec(files).unwrap(),
        )
        .unwrap();
        std::fs::write(metadata.join(STAGED_READY), b"9.9.9").unwrap();
    }

    #[test]
    fn verifies_a_valid_minisign_manifest_before_parsing() {
        let manifest =
            parse_verified_manifest(SIGNED_MANIFEST, VALID_SIGNATURE.as_bytes(), TEST_PUBLIC_KEY)
                .unwrap();
        assert_eq!(manifest.version, "9.9.9");
    }

    #[test]
    fn rejects_tampered_manifest_before_json_parsing() {
        let mut tampered = SIGNED_MANIFEST.to_vec();
        tampered[15] ^= 1;
        let error = parse_verified_manifest(&tampered, VALID_SIGNATURE.as_bytes(), TEST_PUBLIC_KEY)
            .unwrap_err();
        assert!(error.contains("签名"), "{error}");
    }

    #[test]
    fn rejects_wrong_key_missing_signature_and_corrupt_signature() {
        assert!(verify_signature(
            SIGNED_MANIFEST,
            VALID_SIGNATURE.as_bytes(),
            WRONG_PUBLIC_KEY
        )
        .is_err());
        assert!(verify_signature(SIGNED_MANIFEST, b"", TEST_PUBLIC_KEY).is_err());
        assert!(verify_signature(
            SIGNED_MANIFEST,
            b"not a minisign signature",
            TEST_PUBLIC_KEY
        )
        .is_err());
    }

    #[test]
    fn rejects_manifest_assets_with_hash_mismatch() {
        let root = test_root("asset-hash");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("asset.exe");
        std::fs::write(&path, b"evil").unwrap();
        let expected = manifest_file("asset.exe", b"good");
        assert!(verify_asset(&path, &expected)
            .unwrap_err()
            .contains("哈希校验失败"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_download_hash_clears_stage_before_apply() {
        let root = test_root("download-hash");
        std::fs::create_dir_all(&root).unwrap();
        let signed = test_signed_manifest();
        let result = stage_update_at(
            &root,
            &signed,
            &["FaceWinUnlock-Server.exe".to_string()],
            |_, dest| std::fs::write(dest, b"bad").map_err(|e| e.to_string()),
        );
        assert!(result.unwrap_err().contains("哈希校验失败"));
        assert!(!root.join("update_temp").exists());

        let mut replacement_started = false;
        assert!(
            apply_staged_update_with_keyring(&root, TEST_PUBLIC_KEY, |_| {
                replacement_started = true;
            })
            .unwrap()
            .is_empty()
        );
        assert!(!replacement_started);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_signature_or_hash_never_reaches_component_replacement() {
        for (label, signature, content) in [
            ("bad-signature", b"corrupt".as_slice(), b"new".as_slice()),
            ("bad-hash", VALID_SIGNATURE.as_bytes(), b"bad".as_slice()),
        ] {
            let root = test_root(label);
            std::fs::create_dir_all(&root).unwrap();
            let installed = root.join("FaceWinUnlock-Server.exe");
            std::fs::write(&installed, b"old").unwrap();
            let stage = root.join("update_temp");
            write_stage_metadata(
                &root,
                SIGNED_MANIFEST,
                signature,
                &["FaceWinUnlock-Server.exe"],
            );
            std::fs::write(stage.join("FaceWinUnlock-Server.exe"), content).unwrap();

            let mut replacement_started = false;
            let result = apply_staged_update_with_keyring(&root, TEST_PUBLIC_KEY, |_| {
                replacement_started = true;
            });
            assert!(result.is_err(), "{label}");
            assert!(!replacement_started, "{label}");
            assert_eq!(std::fs::read(&installed).unwrap(), b"old", "{label}");
            assert!(
                !root.join("FaceWinUnlock-Server.exe.new").exists(),
                "{label}"
            );
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn replaces_only_after_signature_and_every_staged_hash_are_valid() {
        let root = test_root("valid-replacement");
        std::fs::create_dir_all(&root).unwrap();
        let installed = root.join("FaceWinUnlock-Server.exe");
        std::fs::write(&installed, b"old").unwrap();
        let stage = root.join("update_temp");
        write_stage_metadata(
            &root,
            SIGNED_MANIFEST,
            VALID_SIGNATURE.as_bytes(),
            &["FaceWinUnlock-Server.exe"],
        );
        std::fs::write(stage.join("FaceWinUnlock-Server.exe"), b"new").unwrap();

        let mut replacement_started = false;
        let files = apply_staged_update_with_keyring(&root, TEST_PUBLIC_KEY, |_| {
            replacement_started = true;
        })
        .unwrap();
        assert!(replacement_started);
        assert_eq!(files, ["FaceWinUnlock-Server.exe"]);
        assert_eq!(std::fs::read(&installed).unwrap(), b"new");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_manifest_path_traversal() {
        for path in [
            "",
            "../evil.exe",
            r"C:\evil.exe",
            "/evil.exe",
            "bin/../evil.exe",
            "tools/helper.exe",
        ] {
            assert!(validated_manifest_path(path).is_err(), "{path}");
        }
        assert!(validated_manifest_path("FaceWinUnlock-Server.exe").is_ok());
    }

    #[test]
    fn compute_diff_only_returns_changed_files() {
        let root = test_root("diff");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("same.exe"), b"same").unwrap();
        std::fs::write(root.join("changed.exe"), b"old").unwrap();

        let manifest = UpdateManifest {
            version: "9.9.9".to_string(),
            files: vec![
                manifest_file("same.exe", b"same"),
                manifest_file("changed.exe", b"new"),
                manifest_file("missing.exe", b"missing"),
            ],
        };
        let diff = compute_diff_at(&root, &manifest).unwrap();
        assert_eq!(diff.files_to_update, ["changed.exe", "missing.exe"]);
        assert_eq!(diff.total_size_mb, 10.0 / 1_048_576.0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "Release CI supplies the actual signed manifest and checksum files"]
    fn release_signatures_match_the_embedded_keyring() {
        let manifest =
            std::fs::read(std::env::var("UPDATE_RELEASE_MANIFEST_PATH").unwrap()).unwrap();
        let manifest_sig =
            std::fs::read(std::env::var("UPDATE_RELEASE_MANIFEST_SIGNATURE_PATH").unwrap())
                .unwrap();
        parse_verified_manifest_with_compiled_keyring(&manifest, &manifest_sig).unwrap();

        let sums = std::fs::read(std::env::var("UPDATE_RELEASE_SHA256SUMS_PATH").unwrap()).unwrap();
        let sums_sig =
            std::fs::read(std::env::var("UPDATE_RELEASE_SHA256SUMS_SIGNATURE_PATH").unwrap())
                .unwrap();
        verify_signature(&sums, &sums_sig, RELEASE_SIGNING_PUBLIC_KEYS).unwrap();
    }
}
