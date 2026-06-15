//! 增量更新下载模块
//!
//! 在 `check_update`（仅比对版本号）之上扩展，实现「只下载变化文件」：
//!   - `fetch_update_diff` — 下载 `update_manifest.json`，按 SHA256 比对本地文件，算出差异清单
//!   - `apply_update`      — 下载差异文件到 `ROOT_DIR/update_temp`，退出时由 `close_app` 落盘替换
//!
//! 联网请求：
//!   GET https://github.com/<repo>/releases/latest/download/update_manifest.json
//!   GET 各文件的 Release 下载直链（manifest 内提供）
//!
//! 复用 `check_update` 已有的 `ureq` + `sha2` + `hex` 依赖，无新增依赖。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use crate::ROOT_DIR;

/// 最新版 manifest 的固定直链（GitHub 的 `releases/latest/download/<asset>` 永远指向最新 Release）。
const MANIFEST_URL: &str =
    "https://github.com/starnotes-xj/FaceWinUnlock-Tauri/releases/latest/download/update_manifest.json";

const USER_AGENT: &str = "FaceWinUnlock-Tauri-UpdateDownload";

#[derive(Deserialize, Clone)]
struct ManifestFile {
    /// 安装目录下的文件名（如 `FaceWinUnlock-Server.exe`）
    path: String,
    /// 期望的 SHA256（小写 hex）
    sha256: String,
    /// 文件字节数，用于估算下载量
    size: u64,
    /// Release 下载直链
    url: String,
}

#[derive(Deserialize)]
struct UpdateManifest {
    version: String,
    files: Vec<ManifestFile>,
}

/// 差异比对结果，返回给前端用于确认弹窗。
#[derive(Serialize)]
pub struct DiffResult {
    pub version: String,
    pub files_to_update: Vec<String>,
    pub total_size_mb: f64,
    /// 始终为空：见 `compute_diff` 中的安全说明（不删除任何本地文件）。
    pub files_to_delete: Vec<String>,
}

/// 步骤1：下载 manifest 并比对差异（不下载任何二进制文件，供确认弹窗预估流量）。
#[tauri::command]
pub fn fetch_update_diff() -> Result<DiffResult, String> {
    let manifest = download_manifest()?;
    compute_diff(&manifest)
}

/// 步骤2：下载差异文件到 `ROOT_DIR/update_temp`（退出时由 `close_app` 负责替换到安装目录）。
/// 返回临时目录路径。
#[tauri::command]
pub fn apply_update() -> Result<String, String> {
    let manifest = download_manifest()?;
    let diff = compute_diff(&manifest)?;

    if diff.files_to_update.is_empty() {
        return Err("已是最新版本，无需下载".to_string());
    }

    let tmp_dir = ROOT_DIR.join("update_temp");
    // 清理上一次可能残留的临时目录，避免脏文件混入。
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).map_err(|e| format!("创建临时目录失败: {e}"))?;

    for name in &diff.files_to_update {
        let mf = manifest
            .files
            .iter()
            .find(|x| &x.path == name)
            .ok_or_else(|| format!("manifest 缺少文件项: {name}"))?;
        let dest = tmp_dir.join(validated_manifest_path(&mf.path)?);
        download_file(&mf.url, &dest, mf.size)?;

        // 下载后立即校验 SHA256；损坏/不完整直接整体失败，避免把坏文件替换进安装目录。
        let got = sha256_file(&dest)?;
        if got != mf.sha256.to_lowercase() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(format!(
                "{} 下载校验失败（期望 {}，实际 {}）",
                mf.path, mf.sha256, got
            ));
        }
    }

    Ok(tmp_dir.to_string_lossy().to_string())
}

fn download_manifest() -> Result<UpdateManifest, String> {
    let resp = ureq::get(MANIFEST_URL)
        .set("User-Agent", USER_AGENT)
        .set("Accept", "application/json")
        .call()
        .map_err(|e| format!("下载更新清单失败: {e}"))?;
    let manifest: UpdateManifest = resp
        .into_json()
        .map_err(|e| format!("解析更新清单失败: {e}"))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn compute_diff(manifest: &UpdateManifest) -> Result<DiffResult, String> {
    compute_diff_at(&ROOT_DIR, manifest)
}

fn compute_diff_at(root: &Path, manifest: &UpdateManifest) -> Result<DiffResult, String> {
    let mut files_to_update = Vec::new();
    let mut total_size = 0u64;

    for mf in &manifest.files {
        let relative = validated_manifest_path(&mf.path)?;
        let local = root.join(relative);
        let need = if local.exists() {
            sha256_file(&local)? != mf.sha256.to_lowercase()
        } else {
            true
        };
        if need {
            files_to_update.push(mf.path.clone());
            total_size += mf.size;
        }
    }

    Ok(DiffResult {
        version: manifest.version.clone(),
        files_to_update,
        total_size_mb: total_size as f64 / 1_048_576.0,
        // 安全考量：绝不按「本地有但 manifest 没有」推断删除——安装目录里有
        // database.db / faces\ / logs\ 等用户数据，naive 删除会造成数据丢失。
        // 增量更新只新增/覆盖 manifest 列出的文件，从不删除任何本地文件。
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
        if !seen.insert(file.path.to_ascii_lowercase()) {
            return Err(format!("更新清单包含重复文件: {}", file.path));
        }
        if file.size == 0 || file.size > 512 * 1024 * 1024 {
            return Err(format!("更新文件大小异常: {} ({})", file.path, file.size));
        }
        if file.sha256.len() != 64 || !file.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("更新文件 SHA256 无效: {}", file.path));
        }
        if !file.url.starts_with(
            "https://github.com/starnotes-xj/FaceWinUnlock-Tauri/releases/download/",
        ) {
            return Err(format!("更新文件来源不受信任: {}", file.path));
        }
    }
    Ok(())
}

fn validated_manifest_path(raw: &str) -> Result<PathBuf, String> {
    let path = Path::new(raw);
    let mut components = path.components();
    let is_single_file = matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none();
    if raw.trim().is_empty() || path.is_absolute() || !is_single_file {
        return Err(format!("更新清单包含不安全路径: {raw}"));
    }
    Ok(path.to_path_buf())
}

fn download_file(url: &str, dest: &Path, expected_size: u64) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建目录失败: {e}"))?;
    }
    let resp = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .call()
        .map_err(|e| format!("下载 {url} 失败: {e}"))?;

    let file_name = dest
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("无效目标路径: {}", dest.display()))?;
    let part_path = dest.with_file_name(format!("{file_name}.part"));
    let mut file = std::fs::File::create(&part_path)
        .map_err(|e| format!("创建 {} 失败: {e}", part_path.display()))?;
    let mut reader = resp.into_reader().take(expected_size.saturating_add(1));
    let written = std::io::copy(&mut reader, &mut file)
        .map_err(|e| format!("读取下载内容失败: {e}"))?;
    file.flush()
        .map_err(|e| format!("刷新 {} 失败: {e}", part_path.display()))?;

    if written != expected_size {
        let _ = std::fs::remove_file(&part_path);
        return Err(format!(
            "{} 下载大小不符（期望 {}，实际 {}）",
            dest.display(),
            expected_size,
            written
        ));
    }

    std::fs::rename(&part_path, dest)
        .map_err(|e| format!("写入 {} 失败: {e}", dest.display()))?;
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

    #[test]
    fn rejects_manifest_path_traversal() {
        for path in [
            "",
            "../evil.exe",
            r"C:\evil.exe",
            "/evil.exe",
            "bin/../evil.exe",
            "tools/key_verify.exe",
        ] {
            assert!(validated_manifest_path(path).is_err(), "{path}");
        }
        assert!(validated_manifest_path("FaceWinUnlock-Server.exe").is_ok());
    }

    #[test]
    fn compute_diff_only_returns_changed_files() {
        let root = std::env::temp_dir().join(format!(
            "facewinunlock-update-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
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
        assert_eq!(
            diff.files_to_update,
            vec!["changed.exe".to_string(), "missing.exe".to_string()]
        );
        assert_eq!(diff.total_size_mb, 10.0 / 1_048_576.0);

        std::fs::remove_dir_all(root).unwrap();
    }
}
