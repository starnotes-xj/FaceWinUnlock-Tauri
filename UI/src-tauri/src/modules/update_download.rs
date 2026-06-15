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
use std::io::Read;
use std::path::Path;

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
        let dest = tmp_dir.join(&mf.path);
        download_file(&mf.url, &dest)?;

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
    resp.into_json()
        .map_err(|e| format!("解析更新清单失败: {e}"))
}

fn compute_diff(manifest: &UpdateManifest) -> Result<DiffResult, String> {
    let mut files_to_update = Vec::new();
    let mut total_size = 0u64;

    for mf in &manifest.files {
        let local = ROOT_DIR.join(&mf.path);
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

fn download_file(url: &str, dest: &Path) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建目录失败: {e}"))?;
    }
    let resp = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .call()
        .map_err(|e| format!("下载 {url} 失败: {e}"))?;

    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| format!("读取下载内容失败: {e}"))?;
    std::fs::write(dest, &buf).map_err(|e| format!("写入 {} 失败: {e}", dest.display()))?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("读取 {} 失败: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}
