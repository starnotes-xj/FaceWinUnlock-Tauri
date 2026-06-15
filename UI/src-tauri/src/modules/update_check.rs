/// 版本更新检查模块
///
/// 仅检查 GitHub Release 是否有新版本，不做任何下载或安装操作。
/// 联网请求：GET https://api.github.com/repos/<owner>/<repo>/releases/latest

use serde::Deserialize;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const GITHUB_API: &str = "https://api.github.com/repos/starnotes-xj/FaceWinUnlock-Tauri/releases/latest";

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
}

#[derive(serde::Serialize)]
pub struct UpdateInfo {
    pub has_update: bool,
    pub current_version: String,
    pub latest_version: String,
    pub release_url: String,
}

/// 检查 GitHub Release 是否有新版本（GET 一个 API，无其他操作）
#[tauri::command]
pub fn check_update() -> Result<UpdateInfo, String> {
    let current = CURRENT_VERSION.trim_start_matches('v');

    let resp = ureq::get(GITHUB_API)
        .set("User-Agent", "FaceWinUnlock-Tauri-UpdateCheck")
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| format!("网络请求失败: {e}"))?;

    let release: GithubRelease = resp.into_json().map_err(|e| format!("解析失败: {e}"))?;
    let latest = release.tag_name.trim_start_matches('v');

    let has_update = latest != current;

    Ok(UpdateInfo {
        has_update,
        current_version: current.to_string(),
        latest_version: latest.to_string(),
        release_url: format!(
            "https://github.com/starnotes-xj/FaceWinUnlock-Tauri/releases/tag/{}",
            release.tag_name
        ),
    })
}
