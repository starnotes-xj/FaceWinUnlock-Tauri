/// 版本更新检查模块
///
/// 语义版本比较规则：
/// - 只在最新 Release 版本高于当前版本时提示更新
/// - 若版本相同，则额外比对 update_manifest.json 中的运行时文件 hash；
///   只要本地文件与最新 Release 资产不一致，也提示同步更新
/// - 若最新 Release 版本低于当前版本，不提示“降级更新”
use std::cmp::Ordering;

use serde::Deserialize;

use super::update_download::fetch_update_diff_internal;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const GITHUB_API: &str =
    "https://api.github.com/repos/starnotes-xj/FaceWinUnlock-Tauri/releases/latest";

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
    pub update_reason: String,
}

/// 检查 GitHub Release 是否有新版本（GET latest release；必要时再读取 manifest 做同版本 hash 校验）
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

    let (has_update, update_reason) = match compare_semver(current, latest)? {
        Ordering::Less => (true, format!("发现新版本 v{latest}")),
        Ordering::Greater => (false, String::new()),
        Ordering::Equal => match has_same_version_file_update() {
            Ok(true) => (
                true,
                format!("检测到 v{latest} 的发布文件已更新，请同步最新构建"),
            ),
            Ok(false) => (false, String::new()),
            Err(_) => (false, String::new()),
        },
    };

    Ok(UpdateInfo {
        has_update,
        current_version: current.to_string(),
        latest_version: latest.to_string(),
        release_url: format!(
            "https://github.com/starnotes-xj/FaceWinUnlock-Tauri/releases/tag/{}",
            release.tag_name
        ),
        update_reason,
    })
}

fn has_same_version_file_update() -> Result<bool, String> {
    let diff = fetch_update_diff_internal()?;
    Ok(!diff.files_to_update.is_empty())
}

fn compare_semver(current: &str, latest: &str) -> Result<Ordering, String> {
    let current = SemVer::parse(current)?;
    let latest = SemVer::parse(latest)?;
    Ok(current.cmp(&latest))
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct SemVer {
    major: u64,
    minor: u64,
    patch: u64,
    pre_release: Vec<PreReleaseIdent>,
}

impl SemVer {
    fn parse(raw: &str) -> Result<Self, String> {
        let normalized = raw.trim().trim_start_matches('v');
        let (without_build, _) = normalized.split_once('+').unwrap_or((normalized, ""));
        let (core, pre_release) = without_build
            .split_once('-')
            .map_or((without_build, ""), |(core, pre)| (core, pre));

        let mut core_parts = core.split('.');
        let major = parse_core_part(core_parts.next(), raw, "major")?;
        let minor = parse_core_part(core_parts.next(), raw, "minor")?;
        let patch = parse_core_part(core_parts.next(), raw, "patch")?;
        if core_parts.next().is_some() {
            return Err(format!("无效版本号: {raw}"));
        }

        let pre_release = if pre_release.is_empty() {
            Vec::new()
        } else {
            pre_release
                .split('.')
                .map(PreReleaseIdent::parse)
                .collect::<Result<Vec<_>, _>>()?
        };

        Ok(Self {
            major,
            minor,
            patch,
            pre_release,
        })
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then_with(|| self.minor.cmp(&other.minor))
            .then_with(|| self.patch.cmp(&other.patch))
            .then_with(|| compare_pre_release(&self.pre_release, &other.pre_release))
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum PreReleaseIdent {
    Numeric(u64),
    Alpha(String),
}

impl PreReleaseIdent {
    fn parse(raw: &str) -> Result<Self, String> {
        if raw.is_empty() {
            return Err("预发布标识不能为空".to_string());
        }
        if raw.chars().all(|c| c.is_ascii_digit()) {
            return raw
                .parse::<u64>()
                .map(Self::Numeric)
                .map_err(|_| format!("无效预发布标识: {raw}"));
        }
        Ok(Self::Alpha(raw.to_ascii_lowercase()))
    }
}

fn parse_core_part(part: Option<&str>, raw: &str, label: &str) -> Result<u64, String> {
    let value = part.ok_or_else(|| format!("无效版本号: {raw}"))?;
    value
        .parse::<u64>()
        .map_err(|_| format!("无效版本号 {label}: {raw}"))
}

fn compare_pre_release(current: &[PreReleaseIdent], latest: &[PreReleaseIdent]) -> Ordering {
    match (current.is_empty(), latest.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => {
            for (left, right) in current.iter().zip(latest.iter()) {
                let ordering = match (left, right) {
                    (PreReleaseIdent::Numeric(a), PreReleaseIdent::Numeric(b)) => a.cmp(b),
                    (PreReleaseIdent::Numeric(_), PreReleaseIdent::Alpha(_)) => Ordering::Less,
                    (PreReleaseIdent::Alpha(_), PreReleaseIdent::Numeric(_)) => Ordering::Greater,
                    (PreReleaseIdent::Alpha(a), PreReleaseIdent::Alpha(b)) => a.cmp(b),
                };
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            current.len().cmp(&latest.len())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_blocks_downgrade_prompts() {
        assert_eq!(compare_semver("0.5.0", "0.4.4").unwrap(), Ordering::Greater);
        assert_eq!(compare_semver("0.4.4", "0.5.0").unwrap(), Ordering::Less);
    }

    #[test]
    fn semver_handles_pre_release_ordering() {
        assert_eq!(
            compare_semver("0.5.0-rc.1", "0.5.0").unwrap(),
            Ordering::Less
        );
        assert_eq!(
            compare_semver("0.5.0-beta.2", "0.5.0-beta.10").unwrap(),
            Ordering::Less
        );
        assert_eq!(
            compare_semver("0.5.0-rc.1", "0.5.0-rc.1+build.9").unwrap(),
            Ordering::Equal
        );
    }
}
