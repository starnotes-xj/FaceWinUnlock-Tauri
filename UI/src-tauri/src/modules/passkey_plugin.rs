use std::cmp::Ordering;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{json, Value};

use crate::utils::custom_result::CustomResult;
use crate::ROOT_DIR;

const FORMAL_PACKAGE_NAME: &str = "FaceWinUnlock.PasskeyManager";
const FORMAL_APP_ID: &str = "FaceWinUnlock.PasskeyManager";
const SAMPLE_PACKAGE_NAME: &str = "Contoso.PasskeyManager";
const SAMPLE_APP_ID: &str = "Contoso.PasskeyManager";
const APPX_ALL_USER_STORE_PATH: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore";
const PASSKEY_PLUGIN_REG_PATH: &str = r"Software\FaceWinUnlock\PasskeyManager";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn run_powershell(script: &str) -> std::io::Result<Output> {
    Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
}

fn powershell_literal(value: &Path) -> String {
    format!("'{}'", value.display().to_string().replace('\'', "''"))
}

fn powershell_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn artifact_path(file_name: &str) -> PathBuf {
    let installed = ROOT_DIR.join(file_name);
    if installed.exists() {
        return installed;
    }

    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("release")
        .join(file_name)
}

fn query_package(package_name: &str) -> Result<Option<Value>, String> {
    // 合并 per-user 和 -AllUsers 两次查询（取最高版本），避免管理员上下文
    // 下 Get-AppxPackage 漏掉 per-user MSIX 包。
    let name_literal = powershell_string_literal(package_name);
    let script = format!(
        "$pkgs = @(Get-AppxPackage -Name {name_literal} -ErrorAction SilentlyContinue); \
         $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); \
         if ($isAdmin) {{ $pkgs += @(Get-AppxPackage -AllUsers -Name {name_literal} -ErrorAction SilentlyContinue) }}; \
         $pkg = $pkgs | Sort-Object Version -Descending | Select-Object -First 1; \
         if ($null -ne $pkg) {{ \
           [pscustomobject]@{{ \
             name = $pkg.Name; \
             package_full_name = $pkg.PackageFullName; \
             package_family_name = $pkg.PackageFamilyName; \
             version = $pkg.Version.ToString() \
           }} | ConvertTo-Json -Compress \
         }}"
    );
    let output = run_powershell(&script).map_err(|e| format!("查询插件包失败: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "查询插件包失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();
    if !stdout.is_empty() {
        return serde_json::from_str(stdout)
            .map(Some)
            .map_err(|e| format!("解析插件状态失败: {e}"));
    }

    // PowerShell 查询为空时，用文件系统兜底：
    // 提权进程的 Get-AppxPackage 可能完全找不到 per-user MSIX 包（已知 Windows 行为），
    // 但 MSIX 安装后必然在 %LOCALAPPDATA%\Packages\ 下创建包家族名目录。
    // 从目录名提取 FamilyName，再尝试从注册表读取版本号。
    if let Some(info) = detect_package_via_local_appdata(package_name) {
        return Ok(Some(info));
    }

    Ok(None)
}

/// 文件系统兜底：检查 `%LOCALAPPDATA%\Packages\` 是否存在以 `{package_name}_` 开头的目录。
///
/// MSIX 安装时会在 `LocalAppData\Packages` 下创建名为 `{FamilyName}` 的目录，
/// 其中 `FamilyName` 格式为 `{PackageName}_{PublisherId}`。该目录对提权进程同样可见，
/// 因此在 `Get-AppxPackage` 不可靠时作为最后的检测手段。
///
/// 返回的 `Value` 包含 `name`、`package_family_name`，以及从注册表读取的 `version`（若读取失败
/// 则为 `"0.0.0.0"`）。`package_full_name` 设为与 `package_family_name` 相同（文件系统无法获得完整名）。
fn detect_package_via_local_appdata(package_name: &str) -> Option<Value> {
    let local_app_data = std::env::var("LOCALAPPDATA").ok()?;
    let packages_dir = Path::new(&local_app_data).join("Packages");

    for entry in std::fs::read_dir(&packages_dir).ok()?.flatten() {
        let dir_name = entry.file_name();
        let dir_str = dir_name.to_str()?;
        // MSIX 包目录格式: {PackageName}_{PublisherId}
        if !dir_str.starts_with(&format!("{package_name}_")) {
            continue;
        }

        let package_family_name = dir_str.to_string();
        // 从注册表 AppxAllUserStore 读取版本号；读取失败则标记 "0.0.0.0"
        // （0.0.0.0 会使 compare_versions 判定为可更新，用户可在 UI 手动触发更新）
        let version = read_appx_version_from_registry(&package_family_name)
            .unwrap_or_else(|| "0.0.0.0".to_string());

        return Some(json!({
            "name": package_name,
            "package_full_name": package_family_name,
            "package_family_name": package_family_name,
            "version": version,
        }));
    }

    None
}

/// 从注册表读取已安装 MSIX 包的版本号。
///
/// 查找路径：`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\`
/// 下各级子键中匹配 `{package_family_name}` 的包全名键，从键名提取版本。
///
/// MSIX 包全名格式为 `{FamilyName}_{Version}_{Architecture}__{PublisherId}`，
/// 但在 AppxAllUserStore 中键名即包全名，其中嵌入版本号。
fn read_appx_version_from_registry(package_family_name: &str) -> Option<String> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let store_key = hklm
        .open_subkey_with_flags(APPX_ALL_USER_STORE_PATH, KEY_READ)
        .ok()?;

    // 遍历所有子键（每个子键是用户 SID 或 Installed、Staged 等特殊键）
    for sid_key in store_key.enum_keys().flatten() {
        let sid_subkey = match store_key.open_subkey_with_flags(&sid_key, KEY_READ) {
            Ok(k) => k,
            Err(_) => continue,
        };
        // 遍历该用户下注册的包全名
        for pkg_full_name in sid_subkey.enum_keys().flatten() {
            if pkg_full_name.starts_with(package_family_name) {
                // 包全名格式: {FamilyName}_{Major}_{Minor}_{Build}_{Rev}_{Arch}__{PublisherId}
                // 或: {FamilyName}_{Version}_{Arch}__{PublisherId}
                // 从 FamilyName 之后、Architecture 之前的下划线段提取版本
                let suffix = &pkg_full_name[package_family_name.len()..];
                let version = extract_version_from_pkg_full_name(suffix);
                if version.is_some() {
                    return version;
                }
            }
        }
    }

    None
}

fn is_passkey_appx_entry(key_name: &str) -> bool {
    [FORMAL_PACKAGE_NAME, SAMPLE_PACKAGE_NAME]
        .iter()
        .any(|package_name| {
            key_name == *package_name || key_name.starts_with(&format!("{package_name}_"))
        })
}

fn collect_passkey_appx_entries(key: &winreg::RegKey, prefix: &str, matches: &mut Vec<String>) {
    use winreg::enums::KEY_READ;

    for child_name in key.enum_keys().flatten() {
        let child_path = if prefix.is_empty() {
            child_name.clone()
        } else {
            format!(r"{prefix}\{child_name}")
        };

        if is_passkey_appx_entry(&child_name) {
            matches.push(child_path);
            continue;
        }

        if let Ok(child_key) = key.open_subkey_with_flags(&child_name, KEY_READ) {
            collect_passkey_appx_entries(&child_key, &child_path, matches);
        }
    }
}

fn cleanup_passkey_registry_residue() -> Result<(), String> {
    use std::io::ErrorKind;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.delete_subkey_all(PASSKEY_PLUGIN_REG_PATH) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(format!("清理 Passkey 插件用户注册表失败: {e}")),
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let store_key = match hklm
        .open_subkey_with_flags(APPX_ALL_USER_STORE_PATH, KEY_READ | KEY_WRITE)
    {
        Ok(key) => key,
        Err(e) if e.kind() == ErrorKind::NotFound || e.kind() == ErrorKind::PermissionDenied => {
            return Ok(())
        }
        Err(e) => return Err(format!("打开 Appx CurrentVersion 注册表失败: {e}")),
    };

    let mut matches = Vec::new();
    collect_passkey_appx_entries(&store_key, "", &mut matches);
    matches.sort_by_key(|path| std::cmp::Reverse(path.len()));

    for entry_path in matches {
        match store_key.delete_subkey_all(&entry_path) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => {
                return Err(format!(
                    "清理 Passkey Appx CurrentVersion 注册表残留失败 ({entry_path}): {e}"
                ));
            }
        }
    }

    Ok(())
}

/// 从包全名的后缀（FamilyName 之后的 `_1_0_0_0_x64__PublisherId` 部分）提取版本号。
/// 返回格式: "1.0.0.0"
fn extract_version_from_pkg_full_name(suffix: &str) -> Option<String> {
    // suffix 形如 "_1_0_0_0_x64__8wekyb3d8bbwe" 或 "_1.0.0.0_x64__PublisherId"
    let trimmed = suffix.trim_start_matches('_');
    // 按 "__" 分离出版本+架构和发布者 ID
    let before_publisher = trimmed.split("__").next()?;
    // 按 "_" 分离版本段和架构；版本段在前，架构（x64/arm64/neutral 等）在后
    let parts: Vec<&str> = before_publisher.split('_').collect();
    if parts.len() < 5 {
        // 可能是圆点分隔的版本: "1.0.0.0_x64"
        if let Some(v) = parts.first() {
            let v_parts: Vec<&str> = v.split('.').collect();
            if v_parts.len() == 4 && v_parts.iter().all(|p| p.parse::<u64>().is_ok()) {
                return Some(v.to_string());
            }
        }
        return None;
    }
    // 下划线分隔: _1_0_0_0_x64 → parts = ["1","0","0","0","x64"]
    // 取前 4 段作为版本号
    let version_parts: Vec<&str> = parts.iter().take(4).copied().collect();
    if version_parts.iter().all(|p| p.parse::<u64>().is_ok()) {
        return Some(version_parts.join("."));
    }
    None
}

fn query_msix_version(package_path: &Path) -> Result<Option<String>, String> {
    if !package_path.exists() {
        return Ok(None);
    }

    let script = format!(
        "Add-Type -AssemblyName System.IO.Compression.FileSystem; \
         $zip = [System.IO.Compression.ZipFile]::OpenRead({}); \
         try {{ \
           $entry = $zip.GetEntry('AppxManifest.xml'); \
           if ($null -eq $entry) {{ throw 'AppxManifest.xml not found' }}; \
           $stream = $entry.Open(); \
           try {{ \
             $reader = [System.IO.StreamReader]::new($stream); \
             try {{ \
               [xml]$manifest = $reader.ReadToEnd(); \
               $manifest.Package.Identity.Version \
             }} finally {{ $reader.Dispose() }} \
           }} finally {{ $stream.Dispose() }} \
         }} finally {{ $zip.Dispose() }}",
        powershell_literal(package_path)
    );
    let output = run_powershell(&script).map_err(|e| format!("读取插件 MSIX 版本失败: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "读取插件 MSIX 版本失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if version.is_empty() {
        Ok(None)
    } else {
        Ok(Some(version))
    }
}

fn package_version(package: &Value) -> Option<&str> {
    package["version"]
        .as_str()
        .filter(|value| !value.is_empty())
}

fn compare_versions(left: &str, right: &str) -> Ordering {
    let left = left.trim().trim_start_matches('v').trim_start_matches('V');
    let right = right.trim().trim_start_matches('v').trim_start_matches('V');
    let mut left_parts = left
        .split(['.', '-'])
        .map(|part| part.parse::<u64>().unwrap_or(0));
    let mut right_parts = right
        .split(['.', '-'])
        .map(|part| part.parse::<u64>().unwrap_or(0));

    for _ in 0..4 {
        let l = left_parts.next().unwrap_or(0);
        let r = right_parts.next().unwrap_or(0);
        match l.cmp(&r) {
            Ordering::Equal => {}
            order => return order,
        }
    }

    Ordering::Equal
}

/// 第三方通行密钥（passkey）凭据 Provider 是 Windows 11 24H2 (build 26100) 引入的
/// 系统功能，更旧的系统（含**全部 Windows 10**）无法注册/使用该插件——MSIX 的
/// `TargetDeviceFamily MinVersion` 即为 `10.0.26100.0`，在 Win10 上 `Add-AppxPackage`
/// 会直接报 `0x80073CFD`(ERROR_INSTALL_PREREQUISITE_FAILED)。
///
/// 用于让初始化向导在不支持的系统上**优雅跳过** Passkey 步骤（给友好提示而非弹出
/// 红色安装错误，避免用户误以为整个初始化失败 —— 面容解锁的核心在第二步已配好）。
const PASSKEY_MIN_BUILD: u32 = 26100;

fn current_os_build() -> u32 {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", KEY_READ)
        .ok()
        .and_then(|key| key.get_value::<String, _>("CurrentBuildNumber").ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

fn is_passkey_os_supported() -> bool {
    current_os_build() >= PASSKEY_MIN_BUILD
}

fn status_value() -> Result<Value, String> {
    let formal = query_package(FORMAL_PACKAGE_NAME)?;
    // 主动备份兜底（修「Geek 卸载重装后通行密钥凭据过期」）：插件已安装且 LocalState 有
    // credentials.dat 时，把它备份到包外目录。v0.5.4 只在【应用内卸载】(uninstall_passkey_plugin)
    // 时备份，而用户走 Geek/NSIS 卸载脚本的路径【不】做包外备份、Geek 深度清理又会抹掉
    // LocalState，导致重装时 restore 无备份可恢复。改为每次状态查询（Options/初始化/安装后都会
    // 调用本函数、且都在用户上下文）主动刷新备份，使无论经何种方式卸载，包外备份都已存在，
    // 重装时 restore_passkey_credentials 即可恢复（私钥本就在 KSP 保留）。
    // backup_passkey_credentials 在 LocalState 无 credentials.dat 时自动跳过、不会用空备份覆盖，
    // 纯 best-effort，不影响状态查询结果。
    if let Some(pfn) = formal
        .as_ref()
        .and_then(|p| p["package_family_name"].as_str())
    {
        backup_passkey_credentials(pfn);
    }
    let sample = query_package(SAMPLE_PACKAGE_NAME)?;
    let msix_path = artifact_path("FaceWinUnlock-Passkey.msix");
    let bundled_version = query_msix_version(&msix_path).ok().flatten();
    let update_available = match (
        formal.as_ref().and_then(package_version),
        bundled_version.as_deref(),
    ) {
        (Some(installed), Some(bundled)) => compare_versions(installed, bundled).is_lt(),
        _ => false,
    };
    Ok(json!({
        "installed": formal.is_some(),
        "sample_installed": sample.is_some(),
        "package": formal,
        "sample_package": sample,
        "msix_available": msix_path.exists(),
        "certificate_available": artifact_path("FaceWinUnlock-Passkey.cer").exists(),
        "bundled_version": bundled_version,
        "update_available": update_available,
        "os_supported": is_passkey_os_supported(),
    }))
}

fn install_or_update_package(
    package_path: &Path,
    certificate_path: &Path,
    is_update: bool,
) -> Result<(), String> {
    let appx_command = if is_update {
        format!(
            "Add-AppxPackage -Update -Path {} -ForceApplicationShutdown -ForceUpdateFromAnyVersion -ErrorAction Stop;",
            powershell_literal(package_path),
        )
    } else {
        format!(
            "Add-AppxPackage -Path {} -ForceApplicationShutdown -ForceUpdateFromAnyVersion -ErrorAction Stop;",
            powershell_literal(package_path),
        )
    };

    let script = format!(
        "$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); \
         if ($isAdmin) {{ \
           Import-Certificate -FilePath {} -CertStoreLocation 'Cert:\\LocalMachine\\TrustedPeople' -ErrorAction Stop | Out-Null; \
           Import-Certificate -FilePath {} -CertStoreLocation 'Cert:\\LocalMachine\\Root' -ErrorAction Stop | Out-Null; \
         }} else {{ \
           Import-Certificate -FilePath {} -CertStoreLocation 'Cert:\\CurrentUser\\TrustedPeople' -ErrorAction Stop | Out-Null; \
         }}; \
         Get-Process -Name 'PasskeyManager' -ErrorAction SilentlyContinue | Stop-Process -Force; \
         {appx_command}",
        powershell_literal(certificate_path),
        powershell_literal(certificate_path),
        powershell_literal(certificate_path),
    );
    let output = run_powershell(&script).map_err(|e| format!("启动插件安装失败: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "安装 FaceWinUnlock Passkey 失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// 更新已安装的正式 Passkey MSIX 包。
///
/// 只调用 `Add-AppxPackage -Update/-ForceUpdateFromAnyVersion`，不移除包，因此 MSIX
/// `LocalState` 中的本地通行密钥库、HKCU 插件设置和 Windows 插件索引都会保留。
/// 返回 `Ok(None)` 表示未安装或无需更新。
pub(crate) fn update_bundled_passkey_plugin_preserving_data() -> Result<Option<String>, String> {
    let Some(formal) = query_package(FORMAL_PACKAGE_NAME)? else {
        return Ok(None);
    };

    let package_path = artifact_path("FaceWinUnlock-Passkey.msix");
    let certificate_path = artifact_path("FaceWinUnlock-Passkey.cer");
    if !package_path.exists() || !certificate_path.exists() {
        return Err("安装目录中缺少 FaceWinUnlock Passkey 的 MSIX 或签名证书".to_string());
    }

    let Some(bundled_version) = query_msix_version(&package_path)? else {
        return Err("无法读取 FaceWinUnlock Passkey MSIX 版本".to_string());
    };
    let installed_version = package_version(&formal).unwrap_or("0.0.0.0");
    if compare_versions(installed_version, &bundled_version).is_ge() {
        return Ok(None);
    }

    install_or_update_package(&package_path, &certificate_path, true)?;
    Ok(Some(format!(
        "FaceWinUnlock Passkey 已从 {installed_version} 更新到 {bundled_version}，本地通行密钥已保留"
    )))
}

#[tauri::command]
pub fn get_passkey_plugin_status() -> Result<CustomResult, CustomResult> {
    status_value()
        .map(|value| CustomResult::success(None, Some(value)))
        .map_err(|e| CustomResult::error(Some(e), None))
}

#[tauri::command]
pub fn install_passkey_plugin(replace_sample: bool) -> Result<CustomResult, CustomResult> {
    // OS 兜底：旧系统（含全部 Win10）不支持第三方 passkey Provider，直接返回可读提示，
    // 不把 Add-AppxPackage 的 0x80073CFD 原始错误透传给用户（前端通常已据 os_supported 跳过）。
    if !is_passkey_os_supported() {
        return Err(CustomResult::error(
            Some(format!(
                "当前 Windows 版本（build {}）不支持第三方通行密钥 Provider，该功能需 Windows 11 24H2（build {}）及以上。已跳过 Passkey 插件，不影响面容解锁。",
                current_os_build(),
                PASSKEY_MIN_BUILD
            )),
            status_value().ok(),
        ));
    }

    let package_path = artifact_path("FaceWinUnlock-Passkey.msix");
    let certificate_path = artifact_path("FaceWinUnlock-Passkey.cer");
    if !package_path.exists() || !certificate_path.exists() {
        return Err(CustomResult::error(
            Some("安装包中缺少 FaceWinUnlock Passkey 的 MSIX 或签名证书".to_string()),
            None,
        ));
    }

    let formal =
        query_package(FORMAL_PACKAGE_NAME).map_err(|e| CustomResult::error(Some(e), None))?;
    let sample =
        query_package(SAMPLE_PACKAGE_NAME).map_err(|e| CustomResult::error(Some(e), None))?;
    let should_remove_sample = replace_sample && sample.is_some();
    if formal.is_none() && sample.is_some() && !replace_sample {
        return Err(CustomResult::error(
            Some(
                "检测到 Contoso 测试插件。替换它会删除测试插件本地保存的通行密钥，必须确认后再迁移。"
                    .to_string(),
            ),
            status_value().ok(),
        ));
    }

    let bundled_version =
        query_msix_version(&package_path).map_err(|e| CustomResult::error(Some(e), None))?;
    let needs_install = match (formal.as_ref(), bundled_version.as_deref()) {
        (None, _) => true,
        (Some(package), Some(bundled)) => package_version(package)
            .map(|installed| compare_versions(installed, bundled).is_ne())
            .unwrap_or(true),
        (Some(_), None) => true,
    };
    if let (Some(package), Some(bundled)) = (formal.as_ref(), bundled_version.as_deref()) {
        if let Some(installed) = package_version(package) {
            if compare_versions(installed, bundled).is_ge() && !should_remove_sample {
                let status = status_value().map_err(|e| CustomResult::error(Some(e), None))?;
                return Ok(CustomResult::success(
                    Some("FaceWinUnlock Passkey 已是当前版本，已跳过重新安装，正在打开注册与启用流程".to_string()),
                    Some(status),
                ));
            }
        }
    }

    let replace_script = if should_remove_sample {
        format!(
            "Get-Process -Name 'PasskeyManager' -ErrorAction SilentlyContinue | Stop-Process -Force; \
             $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); \
             $pkgs = @(Get-AppxPackage -Name '{SAMPLE_PACKAGE_NAME}' -ErrorAction SilentlyContinue); \
             if ($isAdmin) {{ $pkgs += @(Get-AppxPackage -AllUsers -Name '{SAMPLE_PACKAGE_NAME}' -ErrorAction SilentlyContinue) }}; \
             if ($pkgs.Count -gt 1) {{ $pkgs = $pkgs | Sort-Object PackageFullName -Unique }}; \
             $pkgs | Remove-AppxPackage -ErrorAction Stop;"
        )
    } else {
        String::new()
    };
    if !replace_script.is_empty() {
        let output = run_powershell(&replace_script)
            .map_err(|e| CustomResult::error(Some(format!("启动测试插件清理失败: {e}")), None))?;
        if !output.status.success() {
            return Err(CustomResult::error(
                Some(format!(
                    "清理 Contoso 测试插件失败: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )),
                None,
            ));
        }
    }

    if needs_install {
        install_or_update_package(&package_path, &certificate_path, formal.is_some())
            .map_err(|e| CustomResult::error(Some(e), None))?;
        // 安装/重装后，若新 LocalState 无元数据但包外有备份则恢复，使卸载重装/全量更新后
        // 免重新注册通行密钥（私钥本就在 KSP 中保留）。best-effort，不阻断安装。
        if let Ok(Some(pkg)) = query_package(FORMAL_PACKAGE_NAME) {
            if let Some(pfn) = pkg["package_family_name"].as_str() {
                restore_passkey_credentials(pfn);
            }
        }
    }

    let status = status_value().map_err(|e| CustomResult::error(Some(e), None))?;
    Ok(CustomResult::success(
        Some(
            if needs_install {
                "FaceWinUnlock Passkey 已安装，正在打开注册与启用流程"
            } else {
                "Contoso 测试插件已清理，FaceWinUnlock Passkey 保持当前版本，正在打开注册与启用流程"
            }
            .to_string(),
        ),
        Some(status),
    ))
}

#[tauri::command]
pub fn open_passkey_plugin_setup() -> Result<CustomResult, CustomResult> {
    let formal =
        query_package(FORMAL_PACKAGE_NAME).map_err(|e| CustomResult::error(Some(e), None))?;
    let Some(package) = formal else {
        return Err(CustomResult::error(
            Some("尚未安装 FaceWinUnlock Passkey 正式插件".to_string()),
            None,
        ));
    };

    let package_family_name = package["package_family_name"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if package_family_name.is_empty() {
        return Err(CustomResult::error(
            Some("插件包信息不完整，无法打开设置流程".to_string()),
            None,
        ));
    }

    let target = format!("shell:AppsFolder\\{package_family_name}!{FORMAL_APP_ID}");
    let script = format!(
        "$localState = Join-Path $env:LOCALAPPDATA {}; \
         New-Item -ItemType Directory -Path $localState -Force | Out-Null; \
         Set-Content -Path (Join-Path $localState 'FaceWinUnlockSetupRequested.flag') -Value '1' -Encoding ASCII -Force; \
         Start-Process -FilePath 'explorer.exe' -ArgumentList {} -ErrorAction Stop;",
        powershell_string_literal(&format!(
            "Packages\\{package_family_name}\\LocalState"
        )),
        powershell_string_literal(&target)
    );
    let output = run_powershell(&script)
        .map_err(|e| CustomResult::error(Some(format!("启动 Passkey 设置流程失败: {e}")), None))?;
    if !output.status.success() {
        return Err(CustomResult::error(
            Some(format!(
                "启动 Passkey 设置流程失败: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )),
            None,
        ));
    }

    Ok(CustomResult::success(
        Some("已打开 Passkey 插件设置流程".to_string()),
        None,
    ))
}

#[tauri::command]
pub fn open_passkey_plugin_manager() -> Result<CustomResult, CustomResult> {
    let formal =
        query_package(FORMAL_PACKAGE_NAME).map_err(|e| CustomResult::error(Some(e), None))?;
    let sample =
        query_package(SAMPLE_PACKAGE_NAME).map_err(|e| CustomResult::error(Some(e), None))?;

    let (package_family_name, app_id) = if let Some(package) = formal {
        (
            package["package_family_name"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            FORMAL_APP_ID,
        )
    } else if let Some(package) = sample {
        (
            package["package_family_name"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            SAMPLE_APP_ID,
        )
    } else {
        return Err(CustomResult::error(
            Some("尚未安装 FaceWinUnlock Passkey 插件".to_string()),
            None,
        ));
    };

    if package_family_name.is_empty() {
        return Err(CustomResult::error(
            Some("插件包信息不完整，无法打开管理器".to_string()),
            None,
        ));
    }

    let target = format!("shell:AppsFolder\\{package_family_name}!{app_id}");
    Command::new("explorer.exe")
        .arg(target)
        .spawn()
        .map_err(|e| CustomResult::error(Some(format!("打开插件管理器失败: {e}")), None))?;

    Ok(CustomResult::success(None, None))
}

/// 卸载模式：是否保留本地通行密钥（凭据元数据 + KSP 私钥 + 插件配置）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum UninstallMode {
    /// 保留：Remove-AppxPackage 用 `-PreserveApplicationData` 保留 MSIX LocalState 元数据，
    /// 卸载前额外备份到包外目录，且不删 KSP 私钥/证书/注册表配置——卸载/重装/全量更新后
    /// 仍可用之前注册的通行密钥，无需重新注册。私钥本就在 Microsoft Software KSP（密钥名
    /// `facewinunlock/<userId>`，per-user）中、不随 MSIX 卸载删除。
    KeepCredentials,
    /// 彻底清除：删 MSIX 数据 + KSP 私钥(`facewinunlock/*`) + 证书 + 注册表配置 + 包外备份。
    Purge,
}

const PASSKEY_CREDENTIALS_FILE: &str = "credentials.dat";

/// 包外通行密钥元数据备份目录（per-user 持久，仅 Purge 时清除）。
fn passkey_backup_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(|p| PathBuf::from(p).join("FaceWinUnlock").join("PasskeyBackup"))
}

/// 插件在 MSIX LocalState 下存元数据的目录（与 C++ 端 `PluginCredentialManager` 约定一致）：
/// `%LOCALAPPDATA%\Packages\<FamilyName>\LocalState\CredentialsDB`。
fn passkey_localstate_db_dir(package_family_name: &str) -> Option<PathBuf> {
    if package_family_name.is_empty() {
        return None;
    }
    std::env::var_os("LOCALAPPDATA").map(|p| {
        PathBuf::from(p)
            .join("Packages")
            .join(package_family_name)
            .join("LocalState")
            .join("CredentialsDB")
    })
}

/// 卸载前把凭据元数据备份到包外（best-effort），兜底 `-PreserveApplicationData` 失效或被清理。
fn backup_passkey_credentials(package_family_name: &str) -> bool {
    let (Some(db_dir), Some(backup_dir)) = (
        passkey_localstate_db_dir(package_family_name),
        passkey_backup_dir(),
    ) else {
        return false;
    };
    let src = db_dir.join(PASSKEY_CREDENTIALS_FILE);
    if !src.exists() || std::fs::create_dir_all(&backup_dir).is_err() {
        return false;
    }
    std::fs::copy(&src, backup_dir.join(PASSKEY_CREDENTIALS_FILE)).is_ok()
}

/// 安装/重装后恢复元数据（best-effort）：仅当当前 LocalState 无元数据、而包外备份存在时
/// 才恢复，避免覆盖 `-PreserveApplicationData` 已保留的数据。
pub(crate) fn restore_passkey_credentials(package_family_name: &str) -> bool {
    let Some(backup) = passkey_backup_dir().map(|d| d.join(PASSKEY_CREDENTIALS_FILE)) else {
        return false;
    };
    if !backup.exists() {
        return false;
    }
    let Some(db_dir) = passkey_localstate_db_dir(package_family_name) else {
        return false;
    };
    let dst = db_dir.join(PASSKEY_CREDENTIALS_FILE);
    if dst.exists() || std::fs::create_dir_all(&db_dir).is_err() {
        return false;
    }
    std::fs::copy(&backup, &dst).is_ok()
}

/// 清除包外通行密钥备份（仅 Purge 调用）。
fn delete_passkey_backup() {
    if let Some(dir) = passkey_backup_dir() {
        let _ = std::fs::remove_dir_all(&dir);
    }
}

fn uninstall_passkey_plugin_impl(
    ignore_missing: bool,
    mode: UninstallMode,
) -> Result<(bool, Value), String> {
    let formal = query_package(FORMAL_PACKAGE_NAME)
        .map_err(|e| format!("查询正式 Passkey 插件失败: {e}"))?;
    let sample = query_package(SAMPLE_PACKAGE_NAME)
        .map_err(|e| format!("查询测试 Passkey 插件失败: {e}"))?;

    if formal.is_none() && sample.is_none() {
        // 保留模式不动注册表/备份；彻底清除才清理残留 + 删备份。
        if mode == UninstallMode::Purge {
            cleanup_passkey_registry_residue()?;
            delete_passkey_backup();
        }
        if ignore_missing {
            return Ok((false, status_value()?));
        }
        return Err("没有检测到已安装的 Passkey 插件，无需卸载".to_string());
    }

    // 保留模式：卸载前把正式插件的凭据元数据备份到包外（兜底 -PreserveApplicationData 失效）。
    if mode == UninstallMode::KeepCredentials {
        if let Some(pfn) = formal
            .as_ref()
            .and_then(|p| p["package_family_name"].as_str())
        {
            let _ = backup_passkey_credentials(pfn);
        }
    }

    let certificate_path = artifact_path("FaceWinUnlock-Passkey.cer");

    // 如果卸载脚本存在就用它（处理证书清理等完整流程），否则内联 Remove-AppxPackage
    let uninstall_script_path = ROOT_DIR
        .join("scripts")
        .join("uninstall-passkey-plugin.ps1");
    if uninstall_script_path.exists() {
        let mode_arg = match mode {
            UninstallMode::Purge => "-Purge",
            UninstallMode::KeepCredentials => "-PreserveApplicationData",
        };
        let script = format!(
            "& {} -CertificatePath {} {} -ErrorAction Stop",
            powershell_literal(&uninstall_script_path),
            powershell_literal(&certificate_path),
            mode_arg,
        );
        let output = run_powershell(&script).map_err(|e| format!("启动插件卸载失败: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "卸载 Passkey 插件失败: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    } else {
        // 内联卸载（fallback：随附脚本不存在时）。保留模式只卸 MSIX 并 -PreserveApplicationData
        // 保留数据；彻底清除才删证书与 KSP 私钥（facewinunlock/*，best-effort）。
        let preserve = if mode == UninstallMode::KeepCredentials {
            "-PreserveApplicationData "
        } else {
            ""
        };
        let remove_pkgs = format!(
            "Get-Process -Name 'PasskeyManager' -ErrorAction SilentlyContinue | Stop-Process -Force; \
             $ErrorActionPreference = 'Stop'; \
             $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); \
             foreach ($name in @('{FORMAL_PACKAGE_NAME}', '{SAMPLE_PACKAGE_NAME}')) {{ \
               $pkgs = @(Get-AppxPackage -Name $name -ErrorAction SilentlyContinue); \
               if ($isAdmin) {{ $pkgs += @(Get-AppxPackage -AllUsers -Name $name -ErrorAction SilentlyContinue) }}; \
               if ($pkgs.Count -gt 1) {{ $pkgs = $pkgs | Sort-Object PackageFullName -Unique }}; \
               $pkgs | Remove-AppxPackage {preserve}-ErrorAction Stop; \
             }};"
        );
        let purge_extra = if mode == UninstallMode::Purge {
            format!(
                " if (Test-Path {cert_path}) {{ \
                   $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new({cert_path}); \
                   foreach ($storeName in @('TrustedPeople','Root')) {{ \
                     & certutil.exe -user -delstore $storeName $cert.Thumbprint 2>$null | Out-Null; \
                     if ($isAdmin) {{ & certutil.exe -delstore $storeName $cert.Thumbprint 2>$null | Out-Null }} \
                   }} \
                 }}; \
                 $keys = & certutil.exe -user -key -csp 'Microsoft Software Key Storage Provider' 2>$null; \
                 if ($keys) {{ foreach ($line in $keys) {{ $t = \"$line\".Trim(); if ($t -like 'facewinunlock/*') {{ & certutil.exe -user -csp 'Microsoft Software Key Storage Provider' -delkey \"$t\" 2>$null | Out-Null }} }} }}",
                cert_path = powershell_literal(&certificate_path),
            )
        } else {
            String::new()
        };
        let script = format!("{remove_pkgs}{purge_extra}");
        let output = run_powershell(&script).map_err(|e| format!("启动插件卸载失败: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "卸载 Passkey 插件失败: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }

    // 注册表配置与包外备份仅在彻底清除时删除；保留模式留着配置供重装复用。
    if mode == UninstallMode::Purge {
        cleanup_passkey_registry_residue()?;
        delete_passkey_backup();
    }

    Ok((true, status_value()?))
}

/// 主程序/核心卸载时调用：卸载 Passkey 插件但**默认保留**本地通行密钥（MSIX 数据 +
/// KSP 私钥 + 配置），便于卸载重装/全量更新后免重新注册。彻底清除仅在用户显式选择时执行。
pub(crate) fn uninstall_passkey_plugin_for_core_uninstall() -> Result<Option<String>, String> {
    let (removed, _) = uninstall_passkey_plugin_impl(true, UninstallMode::KeepCredentials)?;
    Ok(removed.then(|| "Passkey 插件已卸载（保留本地通行密钥，重装后可继续使用）".to_string()))
}

/// 手动卸载 Passkey 插件（仅在用户明确确认后调用）。
///
/// - `purge = false`（默认/保留）：仅卸载 MSIX 包并 `-PreserveApplicationData` 保留凭据元数据，
///   额外备份到包外目录，不删 KSP 私钥/证书/配置——重装或全量更新后可继续使用之前注册的通行密钥。
/// - `purge = true`（彻底清除）：删除 MSIX 数据 + KSP 私钥(`facewinunlock/*`) + 证书 + 注册表 + 备份，
///   不可恢复。
///
/// 主程序更新不触发本操作；更新路径走 `Add-AppxPackage -Update`，本就保留已有通行密钥。
#[tauri::command]
pub fn uninstall_passkey_plugin(purge: bool) -> Result<CustomResult, CustomResult> {
    let mode = if purge {
        UninstallMode::Purge
    } else {
        UninstallMode::KeepCredentials
    };
    let (removed, status) = uninstall_passkey_plugin_impl(false, mode)
        .map_err(|e| CustomResult::error(Some(e), None))?;
    let msg = if removed {
        if purge {
            "Passkey 插件已彻底卸载：本地通行密钥、私钥、证书与配置已清除"
        } else {
            "Passkey 插件已卸载，本地通行密钥已保留（重装/更新后可继续使用，无需重新注册）"
        }
    } else {
        "没有检测到已安装的 Passkey 插件，无需卸载"
    };
    Ok(CustomResult::success(Some(msg.to_string()), Some(status)))
}

/// 清理插件残留的 KSP 私钥（`facewinunlock/*`）。
///
/// 背景：插件的「清空/删除通行密钥」只删元数据与 Windows 索引，**不删** NCrypt 私钥，
/// 导致私钥残留在 `%APPDATA%\Microsoft\Crypto\Keys`（每个约 1-2KB，占用极小但属隐私残留）。
/// 本命令用 certutil 枚举并删除所有 `facewinunlock/` 前缀的 Software KSP 私钥，返回删除数量。
/// 与「彻底卸载(Purge)」删私钥逻辑一致，但无需卸载插件、可单独清理。
#[tauri::command]
pub fn cleanup_passkey_residual_keys() -> Result<CustomResult, CustomResult> {
    let script = "\
        $deleted = 0; \
        $keys = & certutil.exe -user -key -csp 'Microsoft Software Key Storage Provider' 2>$null; \
        if ($keys) { foreach ($line in $keys) { \
            $t = \"$line\".Trim(); \
            if ($t -like 'facewinunlock/*') { \
                & certutil.exe -user -csp 'Microsoft Software Key Storage Provider' -delkey \"$t\" 2>$null | Out-Null; \
                if ($LASTEXITCODE -eq 0) { $deleted++ } \
            } \
        } }; \
        Write-Output $deleted";
    let output = run_powershell(script)
        .map_err(|e| CustomResult::error(Some(format!("清理残留私钥失败: {e}")), None))?;
    if !output.status.success() {
        return Err(CustomResult::error(
            Some(format!(
                "清理残留私钥失败: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )),
            None,
        ));
    }
    let deleted: i64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or(0);
    Ok(CustomResult::success(
        Some(format!("已清理 {deleted} 个残留通行密钥私钥")),
        Some(json!({ "deleted": deleted })),
    ))
}
