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
    let script = format!(
        "$pkg = Get-AppxPackage -Name '{package_name}' | Sort-Object Version -Descending | Select-Object -First 1; \
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
    if stdout.is_empty() {
        return Ok(None);
    }

    serde_json::from_str(stdout)
        .map(Some)
        .map_err(|e| format!("解析插件状态失败: {e}"))
}

fn status_value() -> Result<Value, String> {
    let formal = query_package(FORMAL_PACKAGE_NAME)?;
    let sample = query_package(SAMPLE_PACKAGE_NAME)?;
    Ok(json!({
        "installed": formal.is_some(),
        "sample_installed": sample.is_some(),
        "package": formal,
        "sample_package": sample,
        "msix_available": artifact_path("FaceWinUnlock-Passkey.msix").exists(),
        "certificate_available": artifact_path("FaceWinUnlock-Passkey.cer").exists(),
    }))
}

#[tauri::command]
pub fn get_passkey_plugin_status() -> Result<CustomResult, CustomResult> {
    status_value()
        .map(|value| CustomResult::success(None, Some(value)))
        .map_err(|e| CustomResult::error(Some(e), None))
}

#[tauri::command]
pub fn install_passkey_plugin(replace_sample: bool) -> Result<CustomResult, CustomResult> {
    let package_path = artifact_path("FaceWinUnlock-Passkey.msix");
    let certificate_path = artifact_path("FaceWinUnlock-Passkey.cer");
    if !package_path.exists() || !certificate_path.exists() {
        return Err(CustomResult::error(
            Some("安装包中缺少 FaceWinUnlock Passkey 的 MSIX 或签名证书".to_string()),
            None,
        ));
    }

    let sample =
        query_package(SAMPLE_PACKAGE_NAME).map_err(|e| CustomResult::error(Some(e), None))?;
    if sample.is_some() && !replace_sample {
        return Err(CustomResult::error(
            Some(
                "检测到 Contoso 测试插件。替换它会删除测试插件本地保存的通行密钥，必须确认后再迁移。"
                    .to_string(),
            ),
            status_value().ok(),
        ));
    }

    let replace_script = if replace_sample {
        format!(
            "Get-AppxPackage -Name '{SAMPLE_PACKAGE_NAME}' | Remove-AppxPackage -ErrorAction Stop;"
        )
    } else {
        String::new()
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
         {replace_script} \
         Add-AppxPackage -Path {} -ForceApplicationShutdown -ForceUpdateFromAnyVersion -ErrorAction Stop;",
        powershell_literal(&certificate_path),
        powershell_literal(&certificate_path),
        powershell_literal(&certificate_path),
        powershell_literal(&package_path),
    );
    let output = run_powershell(&script)
        .map_err(|e| CustomResult::error(Some(format!("启动插件安装失败: {e}")), None))?;
    if !output.status.success() {
        return Err(CustomResult::error(
            Some(format!(
                "安装 FaceWinUnlock Passkey 失败: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )),
            None,
        ));
    }

    let status = status_value().map_err(|e| CustomResult::error(Some(e), None))?;
    Ok(CustomResult::success(
        Some("FaceWinUnlock Passkey 已安装，正在打开注册与启用流程".to_string()),
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
