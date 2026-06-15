# 增量更新方案设计

> 目标：检测到新版本后，只下载变化文件，最小化更新流量和用户等待时间。
> 现状：已有 `check_update`（仅比对版本号），无下载逻辑。

---

## 1. 整体流程

```
启动 → check_update() → 是否有新版本？
  ├─ 否 → 无操作
  └─ 是 → 下载 update_manifest.json
           ├─ 比对本地文件 hash（SHA256）
           ├─ 生成差异列表（新增/修改/删除）
           ├─ 弹出确认框："有新版本 vX.X.X，需下载 N 个文件（共 X MB），是否更新？"
           │    ├─ 取消 → 关闭
           │    └─ 确定 → 逐文件下载 → 写入临时目录
           │              → 全部下载完 → 弹窗 "更新已就绪，下次启动生效"
           │              → MainLayout 主窗口关闭时 → 替换文件 → 重启
           └─ (若全部文件已是最新) → "已是最新版本"
```

## 2. CI 侧变更（.github/workflows/release.yml）

在现有 Release job 最后新增一步 `Generate update manifest`：

```yaml
- name: Generate update manifest
  shell: pwsh
  run: |
    $manifest = @{
      version = "${{ steps.release_meta.outputs.version }}"
      files = @()
    }
    $assets = @(
      "target/release/FaceWinUnlock-Server.exe",
      "target/release/FaceWinUnlock_Tauri.dll",
      "target/release/ngc_crack.exe",
      "target/release/key_verify.exe",
      "target/release/bundle/nsis/*.exe",
      "target/release/bundle/msi/*.msi"
    )
    foreach ($pattern in $assets) {
      foreach ($f in Get-ChildItem $pattern) {
        $hash = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
        $manifest.files += @{
          path = $f.Name
          sha256 = $hash
          size = $f.Length
          url = "https://github.com/${{ github.repository }}/releases/download/${{ github.ref_name }}/$($f.Name)"
        }
      }
    }
    $manifest | ConvertTo-Json -Depth 3 | Out-File -Encoding UTF8 target/release/update_manifest.json
    Write-Host "Manifest generated: $(Get-Item target/release/update_manifest.json).Length bytes"

- name: Upload manifest as release asset
  uses: softprops/action-gh-release@v2
  with:
    files: target/release/update_manifest.json
```

## 3. 客户端变更

### 3.1 新增 `UI/src-tauri/src/modules/update_download.rs`

```rust
// 职责：下载 update_manifest.json → 比对本地 hash → 下载差异文件 → 写入临时目录

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct ManifestFile {
    path: String,
    sha256: String,
    size: u64,
    url: String,
}

#[derive(Deserialize)]
struct UpdateManifest {
    version: String,
    files: Vec<ManifestFile>,
}

#[derive(serde::Serialize)]
pub struct DiffResult {
    pub version: String,
    pub files_to_update: Vec<String>,
    pub total_size_mb: f64,
    pub files_to_delete: Vec<String>,
}

/// 步骤1: 下载 manifest 并比对差异
#[tauri::command]
pub fn fetch_update_diff() -> Result<DiffResult, String> {
    let manifest = download_manifest()?;
    let diff = compute_diff(&manifest)?;
    Ok(diff)
}

/// 步骤2: 下载差异文件到临时目录
#[tauri::command]
pub async fn apply_update() -> Result<String, String> {
    let manifest = download_manifest()?;
    let diff = compute_diff(&manifest)?;
    let tmp_dir = ROOT_DIR.join("update_temp");
    std::fs::create_dir_all(&tmp_dir).map_err(|e| format!("创建临时目录失败: {e}"))?;

    for f in &diff.files_to_update {
        let mf = manifest.files.iter().find(|x| x.path == *f).unwrap();
        download_file(&mf.url, &tmp_dir.join(f))?;
    }

    // 写删除清单（替换完成后清理）
    std::fs::write(
        tmp_dir.join("files_to_delete.json"),
        serde_json::to_string(&diff.files_to_delete).unwrap_or_default(),
    ).ok();

    Ok(tmp_dir.to_string_lossy().to_string())
}

fn compute_diff(manifest: &UpdateManifest) -> Result<DiffResult, String> {
    let mut files_to_update = Vec::new();
    let mut total_size = 0u64;
    let exe_dir = ROOT_DIR;

    for mf in &manifest.files {
        let local_path = exe_dir.join(&mf.path);
        if !local_path.exists() {
            files_to_update.push(mf.path.clone());
            total_size += mf.size;
        } else {
            let local_hash = sha256_file(&local_path)?;
            if local_hash != mf.sha256 {
                files_to_update.push(mf.path.clone());
                total_size += mf.size;
            }
        }
    }

    // 检查需要删除的文件（本地有但 manifest 无）
    let files_to_delete: Vec<String> = check_deleted_files(manifest, exe_dir);

    Ok(DiffResult {
        version: manifest.version.clone(),
        files_to_update,
        total_size_mb: total_size as f64 / 1_048_576.0,
        files_to_delete,
    })
}
```

### 3.2 修改 `UI/src-tauri/src/lib.rs`

注册两个新命令：
```rust
use modules::update_download::{fetch_update_diff, apply_update};
// ...
generate_handler![ ..., fetch_update_diff, apply_update ]
```

### 3.3 修改 `UI/src/layout/MainLayout.vue`

```typescript
// 替换现有 check_update 逻辑
onMounted(async () => {
    try {
        const info = await invoke('check_update');
        if (info?.has_update) {
            const diff = await invoke('fetch_update_diff');
            ElMessageBox.confirm(
                `v${info.latest_version}（需下载 ${diff.total_size_mb.toFixed(1)} MB）`,
                '发现新版本',
                { confirmButtonText: '立即更新', cancelButtonText: '稍后' }
            ).then(async () => {
                const loading = ElLoading.service({ fullscreen: true, text: '正在下载更新...' });
                try {
                    const tmpDir = await invoke('apply_update');
                    loading.close();
                    ElMessageBox.confirm(
                        `更新文件已就绪，下次启动生效。是否立即重启？`,
                        '更新完成',
                        { confirmButtonText: '立即重启', cancelButtonText: '稍后' }
                    ).then(() => {
                        // 替换文件并重启
                        invoke('close_app');
                    });
                } catch (e) {
                    loading.close();
                    ElMessage.error('更新失败: ' + e);
                }
            });
        }
    } catch {}
});
```

### 3.4 文件替换时机

在 `lib.rs` 的 `close_app` 命令中，退出前检查 `update_temp` 目录是否存在：
```rust
// close_app 中增加：
let update_dir = ROOT_DIR.join("update_temp");
if update_dir.exists() {
    for entry in std::fs::read_dir(&update_dir).flatten() {
        let src = entry.path();
        let name = src.file_name().unwrap().to_string_lossy().to_string();
        if name == "files_to_delete.json" { continue; }
        let dst = ROOT_DIR.join(&name);
        // 被锁定的文件（如当前 exe）→ 改名 + 重启后清理
        if let Err(_) = std::fs::copy(&src, &dst) {
            std::fs::copy(&src, ROOT_DIR.join(format!("{}.new", name))).ok();
        }
    }
    // 清理清单中的文件
    let del_list = update_dir.join("files_to_delete.json");
    if let Ok(js) = std::fs::read_to_string(&del_list) {
        if let Ok(files) = serde_json::from_str::<Vec<String>>(&js) {
            for f in files {
                std::fs::remove_file(ROOT_DIR.join(&f)).ok();
            }
        }
    }
    std::fs::remove_dir_all(&update_dir).ok();
}
```

## 4. 需要新增的文件

| 文件 | 说明 |
|------|------|
| `UI/src-tauri/src/modules/update_download.rs` | `fetch_update_diff` + `apply_update` 命令 |
| `docs/incremental-update-design.md` | 本设计文档 |

## 5. 需要修改的文件

| 文件 | 变更 |
|------|------|
| `.github/workflows/release.yml` | 新增 `Generate update manifest` 步骤 |
| `UI/src-tauri/src/modules/mod.rs` | `pub mod update_download;` |
| `UI/src-tauri/src/lib.rs` | 注册命令 + `close_app` 中增加文件替换逻辑 |
| `UI/src/layout/MainLayout.vue` | 替换 update check 为完整的下载-确认-替换流程 |
| `UI/src-tauri/src/utils/api.rs` | `close_app` 增加 post-update 替换 |
| `UI/src-tauri/Cargo.toml` | 无新依赖（ureq 已就绪，sha2 已有） |

## 6. 不需要的

- 不对比 nsis/msi 安装包（增量更新不走安装包，直接替换文件）
- 不处理 Server DLL（DLL 已在安装包内，增量同样走文件替换）
- 不新增后台 Service（更新由 UI 主窗口驱动，用户触发）

## 7. 风险

- 替换 exe/dll 时文件被占用 → 写 `.new` 后缀，下次启动时替换
- manifest 与 Release 资产不同步 → manifest 在 Release 最后生成，确保一致性
- 跨大版本更新（如 0.4 → 0.5）可能需全量重装 → manifest 里加 `force_full` 标志
