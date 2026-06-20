param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64",
    [string]$CertificateThumbprint = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$projectDir = Join-Path $repoRoot "PasskeyPlugin"
$solution = Join-Path $projectDir "PasskeyManager.sln"
$manifest = Join-Path $projectDir "Package.appxmanifest"
$artifactDir = Join-Path $projectDir "AppPackages-Build"
$releaseDir = Join-Path $repoRoot "target\release"
$windowsTargetPlatformVersion = "10.0.26100.0"

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    throw "Visual Studio Installer vswhere.exe was not found."
}

$msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild `
    -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
if (-not $msbuild -or -not (Test-Path $msbuild)) {
    throw "MSBuild was not found. Install Visual Studio 2022 Build Tools."
}

$windowsKitsRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
$windowsDesktopProps = Join-Path $windowsKitsRoot "Extension SDKs\WindowsDesktop\$windowsTargetPlatformVersion\DesignTime\CommonConfiguration\Neutral\WindowsDesktop.props"
if (-not (Test-Path $windowsDesktopProps)) {
    throw "WindowsDesktop Extension SDK $windowsTargetPlatformVersion was not found. Install the Visual Studio UWP workload and Windows SDK $windowsTargetPlatformVersion."
}

$makeAppx = Join-Path $windowsKitsRoot "bin\$windowsTargetPlatformVersion\x64\makeappx.exe"
if (-not (Test-Path $makeAppx)) {
    throw "MakeAppx for Windows SDK $windowsTargetPlatformVersion was not found: $makeAppx"
}

$msbuildPlatformProperties = @(
    "/p:Configuration=$Configuration",
    "/p:Platform=$Platform",
    "/p:TargetPlatformIdentifier=Windows",
    "/p:TargetPlatformVersion=$windowsTargetPlatformVersion",
    "/p:WindowsTargetPlatformVersion=$windowsTargetPlatformVersion",
    "/p:WindowsTargetPlatformMinVersion=$windowsTargetPlatformVersion"
)

[xml]$manifestXml = Get-Content -LiteralPath $manifest -Raw
$publisher = $manifestXml.Package.Identity.Publisher

if (-not $CertificateThumbprint) {
    $certificate = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $publisher -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(30) } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if (-not $certificate) {
        $certificate = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $publisher `
            -FriendlyName "FaceWinUnlock Passkey Development" `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -KeyAlgorithm RSA `
            -KeyLength 2048 `
            -HashAlgorithm SHA256 `
            -KeyExportPolicy Exportable `
            -NotAfter (Get-Date).AddYears(2)
    }
    $CertificateThumbprint = $certificate.Thumbprint
} else {
    $certificate = Get-Item "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction Stop
    if ($certificate.Subject -ne $publisher) {
        throw "Certificate subject '$($certificate.Subject)' does not match manifest publisher '$publisher'."
    }
}

New-Item -ItemType Directory -Path $artifactDir -Force | Out-Null
New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null

$cerPath = Join-Path $releaseDir "FaceWinUnlock-Passkey.cer"
Export-Certificate -Cert $certificate -FilePath $cerPath -Force | Out-Null
Import-Certificate -FilePath $cerPath -CertStoreLocation Cert:\CurrentUser\TrustedPeople | Out-Null

Push-Location $projectDir
try {
    $restoreArgs = @(
        $solution,
        "/t:Restore",
        "/p:RestorePackagesConfig=true",
        $msbuildPlatformProperties,
        "/v:minimal"
    )
    & $msbuild @restoreArgs
    if ($LASTEXITCODE -ne 0) {
        throw "NuGet restore failed."
    }

    $buildArgs = @(
        $solution,
        "/t:Rebuild",
        $msbuildPlatformProperties,
        "/p:GenerateAppxPackageOnBuild=true",
        "/p:AppxBundle=Never",
        "/p:AppxPackageDir=$artifactDir\",
        "/p:AppxPackageSigningEnabled=true",
        "/p:PackageCertificateThumbprint=$CertificateThumbprint",
        "/p:UapAppxPackageBuildMode=SideloadOnly",
        "/p:DebugInformationFormat=OldStyle",
        "/p:RunCodeAnalysis=false",
        "/v:minimal"
    )
    & $msbuild @buildArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Passkey plugin build failed."
    }
} finally {
    Pop-Location
}

$package = Get-ChildItem -Path $artifactDir -Filter "*.msix" -File -Recurse |
    Where-Object { $_.FullName -notmatch "\\Dependencies\\" } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if (-not $package) {
    throw "MSIX output was not found under $artifactDir."
}

# ── 注入 Assets 图片（修复命令行 msbuild/makepri 不索引图片导致的部署失败）──
# 命令行 msbuild 构建下，makepri 不索引 <Image> 声明的 Assets 图片，产出的 MSIX
# 里一张图片都没有、resources.pri 也不含任何图片资源，manifest 引用的
# Assets\SplashScreen.png 等在部署时无法解析，报 0x80073CF6 / 0x80070003。
# 这里在打包后解包 → 注入全部 Assets 图片，并为 manifest 里无后缀的引用从对应
# scale 变体补出基础文件 → 重打包 → 重签名。保留 msbuild 生成的 resources.pri
# （XAML 编译产物 xbf 嵌于其中，重新生成会丢失），仅靠 manifest 直接路径引用图片。
$signtool = Join-Path $windowsKitsRoot "bin\$windowsTargetPlatformVersion\x64\signtool.exe"
if (-not (Test-Path $signtool)) {
    throw "signtool for Windows SDK $windowsTargetPlatformVersion was not found: $signtool"
}
$repackRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("passkey_repack_" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
$repackLayout = Join-Path $repackRoot "layout"
New-Item -ItemType Directory -Path $repackLayout -Force | Out-Null
try {
    & $makeAppx unpack /p $package.FullName /d $repackLayout /o
    if ($LASTEXITCODE -ne 0) { throw "makeappx unpack failed." }

    $repackAssets = Join-Path $repackLayout "Assets"
    New-Item -ItemType Directory -Path $repackAssets -Force | Out-Null
    Copy-Item (Join-Path $projectDir "Assets\*") $repackAssets -Recurse -Force -ErrorAction SilentlyContinue

    # 为打包后 manifest 中每个 Assets\xxx.png 引用确保物理文件存在；
    # 无后缀基础名（SplashScreen.png 等）从同名 scale 变体补出。
    $packedManifest = Join-Path $repackLayout "AppxManifest.xml"
    $manifestText = Get-Content -LiteralPath $packedManifest -Raw
    $imageRefs = [regex]::Matches($manifestText, 'Assets\\([A-Za-z0-9_.-]+\.png)') |
        ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
    foreach ($ref in $imageRefs) {
        $refTarget = Join-Path $repackAssets $ref
        if (Test-Path $refTarget) { continue }
        $stem = [System.IO.Path]::GetFileNameWithoutExtension($ref)
        $fallback = Get-ChildItem $repackAssets -Filter "$stem.scale-*.png" -ErrorAction SilentlyContinue |
            Sort-Object Name | Select-Object -First 1
        if ($fallback) { Copy-Item $fallback.FullName $refTarget -Force }
        else { Write-Warning "无法为 manifest 图片引用 $ref 补出基础文件" }
    }

    # 清理 unpack 残留的签名/块映射元数据，makeappx pack 会重新生成
    foreach ($meta in @("AppxBlockMap.xml", "AppxSignature.p7x", "[Content_Types].xml")) {
        $metaPath = Join-Path $repackLayout $meta
        if ([System.IO.File]::Exists($metaPath)) { [System.IO.File]::Delete($metaPath) }
    }
    $metaDir = Join-Path $repackLayout "AppxMetadata"
    if ([System.IO.Directory]::Exists($metaDir)) { [System.IO.Directory]::Delete($metaDir, $true) }

    $repackedMsix = Join-Path $repackRoot "FaceWinUnlock-Passkey.msix"
    & $makeAppx pack /d $repackLayout /p $repackedMsix /o
    if ($LASTEXITCODE -ne 0) { throw "makeappx repack failed." }
    & $signtool sign /fd SHA256 /sha1 $CertificateThumbprint $repackedMsix
    if ($LASTEXITCODE -ne 0) { throw "signtool sign failed." }

    $targetPackage = Join-Path $releaseDir "FaceWinUnlock-Passkey.msix"
    Copy-Item -LiteralPath $repackedMsix -Destination $targetPackage -Force
} finally {
    if ([System.IO.Directory]::Exists($repackRoot)) { [System.IO.Directory]::Delete($repackRoot, $true) }
}

Write-Host "Passkey plugin package: $targetPackage" -ForegroundColor Green
Write-Host "Development certificate: $cerPath" -ForegroundColor Green
