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

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    throw "Visual Studio Installer vswhere.exe was not found."
}

$msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild `
    -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
if (-not $msbuild -or -not (Test-Path $msbuild)) {
    throw "MSBuild was not found. Install Visual Studio 2022 Build Tools."
}

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
    & $msbuild $solution /t:Restore /p:RestorePackagesConfig=true /v:minimal
    if ($LASTEXITCODE -ne 0) {
        throw "NuGet restore failed."
    }

    & $msbuild $solution `
        /t:Rebuild `
        "/p:Configuration=$Configuration" `
        "/p:Platform=$Platform" `
        /p:GenerateAppxPackageOnBuild=true `
        /p:AppxBundle=Never `
        "/p:AppxPackageDir=$artifactDir\" `
        /p:AppxPackageSigningEnabled=true `
        "/p:PackageCertificateThumbprint=$CertificateThumbprint" `
        /p:UapAppxPackageBuildMode=SideloadOnly `
        /p:DebugInformationFormat=OldStyle `
        /p:RunCodeAnalysis=false `
        /v:minimal
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

$targetPackage = Join-Path $releaseDir "FaceWinUnlock-Passkey.msix"
Copy-Item -LiteralPath $package.FullName -Destination $targetPackage -Force

Write-Host "Passkey plugin package: $targetPackage" -ForegroundColor Green
Write-Host "Development certificate: $cerPath" -ForegroundColor Green
