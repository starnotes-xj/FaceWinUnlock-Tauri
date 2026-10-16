param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [switch]$Test
)

$ErrorActionPreference = "Stop"
$probeRepoRoot = Split-Path -Parent $PSScriptRoot
$probeSource = Join-Path $probeRepoRoot "CredUIProbe"
$probeBuild = Join-Path $probeSource "build"
$probeVswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $probeVswhere)) {
    throw "Visual Studio Installer vswhere.exe was not found."
}
$probeVsPath = & $probeVswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $probeVsPath) {
    throw "Install Visual Studio C++ x64 build tools and a Windows SDK."
}
$probeCmake = Get-Command cmake -ErrorAction SilentlyContinue
if (-not $probeCmake) {
    throw "CMake was not found in PATH."
}
& $probeCmake.Source -S $probeSource -B $probeBuild -G "Visual Studio 17 2022" -A x64 `
    "-DCMAKE_GENERATOR_INSTANCE=$probeVsPath"
if ($LASTEXITCODE -ne 0) { throw "CredUIProbe CMake configure failed." }
& $probeCmake.Source --build $probeBuild --config $Configuration
if ($LASTEXITCODE -ne 0) { throw "CredUIProbe build failed." }
if ($Test) {
    $probeCtest = Join-Path (Split-Path -Parent $probeCmake.Source) "ctest.exe"
    & $probeCtest --test-dir $probeBuild -C $Configuration --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw "CredUIProbe fixture tests failed." }
}
Write-Output "Observer: $(Join-Path $probeBuild "$Configuration\CredUIProbeHost.exe")"
