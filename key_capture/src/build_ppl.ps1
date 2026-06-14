# Build PPL bypass kernel driver
$WINKIT = "C:\Program Files (x86)\Windows Kits\10"
$WINSDK = "$WINKIT\Include\10.0.26100.0"
$WINLIB = "$WINKIT\Lib\10.0.26100.0"
$MSVC   = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207"

$SRC  = "$PSScriptRoot\ppl_bypass.c"
$OBJ  = "$PSScriptRoot\ppl_bypass.obj"
$OUT  = "$PSScriptRoot\..\..\target\release\ppl_bypass.sys"

$clFlags = @(
    "/nologo", "/GS-", "/kernel",
    "/D_AMD64_", "/D_WIN64", "/DNKERNEL",
    "/DNTDDI_VERSION=NTDDI_WIN10_19H1",
    "/D_WIN32_WINNT=0x0A00",
    "/I$WINSDK\km",
    "/I$WINSDK\shared",
    "/I$WINSDK\ucrt",
    "/I$MSVC\include",
    "/c",
    "/Fo$OBJ",
    $SRC
)

$linkFlags = @(
    "/nologo", "/driver", "/subsystem:native", "/machine:x64",
    "/out:$OUT",
    $OBJ,
    "$WINLIB\km\x64\ntoskrnl.lib",
    "$WINLIB\km\x64\hal.lib",
    "$WINLIB\km\x64\wmilib.lib",
    "/MERGE:_PAGE=PAGE",
    "/MERGE:_TEXT=.text",
    "/SECTION:INIT,d",
    "/IGNORE:4104,4078,4210"
)

Write-Host "Compiling..." -ForegroundColor Cyan
$compileResult = & cl.exe $clFlags 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Compile FAILED:" -ForegroundColor Red
    Write-Host ($compileResult -join "`n")
    exit 1
}
Write-Host "Compile OK" -ForegroundColor Green

Write-Host "Linking..." -ForegroundColor Cyan
$linkResult = & link.exe $linkFlags 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Link FAILED:" -ForegroundColor Red
    Write-Host ($linkResult -join "`n")
    exit 1
}
Write-Host "Link OK" -ForegroundColor Green

Remove-Item $OBJ -ErrorAction SilentlyContinue
Write-Host "Driver: $OUT" -ForegroundColor Green
