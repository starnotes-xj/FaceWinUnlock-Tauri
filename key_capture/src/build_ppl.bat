@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" > NUL
if %ERRORLEVEL% NEQ 0 (echo vcvars64 failed & exit /b 1)

set WINSDK=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0
set WINLIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0
set SRC=%~dp0ppl_bypass.c
set OBJ=%~dp0ppl_bypass.obj
set OUT=%~dp0..\..\target\release\ppl_bypass.sys

echo Compiling kernel driver...
cl.exe /nologo /GS- /kernel /D_AMD64_ /D_WIN64 /I"%WINSDK%\km" /I"%WINSDK%\shared" /I"%WINSDK%\ucrt" /I"%WINSDK%\um" /c /Fo"%OBJ%" "%SRC%"
if %ERRORLEVEL% NEQ 0 (echo Compile FAILED & exit /b 1)
echo Compile OK

echo Linking...
link.exe /nologo /driver /subsystem:native /machine:x64 /entry:DriverEntry /out:"%OUT%" "%OBJ%" "%WINLIB%\km\x64\ntoskrnl.lib"
if %ERRORLEVEL% NEQ 0 (echo Link FAILED & exit /b 1)
echo Link OK

del "%OBJ%" 2>NUL
echo Driver: %OUT%
