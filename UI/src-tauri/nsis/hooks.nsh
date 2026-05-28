# FaceWinUnlock NSIS 安装/卸载钩子

!macro NSIS_HOOK_PREINSTALL
  DetailPrint "正在检查 FaceWinUnlock-Server.exe 进程..."
  nsExec::ExecToStack 'taskkill /F /IM "FaceWinUnlock-Server.exe"'
  Pop $0
  ${If} $0 == 0
    DetailPrint "FaceWinUnlock-Server.exe 进程已成功结束"
  ${ElseIf} $0 == 128
    DetailPrint "未找到 FaceWinUnlock-Server.exe 进程"
  ${EndIf}
  Sleep 1000
!macroend

!macro NSIS_HOOK_POSTINSTALL
  CreateDirectory "$INSTDIR\logs"

  ; 兜底: 如果 DLL 被放到了 resources/ 子目录, 复制到安装根目录
  IfFileExists "$INSTDIR\resources\opencv_world4120.dll" 0 +2
    CopyFiles /SILENT "$INSTDIR\resources\opencv_world4120.dll" "$INSTDIR\"
  IfFileExists "$INSTDIR\resources\opencv_videoio_ffmpeg4120_64.dll" 0 +2
    CopyFiles /SILENT "$INSTDIR\resources\opencv_videoio_ffmpeg4120_64.dll" "$INSTDIR\"

  ; 同步部署 Credential Provider DLL。登录/锁屏磁贴加载的是 System32 中注册的 DLL，
  ; 仅覆盖安装目录资源文件不会更新锁屏界面的文字和逻辑。
  SetRegView 64
  IfFileExists "$INSTDIR\resources\FaceWinUnlock-Tauri.dll" 0 done_cp_dll
    DetailPrint "正在更新 Credential Provider DLL..."
    ClearErrors
    CopyFiles /SILENT "$INSTDIR\resources\FaceWinUnlock-Tauri.dll" "$SYSDIR\FaceWinUnlock-Tauri.dll"
    ${If} ${Errors}
      DetailPrint "Credential Provider DLL 正在使用，安排重启后更新..."
      CopyFiles /SILENT "$INSTDIR\resources\FaceWinUnlock-Tauri.dll" "$SYSDIR\FaceWinUnlock-Tauri.dll.new"
      Delete /REBOOTOK "$SYSDIR\FaceWinUnlock-Tauri.dll"
      Rename /REBOOTOK "$SYSDIR\FaceWinUnlock-Tauri.dll.new" "$SYSDIR\FaceWinUnlock-Tauri.dll"
    ${EndIf}
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8a7b9c6d-4e5f-89a0-8b7c-6d5e4f3e2d1c}" "" "FaceWinUnlock-Tauri"
    WriteRegStr HKCR "CLSID\{8a7b9c6d-4e5f-89a0-8b7c-6d5e4f3e2d1c}" "" "FaceWinUnlock-Tauri"
    WriteRegStr HKCR "CLSID\{8a7b9c6d-4e5f-89a0-8b7c-6d5e4f3e2d1c}\InprocServer32" "" "$SYSDIR\FaceWinUnlock-Tauri.dll"
    WriteRegStr HKCR "CLSID\{8a7b9c6d-4e5f-89a0-8b7c-6d5e4f3e2d1c}\InprocServer32" "ThreadingModel" "Apartment"
  done_cp_dll:

  ; 让安装后的主程序默认按管理员权限启动。主 EXE 也会嵌入 requireAdministrator manifest，
  ; 这里再写 AppCompat RUNASADMIN 作为快捷方式/外壳启动兜底。
  WriteRegStr HKLM "Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" "$INSTDIR\${MAINBINARYNAME}.exe" "RUNASADMIN"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "DLL_LOG_PATH" "$INSTDIR\logs"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "ANIMATION_FRAMES_PATH" "$INSTDIR\resources\animation_frames.bin"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "UNLOCK_GRACE_PERIOD" "0.0"

  DetailPrint "FaceWinUnlock 安装完成"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "正在结束 FaceWinUnlock-Server.exe..."
  nsExec::ExecToStack 'taskkill /F /IM "FaceWinUnlock-Server.exe"'
  Sleep 1000
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  DeleteRegValue HKLM "Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" "$INSTDIR\${MAINBINARYNAME}.exe"
  DetailPrint "FaceWinUnlock 卸载完成"
!macroend
