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
  ; 兜底: 如果 DLL 被放到了 resources/ 子目录, 复制到安装根目录
  IfFileExists "$INSTDIR\resources\opencv_world490.dll" 0 +2
    CopyFiles /SILENT "$INSTDIR\resources\opencv_world490.dll" "$INSTDIR\"
  IfFileExists "$INSTDIR\resources\opencv_videoio_ffmpeg490_64.dll" 0 +2
    CopyFiles /SILENT "$INSTDIR\resources\opencv_videoio_ffmpeg490_64.dll" "$INSTDIR\"
  DetailPrint "FaceWinUnlock 安装完成"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "正在结束 FaceWinUnlock-Server.exe..."
  nsExec::ExecToStack 'taskkill /F /IM "FaceWinUnlock-Server.exe"'
  Sleep 1000
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  DetailPrint "FaceWinUnlock 卸载完成"
!macroend
