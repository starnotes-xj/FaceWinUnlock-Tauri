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
  ; Passkey 浏览器扩展当前仅部署解压资源。若未来同时打包 CRX + update.xml，
  ; 再启用外部扩展注册；现在跳过失效注册，避免浏览器反复读取不存在的更新源。
  IfFileExists "$INSTDIR\BrowserExt\facewinunlock-passkey.crx" 0 skip_browserext_registry
  IfFileExists "$INSTDIR\BrowserExt\update.xml" 0 skip_browserext_registry
    WriteRegStr HKLM "Software\Google\Chrome\Extensions\facewinunlock-passkey-bridge" "update_url" "file:///$INSTDIR\BrowserExt\update.xml"
    WriteRegStr HKLM "Software\Microsoft\Edge\Extensions\facewinunlock-passkey-bridge" "update_url" "file:///$INSTDIR\BrowserExt\update.xml"
    DetailPrint "已注册浏览器扩展更新源"
    Goto done_browserext_registry
  skip_browserext_registry:
    DetailPrint "未检测到打包好的 BrowserExt CRX，跳过自动注册；请在 chrome://extensions 手动加载 $INSTDIR\\BrowserExt"
  done_browserext_registry:

  WriteRegStr HKLM "Software\facewinunlock-tauri" "UNLOCK_SCENE" "1,2,4"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "SHOW_TILE" "1"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "CONNECT_TO_PIPE" "1"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "DLL_LOG_PATH" "$INSTDIR\logs"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "ANIMATION_FRAMES_PATH" "$INSTDIR\resources\animation_frames.bin"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "UNLOCK_GRACE_PERIOD" "0.0"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "RETRY_DELAY" "1.0"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "CREDUI_ALLOW_BROKER" "1"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "CREDUI_BROKER_FALLBACK_TIMEOUT" "2.0"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "PASSKEY_TAKEOVER_ENABLED" "1"

  DetailPrint "FaceWinUnlock 安装完成"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "正在结束 FaceWinUnlock-Server.exe..."
  nsExec::ExecToStack 'taskkill /F /IM "FaceWinUnlock-Server.exe"'
  Sleep 1000
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  SetRegView 64

  ; ─── 1. 先删值后删键（DeleteRegKey 会连带所有子键值一起清除，先单独删避免残留）───

  ; 1a. 凭据提供程序 CLSID COM 注册
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8a7b9c6d-4e5f-89a0-8b7c-6d5e4f3e2d1c}"
  DeleteRegKey HKCR "CLSID\{8a7b9c6d-4e5f-89a0-8b7c-6d5e4f3e2d1c}"
  DeleteRegKey HKLM "Software\Classes\CLSID\{8a7b9c6d-4e5f-89a0-8b7c-6d5e4f3e2d1c}"

  ; 1b. AppCompat 注册（RUNASADMIN）
  DeleteRegValue HKLM "Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" "$INSTDIR\${MAINBINARYNAME}.exe"

  ; 1c. 浏览器扩展注册（Chrome / Edge 外部扩展 + 策略强制安装）
  DeleteRegKey HKLM "Software\Google\Chrome\Extensions\facewinunlock-passkey-bridge"
  DeleteRegKey HKLM "Software\Microsoft\Edge\Extensions\facewinunlock-passkey-bridge"
  DeleteRegValue HKLM "Software\Policies\Google\Chrome\ExtensionInstallForcelist" "1"

  ; 1d. 应用设置键（所有值：UNLOCK_SCENE, SHOW_TILE, CONNECT_TO_PIPE, DLL_LOG_PATH,
  ;     ANIMATION_FRAMES_PATH, UNLOCK_GRACE_PERIOD, RETRY_DELAY, CREDUI_ALLOW_BROKER,
  ;     CREDUI_BROKER_FALLBACK_TIMEOUT, PASSKEY_TAKEOVER_ENABLED, PIN_ENABLED 等）
  ;     先逐个 DeleteRegValue 确保不残留，再 DeleteRegKey 清理空键
  DeleteRegValue HKLM "Software\facewinunlock-tauri" "PASSKEY_TAKEOVER_ENABLED"
  DeleteRegValue HKLM "Software\facewinunlock-tauri" "PIN_ENABLED"
  DeleteRegValue HKLM "Software\facewinunlock-tauri" "UNLOCK_SCENE"
  DeleteRegValue HKLM "Software\facewinunlock-tauri" "SHOW_TILE"
  DeleteRegValue HKLM "Software\facewinunlock-tauri" "CONNECT_TO_PIPE"
  DeleteRegValue HKLM "Software\facewinunlock-tauri" "DLL_LOG_PATH"
  DeleteRegValue HKLM "Software\facewinunlock-tauri" "ANIMATION_FRAMES_PATH"
  DeleteRegValue HKLM "Software\facewinunlock-tauri" "UNLOCK_GRACE_PERIOD"
  DeleteRegValue HKLM "Software\facewinunlock-tauri" "RETRY_DELAY"
  DeleteRegValue HKLM "Software\facewinunlock-tauri" "CREDUI_ALLOW_BROKER"
  DeleteRegValue HKLM "Software\facewinunlock-tauri" "CREDUI_BROKER_FALLBACK_TIMEOUT"
  DeleteRegValue HKLM "Software\facewinunlock-tauri" "ANIMATION_FPS"
  DeleteRegValue HKLM "Software\facewinunlock-tauri" "ANIMATION_UI_ENABLED"
  DeleteRegValue HKLM "Software\facewinunlock-tauri" "CREDUI_ALLOW_GENERIC"
  DeleteRegKey HKLM "Software\facewinunlock-tauri"

  ; 1e. 各用户 HKCU 下的 facewinunlock-tauri 残留（WebView2/EBWebView 路径等）
  DeleteRegKey HKCU "Software\facewinunlock-tauri"

  ; ─── 2. 计划任务 ─────────────────────────────────────────────────
  nsExec::ExecToStack 'schtasks /Delete /TN "FaceWinUnlockServer" /F'
  Pop $0
  nsExec::ExecToStack 'schtasks /Delete /TN "FaceWinUnlockAutoStart" /F'
  Pop $0
  ; 增量更新可能残留的一次性任务
  nsExec::ExecToStack 'schtasks /Delete /TN "FaceWinUnlockNgcCrack" /F'
  Pop $0

  ; ─── 3. System32 DLL 残留 ────────────────────────────────────────
  Delete /REBOOTOK "$SYSDIR\FaceWinUnlock-Tauri.dll"
  Delete /REBOOTOK "$SYSDIR\FaceWinUnlock-Tauri.dll.new"
  Delete /REBOOTOK "$SYSDIR\FaceWinUnlock-UIA-Helper.exe"

  ; ─── 4. 开始菜单磁贴备份（HKCU AppListBackup）────────────────────
  IfFileExists "$INSTDIR\nsis\cleanup_tiles.ps1" 0 skip_tile_cleanup
    nsExec::ExecToStack 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\nsis\cleanup_tiles.ps1"'
    Pop $0
  skip_tile_cleanup:

  ; ─── 5. 应用数据目录 ─────────────────────────────────────────────
  SetShellVarContext all
  RMDir /r "$APPDATA\facewinunlock-tauri"
  ; 程序数据目录（WebView2 缓存等）
  RMDir /r "$PROGRAMDATA\facewinunlock-tauri"
  ; 安装目录自身（NSIS 默认保留空目录，显式清理）
  RMDir /r "$INSTDIR\logs"
  RMDir /r "$INSTDIR\BrowserExt"
  RMDir /r "$INSTDIR\nsis"
  RMDir /r "$INSTDIR\resources"
  Delete "$INSTDIR\*.*"
  RMDir "$INSTDIR"

  DetailPrint "FaceWinUnlock 卸载完成（已清理凭据提供程序/CLSID/注册表/计划任务/System32/磁贴缓存/数据目录）"
!macroend
