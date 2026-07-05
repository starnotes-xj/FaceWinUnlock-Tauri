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

  ; 运行时文件部署到安装根目录（= 主 EXE 同目录 = Windows DLL 搜索路径起点）。
  ; opencv_world4120.dll 与 FaceWinUnlock-Server.exe 改由 resources/ 子目录打包：
  ; Tauri v2 对「映射到安装根的单文件」打包不稳定，这两个文件曾整体从 NSIS 安装包
  ; 丢失（运行时报「找不到 opencv_world4120.dll」、后台人脸服务缺失）。这里安装后
  ; 复制到根，并删除 resources 副本，避免 61MB 的 DLL 占双份磁盘。
  IfFileExists "$INSTDIR\resources\opencv_world4120.dll" 0 +3
    CopyFiles /SILENT "$INSTDIR\resources\opencv_world4120.dll" "$INSTDIR\"
    Delete "$INSTDIR\resources\opencv_world4120.dll"
  IfFileExists "$INSTDIR\resources\FaceWinUnlock-Server.exe" 0 +3
    CopyFiles /SILENT "$INSTDIR\resources\FaceWinUnlock-Server.exe" "$INSTDIR\"
    Delete "$INSTDIR\resources\FaceWinUnlock-Server.exe"

  ; ── 杀软误删自愈（根治「安装后第二天 opencv_world4120.dll / FaceWinUnlock-Server.exe 丢失」）──
  ; 两个无签名二进制（OpenCV DLL + 开摄像头/注入凭据的后台服务）可能被火绒/Defender
  ; 云查杀当成可疑文件删除。resilience.ps1 -Mode Setup 会：①把两文件打成压缩备份
  ; runtime-backup.zip；②注册 FaceWinUnlockHealer 计划任务（开机/登录/每15分钟检测缺失即恢复）；
  ; ③尝试把安装目录加入 Windows Defender 排除。
  DetailPrint "正在配置运行时文件自愈与杀软排除..."
  nsExec::ExecToStack 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\nsis\resilience.ps1" -Mode Setup -InstallDir "$INSTDIR"'
  Pop $0

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
  ; 官方 Windows Passkey Provider 插件（FaceWinUnlock-Passkey.msix + .cer + 安装脚本）
  ; 已由安装包放置到 $INSTDIR。此处【不】直接 Add-AppxPackage：
  ; NSIS 以管理员 / perMachine 提权运行，而 MSIX 是“按用户”安装的——提权上下文的账户
  ; 可能不是目标桌面用户（标准用户 + 管理员凭据提权场景），会把插件装到管理员账户，
  ; 对桌面用户不可见。因此插件安装改由应用内“当前登录用户”触发
  ; （初始化页 / 设置页 → “安装正式插件”，调用 install_passkey_plugin 命令），
  ; 该路径在检测到 Contoso 测试包时还会要求显式确认迁移，避免静默删除测试凭据。
  ; “信任自签名证书”是机器级、需要管理员的步骤，正好由提权的 NSIS 完成一次：
  ; 把证书导入 LocalMachine 的 TrustedPeople + Root，否则 per-user 的 Add-AppxPackage 会报
  ; 0x800B0109（应用包签名的根证书必须是受信任的证书）。证书信任是机器级、与具体用户无关，
  ; 因此放在提权安装器里安全；真正的 MSIX 安装仍由应用内当前登录用户完成。
  IfFileExists "$INSTDIR\FaceWinUnlock-Passkey.cer" 0 done_passkey_cert
    DetailPrint "正在信任 FaceWinUnlock Passkey 证书（机器级 TrustedPeople + Root）..."
    nsExec::ExecToStack 'certutil -f -addstore TrustedPeople "$INSTDIR\FaceWinUnlock-Passkey.cer"'
    Pop $0
    nsExec::ExecToStack 'certutil -f -addstore Root "$INSTDIR\FaceWinUnlock-Passkey.cer"'
    Pop $0
  done_passkey_cert:
  DetailPrint "Passkey 插件文件与证书已就绪，请在 FaceWinUnlock 应用内完成安装与启用"

  WriteRegStr HKLM "Software\facewinunlock-tauri" "UNLOCK_SCENE" "1,2,4"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "SHOW_TILE" "1"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "CONNECT_TO_PIPE" "1"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "DLL_LOG_PATH" "$INSTDIR\logs"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "UNLOCK_GRACE_PERIOD" "0.0"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "RETRY_DELAY" "1.0"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "CREDUI_ALLOW_BROKER" "1"
  ; broker(查看密码等)场景从开始人脸识别起，超过此秒数仍未刷脸成功才回退 Windows PIN。
  ; 必须 ≥ 人脸识别耗时（开摄像头预热 ~2s + 检测匹配 ~1-2s ≈ 3-4s），否则查看密码会在
  ; 刷脸完成前就超时回退 PIN（修复 Chrome 查看密码人脸的前提）。代价：选原生通行密钥时
  ; 回退 PIN 会多等这几秒。取 6.0 兼顾两者。
  WriteRegStr HKLM "Software\facewinunlock-tauri" "CREDUI_BROKER_FALLBACK_TIMEOUT" "6.0"
  WriteRegStr HKLM "Software\facewinunlock-tauri" "PASSKEY_TAKEOVER_ENABLED" "0"

  DetailPrint "FaceWinUnlock 安装完成"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "正在结束 FaceWinUnlock-Server.exe..."
  nsExec::ExecToStack 'taskkill /F /IM "FaceWinUnlock-Server.exe"'
  Sleep 1000

  ; ── Passkey 插件卸载策略 ────────────────────────────────────────
  ; 卸载主程序 = 完整清理：同步卸载官方 Passkey MSIX，并删除插件 LocalState 中
  ; 的本地通行密钥。普通更新不走这里；更新只替换 MSIX 包体并保留密钥。
  ; ──────────────────────────────────────────────────────────────
  DetailPrint "正在卸载 FaceWinUnlock Passkey 插件..."
  IfFileExists "$INSTDIR\scripts\uninstall-passkey-plugin.ps1" 0 passkey_uninstall_inline
    ; app 卸载默认保留通行密钥（-PreserveApplicationData），便于重装后免重新注册；
    ; 彻底清除由应用内「彻底卸载」选项 (uninstall_passkey_plugin purge=true) 提供。
    nsExec::ExecToStack 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\scripts\uninstall-passkey-plugin.ps1" -CertificatePath "$INSTDIR\FaceWinUnlock-Passkey.cer" -PreserveApplicationData'
    Pop $0
    ${If} $0 == 0
      DetailPrint "FaceWinUnlock Passkey 插件已卸载。"
    ${Else}
      DetailPrint "FaceWinUnlock Passkey 插件卸载脚本返回非零状态，继续卸载主程序。"
    ${EndIf}
    Goto passkey_uninstall_done
  passkey_uninstall_inline:
    nsExec::ExecToStack 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Get-Process -Name PasskeyManager -ErrorAction SilentlyContinue | Stop-Process -Force; $cmd = Get-Command Remove-AppxPackage -ErrorAction Stop; $removeArgs = @{ ErrorAction = \"SilentlyContinue\" }; if ($cmd.Parameters.ContainsKey(\"PreserveApplicationData\")) { $removeArgs[\"PreserveApplicationData\"] = $true; Get-AppxPackage -Name FaceWinUnlock.PasskeyManager -ErrorAction SilentlyContinue | Remove-AppxPackage @removeArgs; Get-AppxPackage -Name Contoso.PasskeyManager -ErrorAction SilentlyContinue | Remove-AppxPackage @removeArgs } else { Write-Warning \"Remove-AppxPackage has no PreserveApplicationData; keeping Passkey package installed.\" }"'
    Pop $0
    ${If} $0 == 0
      DetailPrint "FaceWinUnlock Passkey 插件已卸载。"
    ${Else}
      DetailPrint "FaceWinUnlock Passkey 插件内联卸载返回非零状态，继续卸载主程序。"
    ${EndIf}
  passkey_uninstall_done:
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

  ; 1c. 应用设置键（所有值：UNLOCK_SCENE, SHOW_TILE, CONNECT_TO_PIPE, DLL_LOG_PATH,
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

  ; 1d. 各用户 HKCU 下的 facewinunlock-tauri 残留（WebView2/EBWebView 路径等）
  DeleteRegKey HKCU "Software\facewinunlock-tauri"

  ; ─── 2. 计划任务 ─────────────────────────────────────────────────
  nsExec::ExecToStack 'schtasks /Delete /TN "FaceWinUnlockServer" /F'
  Pop $0
  nsExec::ExecToStack 'schtasks /Delete /TN "FaceWinUnlockAutoStart" /F'
  Pop $0
  ; 增量更新可能残留的一次性任务
  nsExec::ExecToStack 'schtasks /Delete /TN "FaceWinUnlockNgcCrack" /F'
  Pop $0
  ; 杀软误删自愈计划任务与 Defender 排除（POSTINSTALL 由 resilience.ps1 -Mode Setup 注册）
  IfFileExists "$INSTDIR\nsis\resilience.ps1" 0 resilience_uninstall_fallback
    nsExec::ExecToStack 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\nsis\resilience.ps1" -Mode Teardown -InstallDir "$INSTDIR"'
    Pop $0
    Goto resilience_uninstall_done
  resilience_uninstall_fallback:
    nsExec::ExecToStack 'schtasks /Delete /TN "FaceWinUnlockHealer" /F'
    Pop $0
    nsExec::ExecToStack 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Remove-MpPreference -ExclusionPath \"$INSTDIR\" -ErrorAction SilentlyContinue"'
    Pop $0
  resilience_uninstall_done:

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
  RMDir /r "$INSTDIR\scripts"
  RMDir /r "$INSTDIR\nsis"
  RMDir /r "$INSTDIR\resources"
  Delete "$INSTDIR\*.*"
  RMDir "$INSTDIR"

  DetailPrint "FaceWinUnlock 卸载完成（已清理凭据提供程序/CLSID/注册表/计划任务/System32/磁贴缓存/数据目录）"
!macroend
