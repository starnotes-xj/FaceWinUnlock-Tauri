#include "pch.h"
#include "MainPage.xaml.h"
#if __has_include("MainPage.g.cpp")
#include "MainPage.g.cpp"
#include "App.xaml.h"
#include <ncrypt.h>
#include "Credential.h"
#endif
#include "PluginManagement/PluginRegistrationManager.h"
#include "PluginManagement/PluginCredentialManager.h"
#include "PluginAuthenticator/PluginAuthenticatorImpl.h"
#include <future>
#include <coroutine>
#include <DispatcherQueue.h>
#include <winrt/Microsoft.ui.interop.h>
#include <winrt/Microsoft.UI.Content.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.System.h>

namespace winrt {
    using namespace winrt::Microsoft::UI::Xaml;
}

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace {

    constexpr wchar_t c_setupArgument[] = L"-FaceWinUnlockSetup";
    constexpr wchar_t c_setupRequestFileName[] = L"FaceWinUnlockSetupRequested.flag";
    constexpr wchar_t c_uiLanguageSettingKey[] = L"UILanguage";
    constexpr wchar_t c_uiLanguageZhCn[] = L"zh-CN";
    constexpr wchar_t c_uiLanguageEnUs[] = L"en-US";

    bool HasSetupArgument(winrt::hstring const& launchArgs)
    {
        std::wstring argsString{ launchArgs.c_str() };
        return argsString.find(c_setupArgument) != std::wstring::npos;
    }

    bool ConsumeRegistrySetupRequest()
    {
        auto setupRequested = wil::reg::try_get_value_dword(
            HKEY_CURRENT_USER,
            c_pluginRegistryPath,
            c_windowsPluginSetupRequestedRegKeyName);
        if (setupRequested.value_or(0) == 0)
        {
            return false;
        }

        wil::unique_hkey hKey;
        if (RegOpenKeyEx(HKEY_CURRENT_USER, c_pluginRegistryPath, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
        {
            RegDeleteValue(hKey.get(), c_windowsPluginSetupRequestedRegKeyName);
        }

        return true;
    }

    bool ConsumeFileSetupRequest()
    {
        winrt::Windows::Storage::ApplicationData appData = winrt::Windows::Storage::ApplicationData::Current();
        std::wstring requestPath{ appData.LocalFolder().Path().c_str() };
        requestPath += L"\\";
        requestPath += c_setupRequestFileName;

        DWORD attributes = GetFileAttributes(requestPath.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            return false;
        }

        DeleteFile(requestPath.c_str());
        return true;
    }

    bool ConsumeSetupRequest()
    {
        return ConsumeRegistrySetupRequest() || ConsumeFileSetupRequest();
    }

    void CALLBACK WebAuthNStatusChangeCallback(void* context)
    {
        auto mainPage = static_cast<winrt::PasskeyManager::implementation::MainPage*>(context);
        if (mainPage)
        {
            mainPage->DispatcherQueue().TryEnqueue([mainPage]()
            {
                mainPage->UpdatePluginEnableState();
            });
        }
    }

    DWORD RegisterWebAuthNStatusChangeCallback(void* context)
    {
        auto app = winrt::Microsoft::UI::Xaml::Application::Current().as<winrt::PasskeyManager::implementation::App>();

        DWORD cookie{};
        THROW_IF_FAILED(WebAuthNPluginRegisterStatusChangeCallback(
            &WebAuthNStatusChangeCallback,
            context,
            facewinunlock_plugin_guid,
            &cookie));
        return cookie;
    }

    DWORD UnregisterWebAuthNStatusChangeCallback()
    {
        auto app = winrt::Microsoft::UI::Xaml::Application::Current().as<winrt::PasskeyManager::implementation::App>();

        DWORD cookie{};
        THROW_IF_FAILED(WebAuthNPluginUnregisterStatusChangeCallback(&cookie));
        return cookie;
    }
}

namespace winrt::PasskeyManager::implementation
{
    winrt::fire_and_forget MainPage::UpdatePluginEnableState()
    {
        winrt::apartment_context ui_thread;

        co_await winrt::resume_background();
        auto hr = PluginRegistrationManager::getInstance().RefreshPluginState();
        auto pluginState = PluginRegistrationManager::getInstance().GetPluginState();
        bool vaultLocked = PluginCredentialManager::getInstance().GetVaultLock();
        bool silentOperation = PluginCredentialManager::getInstance().GetSilentOperation();
        VaultUnlockMethod vaultUnlockMethod = PluginCredentialManager::getInstance().GetVaultUnlockMethod();

        co_await ui_thread;
        VaultUnlockControl().IsChecked(vaultLocked);
        UpdateVaultUnlockControlText(vaultLocked);
        vaultLockSwitch().IsOn(vaultUnlockMethod == VaultUnlockMethod::Passkey);
        silentOperationSwitch().IsOn(silentOperation);
        if (FAILED(hr))
        {
            pluginStateRun().Text(LocalizedText(L"未注册", L"Not Registered"));
            auto resources = Application::Current().Resources();
            auto neutralBrush = resources.Lookup(winrt::box_value(L"SystemFillColorNeutralBrush")).as<winrt::Microsoft::UI::Xaml::Media::SolidColorBrush>();
            pluginStateRun().Foreground(neutralBrush);
            registerPluginButton().IsEnabled(true);
            updatePluginButton().IsEnabled(false);
            unregisterPluginButton().IsEnabled(false);
            activatePluginButton().IsEnabled(false);
        }
        else
        {
            registerPluginButton().IsEnabled(false);
            updatePluginButton().IsEnabled(true);
            unregisterPluginButton().IsEnabled(true);
            activatePluginButton().IsEnabled(pluginState != AuthenticatorState_Enabled);
            UpdatePluginStateTextBlock(pluginState);
        }
        co_return;
    }

    winrt::IAsyncAction MainPage::vaultLockSwitch_Toggled(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        auto toggleSwitch = sender.as<Microsoft::UI::Xaml::Controls::ToggleSwitch>();
        bool toggleSwitchState = toggleSwitch.IsOn();

        com_ptr<App> curApp = winrt::Microsoft::UI::Xaml::Application::Current().as<App>();
        HWND hwnd = curApp->GetNativeWindowHandle();

        auto weakThis = get_weak();
        co_await winrt::resume_background();
        auto unlockMethod = toggleSwitchState ? VaultUnlockMethod::Passkey : VaultUnlockMethod::Consent;
        auto hr = PluginCredentialManager::getInstance().SetVaultUnlockMethod(unlockMethod);

        co_await wil::resume_foreground(DispatcherQueue());
        auto self = weakThis.get();
        if (FAILED(hr))
        {
            toggleSwitch.IsOn(!toggleSwitchState);
            if (self)
            {
                self->LogFailure(self->LocalizedText(L"切换密码库解锁方式失败", L"Failed to change vault unlock control"), hr);
            }
        }
        else if (self)
        {
            self->LogSuccess(self->LocalizedText(L"密码库解锁方式已更新", L"Vault unlock method updated"));
        }

        if (unlockMethod == VaultUnlockMethod::Passkey)
        {
            weakThis = get_weak();
            co_await winrt::resume_background();
            hr = PluginRegistrationManager::getInstance().CreateVaultPasskey(hwnd);

            co_await wil::resume_foreground(DispatcherQueue());
            self = weakThis.get();
            if (SUCCEEDED(hr) || hr == NTE_EXISTS)
            {
                if (self)
                {
                    if (hr == NTE_EXISTS)
                    {
                        self->LogSuccess(self->LocalizedText(L"密码库解锁通行密钥已存在", L"Vault unlock passkey already exists"));
                    }
                    else
                    {
                        self->LogSuccess(self->LocalizedText(L"已创建密码库解锁通行密钥", L"Created passkey for vault unlock"));
                    }
                }
            }
            else
            {
                toggleSwitch.IsOn(false);
                if (self)
                {
                    if (hr == NTE_USER_CANCELLED || hr == HRESULT_FROM_WIN32(ERROR_CANCELLED))
                    {
                        self->LogWarning(self->LocalizedText(L"通行密钥注册已取消", L"Passkey registration cancelled"), hr);
                    }
                    else
                    {
                        self->LogFailure(self->LocalizedText(L"注册通行密钥失败", L"Failed to register passkey"), hr);
                    }

                    if (hr == NTE_NOT_SUPPORTED)
                    {
                        self->LogWarning(self->LocalizedText(
                            L"当前认证器可能不支持 PRF。通行密钥已创建，但 FaceWinUnlock 无法完成注册，请先删除后再重试。",
                            L"The selected authenticator likely does not support PRF. The passkey was created, but FaceWinUnlock could not register it. Delete it before retrying."));
                    }
                }
            }
        }
        co_return;
    }

    winrt::IAsyncAction MainPage::silentOperationSwitch_Toggled(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        auto toggleSwitch = sender.as<Microsoft::UI::Xaml::Controls::ToggleSwitch>();
        auto toggleSwitchState = toggleSwitch.IsOn();

        auto weakThis = get_weak();

        co_await winrt::resume_background();
        auto hr = PluginCredentialManager::getInstance().SetSilentOperation(toggleSwitchState);
        if (FAILED(hr))
        {
            co_await wil::resume_foreground(DispatcherQueue());
            if (auto self{ weakThis.get() })
            {
                self->LogFailure(self->LocalizedText(L"切换静默模式失败", L"Failed to change silent operation"), hr);
            }
        }
        co_return;
    }

    MainPage::MainPage()
    {
        m_credentialListViewModel = winrt::make<PasskeyManager::implementation::CredentialListViewModel>();
        DataContext(m_credentialListViewModel);
        m_uiLanguage = LoadPreferredLanguage();

        auto weakThis = get_weak();
        // 本地化必须等命名 XAML 元素就绪（Loaded 之后）再应用：构造期可视化树尚未建立，
        // languageSelector()/各 TextBlock() 返回空，直接访问会触发访问违例(0xC0000005)，
        // 导致管理器一启动就崩溃。LoadPreferredLanguage 只读设置、不碰 UI，可留在构造期。
        Loaded([weakThis](winrt::Windows::Foundation::IInspectable const&,
                          winrt::Microsoft::UI::Xaml::RoutedEventArgs const&) {
            if (auto self{ weakThis.get() })
            {
                self->m_uiReadyForLocalization = true;
                self->SetLanguageSelection(self->m_uiLanguage);
                self->ApplyLocalizedTexts();
            }
        });
        m_registryWatcher = wil::make_registry_watcher(
            HKEY_CURRENT_USER,
            c_pluginRegistryPath,
            true,
            [weakThis](wil::RegistryChangeKind changeKind) -> winrt::fire_and_forget {
                if (changeKind == wil::RegistryChangeKind::Modify)
                {
                    // 人脸门模式（vault 锁定）现在支持静默自动确认（人脸识别即 UV + 操作确认），
                    // 因此不再强制关闭 SilentOperation，也不再报 "Vault unlock requires UI" 警告。
                    PluginCredentialManager::getInstance().ReloadRegistryValues();
                }
                if (auto self{ weakThis.get() })
                {
                    co_await wil::resume_foreground(self->DispatcherQueue());
                    self->UpdatePluginEnableState();
                }
            });
        std::wstring mockDBfilePath;
        PluginCredentialManager::getInstance().GetCredentialStorageFolderPath(mockDBfilePath);
        THROW_IF_FAILED(m_mockCredentialsDBWatcher.create(mockDBfilePath.c_str(),
            true,
            wil::FolderChangeEvents::All,
            [weakThis](wil::FolderChangeEvent, PCWSTR) -> winrt::fire_and_forget {
                PluginCredentialManager::getInstance().ReloadRegistryValues();
                if (auto self{ weakThis.get() })
                {
                    co_await wil::resume_foreground(self->DispatcherQueue());
                    self->UpdatePluginEnableState();
                    self->UpdateCredentialList();
                }
            }));

        m_cookie = RegisterWebAuthNStatusChangeCallback(static_cast<void*>(this));
    }

    MainPage::~MainPage()
    {
        if (m_cookie.has_value())
        {
            m_cookie = UnregisterWebAuthNStatusChangeCallback();
        }
    }

    MainPage::UiLanguage MainPage::LoadPreferredLanguage() const
    {
        auto values = winrt::Windows::Storage::ApplicationData::Current().LocalSettings().Values();
        if (auto storedValue = values.TryLookup(c_uiLanguageSettingKey))
        {
            auto language = winrt::unbox_value_or<winrt::hstring>(storedValue, c_uiLanguageZhCn);
            if (language == c_uiLanguageEnUs)
            {
                return UiLanguage::English;
            }
        }
        return UiLanguage::Chinese;
    }

    void MainPage::SavePreferredLanguage() const
    {
        auto values = winrt::Windows::Storage::ApplicationData::Current().LocalSettings().Values();
        values.Insert(
            c_uiLanguageSettingKey,
            winrt::box_value(m_uiLanguage == UiLanguage::English ? c_uiLanguageEnUs : c_uiLanguageZhCn));
    }

    void MainPage::SetLanguageSelection(UiLanguage language)
    {
        if (!m_uiReadyForLocalization)
        {
            return;
        }

        m_updatingLanguageSelector = true;
        languageSelector().SelectedIndex(language == UiLanguage::English ? 1 : 0);
        m_updatingLanguageSelector = false;
    }

    winrt::hstring MainPage::LocalizedText(wchar_t const* chinese, wchar_t const* english) const
    {
        return m_uiLanguage == UiLanguage::English ? winrt::hstring{ english } : winrt::hstring{ chinese };
    }

    void MainPage::ApplyLocalizedTexts()
    {
        if (!m_uiReadyForLocalization)
        {
            return;
        }

        headerTitleTextBlock().Text(LocalizedText(L"FaceWinUnlock 通行密钥", L"FaceWinUnlock Passkey"));
        languageLabelTextBlock().Text(LocalizedText(L"语言", L"Language"));
        pluginSectionTitle().Text(LocalizedText(L"插件", L"Plugin"));
        pluginStateLabelRun().Text(LocalizedText(L"状态：", L"State: "));
        registerPluginButton().Content(winrt::box_value(LocalizedText(L"注册", L"Register")));
        updatePluginButton().Content(winrt::box_value(LocalizedText(L"更新", L"Update")));
        activatePluginButton().Content(winrt::box_value(LocalizedText(L"启用", L"Enable")));
        unregisterPluginButton().Content(winrt::box_value(LocalizedText(L"移除", L"Remove")));

        statsSectionTitle().Text(LocalizedText(L"统计", L"Stats"));
        localDbLabelRun().Text(LocalizedText(L"本地库：", L"Local DB: "));
        windowsCacheLabelRun().Text(LocalizedText(L"Windows 缓存：", L"Windows Cache: "));
        credsStatsRun1().Text(LocalizedText(L"未加载", L"Not available"));
        credsStatsRun2().Text(LocalizedText(L"未加载", L"Not available"));

        configurationSectionTitle().Text(LocalizedText(L"配置", L"Configuration"));
        UpdateVaultUnlockControlText(VaultUnlockControl().IsChecked());
        vaultLockSwitch().Header(winrt::box_value(LocalizedText(L"解锁方式", L"Unlock method")));
        vaultLockSwitch().OffContent(winrt::box_value(LocalizedText(L"确认", L"Consent")));
        vaultLockSwitch().OnContent(winrt::box_value(LocalizedText(L"通行密钥", L"Passkey")));
        silentOperationSwitch().Header(winrt::box_value(LocalizedText(L"最小化界面", L"Minimize UI")));
        silentOperationSwitch().OffContent(winrt::box_value(LocalizedText(L"显示", L"Show")));
        silentOperationSwitch().OnContent(winrt::box_value(LocalizedText(L"隐藏", L"Hide")));

        credentialsSectionTitle().Text(LocalizedText(L"凭据", L"Credentials"));
        refreshButton().Content(winrt::box_value(LocalizedText(L"刷新", L"Refresh")));
        addCredentialsButton().Content(winrt::box_value(LocalizedText(L"添加", L"Add")));
        addAllPluginCredentialsMenuItem().Text(LocalizedText(L"全部通行密钥写入缓存", L"All passkeys to cache"));
        selectedAddButton().Text(LocalizedText(L"所选通行密钥写入缓存", L"Selected passkeys to cache"));
        deleteCredentialsButton().Content(winrt::box_value(LocalizedText(L"删除", L"Delete")));
        deleteAllPluginCredentialsMenuItem().Text(LocalizedText(L"清空缓存中的全部通行密钥", L"All passkeys from cache"));
        deleteSelectedCacheButton().Text(LocalizedText(L"删除缓存中的所选通行密钥", L"Selected passkeys from cache"));
        deleteSelectedLocalButton().Text(LocalizedText(L"删除所选通行密钥", L"Delete selected passkey"));
        deleteAllLocalCredentialsMenuItem().Text(LocalizedText(L"清空本地库中的全部通行密钥", L"All passkeys from local"));
        deleteAllCredentialsMenuItem().Text(LocalizedText(L"清空全部通行密钥", L"Clear all passkeys"));

        logsSectionTitle().Text(LocalizedText(L"日志", L"Logs"));
        clearLogsButton().Content(winrt::box_value(LocalizedText(L"清空", L"Clear")));
    }

    winrt::IAsyncAction MainPage::refreshButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        UpdatePluginEnableState();
        UpdateCredentialList();
        co_return;
    }

    winrt::fire_and_forget MainPage::UpdateCredentialList()
    {
        m_credentialListViewModel.credentials().Clear();
        auto weakThis = get_weak();
        co_await winrt::resume_background();

        PluginCredentialManager& pluginCredentialManager = PluginCredentialManager::getInstance();
        pluginCredentialManager.ReloadCredentialManager();

        co_await wil::resume_foreground(DispatcherQueue());
        auto credentialViewList = pluginCredentialManager.GetCredentialListViewModel();

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        if (pluginCredentialManager.IsLocalCredentialMetadataLoaded())
        {
            std::wstring countOfLocalCreds = std::to_wstring(pluginCredentialManager.GetLocalCredentialCount())
                + std::wstring(self->LocalizedText(L" 个通行密钥在本地库", L" passkeys in Local DB").c_str());
            self->credsStatsRun1().Text(countOfLocalCreds);
        }
        else
        {
            self->credsStatsRun1().Text(self->LocalizedText(L"未加载", L"Not loaded"));
        }

        if (pluginCredentialManager.IsCachedCredentialsMetadataLoaded())
        {
            std::wstring countOfPluginCreds = std::to_wstring(pluginCredentialManager.GetCachedCredentialCount())
                + std::wstring(self->LocalizedText(L" 个通行密钥在系统缓存", L" passkeys in system cache").c_str());
            self->credsStatsRun2().Text(countOfPluginCreds);
        }
        else
        {
            self->credsStatsRun2().Text(self->LocalizedText(L"未加载", L"Not loaded"));
        }

        self->m_credentialListViewModel.credentials().Clear();
        for (auto& credListItem : credentialViewList)
        {
            self->m_credentialListViewModel.credentials().Append(*credListItem.detach());
        }
        co_return;
    }

    winrt::IAsyncAction MainPage::OnNavigatedTo(Navigation::NavigationEventArgs e)
    {
        UpdatePluginEnableState();
        UpdateCredentialList();
        auto launchArgs = winrt::unbox_value_or<winrt::hstring>(e.Parameter(), L"");
        if (!m_setupFlowStarted && (HasSetupArgument(launchArgs) || ConsumeSetupRequest()))
        {
            m_setupFlowStarted = true;
            RunFirstRunSetup();
        }
        co_return;
    }

    winrt::fire_and_forget MainPage::RunFirstRunSetup()
    {
        auto lifetime = get_strong();
        auto weakThis = get_weak();
        auto dispatcherQueue = DispatcherQueue();

        LogInProgress(LocalizedText(L"正在准备 FaceWinUnlock 通行密钥设置...", L"Preparing FaceWinUnlock Passkey setup..."));

        bool wasRegistered = false;
        HRESULT operationHr = S_OK;
        HRESULT stateHr = S_OK;
        AUTHENTICATOR_STATE pluginState = AuthenticatorState_Disabled;

        co_await winrt::resume_background();
        auto& registrationManager = PluginRegistrationManager::getInstance();
        stateHr = registrationManager.RefreshPluginState();
        wasRegistered = SUCCEEDED(stateHr);

        if (wasRegistered)
        {
            operationHr = registrationManager.UpdatePlugin();
        }
        else
        {
            operationHr = registrationManager.RegisterPlugin();
        }

        if (SUCCEEDED(operationHr))
        {
            stateHr = registrationManager.RefreshPluginState();
            pluginState = registrationManager.GetPluginState();
        }

        co_await wil::resume_foreground(dispatcherQueue);
        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdatePluginEnableState();
        self->UpdateCredentialList();

        if (FAILED(operationHr))
        {
            self->LogFailure(
                wasRegistered
                    ? self->LocalizedText(L"更新插件详情失败", L"Failed to update plugin details")
                    : self->LocalizedText(L"注册插件失败", L"Failed to register plugin"),
                operationHr);
            co_return;
        }

        self->LogSuccess(wasRegistered
            ? self->LocalizedText(L"插件详情已更新", L"Plugin details updated")
            : self->LocalizedText(L"插件已注册", L"Plugin registered"));

        if (FAILED(stateHr))
        {
            self->LogWarning(self->LocalizedText(L"设置后刷新插件状态失败", L"Plugin state refresh failed after setup"), stateHr);
            co_return;
        }

        if (pluginState == AuthenticatorState_Enabled)
        {
            self->LogSuccess(self->LocalizedText(L"插件已启用", L"Plugin is already enabled"));
            co_return;
        }

        self->LogInProgress(self->LocalizedText(
            L"正在打开 Windows 通行密钥设置，请在那里启用 FaceWinUnlock 通行密钥...",
            L"Opening Windows passkey settings. Enable FaceWinUnlock Passkey there..."));
        auto uri = Windows::Foundation::Uri(L"ms-settings:passkeys-advancedoptions");
        bool launched = co_await Windows::System::Launcher::LaunchUriAsync(uri);
        if (!launched)
        {
            self->LogWarning(self->LocalizedText(L"无法打开 Windows 通行密钥设置", L"Could not open Windows passkey settings"));
        }
    }

    winrt::IAsyncAction MainPage::unregisterPluginButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        LogInProgress(LocalizedText(L"正在移除插件...", L"Unregistering plugin..."));
        auto weakThis = get_weak();

        if (m_cookie.has_value())
        {
            m_cookie = UnregisterWebAuthNStatusChangeCallback();
        }

        co_await winrt::resume_background();
        HRESULT hr = PluginRegistrationManager::getInstance().UnregisterPlugin();

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdatePluginEnableState();
        if (FAILED(hr))
        {
            self->LogFailure(self->LocalizedText(L"移除插件失败", L"Failed to unregister plugin"), hr);
            co_return;
        }
        self->LogSuccess(self->LocalizedText(L"插件已移除", L"Plugin unregistered"));
    }

    winrt::IAsyncAction MainPage::registerPluginButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        LogInProgress(LocalizedText(L"正在注册插件...", L"Registering plugin..."));
        auto weakThis = get_weak();
        co_await winrt::resume_background();
        HRESULT hr = PluginRegistrationManager::getInstance().RegisterPlugin();

        co_await wil::resume_foreground(DispatcherQueue());
        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdatePluginEnableState();

        if (FAILED(hr))
        {
            self->LogFailure(self->LocalizedText(L"注册插件失败", L"Failed to register plugin"), hr);
            co_return;
        }
        self->LogSuccess(self->LocalizedText(L"插件已注册", L"Plugin registered"));

        m_cookie = RegisterWebAuthNStatusChangeCallback(static_cast<void*>(this));
    }

    winrt::IAsyncAction MainPage::updatePluginButton_Click(IInspectable const&, RoutedEventArgs const&)
    {
        LogInProgress(LocalizedText(L"正在更新插件...", L"Updating plugin..."));
        auto weakThis = get_weak();
        co_await winrt::resume_background();
        HRESULT hr = PluginRegistrationManager::getInstance().UpdatePlugin();

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdatePluginEnableState();

        if (FAILED(hr))
        {
            self->LogFailure(self->LocalizedText(L"更新插件失败", L"Failed to update plugin"), hr);
            co_return;
        }
        self->LogSuccess(self->LocalizedText(L"插件已更新", L"Plugin updated"));
    }

    winrt::IAsyncAction MainPage::addAllPluginCredentials_Click(IInspectable const&, RoutedEventArgs const&)
    {
        LogInProgress(LocalizedText(L"正在把全部通行密钥写入 Windows 缓存...", L"Adding all credentials to Windows..."));

        auto weakThis = get_weak();
        co_await winrt::resume_background();
        HRESULT hr = PluginCredentialManager::getInstance().AddAllPluginCredentials();

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdateCredentialList();
        if (FAILED(hr))
        {
            self->LogFailure(self->LocalizedText(L"写入系统缓存失败", L"Failed to add credentials to system cache"), hr);
            co_return;
        }
        self->LogSuccess(self->LocalizedText(L"凭据已同步", L"Credentials synced"));
        co_return;
    }

    winrt::IAsyncAction MainPage::addSelectedCredentials_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        LogInProgress(LocalizedText(L"正在把所选通行密钥写入系统缓存...", L"Adding selected passkey metadata to system cache..."));

        std::vector<std::vector<UINT8>> credentialIdList;
        auto selectedItems = credentialListView().SelectedItems();
        if (selectedItems.Size() == 0)
        {
            LogWarning(LocalizedText(L"未选择任何凭据", L"No credentials selected"), E_NOT_SET);
            co_return;
        }

        for (auto item : selectedItems)
        {
            auto credential = item.as<PasskeyManager::implementation::Credential>();
            auto reader = winrt::Windows::Storage::Streams::DataReader::FromBuffer(credential->CredentialId());
            std::vector<UINT8> credentialIdToAdd(reader.UnconsumedBufferLength());
            reader.ReadBytes(credentialIdToAdd);
            credentialIdList.push_back(credentialIdToAdd);
        }

        hstring statusText = m_uiLanguage == UiLanguage::English
            ? (L"Adding " + winrt::to_hstring(credentialIdList.size()) + L" selected credentials...")
            : (L"正在写入 " + winrt::to_hstring(credentialIdList.size()) + L" 个所选凭据...");
        UpdatePasskeyOperationStatusText(statusText);

        auto weakThis = get_weak();
        co_await winrt::resume_background();
        HRESULT hr = PluginCredentialManager::getInstance().AddPluginCredentialById(credentialIdList);

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdateCredentialList();
        if (FAILED(hr))
        {
            self->LogFailure(self->LocalizedText(L"写入系统缓存失败", L"Failed to add credentials to system cache"), hr);
            co_return;
        }
        self->LogSuccess(self->LocalizedText(L"所选凭据已写入系统缓存", L"Selected credentials are added to system cache"));
        co_return;
    }

    winrt::IAsyncAction MainPage::deleteAllPluginCredentials_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        LogInProgress(LocalizedText(L"正在删除系统缓存中的全部凭据...", L"Deleting all credentials stored on this device..."));

        auto weakThis = get_weak();
        co_await winrt::resume_background();
        HRESULT hr = PluginCredentialManager::getInstance().DeleteAllPluginCredentials();

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdateCredentialList();
        if (FAILED(hr))
        {
            self->LogFailure(self->LocalizedText(L"删除系统缓存凭据失败", L"Failed to delete credentials from system cache"), hr);
            co_return;
        }
        self->LogSuccess(self->LocalizedText(L"系统缓存中的全部凭据已删除", L"All credentials deleted from system cache"));
        co_return;
    }

    winrt::IAsyncAction MainPage::deleteSelectedPluginCredentials_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        LogInProgress(LocalizedText(L"正在删除所选凭据...", L"Deleting selected credentials..."));

        // find the list of creds with checkbox checked
        std::vector<std::vector<UINT8>> credentialIdList;
        auto selectedItems = credentialListView().SelectedItems();
        if (selectedItems.Size() == 0)
        {
            LogWarning(LocalizedText(L"未选择任何凭据", L"No credentials selected"), E_NOT_SET);
            co_return;
        }

        for (auto item : selectedItems)
        {
            auto credential = item.as<PasskeyManager::implementation::Credential>();
            auto reader = winrt::Windows::Storage::Streams::DataReader::FromBuffer(credential->CredentialId());
            std::vector<UINT8> credentialIdToDelete(reader.UnconsumedBufferLength());
            reader.ReadBytes(credentialIdToDelete);
            credentialIdList.push_back(credentialIdToDelete);
        }

        // update the status block with count of selected creds
        hstring statusText = m_uiLanguage == UiLanguage::English
            ? (L"Deleting " + winrt::to_hstring(credentialIdList.size()) + L" selected credentials...")
            : (L"正在删除 " + winrt::to_hstring(credentialIdList.size()) + L" 个所选凭据...");
        UpdatePasskeyOperationStatusText(statusText);

        auto weakThis = get_weak();
        co_await winrt::resume_background();
        HRESULT hr = PluginCredentialManager::getInstance().DeletePluginCredentialById(credentialIdList, false);

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdateCredentialList();
        if (FAILED(hr))
        {
            self->LogFailure(self->LocalizedText(L"删除系统缓存凭据失败", L"Failed to delete credentials from system cache"), hr);
            co_return;
        }
        self->LogSuccess(self->LocalizedText(L"已删除系统缓存中的所选凭据", L"Selected credentials deleted from system cache"));
        co_return;
    }

    winrt::IAsyncAction MainPage::deleteSelectedPluginCredentialsEverywhere_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        LogInProgress(LocalizedText(L"正在删除全部位置中的所选凭据...", L"Deleting selected credentials everywhere..."));

        // find the list of creds with checkbox checked
        std::vector<std::vector<UINT8>> credentialIdList;
        auto selectedItems = credentialListView().SelectedItems();
        if (selectedItems.Size() == 0)
        {
            LogWarning(LocalizedText(L"未选择任何凭据", L"No credentials selected"), E_NOT_SET);
            co_return;
        }

        for (auto item : selectedItems)
        {
            auto credential = item.as<PasskeyManager::implementation::Credential>();
            auto reader = winrt::Windows::Storage::Streams::DataReader::FromBuffer(credential->CredentialId());
            std::vector<UINT8> credentialIdToDelete(reader.UnconsumedBufferLength());
            reader.ReadBytes(credentialIdToDelete);
            credentialIdList.push_back(credentialIdToDelete);
        }

        // update the status block with count of selected creds
        hstring statusText = m_uiLanguage == UiLanguage::English
            ? (winrt::to_hstring(credentialIdList.size()) + L" credentials selected...")
            : (L"已选择 " + winrt::to_hstring(credentialIdList.size()) + L" 个凭据...");
        UpdatePasskeyOperationStatusText(statusText);

        auto weakThis = get_weak();
        co_await winrt::resume_background();
        HRESULT hr = PluginCredentialManager::getInstance().DeletePluginCredentialById(credentialIdList, true);

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdateCredentialList();
        if (FAILED(hr))
        {
            self->LogFailure(self->LocalizedText(L"删除凭据失败", L"Failed to delete credentials"), hr);
            co_return;
        }
        self->LogSuccess(self->LocalizedText(L"已删除全部位置中的所选凭据", L"Selected credentials deleted everywhere"));
        co_return;
    }

    winrt::IAsyncAction MainPage::clearLogsButton_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        textContent().Inlines().Clear();
        co_return;
    }

    winrt::IAsyncAction MainPage::deleteAllLocalCredentials_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        LogInProgress(LocalizedText(L"正在删除本地库中的全部凭据...", L"Deleting all local credentials..."));

        auto weakThis = get_weak();
        co_await winrt::resume_background();

        bool resetResult = PluginCredentialManager::getInstance().ResetLocalCredentialsStore();

        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdateCredentialList();
        if (resetResult)
        {
            self->LogFailure(self->LocalizedText(L"删除本地库全部凭据失败", L"Failed to delete all local credentials"), E_FAIL);
            co_return;
        }
        self->LogSuccess(self->LocalizedText(L"本地库中的全部凭据已删除", L"All local credentials deleted"));
        co_return;
    }

    winrt::IAsyncAction MainPage::deleteAllCredentials_Click(IInspectable const&, Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        LogInProgress(LocalizedText(L"正在删除全部位置中的所有凭据...", L"Deleting all credentials stored on this device and cache..."));
        auto weakThis = get_weak();
        co_await winrt::resume_background();
        auto& credManager = PluginCredentialManager::getInstance();
        HRESULT hr = credManager.DeleteAllPluginCredentials();
        bool resetResult = credManager.ResetLocalCredentialsStore();
        co_await wil::resume_foreground(DispatcherQueue());

        auto self = weakThis.get();
        if (!self)
        {
            co_return;
        }

        self->UpdateCredentialList();
        if (FAILED(hr) || !resetResult)
        {
            self->LogFailure(self->LocalizedText(L"删除全部凭据失败", L"Failed to delete all credentials"), hr);
            co_return;
        }
        self->LogSuccess(self->LocalizedText(L"全部凭据已删除", L"All credentials deleted"));
    }

    void MainPage::UpdatePluginStateTextBlock(AUTHENTICATOR_STATE state)
    {
        auto resources = Application::Current().Resources();
        auto successBrush = resources.Lookup(winrt::box_value(L"SystemFillColorSuccessBrush")).as<winrt::Microsoft::UI::Xaml::Media::SolidColorBrush>();
        auto criticalBrush = resources.Lookup(winrt::box_value(L"SystemFillColorCriticalBrush")).as<winrt::Microsoft::UI::Xaml::Media::SolidColorBrush>();
        auto cautionBrush = resources.Lookup(winrt::box_value(L"SystemFillColorCautionBrush")).as<winrt::Microsoft::UI::Xaml::Media::SolidColorBrush>();

        switch (state)
        {
        case AuthenticatorState_Enabled:
            pluginStateRun().Text(LocalizedText(L"已启用", L"Enabled"));
            pluginStateRun().Foreground(successBrush);
            break;
        case AuthenticatorState_Disabled:
            pluginStateRun().Text(LocalizedText(L"未启用", L"Disabled"));
            pluginStateRun().Foreground(criticalBrush);
            break;
        default:
            pluginStateRun().Text(LocalizedText(L"未知", L"Unknown"));
            pluginStateRun().Foreground(cautionBrush);
            break;
        }
    }

    winrt::IAsyncAction MainPage::SelectionChanged(IInspectable const& sender, Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const&)
    {
        Microsoft::UI::Xaml::Controls::ListView listView = sender.as<Microsoft::UI::Xaml::Controls::ListView>();
        auto selected = listView.SelectedItems().Size() > 0;
        selectedAddButton().IsEnabled(selected);
        deleteSelectedCacheButton().IsEnabled(selected);
        deleteSelectedLocalButton().IsEnabled(selected);
        co_return;
    }

    winrt::IAsyncAction MainPage::activatePluginButton_Click(IInspectable const& sender, Microsoft::UI::Xaml::RoutedEventArgs const& e)
    {
        // URI ms-settings:passkeys-advancedoptions to navigate to the page on Settings app where the users can enable the plugin
        auto uri = Windows::Foundation::Uri(L"ms-settings:passkeys-advancedoptions");
        co_await Windows::System::Launcher::LaunchUriAsync(uri);
        co_return;
    }

    void MainPage::UpdateVaultUnlockControlText(bool isLocked)
    {
        if (isLocked)
        {
            VaultUnlockControl().Content(box_value(LocalizedText(L"密码库已锁定", L"Vault locked")));
        }
        else
        {
            VaultUnlockControl().Content(box_value(LocalizedText(L"密码库已解锁", L"Vault unlocked")));
        }
    }

    winrt::IAsyncAction MainPage::languageSelector_SelectionChanged(IInspectable const&, winrt::Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const&)
    {
        if (m_updatingLanguageSelector || !m_uiReadyForLocalization)
        {
            co_return;
        }

        m_uiLanguage = languageSelector().SelectedIndex() == 1 ? UiLanguage::English : UiLanguage::Chinese;
        SavePreferredLanguage();
        ApplyLocalizedTexts();
        UpdatePluginEnableState();
        UpdateCredentialList();
        co_return;
    }

    winrt::IAsyncAction MainPage::VaultUnlockControl_IsCheckedChanged(winrt::Microsoft::UI::Xaml::Controls::ToggleSplitButton const& sender, winrt::Microsoft::UI::Xaml::Controls::ToggleSplitButtonIsCheckedChangedEventArgs const& args)
    {
        // Capture the value we need before switching context
        bool toggleSplitState = sender.IsChecked();

        auto hr = PluginCredentialManager::getInstance().SetVaultLock(toggleSplitState);

        if (FAILED(hr))
        {
            LogFailure(LocalizedText(L"切换密码库锁定状态失败", L"Failed to change simulated vault unlock"), hr);
        }

        UpdateVaultUnlockControlText(toggleSplitState);

        co_return;
    }

}
