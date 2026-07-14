#pragma once
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <filesystem>
#include <windows.h>
#include <winrt/Microsoft.UI.Xaml.h>
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include "PluginRegistrationManager.h"
#include <CredentialListViewModel.h>
#include <Credential.h>
#include <wil/registry.h>
#include <wil/registry_helpers.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/base.h>


namespace winrt {
    using namespace winrt::Microsoft::UI::Xaml::Controls;
}

const DWORD maxWebAuthnWStringSize = 64;
constexpr wchar_t c_pluginLocalAppDataDBDir[] = L"CredentialsDB";
constexpr wchar_t c_credentialsFileName[] = L"credentials.dat";

struct PluginCredentialDetailsDeleter {
    void operator()(PWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS p) noexcept {
        if (p) {
            delete[] const_cast<BYTE*>(p->pbCredentialId);
            if (p->pwszRpId) CoTaskMemFree(const_cast<LPWSTR>(p->pwszRpId));
            if (p->pwszRpName) CoTaskMemFree(const_cast<LPWSTR>(p->pwszRpName));
            delete[] const_cast<BYTE*>(p->pbUserId);
            if (p->pwszUserName) CoTaskMemFree(const_cast<LPWSTR>(p->pwszUserName));
            if (p->pwszUserDisplayName) CoTaskMemFree(const_cast<LPWSTR>(p->pwszUserDisplayName));
            delete p;
        }
    }
};
using unique_plugin_credential_details = std::unique_ptr<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS, PluginCredentialDetailsDeleter>;

struct CredentialDetailsDeleter {
    void operator()(PWEBAUTHN_CREDENTIAL_DETAILS p) noexcept {
        if (p) {
            delete[] p->pbCredentialID;
            if (p->pUserInformation) {
                delete[] p->pUserInformation->pbId;
                delete[] reinterpret_cast<BYTE*>(const_cast<PWSTR>(p->pUserInformation->pwszName));
                delete[] reinterpret_cast<BYTE*>(const_cast<PWSTR>(p->pUserInformation->pwszDisplayName));
                delete p->pUserInformation;
            }
            if (p->pRpInformation) {
                delete[] reinterpret_cast<BYTE*>(const_cast<PWSTR>(p->pRpInformation->pwszId));
                delete[] reinterpret_cast<BYTE*>(const_cast<PWSTR>(p->pRpInformation->pwszName));
                delete p->pRpInformation;
            }
            delete p;
        }
    }
};
using unique_credential_details = std::unique_ptr<WEBAUTHN_CREDENTIAL_DETAILS, CredentialDetailsDeleter>;

enum class VaultUnlockMethod
{
    Consent = 0,
    Passkey = 1
};

namespace winrt::PasskeyManager::implementation
{
    class PluginCredentialManager
    {
    public:
        static PluginCredentialManager& getInstance()
        {
            static PluginCredentialManager instance;
            return instance;
        }

        HRESULT Initialize()
        {
            if (!m_initialized)
            {
                ReloadRegistryValues();
                ReloadCredentialManager();
                m_initialized = true;
                return S_OK;
            }
            RETURN_HR(E_FAIL);
        }

        bool IsLocalCredentialMetadataLoaded()
        {
            std::lock_guard<std::mutex> lock(m_pluginLocalCredentialsOperationMutex);
            return m_localCredentialsLoaded;
        }

        bool IsCachedCredentialsMetadataLoaded()
        {
            std::lock_guard<std::mutex> lock(m_pluginCachedCredentialsOperationMutex);
            return m_cachedCredentialsLoaded;
        }

        void ReloadRegistryValues()
        {
            std::lock_guard<std::mutex> lock(m_pluginOperationConfigMutex);
            auto opt = wil::reg::try_get_value_dword(HKEY_CURRENT_USER, c_pluginRegistryPath, c_windowsPluginSilentOperationRegKeyName);
            m_silentOperation = opt.value_or(m_silentOperation) != 0;

            opt = wil::reg::try_get_value_dword(HKEY_CURRENT_USER, c_pluginRegistryPath, c_windowsPluginVaultLockedRegKeyName);
            m_vaultLocked = opt.value_or(m_vaultLocked) != 0;

            opt = wil::reg::try_get_value_dword(HKEY_CURRENT_USER, c_pluginRegistryPath, c_windowsPluginVaultUnlockMethodRegKeyName);
            m_vaultUnlockMethod = static_cast<VaultUnlockMethod>(opt.value_or(static_cast<DWORD>(m_vaultUnlockMethod)));
        }

        HRESULT AddAllPluginCredentials();
        HRESULT AddPluginCredentialById(const std::vector<std::vector<UINT8>> &credentialIdList);
        HRESULT DeleteAllPluginCredentials();
        HRESULT DeletePluginCredentialById(const std::vector<std::vector<UINT8>> &credentialIdList, bool deleteEverywhere);
        HRESULT RefreshAutofillPluginCredentialsList();
        bool IsPluginCredentialIdAutofillSupported(DWORD cbCredentialId, PBYTE pbCredentialId) const;

        // Local credential metadata management
        bool GetCredentialStorageFilePath(std::wstring& filePath);
        bool SaveCredentialMetadataToMockDB(const WEBAUTHN_CREDENTIAL_DETAILS& newCredential);
        void GetLocalCredsByRpIdAndAllowList(PCWSTR rpId, PWEBAUTHN_CREDENTIAL_EX* ppCredentialList, DWORD pcCredentials, std::vector<const WEBAUTHN_CREDENTIAL_DETAILS *>& matchingCredentials);
        bool ResetLocalCredentialsStore();
        DWORD GetLocalCredentialCount()
        {
            std::lock_guard<std::mutex> lock(m_pluginLocalCredentialsOperationMutex);
            return static_cast<DWORD>(m_pluginLocalCredentialMetadataMap.size());
        }
        DWORD GetCachedCredentialCount()
        {
            std::lock_guard<std::mutex> lock(m_pluginCachedCredentialsOperationMutex);
            return static_cast<DWORD>(m_pluginCachedCredentialMetadataMap.size());
        }
        void ReloadCredentialManager()
        {
            LoadSavedCredentialsFromMockDatabase();
            RefreshAutofillPluginCredentialsList();
            // v0.5.10: 检测主程序写入的 PurgeRequested.flag 信号文件，若存在则
            // 调用 DeleteAllPluginCredentials（清理 Windows 平台数据库凭据索引）+
            // ResetLocalCredentialsStore（清理本地元数据 credentials.dat），
            // 实现「清理残留私钥」命令的完整闭环：KSP 私钥由主程序侧的 certutil 删除，
            // 元数据与平台数据库由本侧在下次启动时补清。
            std::wstring purgeFlagPath;
            if (GetCredentialStorageFilePath(purgeFlagPath)) {
                std::wstring flagFile = purgeFlagPath;
                // purgeFlagPath 指向 ...\CredentialsDB\credentials.dat，
                // PurgeRequested.flag 在同一目录。
                size_t lastSep = flagFile.find_last_of(L'\\');
                if (lastSep != std::wstring::npos) {
                    flagFile.replace(lastSep + 1, std::wstring::npos, L"PurgeRequested.flag");
                }
                if (std::filesystem::exists(flagFile)) {
                    DeleteAllPluginCredentials();
                    ResetLocalCredentialsStore();
                    std::filesystem::remove(flagFile);
                }
            }
        }
        bool GetCredentialStorageFolderPath(std::wstring& outPath)
        {
            Windows::Storage::ApplicationData appData = Windows::Storage::ApplicationData::Current();
            Windows::Storage::StorageFolder localFolder = appData.LocalFolder();
            std::wstring localFolderPath = localFolder.Path().c_str();
            outPath = localFolderPath + L"\\" + c_pluginLocalAppDataDBDir;
            return true;
        }

        // UI Related Functions
        std::vector< winrt::com_ptr<Credential>> GetCredentialListViewModel();

        // Plugin Operations Toggles
        HRESULT SetVaultLock(bool lock);
        bool GetVaultLock();
        HRESULT SetSilentOperation(bool silent);
        bool GetSilentOperation();
        HRESULT SetVaultUnlockMethod(VaultUnlockMethod method);
        VaultUnlockMethod GetVaultUnlockMethod();
        HRESULT UnlockCredentialVaultWithPasskey(HWND hwnd);
    private:
        PluginCredentialManager();
        ~PluginCredentialManager();
        PluginCredentialManager(const PluginCredentialManager&) = delete;
        PluginCredentialManager& operator=(const PluginCredentialManager&) = delete;
        bool m_initialized = false;

        //Local Credential Metadata Management
        bool LoadSavedCredentialsFromMockDatabase();
        bool RecreateCredentialMetadataFile();
        std::mutex m_pluginLocalCredentialsOperationMutex;
        _Guarded_by_(m_pluginLocalCredentialsOperationMutex) bool m_localCredentialsLoaded = false;
        _Guarded_by_(m_pluginLocalCredentialsOperationMutex) std::map<std::vector<UINT8>, unique_credential_details> m_pluginLocalCredentialMetadataMap;

        //Cached Credential Metadata Management
        mutable std::mutex m_pluginCachedCredentialsOperationMutex;
        _Guarded_by_(m_pluginCachedCredentialsOperationMutex) bool m_cachedCredentialsLoaded = false;
        _Guarded_by_(m_pluginCachedCredentialsOperationMutex) std::map<std::vector<UINT8>, unique_plugin_credential_details> m_pluginCachedCredentialMetadataMap;

        std::mutex m_pluginOperationConfigMutex;
        _Guarded_by_(m_pluginOperationConfigMutex) bool m_vaultLocked = true;
        _Guarded_by_(m_pluginOperationConfigMutex) VaultUnlockMethod m_vaultUnlockMethod = VaultUnlockMethod::Consent;
        _Guarded_by_(m_pluginOperationConfigMutex) bool m_silentOperation = true;
    };
}
