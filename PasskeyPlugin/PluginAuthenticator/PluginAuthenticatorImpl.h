#pragma once
#include <pch.h>
#include <pluginauthenticator.h>
#include <winrt/Microsoft.UI.Xaml.h>
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <vector>

static constexpr GUID facewinunlock_plugin_guid // 18d38e09-dd74-4154-a11d-30f48ffe73f8
{
    0x18d38e09, 0xdd74, 0x4154, { 0xa1, 0x1d, 0x30, 0xf4, 0x8f, 0xfe, 0x73, 0xf8 }
};
// 必须区别于微软样例(0x7fa07696)和早期复用的 Contoso 测试 CLSID(0x04acca15)，
// 否则与系统中残留的他包 WebAuthn 注册冲突（WebAuthNPluginAddAuthenticator → NTE_EXISTS）。
static_assert(facewinunlock_plugin_guid.Data1 != 0x7fa07696);
static_assert(facewinunlock_plugin_guid.Data1 != 0x04acca15);

static constexpr wchar_t facewinunlock_plugin_key_domain[] = L"facewinunlock/";

namespace winrt::PasskeyManager::implementation
{
    enum class PluginOperationType
    {
        MakeCredential = 0,
        GetAssertion = 1
    };

    struct ContosoPlugin : winrt::implements<ContosoPlugin, IPluginAuthenticator>
    {
        HRESULT __stdcall MakeCredential(__RPC__in PCWEBAUTHN_PLUGIN_OPERATION_REQUEST pPluginMakeCredentialRequest, __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept;
        HRESULT __stdcall GetAssertion(__RPC__in PCWEBAUTHN_PLUGIN_OPERATION_REQUEST pPluginGetAssertionRequest, __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept;
        HRESULT __stdcall CancelOperation(__RPC__in PCWEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST pCancelRequest);
        HRESULT __stdcall GetLockStatus(__RPC__out PLUGIN_LOCK_STATUS* lockStatus) noexcept;

        HRESULT PerformUserVerification(
            HWND hWnd,
            GUID transactionId,
            PluginOperationType operationType,
            const std::vector<BYTE>& requestBuffer,
            wil::shared_cotaskmem_string rpName,
            wil::shared_cotaskmem_string userName);

        wil::shared_event m_hPluginOpCompletedEvent;
        wil::shared_event m_hAppReadyForPluginOpEvent;
        wil::shared_event m_hPluginCancelOperationEvent;
        ContosoPlugin() = delete;
        // Contructor that takes in the event that set hPluginOpCompletedEvent
        ContosoPlugin(wil::shared_event hPluginOpCompletedEvent,
            wil::shared_event hAppReadyForPluginOpEvent,
            wil::shared_event hPluginUserCancelEvent) :
            m_hPluginOpCompletedEvent(hPluginOpCompletedEvent),
            m_hAppReadyForPluginOpEvent(hAppReadyForPluginOpEvent),
            m_hPluginCancelOperationEvent(hPluginUserCancelEvent)
        {
        }
    };

    struct ContosoPluginFactory : implements<ContosoPluginFactory, IClassFactory>
    {
        HRESULT __stdcall CreateInstance(::IUnknown* outer, GUID const& iid, void** result) noexcept;
        HRESULT __stdcall LockServer(BOOL) noexcept;
        wil::shared_event m_hPluginOpCompletedEvent;
        wil::shared_event m_hAppReadyForPluginOpEvent;
        wil::shared_event m_hPluginCancelOperationEvent;
        ContosoPluginFactory() = delete;
        ContosoPluginFactory(wil::shared_event hPluginOpCompletedEvent,
            wil::shared_event hAppReadyForPluginOpEvent,
            wil::shared_event hPluginUserCancelEvent) :
            m_hPluginOpCompletedEvent(hPluginOpCompletedEvent),
            m_hAppReadyForPluginOpEvent(hAppReadyForPluginOpEvent),
            m_hPluginCancelOperationEvent(hPluginUserCancelEvent)
        {
        }
    };
}
