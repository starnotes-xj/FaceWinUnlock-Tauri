#include <windows.h>
#include <wincred.h>
#include <array>
#include <string>

using PromptW = DWORD(WINAPI*)(PCREDUI_INFOW, DWORD, ULONG*, LPCVOID, ULONG, LPVOID*, ULONG*, BOOL*, DWORD);
using PromptA = DWORD(WINAPI*)(PCREDUI_INFOA, DWORD, ULONG*, LPCVOID, ULONG, LPVOID*, ULONG*, BOOL*, DWORD);

struct WorkerArgs { PromptW prompt; DWORD result; };
DWORD WINAPI Worker(void* value) {
    auto& args = *static_cast<WorkerArgs*>(value);
    CREDUI_INFOW info{};
    info.cbSize = sizeof(info);
    info.pszMessageText = L"worker-fixture";
    args.result = args.prompt(&info, 5, nullptr, nullptr, 0, nullptr, nullptr, nullptr, 0x200);
    return 0;
}

struct RestoreCheck { HANDLE main_thread; bool restored = false; };
DWORD WINAPI CheckRestored(void* value) {
    auto& check = *static_cast<RestoreCheck*>(value);
    if (SuspendThread(check.main_thread) == DWORD(-1)) { return 1; }
    CONTEXT context{};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    check.restored = GetThreadContext(check.main_thread, &context) &&
        context.Dr0 == 0 && context.Dr1 == 0 && context.Dr2 == 0 && context.Dr3 == 0 &&
        (context.Dr7 & 0xff) == 0;
    ResumeThread(check.main_thread);
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    const std::wstring mode = argc == 2 ? argv[1] : L"normal";
    // Exercise real system-module export discovery without calling CredUI.
    HMODULE real = LoadLibraryExW(L"credui.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!real) { return 10; }
    std::array<wchar_t, 32768> path{};
    DWORD size = GetModuleFileNameW(nullptr, path.data(), DWORD(path.size()));
    if (!size || size >= path.size()) { return 11; }
    std::wstring dll(path.data(), size);
    dll.resize(dll.find_last_of(L"\\/") + 1);
    dll += L"CredUIProbeFixture.dll";
    HMODULE fixture = LoadLibraryExW(dll.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!fixture) { return 12; }
    const auto prompt_w = reinterpret_cast<PromptW>(GetProcAddress(fixture, "ProbeFixtureW"));
    const auto prompt_a = reinterpret_cast<PromptA>(GetProcAddress(fixture, "ProbeFixtureA"));
    if (!prompt_w || !prompt_a) { return 13; }

    CREDUI_INFOW info_w{};
    info_w.cbSize = sizeof(info_w);
    info_w.hwndParent = reinterpret_cast<HWND>(0x12340000);
    info_w.pszMessageText = L"wide-fixture";
    if (prompt_w(&info_w, 101, nullptr, nullptr, 0, nullptr, nullptr, nullptr, 0x200) != ERROR_CANCELLED) { return 14; }
    CREDUI_INFOA info_a{};
    info_a.cbSize = sizeof(info_a);
    info_a.pszMessageText = "ansi-fixture";
    if (prompt_a(&info_a, 0, nullptr, nullptr, 0, nullptr, nullptr, nullptr, 0x200) != ERROR_SUCCESS) { return 15; }
    std::array<wchar_t, 1100> long_text{};
    long_text.fill(L'x');
    long_text.back() = L'\0';
    info_w.pszMessageText = long_text.data();
    if (prompt_w(&info_w, 0, nullptr, nullptr, 0, nullptr, nullptr, nullptr, 0x200) != ERROR_CANCELLED) { return 16; }
    info_w.pszMessageText = reinterpret_cast<PCWSTR>(1);
    if (prompt_w(&info_w, 0, nullptr, nullptr, 0, nullptr, nullptr, nullptr, 0x200) != ERROR_CANCELLED) { return 17; }
    if (prompt_a(nullptr, 0, nullptr, nullptr, 0, nullptr, nullptr, nullptr, 0x200) != ERROR_SUCCESS) { return 18; }
    WorkerArgs args{prompt_w, ERROR_INVALID_FUNCTION};
    HANDLE worker = CreateThread(nullptr, 0, Worker, &args, 0, nullptr);
    if (!worker) { return 19; }
    WaitForSingleObject(worker, INFINITE);
    CloseHandle(worker);
    if (args.result != ERROR_CANCELLED) { return 20; }

    if (mode == L"detach") {
        Sleep(2000);
        RestoreCheck check{OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, GetCurrentThreadId())};
        if (!check.main_thread) { return 21; }
        HANDLE checker = CreateThread(nullptr, 0, CheckRestored, &check, 0, nullptr);
        if (!checker) { CloseHandle(check.main_thread); return 22; }
        WaitForSingleObject(checker, INFINITE);
        CloseHandle(checker);
        CloseHandle(check.main_thread);
        if (!check.restored || IsDebuggerPresent()) { return 23; }
    } else if (mode == L"unload") {
        FreeLibrary(fixture);
        fixture = nullptr;
        Sleep(500);
    } else if (mode == L"crash") {
        RaiseException(0xe0123456, EXCEPTION_NONCONTINUABLE, 0, nullptr);
        return 24;
    }
    if (fixture) { FreeLibrary(fixture); }
    FreeLibrary(real);
    return 0;
}
