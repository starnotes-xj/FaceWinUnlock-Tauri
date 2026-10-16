#include <windows.h>
#include <wincred.h>

// Synthetic ABI fixture. No dialog and no credential-buffer access.
extern "C" __declspec(dllexport) __declspec(noinline) DWORD WINAPI ProbeFixtureA(
    PCREDUI_INFOA info, DWORD error, ULONG* package, LPCVOID input, ULONG input_size,
    LPVOID* output, ULONG* output_size, BOOL* save, DWORD flags) {
    if (package || input || input_size || output || output_size || save || flags != 0x200) {
        return ERROR_INVALID_PARAMETER;
    }
    // The observer must not need readable info/text to track the return.
    (void)info;
    return error == 101 ? 83 : ERROR_SUCCESS;
}

extern "C" __declspec(dllexport) __declspec(noinline) DWORD WINAPI ProbeFixtureW(
    PCREDUI_INFOW info, DWORD error, ULONG* package, LPCVOID input, ULONG input_size,
    LPVOID* output, ULONG* output_size, BOOL* save, DWORD flags) {
    if (package || input || input_size || output || output_size || save || flags != 0x200) {
        return ERROR_INVALID_PARAMETER;
    }
    if (error == 101) {
        CREDUI_INFOA nested{};
        nested.cbSize = sizeof(nested);
        nested.pszMessageText = "nested-fixture";
        if (ProbeFixtureA(&nested, error, nullptr, nullptr, 0, nullptr, nullptr, nullptr, flags) != 83) {
            return ERROR_INVALID_DATA;
        }
    }
    (void)info;
    return ERROR_CANCELLED;
}
