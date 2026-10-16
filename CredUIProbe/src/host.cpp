#include <windows.h>
#include <wincred.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cwctype>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <vector>

static_assert(sizeof(void*) == 8, "Only native x64 is supported.");
static_assert(sizeof(CREDUI_INFOW) == 40 && offsetof(CREDUI_INFOW, hwndParent) == 8 &&
    offsetof(CREDUI_INFOW, pszMessageText) == 16, "Unexpected CredUI ABI.");
static_assert(sizeof(CREDUI_INFOA) == sizeof(CREDUI_INFOW), "Unexpected ANSI ABI.");

namespace {
constexpr size_t kTextLimit = 1024;
constexpr DWORD kPollMs = 100;
constexpr DWORD kCleanupMs = 5000;
constexpr DWORD kResumeFlag = 0x10000;
constexpr DWORD kTrapFlag = 0x100;

struct Handle {
    HANDLE value = nullptr;
    Handle() = default;
    explicit Handle(HANDLE handle) : value(handle) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value(other.value) { other.value = nullptr; }
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) { reset(); value = other.value; other.value = nullptr; }
        return *this;
    }
    ~Handle() { reset(); }
    void reset() {
        if (value && value != INVALID_HANDLE_VALUE) { CloseHandle(value); }
        value = nullptr;
    }
};

std::wstring Lower(std::wstring text) {
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) { return wchar_t(towlower(ch)); });
    return text;
}

std::wstring FinalPath(HANDLE file) {
    std::array<wchar_t, 32768> buffer{};
    const DWORD length = GetFinalPathNameByHandleW(file, buffer.data(), DWORD(buffer.size()), FILE_NAME_NORMALIZED);
    if (!length || length >= buffer.size()) { return {}; }
    return Lower(std::wstring(buffer.data(), length));
}

std::wstring ExistingPath(const std::wstring& path) {
    Handle file(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    return file.value == INVALID_HANDLE_VALUE ? std::wstring{} : FinalPath(file.value);
}

std::wstring OwnDirectory() {
    std::array<wchar_t, 32768> buffer{};
    DWORD length = GetModuleFileNameW(nullptr, buffer.data(), DWORD(buffer.size()));
    if (!length || length >= buffer.size()) { return {}; }
    std::wstring path(buffer.data(), length);
    const auto slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring{} : path.substr(0, slash + 1);
}

std::wstring QuoteArgument(const std::wstring& argument) {
    std::wstring quoted = L"\"";
    size_t slashes = 0;
    for (wchar_t ch : argument) {
        if (ch == L'\\') { ++slashes; continue; }
        quoted.append(ch == L'\"' ? slashes * 2 + 1 : slashes, L'\\');
        slashes = 0;
        quoted += ch;
    }
    quoted.append(slashes * 2, L'\\');
    quoted += L'\"';
    return quoted;
}

template<class T>
bool ReadValue(HANDLE process, uint64_t address, T& value) {
    SIZE_T read = 0;
    return address && ReadProcessMemory(process, reinterpret_cast<const void*>(address), &value, sizeof(T), &read) &&
        read == sizeof(T);
}

struct TextInfo { bool readable = false; bool truncated = false; size_t units = 0; };
template<class Character>
TextInfo ReadDisplayText(HANDLE process, uint64_t address) {
    TextInfo result;
    if (!address) { return result; }
    std::array<Character, kTextLimit> volatile_copy{};
    for (size_t i = 0; i < volatile_copy.size(); ++i) {
        if (!ReadValue(process, address + i * sizeof(Character), volatile_copy[i])) { break; }
        if (volatile_copy[i] == 0) { result.readable = true; break; }
        ++result.units;
    }
    result.truncated = result.units == kTextLimit;
    // Never serialize the caller's text or retain it in process state.
    SecureZeroMemory(volatile_copy.data(), sizeof(volatile_copy));
    return result;
}

struct Exports { uint64_t wide = 0; uint64_t ansi = 0; };
std::optional<Exports> ReadExports(HANDLE process, uint64_t base, const char* wide_name, const char* ansi_name) {
    IMAGE_DOS_HEADER dos{};
    if (!ReadValue(process, base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000) { return {}; }
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadValue(process, base + uint32_t(dos.e_lfanew), nt) || nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64) ||
        nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) { return {}; }
    const uint32_t image_size = nt.OptionalHeader.SizeOfImage;
    const auto in_image = [image_size](uint32_t rva, uint64_t bytes) {
        return rva && rva < image_size && bytes <= uint64_t(image_size) - rva;
    };
    const auto directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!in_image(directory.VirtualAddress, directory.Size) || directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) { return {}; }
    IMAGE_EXPORT_DIRECTORY table{};
    if (!ReadValue(process, base + directory.VirtualAddress, table) || table.NumberOfNames > 65536 ||
        table.NumberOfFunctions > 65536 || !in_image(table.AddressOfNames, uint64_t(table.NumberOfNames) * 4) ||
        !in_image(table.AddressOfNameOrdinals, uint64_t(table.NumberOfNames) * 2) ||
        !in_image(table.AddressOfFunctions, uint64_t(table.NumberOfFunctions) * 4)) { return {}; }
    Exports exports;
    for (uint32_t i = 0; i < table.NumberOfNames; ++i) {
        uint32_t name_rva = 0;
        uint16_t ordinal = 0;
        if (!ReadValue(process, base + table.AddressOfNames + i * 4, name_rva) ||
            !ReadValue(process, base + table.AddressOfNameOrdinals + i * 2, ordinal) || ordinal >= table.NumberOfFunctions) { return {}; }
        std::array<char, 128> name{};
        bool terminated = false;
        for (size_t j = 0; j < name.size(); ++j) {
            if (!in_image(name_rva, j + 1) || !ReadValue(process, base + name_rva + j, name[j])) { return {}; }
            if (!name[j]) { terminated = true; break; }
        }
        if (!terminated) { return {}; }
        const std::string symbol(name.data());
        if (symbol != wide_name && symbol != ansi_name) { continue; }
        uint32_t function_rva = 0;
        if (!ReadValue(process, base + table.AddressOfFunctions + ordinal * 4, function_rva) || !in_image(function_rva, 1)) { return {}; }
        // A forwarder is text within the export directory, not an executable entry.
        if (function_rva >= directory.VirtualAddress &&
            uint64_t(function_rva) < uint64_t(directory.VirtualAddress) + directory.Size) { return {}; }
        MEMORY_BASIC_INFORMATION memory{};
        if (!VirtualQueryEx(process, reinterpret_cast<void*>(base + function_rva), &memory, sizeof(memory)) ||
            memory.State != MEM_COMMIT || !(memory.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ||
            (memory.Protect & PAGE_GUARD)) { return {}; }
        (symbol == wide_name ? exports.wide : exports.ansi) = base + function_rva;
    }
    return exports.wide && exports.ansi && exports.wide != exports.ansi ? std::optional<Exports>(exports) : std::nullopt;
}

struct Options {
    bool fixture = false;
    std::wstring fixture_mode;
    DWORD duration = 30000;
    std::wstring executable;
    std::wstring command_line;
};

std::optional<Options> ParseOptions(int argc, wchar_t** argv) {
    Options options;
    if (argc == 2) {
        const std::wstring flag(argv[1]);
        if (flag == L"--self-test") { options.fixture_mode = L"normal"; }
        else if (flag == L"--self-test-detach") { options.fixture_mode = L"detach"; }
        else if (flag == L"--self-test-unload") { options.fixture_mode = L"unload"; }
        else if (flag == L"--self-test-crash") { options.fixture_mode = L"crash"; }
        else { return {}; }
        options.fixture = true;
        options.duration = options.fixture_mode == L"detach" ? 750 : 6000;
        options.executable = OwnDirectory() + L"CredUIProbeFixtureHost.exe";
        options.command_line = QuoteArgument(options.executable) + L" " + QuoteArgument(options.fixture_mode);
        return options;
    }
    return {};
}

struct Call { uint64_t id; uint64_t entry_stack; uint64_t return_address; char api; };
struct Thread {
    Handle handle;
    CONTEXT original{};
    bool configured = false;
    bool suspended = false;
    std::optional<Call> call;
};

class Observer {
public:
    explicit Observer(Options options) : options_(std::move(options)) {}
    int Run();
private:
    bool AddThread(DWORD tid, HANDLE event_handle);
    bool Configure(Thread& thread, bool capture);
    bool Capture(DWORD tid, Thread& thread, CONTEXT& context, char api);
    bool OnSingleStep(DWORD tid, DWORD& continuation);
    void OnModule(const LOAD_DLL_DEBUG_INFO& info);
    bool RestoreAndDetach(DEBUG_EVENT& event, DWORD continuation, bool& event_outstanding);
    bool DrainForDetach(DEBUG_EVENT& event, bool& event_outstanding);
    void FatalCleanup(DEBUG_EVENT* event, DWORD continuation);
    void Metadata(const char* event, const char* reason = nullptr, DWORD error = 0) const;
    bool Launch();
    Options options_;
    Handle process_;
    DWORD pid_ = 0;
    DWORD session_ = 0;
    std::map<DWORD, Thread> threads_;
    Exports exports_{};
    uint64_t module_base_ = 0;
    std::wstring system_credui_;
    std::wstring fixture_dll_;
    bool discovered_ = false;
    bool initial_breakpoint_ = false;
    bool stop_requested_ = false;
    bool module_unloaded_ = false;
    bool crashed_ = false;
    bool detached_ = false;
    bool fatal_ = false;
    bool fixture_layout_ = true;
    uint64_t next_call_ = 1;
    size_t begins_ = 0;
    size_t ends_ = 0;
    size_t nested_ = 0;
    size_t truncated_ = 0;
    size_t unreadable_ = 0;
    DWORD exit_code_ = STILL_ACTIVE;
    const char* stop_reason_ = "duration_elapsed";
};

void Observer::Metadata(const char* event, const char* reason, DWORD error) const {
    std::cout << "{\"version\":1,\"event\":\"" << event << "\",\"fixture\":" << (options_.fixture ? "true" : "false")
        << ",\"pid\":" << pid_ << ",\"session\":" << session_;
    if (reason) { std::cout << ",\"reason\":\"" << reason << '"'; }
    if (error) { std::cout << ",\"win32_error\":" << error; }
    std::cout << "}\n" << std::flush;
}

bool Observer::Launch() {
    std::array<wchar_t, MAX_PATH> directory{};
    DWORD length = GetSystemDirectoryW(directory.data(), DWORD(directory.size()));
    if (!length || length >= directory.size()) { return false; }
    system_credui_ = ExistingPath(std::wstring(directory.data(), length) + L"\\credui.dll");
    fixture_dll_ = ExistingPath(OwnDirectory() + L"CredUIProbeFixture.dll");
    if (system_credui_.empty() || (options_.fixture && fixture_dll_.empty())) { return false; }

    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    Handle null_io(CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (null_io.value == INVALID_HANDLE_VALUE) { return false; }
    SIZE_T attribute_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
    std::vector<BYTE> attributes(attribute_size);
    auto* list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    if (!InitializeProcThreadAttributeList(list, 1, 0, &attribute_size)) { return false; }
    const HANDLE inherited = null_io.value;
    bool updated = UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        const_cast<HANDLE*>(&inherited), sizeof(inherited), nullptr, nullptr) != FALSE;
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = null_io.value;
    startup.StartupInfo.hStdOutput = null_io.value;
    startup.StartupInfo.hStdError = null_io.value;
    startup.lpAttributeList = list;
    PROCESS_INFORMATION info{};
    bool created = updated && CreateProcessW(options_.executable.c_str(), options_.command_line.data(), nullptr, nullptr, TRUE,
        DEBUG_ONLY_THIS_PROCESS | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
        nullptr, nullptr, &startup.StartupInfo, &info) != FALSE;
    const DWORD creation_error = GetLastError();
    DeleteProcThreadAttributeList(list);
    if (!created) { SetLastError(creation_error); return false; }
    process_ = Handle(info.hProcess);
    pid_ = info.dwProcessId;
    CloseHandle(info.hThread);
    ProcessIdToSessionId(pid_, &session_);
    // Do not let ordinary observer exit kill a dedicated target.
    if (!DebugSetProcessKillOnExit(FALSE)) { return false; }
    return true;
}

bool Observer::AddThread(DWORD tid, HANDLE event_handle) {
    HANDLE duplicate = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), event_handle, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        return false;
    }
    Thread thread;
    thread.handle = Handle(duplicate);
    thread.original.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;
    if (!GetThreadContext(thread.handle.value, &thread.original) || (thread.original.Dr7 & 0xff) ||
        (thread.original.EFlags & kTrapFlag)) { return false; }
    // Keep our own handle; the system owns debug-event thread handles.
    auto [it, inserted] = threads_.emplace(tid, std::move(thread));
    return inserted && (!exports_.wide || Configure(it->second, true));
}

bool Observer::Configure(Thread& thread, bool capture) {
    CONTEXT context{};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread.handle.value, &context)) { return false; }
    if (capture && !thread.configured && (context.Dr7 & 0xff)) { return false; }
    context.Dr0 = exports_.wide;
    context.Dr1 = exports_.ansi;
    context.Dr2 = thread.call ? thread.call->return_address : 0;
    context.Dr3 = thread.original.Dr3;
    context.Dr6 = 0;
    // Local execute breakpoints only. Leave disabled slot 3 and reserved bits as saved.
    context.Dr7 = (thread.original.Dr7 & ~uint64_t(0x0fff00ff)) | (exports_.wide ? 0x5 : 0) | (thread.call ? 0x10 : 0);
    if (!SetThreadContext(thread.handle.value, &context)) { return false; }
    thread.configured = true;
    return true;
}

void Observer::OnModule(const LOAD_DLL_DEBUG_INFO& info) {
    Handle file(info.hFile);
    if (!file.value || file.value == INVALID_HANDLE_VALUE) { return; }
    const std::wstring path = FinalPath(file.value);
    const bool system = !path.empty() && path == system_credui_;
    const bool fixture = options_.fixture && path == fixture_dll_;
    if (!system && !fixture) { return; }
    const uint64_t base = reinterpret_cast<uint64_t>(info.lpBaseOfDll);
    const auto symbols = ReadExports(process_.value, base, fixture ? "ProbeFixtureW" : "CredUIPromptForWindowsCredentialsW",
        fixture ? "ProbeFixtureA" : "CredUIPromptForWindowsCredentialsA");
    if (!symbols) { Metadata("uncovered", "export_or_architecture_unsupported"); fatal_ = true; return; }
    if (system) { discovered_ = true; Metadata("system_exports", "native_x64_no_forwarders"); }
    if (options_.fixture && !fixture) { return; }
    if (module_base_) { Metadata("uncovered", "multiple_probe_modules"); fatal_ = true; return; }
    exports_ = *symbols;
    module_base_ = base;
    for (auto& [tid, thread] : threads_) {
        (void)tid;
        if (!Configure(thread, true)) { Metadata("uncovered", "thread_context_conflict", GetLastError()); fatal_ = true; return; }
    }
    Metadata("armed", "direct_process_only");
}

bool Observer::Capture(DWORD tid, Thread& thread, CONTEXT& context, char api) {
    if (thread.call) {
        if (context.Rsp >= thread.call->entry_stack) { return false; }
        ++nested_;
        return true;
    }
    uint64_t return_address = 0;
    DWORD flags = 0;
    // The ninth x64 argument is at entry RSP + return-address(8) + shadow-space(32) + four stack arguments(32).
    if (!ReadValue(process_.value, context.Rsp, return_address) ||
        !ReadValue(process_.value, context.Rsp + 0x48, flags)) { return false; }
    MEMORY_BASIC_INFORMATION memory{};
    if (!VirtualQueryEx(process_.value, reinterpret_cast<void*>(return_address), &memory, sizeof(memory)) ||
        memory.State != MEM_COMMIT || !(memory.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ||
        (memory.Protect & PAGE_GUARD)) { return false; }
    CREDUI_INFOW info{};
    // Never follow authentication-package, input/output buffer, save, caption or banner pointers.
    const bool info_readable = ReadValue(process_.value, context.Rcx, info) && info.cbSize == sizeof(info);
    const uint64_t parent = info_readable ? reinterpret_cast<uint64_t>(info.hwndParent) : 0;
    const uint64_t text_address = info_readable ? reinterpret_cast<uint64_t>(info.pszMessageText) : 0;
    const auto text = api == 'W' ? ReadDisplayText<wchar_t>(process_.value, text_address) : ReadDisplayText<char>(process_.value, text_address);
    const DWORD error = DWORD(context.Rdx);
    Call call{next_call_++, context.Rsp, return_address, api};
    thread.call = call;
    ++begins_;
    truncated_ += text.truncated ? 1 : 0;
    unreadable_ += !text.readable && !text.truncated ? 1 : 0;
    if (options_.fixture) {
        fixture_layout_ = fixture_layout_ && flags == 0x200;
        if (call.id == 1) { fixture_layout_ = fixture_layout_ && api == 'W' && error == 101 && parent == 0x12340000 && text.readable && text.units == 12; }
        if (call.id == 2) { fixture_layout_ = fixture_layout_ && api == 'A' && error == 0 && text.readable && text.units == 12; }
        if (call.id == 6) { fixture_layout_ = fixture_layout_ && api == 'W' && error == 5 && text.readable && text.units == 14; }
    }
    std::cout << "{\"version\":1,\"event\":\"begin\",\"fixture\":" << (options_.fixture ? "true" : "false")
        << ",\"pid\":" << pid_ << ",\"tid\":" << tid << ",\"session\":" << session_
        << ",\"call_id\":\"call_" << call.id << "\",\"api\":\"" << api << "\",\"parent_hwnd\":\"0x"
        << std::hex << parent << std::dec << "\",\"api_flags\":" << flags << ",\"auth_error\":" << error
        << ",\"info_readable\":" << (info_readable ? "true" : "false")
        << ",\"text_readable\":" << (text.readable ? "true" : "false") << ",\"text_units\":" << text.units
        << ",\"text_truncated\":" << (text.truncated ? "true" : "false") << ",\"purpose\":\"unknown\"}\n" << std::flush;
    return Configure(thread, false);
}

bool Observer::OnSingleStep(DWORD tid, DWORD& continuation) {
    const auto found = threads_.find(tid);
    if (found == threads_.end()) { return false; }
    auto& thread = found->second;
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread.handle.value, &context)) { return false; }
    const bool wide = (context.Dr6 & 1) && context.Rip == exports_.wide;
    const bool ansi = (context.Dr6 & 2) && context.Rip == exports_.ansi;
    const bool returning = (context.Dr6 & 4) && thread.call && context.Rip == thread.call->return_address;
    if (!wide && !ansi && !returning) { continuation = DBG_EXCEPTION_NOT_HANDLED; return true; }
    if (context.Dr6 & (uint64_t(1) << 14)) { return false; }
    if (returning && context.Rsp == thread.call->entry_stack + 8) {
        const Call call = *thread.call;
        const DWORD result = DWORD(context.Rax);
        ++ends_;
        if (options_.fixture) {
            const DWORD expected = call.api == 'W' ? DWORD(ERROR_CANCELLED) : DWORD(ERROR_SUCCESS);
            fixture_layout_ = fixture_layout_ && result == expected;
        }
        std::cout << "{\"version\":1,\"event\":\"end\",\"fixture\":" << (options_.fixture ? "true" : "false")
            << ",\"pid\":" << pid_ << ",\"tid\":" << tid << ",\"call_id\":\"call_" << call.id
            << "\",\"return_code\":" << result << "}\n" << std::flush;
        thread.call.reset();
        if (!Configure(thread, false)) { return false; }
    } else if (wide || ansi) {
        if (!Capture(tid, thread, context, wide ? 'W' : 'A')) { return false; }
    }
    // Preserve the API's arguments and control flow; RF skips our execution breakpoint once.
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    CONTEXT current{};
    current.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread.handle.value, &current)) { return false; }
    context.Dr0 = current.Dr0; context.Dr1 = current.Dr1; context.Dr2 = current.Dr2;
    context.Dr3 = current.Dr3; context.Dr6 = 0; context.Dr7 = current.Dr7;
    context.EFlags |= kResumeFlag;
    if (!SetThreadContext(thread.handle.value, &context)) { return false; }
    continuation = DBG_CONTINUE;
    return true;
}

bool Observer::DrainForDetach(DEBUG_EVENT& event, bool& event_outstanding) {
    // Tracked live threads remain suspended while any queued events are drained.
    while (true) {
        if (!WaitForDebugEvent(&event, 0)) { return GetLastError() == ERROR_SEM_TIMEOUT; }
        event_outstanding = true;
        DWORD continuation = DBG_CONTINUE;
        if (event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
            // This thread has not been instrumented; new Windows threads do not inherit DR state.
            Handle thread(event.u.CreateThread.hThread);
        } else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            Handle file(event.u.LoadDll.hFile);
        } else if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            const auto& record = event.u.Exception.ExceptionRecord;
            const uint64_t address = reinterpret_cast<uint64_t>(record.ExceptionAddress);
            bool ours = address == exports_.wide || address == exports_.ansi;
            auto thread = threads_.find(event.dwThreadId);
            if (thread != threads_.end() && thread->second.call) { ours = ours || address == thread->second.call->return_address; }
            if (record.ExceptionCode != EXCEPTION_BREAKPOINT && !(record.ExceptionCode == EXCEPTION_SINGLE_STEP && ours)) {
                continuation = DBG_EXCEPTION_NOT_HANDLED;
            }
        } else if (event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
            threads_.erase(event.dwThreadId);
        } else if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            exit_code_ = event.u.ExitProcess.dwExitCode;
            if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continuation)) { return false; }
            event_outstanding = false;
            threads_.clear();
            return true;
        }
        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continuation)) { return false; }
        event_outstanding = false;
    }
}

bool Observer::RestoreAndDetach(DEBUG_EVENT& event, DWORD continuation, bool& event_outstanding) {
    for (auto& [tid, thread] : threads_) {
        (void)tid;
        DWORD exit_code = 0;
        if (!GetExitCodeThread(thread.handle.value, &exit_code)) { return false; }
        if (exit_code != STILL_ACTIVE) { continue; }
        if (SuspendThread(thread.handle.value) == DWORD(-1)) { return false; }
        thread.suspended = true;
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(thread.handle.value, &context)) { return false; }
        // Restore all saved debug registers, including disabled addresses and status.
        context.Dr0 = thread.original.Dr0; context.Dr1 = thread.original.Dr1;
        context.Dr2 = thread.original.Dr2; context.Dr3 = thread.original.Dr3;
        context.Dr6 = thread.original.Dr6; context.Dr7 = thread.original.Dr7;
        if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && event.dwThreadId == tid &&
            event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP && continuation == DBG_CONTINUE) {
            context.EFlags |= kResumeFlag;
        }
        if (!SetThreadContext(thread.handle.value, &context)) { return false; }
    }
    if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continuation)) { return false; }
    event_outstanding = false;
    if (!DrainForDetach(event, event_outstanding)) { return false; }
    if (exit_code_ == STILL_ACTIVE && !DebugActiveProcessStop(pid_)) { return false; }
    detached_ = true;
    bool resumed = true;
    for (auto& [tid, thread] : threads_) {
        (void)tid;
        if (thread.suspended) { resumed = ResumeThread(thread.handle.value) != DWORD(-1) && resumed; thread.suspended = false; }
    }
    Metadata("detached", stop_reason_);
    return resumed;
}

void Observer::FatalCleanup(DEBUG_EVENT* event, DWORD continuation) {
    // Only this explicitly launched disposable test process can be terminated. Never attach to or terminate another PID.
    Metadata("fatal_cleanup", "terminate_dedicated_target_instead_of_leaving_debug_registers", GetLastError());
    TerminateProcess(process_.value, ERROR_DEBUGGER_INACTIVE);
    if (event) { ContinueDebugEvent(event->dwProcessId, event->dwThreadId, continuation); }
    DEBUG_EVENT pending{};
    const ULONGLONG deadline = GetTickCount64() + kCleanupMs;
    while (GetTickCount64() < deadline && WaitForSingleObject(process_.value, 0) != WAIT_OBJECT_0) {
        if (!WaitForDebugEvent(&pending, kPollMs)) { continue; }
        if (pending.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) { Handle file(pending.u.LoadDll.hFile); }
        if (pending.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) { Handle file(pending.u.CreateProcessInfo.hFile); }
        ContinueDebugEvent(pending.dwProcessId, pending.dwThreadId, DBG_CONTINUE);
    }
    // TerminateProcess failure is explicit, never silently reported as a successful detach.
    Metadata("cleanup_result", WaitForSingleObject(process_.value, 0) == WAIT_OBJECT_0 ? "target_exited" : "target_cleanup_failed");
}

int Observer::Run() {
    if (!Launch()) {
        Metadata("uncovered", "launch_or_debug_setup_failed", GetLastError());
        if (process_.value) { FatalCleanup(nullptr, DBG_CONTINUE); }
        return 2;
    }
    Metadata("launched", "observe_only_direct_process_no_existing_pid_attach");
    const ULONGLONG deadline = GetTickCount64() + options_.duration;
    ULONGLONG stop_deadline = 0;
    bool finished = false;
    while (!finished) {
        if (!stop_requested_ && GetTickCount64() >= deadline) {
            stop_requested_ = true;
            stop_deadline = GetTickCount64() + kCleanupMs;
            if (!DebugBreakProcess(process_.value)) { fatal_ = true; FatalCleanup(nullptr, DBG_CONTINUE); break; }
        }
        DEBUG_EVENT event{};
        if (!WaitForDebugEvent(&event, kPollMs)) {
            const DWORD error = GetLastError();
            if (error != ERROR_SEM_TIMEOUT || (stop_requested_ && GetTickCount64() >= stop_deadline)) {
                fatal_ = true; FatalCleanup(nullptr, DBG_CONTINUE); break;
            }
            continue;
        }
        DWORD continuation = DBG_CONTINUE;
        bool stop_here = false;
        switch (event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            Handle file(event.u.CreateProcessInfo.hFile);
            USHORT process_machine = 0, native_machine = 0;
            if (!IsWow64Process2(process_.value, &process_machine, &native_machine) ||
                process_machine != IMAGE_FILE_MACHINE_UNKNOWN || native_machine != IMAGE_FILE_MACHINE_AMD64 ||
                !AddThread(event.dwThreadId, event.u.CreateProcessInfo.hThread)) { fatal_ = true; }
            break;
        }
        case CREATE_THREAD_DEBUG_EVENT:
            if (!AddThread(event.dwThreadId, event.u.CreateThread.hThread)) { fatal_ = true; }
            break;
        case LOAD_DLL_DEBUG_EVENT:
            OnModule(event.u.LoadDll);
            break;
        case UNLOAD_DLL_DEBUG_EVENT:
            if (reinterpret_cast<uint64_t>(event.u.UnloadDll.lpBaseOfDll) == module_base_) {
                module_unloaded_ = true;
                stop_reason_ = "observed_module_unloaded";
                stop_here = true;
            }
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            if (threads_.count(event.dwThreadId) && threads_.at(event.dwThreadId).call) { Metadata("incomplete", "thread_exited_during_call"); }
            threads_.erase(event.dwThreadId);
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            exit_code_ = event.u.ExitProcess.dwExitCode;
            threads_.clear();
            finished = true;
            break;
        case EXCEPTION_DEBUG_EVENT: {
            const auto& exception = event.u.Exception;
            const DWORD code = exception.ExceptionRecord.ExceptionCode;
            continuation = DBG_EXCEPTION_NOT_HANDLED;
            if (code == EXCEPTION_BREAKPOINT && !initial_breakpoint_) { initial_breakpoint_ = true; continuation = DBG_CONTINUE; }
            else if (code == EXCEPTION_BREAKPOINT && stop_requested_) { stop_here = true; continuation = DBG_CONTINUE; }
            else if (code == EXCEPTION_SINGLE_STEP) {
                if (!OnSingleStep(event.dwThreadId, continuation)) { fatal_ = true; }
            } else if (!exception.dwFirstChance) {
                crashed_ = true;
                // Forward the crash unchanged; clear our breakpoints while the process is stopped.
                stop_reason_ = "second_chance_exception";
                stop_here = true;
            }
            break;
        }
        case RIP_EVENT:
            fatal_ = true;
            break;
        default:
            // Do not read OUTPUT_DEBUG_STRING_EVENT: target logs can contain secrets.
            break;
        }
        if (fatal_) {
            Metadata("uncovered", "unsupported_context_or_debug_event", GetLastError());
            // Try to restore even on unsupported paths; never leave armed DRs and silently exit.
            stop_reason_ = "unsupported_path";
            bool event_outstanding = true;
            if (!RestoreAndDetach(event, continuation, event_outstanding)) {
                FatalCleanup(event_outstanding ? &event : nullptr, continuation);
            }
            break;
        }
        if (stop_here) {
            bool event_outstanding = true;
            if (!RestoreAndDetach(event, continuation, event_outstanding)) {
                fatal_ = true;
                FatalCleanup(event_outstanding ? &event : nullptr, continuation);
            }
            break;
        }
        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continuation)) {
            fatal_ = true; FatalCleanup(nullptr, DBG_CONTINUE); break;
        }
    }
    if (options_.fixture && detached_ && exit_code_ == STILL_ACTIVE) {
        if (WaitForSingleObject(process_.value, kCleanupMs) != WAIT_OBJECT_0) {
            fatal_ = true; TerminateProcess(process_.value, ERROR_TIMEOUT);
        }
        GetExitCodeProcess(process_.value, &exit_code_);
    }
    bool passed = !fatal_;
    if (options_.fixture) {
        passed = passed && discovered_ && begins_ == 6 && ends_ == 6 && nested_ == 1 &&
            truncated_ == 1 && unreadable_ == 2 && fixture_layout_;
        if (options_.fixture_mode == L"crash") { passed = passed && crashed_ && exit_code_ == 0xe0123456; }
        else { passed = passed && exit_code_ == ERROR_SUCCESS; }
        if (options_.fixture_mode == L"detach") { passed = passed && detached_ && !module_unloaded_; }
        if (options_.fixture_mode == L"unload") { passed = passed && detached_ && module_unloaded_; }
    }
    std::cout << "{\"version\":1,\"event\":\"summary\",\"fixture\":" << (options_.fixture ? "true" : "false")
        << ",\"pid\":" << pid_ << ",\"system_exports_found\":" << (discovered_ ? "true" : "false")
        << ",\"observed_calls\":" << begins_ << ",\"observed_returns\":" << ends_ << ",\"nested_entries\":" << nested_
        << ",\"target_exit_code\":" << exit_code_ << ",\"detached\":" << (detached_ ? "true" : "false")
        << ",\"fixture_passed\":" << (options_.fixture && passed ? "true" : "false") << "}\n";
    if (!options_.fixture && !begins_) { Metadata("uncovered", "no_calls_observed_possible_singleton_or_other_process"); return fatal_ ? 4 : 3; }
    return passed ? 0 : 4;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    const auto options = ParseOptions(argc, argv);
    if (!options) {
        std::cerr << "Offline x64 fixture only; no browser launch or attach, no credential input/output access.\n"
            "Self-tests: --self-test, --self-test-detach, --self-test-unload, --self-test-crash\n";
        return 1;
    }
    Observer observer(*options);
    return observer.Run();
}
