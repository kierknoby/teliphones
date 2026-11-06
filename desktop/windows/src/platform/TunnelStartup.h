#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <sddl.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

namespace tlp {
namespace win {
namespace tunnel_startup {

struct Failure : std::runtime_error {
    DWORD code;
    Failure(const char* message, DWORD error) : std::runtime_error(message), code(error) {}
};

struct Status {
    DWORD state = 0;
    DWORD error = ERROR_SUCCESS;
    DWORD serviceError = ERROR_SUCCESS;
    DWORD processId = 0;
};

inline bool Absent(const Status& status) { return status.state == 0 && status.error == ERROR_SERVICE_DOES_NOT_EXIST; }

inline Status ReadStatus(const std::wstring& name) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return {0, GetLastError(), 0};
    SC_HANDLE service = OpenServiceW(manager, name.c_str(), SERVICE_QUERY_STATUS);
    const DWORD openError = service ? ERROR_SUCCESS : GetLastError();
    CloseServiceHandle(manager);
    if (!service) return {0, openError, 0};
    SERVICE_STATUS_PROCESS status{};
    DWORD size = 0;
    const BOOL queried = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status), sizeof(status), &size);
    const DWORD queryError = queried ? ERROR_SUCCESS : GetLastError();
    CloseServiceHandle(service);
    return queried ? Status{status.dwCurrentState, status.dwWin32ExitCode, status.dwServiceSpecificExitCode, status.dwProcessId}
                   : Status{0, queryError, 0};
}

inline void WaitForService(const std::wstring& name, bool running, DWORD timeoutMs) {
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    for (;;) {
        const Status status = ReadStatus(name);
        if (status.state != 0 && (!running || status.state == SERVICE_RUNNING)) return;
        if (status.state == 0 && status.error != ERROR_SERVICE_DOES_NOT_EXIST)
            throw Failure("Cannot query the WireGuard tunnel service", status.error);
        if (running && (status.state == SERVICE_STOPPED || status.state == SERVICE_STOP_PENDING))
            throw Failure("The WireGuard tunnel service stopped during startup",
                          status.error == ERROR_SUCCESS ? ERROR_SERVICE_NOT_ACTIVE : status.error);
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) throw Failure("WireGuard tunnel service readiness timed out", ERROR_TIMEOUT);
        Sleep(static_cast<DWORD>(std::min<ULONGLONG>(100, deadline - now)));
    }
}

// Uses short-lived handles only: the SCM deletes a service marked for deletion after every handle closes.
inline void RequestRemoval(const std::wstring& name) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return;
    SC_HANDLE service = OpenServiceW(manager, name.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    CloseServiceHandle(manager);
    if (!service) return;
    SERVICE_STATUS status{};
    if (QueryServiceStatus(service, &status) && status.dwCurrentState == SERVICE_RUNNING)
        ControlService(service, SERVICE_CONTROL_STOP, &status);
    DeleteService(service);
    CloseServiceHandle(service);
}

// START_PENDING does not accept SERVICE_CONTROL_STOP (Windows error 1052), so absence is awaited, never assumed.
inline Status AwaitAbsent(const std::wstring& name, DWORD timeoutMs) {
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    for (;;) {
        const Status status = ReadStatus(name);
        if (Absent(status)) return status;
        if (status.state == SERVICE_RUNNING || status.state == SERVICE_STOPPED) RequestRemoval(name);
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) return status;
        Sleep(static_cast<DWORD>(std::min<ULONGLONG>(100, deadline - now)));
    }
}

class DebugPrivilegeScope {
public:
    DebugPrivilegeScope() {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_)) {
            token_ = nullptr;
            return;
        }
        TOKEN_PRIVILEGES wanted{};
        wanted.PrivilegeCount = 1;
        wanted.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &wanted.Privileges[0].Luid)) return;
        DWORD size = sizeof(previous_);
        adjusted_ = AdjustTokenPrivileges(token_, FALSE, &wanted, sizeof(previous_), &previous_, &size) &&
                    GetLastError() == ERROR_SUCCESS;
    }
    ~DebugPrivilegeScope() {
        if (adjusted_) AdjustTokenPrivileges(token_, FALSE, &previous_, 0, nullptr, nullptr);
        if (token_) CloseHandle(token_);
    }
    DebugPrivilegeScope(const DebugPrivilegeScope&) = delete;
    DebugPrivilegeScope& operator=(const DebugPrivilegeScope&) = delete;

private:
    HANDLE token_ = nullptr;
    TOKEN_PRIVILEGES previous_{};
    bool adjusted_ = false;
};

enum class Termination { NotRunning, NotOwned, Exited, Survived, Failed };

struct TerminationResult {
    Termination outcome = Termination::Failed;
    DWORD error = ERROR_SUCCESS;
};

// Terminates a stuck service's own process only after owned(binaryPathName, processImagePath) confirms both
// belong to the caller's service. The PID is re-read after the process handle is open, so a reused PID is
// never terminated. Survived means TerminateProcess was accepted but the process did not exit, which happens
// when a thread is blocked in kernel mode; user mode cannot recover that process.
template <class Owned>
TerminationResult TerminateOwnedServiceProcess(const std::wstring& name, Owned owned, DWORD exitWaitMs) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return {Termination::Failed, GetLastError()};
    SC_HANDLE service = OpenServiceW(manager, name.c_str(), SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    const DWORD openError = service ? ERROR_SUCCESS : GetLastError();
    CloseServiceHandle(manager);
    if (!service) {
        return {openError == ERROR_SERVICE_DOES_NOT_EXIST ? Termination::NotRunning : Termination::Failed, openError};
    }
    struct ServiceCloser {
        SC_HANDLE value;
        ~ServiceCloser() { CloseServiceHandle(value); }
    } serviceCloser{service};
    DWORD bytes = 0;
    QueryServiceConfigW(service, nullptr, 0, &bytes);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || bytes == 0 || bytes > 65536) return {Termination::Failed, sizeError};
    std::vector<ULONGLONG> storage(bytes / sizeof(ULONGLONG) + 1);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(storage.data());
    if (!QueryServiceConfigW(service, config, static_cast<DWORD>(storage.size() * sizeof(ULONGLONG)), &bytes))
        return {Termination::Failed, GetLastError()};
    if (config->dwServiceType != SERVICE_WIN32_OWN_PROCESS || !config->lpBinaryPathName) return {Termination::NotOwned, 0};
    const std::wstring binaryPath = config->lpBinaryPathName;
    SERVICE_STATUS_PROCESS before{};
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&before), sizeof(before), &bytes))
        return {Termination::Failed, GetLastError()};
    if (before.dwProcessId == 0 || before.dwCurrentState == SERVICE_STOPPED) return {Termination::NotRunning, 0};
    const DWORD access = PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
    HANDLE process = OpenProcess(access, FALSE, before.dwProcessId);
    DWORD processError = process ? ERROR_SUCCESS : GetLastError();
    if (!process && processError == ERROR_ACCESS_DENIED) {
        DebugPrivilegeScope debug;
        process = OpenProcess(access, FALSE, before.dwProcessId);
        processError = process ? ERROR_SUCCESS : GetLastError();
    }
    if (!process) return {Termination::Failed, processError};
    struct ProcessCloser {
        HANDLE value;
        ~ProcessCloser() { CloseHandle(value); }
    } processCloser{process};
    std::vector<wchar_t> image(32768);
    DWORD imageLength = static_cast<DWORD>(image.size());
    if (!QueryFullProcessImageNameW(process, 0, image.data(), &imageLength)) return {Termination::Failed, GetLastError()};
    SERVICE_STATUS_PROCESS after{};
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&after), sizeof(after), &bytes))
        return {Termination::Failed, GetLastError()};
    if (after.dwProcessId != before.dwProcessId) {
        return {WaitForSingleObject(process, 0) == WAIT_OBJECT_0 ? Termination::Exited : Termination::NotOwned, 0};
    }
    if (!owned(binaryPath, std::wstring(image.data(), imageLength))) return {Termination::NotOwned, 0};
    if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) return {Termination::Exited, 0};
    if (!TerminateProcess(process, ERROR_SERVICE_REQUEST_TIMEOUT)) {
        const DWORD error = GetLastError();
        if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) return {Termination::Exited, 0};
        return {Termination::Failed, error};
    }
    if (WaitForSingleObject(process, exitWaitMs) == WAIT_OBJECT_0) return {Termination::Exited, 0};
    return {Termination::Survived, ERROR_TIMEOUT};
}

inline std::wstring HelperLockName(const std::wstring& tunnelName) { return L"Global\\TELIPHONES-tunnel-" + tunnelName; }

// Machine-wide exclusion between elevated helpers for one tunnel, across sessions and application instances.
// Global objects require SeCreateGlobalPrivilege, so a standard user cannot pre-create (squat) the name.
class HelperLock {
public:
    explicit HelperLock(const std::wstring& name) {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1,
                                                                  &descriptor, nullptr))
            throw Failure("Cannot secure the tunnel operation lock", GetLastError());
        SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
        mutex_ = CreateMutexW(&security, FALSE, name.c_str());
        const DWORD error = GetLastError();
        LocalFree(descriptor);
        if (!mutex_) throw Failure("Cannot create the tunnel operation lock", error);
        const DWORD wait = WaitForSingleObject(mutex_, 0);
        // WAIT_ABANDONED: an earlier helper ended without releasing it. The tunnel state is re-verified before reuse.
        owned_ = wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED;
        abandoned_ = wait == WAIT_ABANDONED;
    }
    ~HelperLock() {
        if (owned_) ReleaseMutex(mutex_);
        if (mutex_) CloseHandle(mutex_);
    }
    HelperLock(const HelperLock&) = delete;
    HelperLock& operator=(const HelperLock&) = delete;
    bool owned() const { return owned_; }
    bool abandoned() const { return abandoned_; }

private:
    HANDLE mutex_ = nullptr;
    bool owned_ = false;
    bool abandoned_ = false;
};

}  // namespace tunnel_startup
}  // namespace win
}  // namespace tlp
