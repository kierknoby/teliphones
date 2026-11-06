#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <stdexcept>
#include <string>

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
};

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
    return queried ? Status{status.dwCurrentState, status.dwWin32ExitCode, status.dwServiceSpecificExitCode}
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

}  // namespace tunnel_startup
}  // namespace win
}  // namespace tlp
