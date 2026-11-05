#include "../src/platform/TunnelStartup.h"

#include <iostream>
#include <string>

namespace startup = tlp::win::tunnel_startup;

namespace {
std::wstring fixtureName;
std::wstring fixtureMode;
SERVICE_STATUS_HANDLE statusHandle = nullptr;
HANDLE stopEvent = nullptr;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::wstring pipeName(const std::wstring& name) {
    return L"\\\\.\\pipe\\" + name;
}

void report(DWORD state, DWORD error = ERROR_SUCCESS) {
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP : 0;
    status.dwWin32ExitCode = error;
    status.dwCheckPoint = state == SERVICE_START_PENDING ? 1 : 0;
    status.dwWaitHint = state == SERVICE_START_PENDING ? 5000 : 0;
    SetServiceStatus(statusHandle, &status);
}

DWORD WINAPI control(DWORD code, DWORD, void*, void*) {
    if (code == SERVICE_CONTROL_STOP) {
        report(SERVICE_STOP_PENDING);
        SetEvent(stopEvent);
    }
    return NO_ERROR;
}

void WINAPI serviceMain(DWORD, LPWSTR*) {
    stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    statusHandle = RegisterServiceCtrlHandlerExW(fixtureName.c_str(), control, nullptr);
    if (!stopEvent || !statusHandle) return;
    report(SERVICE_START_PENDING);
    Sleep(1000);
    if (fixtureMode == L"fail") {
        report(SERVICE_STOPPED, ERROR_PROCESS_ABORTED);
        CloseHandle(stopEvent);
        return;
    }
    report(SERVICE_RUNNING);
    // SCM running deliberately precedes control-pipe creation; no network or peer exists.
    if (fixtureMode == L"delayed-pipe") {
        if (WaitForSingleObject(stopEvent, 1000) == WAIT_TIMEOUT) {
            HANDLE pipe = CreateNamedPipeW(pipeName(fixtureName).c_str(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1, 128, 128, 0, nullptr);
            if (pipe != INVALID_HANDLE_VALUE) {
                WaitForSingleObject(stopEvent, 30000);
                CloseHandle(pipe);
            }
        }
    } else {
        WaitForSingleObject(stopEvent, 30000);
    }
    if (fixtureMode == L"delayed-stop") Sleep(1000);
    report(SERVICE_STOPPED);
    CloseHandle(stopEvent);
}

class Fixture {
public:
    std::wstring name;
    SC_HANDLE manager = nullptr;
    SC_HANDLE service = nullptr;

    explicit Fixture(const std::wstring& mode) {
        name = L"TELIPHONES-TunnelStartupTests-" + std::to_wstring(GetCurrentProcessId()) +
               L"-" + std::to_wstring(GetTickCount64());
        wchar_t executable[MAX_PATH]{};
        const DWORD length = GetModuleFileNameW(nullptr, executable, MAX_PATH);
        require(length != 0 && length < MAX_PATH, "Cannot locate native fixture");
        const std::wstring command = L"\"" + std::wstring(executable) + L"\" --service " + name + L" " + mode;
        manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
        require(manager != nullptr, "Native SCM fixture requires an elevated test runner; no service was installed");
        service = CreateServiceW(manager, name.c_str(), name.c_str(), SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            command.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!service) {
            CloseServiceHandle(manager);
            throw std::runtime_error("Cannot create isolated native SCM fixture");
        }
    }
    ~Fixture() {
        if (!service) return;
        SERVICE_STATUS status{};
        ControlService(service, SERVICE_CONTROL_STOP, &status);
        const auto deadline = GetTickCount64() + 5000;
        while (startup::ReadStatus(name).state != SERVICE_STOPPED && GetTickCount64() < deadline) Sleep(50);
        DeleteService(service);
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    void start() { require(StartServiceW(service, 0, nullptr) != FALSE, "Cannot start isolated SCM fixture"); }
    void remove() {
        SERVICE_STATUS status{};
        const auto deadline = GetTickCount64() + 5000;
        while (startup::ReadStatus(name).state != SERVICE_STOPPED && GetTickCount64() < deadline) {
            ControlService(service, SERVICE_CONTROL_STOP, &status);
            Sleep(50);
        }
        require(startup::ReadStatus(name).state == SERVICE_STOPPED, "Native fixture cleanup must confirm service stopped");
        require(DeleteService(service) != FALSE, "Native fixture cleanup must delete its own service");
        CloseServiceHandle(service);
        service = nullptr;
        CloseServiceHandle(manager);
        manager = nullptr;
        const auto deletionDeadline = GetTickCount64() + 5000;
        while (startup::ReadStatus(name).error != ERROR_SERVICE_DOES_NOT_EXIST &&
               GetTickCount64() < deletionDeadline) Sleep(50);
        require(startup::ReadStatus(name).error == ERROR_SERVICE_DOES_NOT_EXIST,
                "Native fixture service must be absent after cleanup");
    }
};

void delayedStartup() {
    Fixture fixture(L"delayed-pipe");
    fixture.start();
    require(startup::ReadStatus(fixture.name).state == SERVICE_START_PENDING,
            "Fixture must exercise an actual SCM transitional state");
    startup::WaitForService(fixture.name, true, 5000);
    const auto started = GetTickCount64();
    const BOOL legacyReady = WaitNamedPipeW(pipeName(fixture.name).c_str(), 5000);
    const DWORD legacyError = legacyReady ? ERROR_SUCCESS : GetLastError();
    require(!legacyReady && legacyError == ERROR_FILE_NOT_FOUND,
            "Legacy WaitNamedPipe must reproduce immediate absent-pipe failure despite Running service");
    require(GetTickCount64() - started < 1000,
            "Legacy creation wait must return before its requested timeout");
    HANDLE pipe = startup::OpenControlPipe(pipeName(fixture.name), fixture.name, 5000);
    require(pipe != INVALID_HANDLE_VALUE, "Delayed pipe must become ready");
    CloseHandle(pipe);
    require(GetTickCount64() - started >= 200, "Pipe readiness must wait beyond SCM Running");
    require(startup::ReadStatus(fixture.name).state == SERVICE_RUNNING,
            "Successful startup without a peer handshake must not stop the service");
    fixture.remove();
}

void stoppingService() {
    Fixture fixture(L"delayed-stop");
    fixture.start();
    startup::WaitForService(fixture.name, true, 5000);
    SERVICE_STATUS status{};
    require(ControlService(fixture.service, SERVICE_CONTROL_STOP, &status) != FALSE,
            "Cannot request fixture transition to StopPending");
    require(startup::ReadStatus(fixture.name).state == SERVICE_STOP_PENDING,
            "Fixture must exercise an actual StopPending transition");
    bool rejected = false;
    try {
        HANDLE pipe = startup::OpenControlPipe(pipeName(fixture.name), fixture.name, 5000);
        CloseHandle(pipe);
    } catch (const startup::Failure& error) { rejected = error.code == ERROR_SERVICE_NOT_ACTIVE; }
    require(rejected, "External service shutdown must fail readiness rather than retry until timeout");
    fixture.remove();
}

void stoppedService() {
    Fixture fixture(L"fail");
    fixture.start();
    bool rejected = false;
    try { startup::WaitForService(fixture.name, true, 5000); }
    catch (const startup::Failure& error) { rejected = error.code == ERROR_PROCESS_ABORTED; }
    require(rejected, "Actual SCM service exit must be reported, not accepted as running");
    require(startup::ReadStatus(fixture.name).state == SERVICE_STOPPED, "Failed service must be stopped before cleanup");
    fixture.remove();
}

void missingPipe() {
    Fixture fixture(L"no-pipe");
    fixture.start();
    startup::WaitForService(fixture.name, true, 5000);
    const auto started = GetTickCount64();
    bool timedOut = false;
    try {
        HANDLE pipe = startup::OpenControlPipe(pipeName(fixture.name), fixture.name, 300);
        CloseHandle(pipe);
    } catch (const startup::Failure& error) { timedOut = error.code == ERROR_TIMEOUT; }
    require(timedOut && GetTickCount64() - started >= 300, "Absent pipe must wait to the bounded deadline");
    require(startup::ReadStatus(fixture.name).state == SERVICE_RUNNING,
            "Polling must not remove a service before the caller decides cleanup");
    fixture.remove();
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 4 && std::wstring(argv[1]) == L"--service") {
        fixtureName = argv[2];
        fixtureMode = argv[3];
        SERVICE_TABLE_ENTRYW table[]{{const_cast<LPWSTR>(fixtureName.c_str()), serviceMain}, {nullptr, nullptr}};
        return StartServiceCtrlDispatcherW(table) ? 0 : 1;
    }
    try {
        delayedStartup();
        stoppedService();
        missingPipe();
        stoppingService();
        std::cout << "Native tunnel startup tests: PASS (real SCM, delayed pipe, no peer, failure, bounded wait)\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Native tunnel startup tests: FAIL: " << error.what() << "\n";
        return 1;
    }
}
