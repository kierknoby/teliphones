#include "WireGuard.h"

#include "Win.h"

#include <aclapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <softpub.h>
#include <wintrust.h>

#include "../core/CommandLine.h"
#include "../core/Json.h"
#include "../core/TunnelConfig.h"
#include "../core/Validation.h"

namespace tlp {
namespace win {
namespace {

constexpr DWORD kHelperOk = 0;
constexpr DWORD kHelperArguments = 2;
constexpr DWORD kHelperConfigRejected = 3;
constexpr DWORD kHelperWireGuardUnavailable = 4;
constexpr DWORD kHelperInstallFailed = 5;
constexpr DWORD kHelperPermissionsFailed = 6;
constexpr DWORD kHelperNotElevated = 7;
constexpr DWORD kHelperStartFailed = 8;
constexpr DWORD kHelperRemoveFailed = 9;

const wchar_t kTunnelFolderSddl[] = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

class ServiceHandle {
public:
    explicit ServiceHandle(SC_HANDLE value = nullptr) : value_(value) {}
    ~ServiceHandle() {
        if (value_) CloseServiceHandle(value_);
    }
    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;
    SC_HANDLE get() const { return value_; }
    explicit operator bool() const { return value_ != nullptr; }

private:
    SC_HANDLE value_;
};

class WipeString {
public:
    explicit WipeString(std::string& value) : value_(value) {}
    ~WipeString() { SecureWipe(value_); }
    WipeString(const WipeString&) = delete;
    WipeString& operator=(const WipeString&) = delete;

private:
    std::string& value_;
};

class WipeTunnelKey {
public:
    explicit WipeTunnelKey(TunnelConfig& config) : config_(config) {}
    ~WipeTunnelKey() { SecureWipe(config_.privateKey); }
    WipeTunnelKey(const WipeTunnelKey&) = delete;
    WipeTunnelKey& operator=(const WipeTunnelKey&) = delete;

private:
    TunnelConfig& config_;
};

class Handle {
public:
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
private:
    HANDLE value_;
};

void pipeTransfer(HANDLE pipe, void* buffer, DWORD size, bool write) {
    DWORD total = 0;
    while (total < size) {
        Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!event.get()) ThrowLastError("Unable to create tunnel IPC event");
        OVERLAPPED operation{};
        operation.hEvent = event.get();
        DWORD count = 0;
        auto* bytes = static_cast<unsigned char*>(buffer) + total;
        BOOL ok = write ? WriteFile(pipe, bytes, size - total, &count, &operation)
                        : ReadFile(pipe, bytes, size - total, &count, &operation);
        if (!ok) {
            if (GetLastError() != ERROR_IO_PENDING) throw Error("Tunnel key IPC failed.");
            if (WaitForSingleObject(event.get(), 10000) != WAIT_OBJECT_0) {
                CancelIoEx(pipe, &operation);
                GetOverlappedResult(pipe, &operation, &count, TRUE);
                throw Error("Tunnel key IPC timed out.");
            }
            if (!GetOverlappedResult(pipe, &operation, &count, FALSE)) throw Error("Tunnel key IPC failed.");
        }
        if (!count) throw Error("Tunnel key IPC closed unexpectedly.");
        total += count;
    }
}

std::wstring keyPipeName(const std::string& token) {
    return L"\\\\.\\pipe\\TELIPHONES-connect-" + Widen(token);
}

class KeyPipe {
public:
    const std::string token = HexEncode(RandomBytes(16));
    explicit KeyPipe(const std::string& key) : key_(key) {
        const auto sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + Widen(CurrentUserSid()) + L")";
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
            ThrowLastError("Unable to secure tunnel key IPC");
        SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
        pipe_ = CreateNamedPipeW(keyPipeName(token).c_str(), PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                1, 128, 128, 0, &security);
        LocalFree(descriptor);
        if (pipe_ == INVALID_HANDLE_VALUE) ThrowLastError("Unable to create tunnel key IPC");
    }
    ~KeyPipe() { CloseHandle(pipe_); }
    KeyPipe(const KeyPipe&) = delete;
    KeyPipe& operator=(const KeyPipe&) = delete;
    void deliver(HANDLE helper) {
        Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!event.get()) ThrowLastError("Unable to create tunnel IPC event");
        OVERLAPPED operation{};
        operation.hEvent = event.get();
        const BOOL connected = ConnectNamedPipe(pipe_, &operation);
        const DWORD error = connected ? ERROR_SUCCESS : GetLastError();
        if (error == ERROR_IO_PENDING) {
            HANDLE waits[]{event.get(), helper};
            const auto result = WaitForMultipleObjects(2, waits, FALSE, 15000);
            if (result != WAIT_OBJECT_0) {
                CancelIoEx(pipe_, &operation);
                DWORD count = 0;
                GetOverlappedResult(pipe_, &operation, &count, TRUE);
                throw Error("The tunnel helper did not request the unlocked key.");
            }
            DWORD count = 0;
            if (!GetOverlappedResult(pipe_, &operation, &count, FALSE)) throw Error("Tunnel key IPC failed.");
        } else if (error != ERROR_SUCCESS && error != ERROR_PIPE_CONNECTED) {
            throw Error("Tunnel key IPC failed.");
        }
        ULONG client = 0;
        if (!GetNamedPipeClientProcessId(pipe_, &client) || client != GetProcessId(helper) ||
            WaitForSingleObject(helper, 0) != WAIT_TIMEOUT)
            throw Error("Tunnel key IPC client was not the approved elevated helper.");
        pipeTransfer(pipe_, const_cast<char*>(key_.data()), static_cast<DWORD>(key_.size()), true);
    }
private:
    HANDLE pipe_ = INVALID_HANDLE_VALUE;
    const std::string& key_;
};

std::string receiveKey(const std::string& token) {
    const auto name = keyPipeName(token);
    if (!WaitNamedPipeW(name.c_str(), 10000)) ThrowLastError("Tunnel key IPC is unavailable");
    Handle pipe(CreateFileW(name.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING,
                            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
    if (pipe.get() == INVALID_HANDLE_VALUE) ThrowLastError("Unable to open tunnel key IPC");
    std::string key(44, '\0');
    try {
        pipeTransfer(pipe.get(), key.data(), static_cast<DWORD>(key.size()), false);
        if (!IsWireGuardKey(key)) throw Error("Invalid unlocked tunnel key.");
    } catch (...) {
        SecureWipe(key);
        throw;
    }
    return key;
}

void activateKey(const std::string& tunnelName, const std::string& privateKey) {
    const auto name = L"\\\\.\\pipe\\ProtectedPrefix\\Administrators\\WireGuard\\" + Widen(tunnelName);
    if (!WaitNamedPipeW(name.c_str(), 10000)) ThrowLastError("The WireGuard control pipe is unavailable");
    Handle pipe(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
    if (pipe.get() == INVALID_HANDLE_VALUE) ThrowLastError("Unable to open the WireGuard control pipe");
    Bytes raw = Base64Decode(privateKey);
    std::string hex = HexEncode(raw);
    SecureZeroMemory(raw.data(), raw.size());
    WipeString hexWiper(hex);
    std::string request = "set=1\nprivate_key=" + hex + "\n\n";
    WipeString requestWiper(request);
    pipeTransfer(pipe.get(), request.data(), static_cast<DWORD>(request.size()), true);
    std::string response;
    for (unsigned i = 0; i < 128; ++i) {
        char byte = 0;
        pipeTransfer(pipe.get(), &byte, 1, false);
        response += byte;
        if (response.size() >= 2 && response.compare(response.size() - 2, 2, "\n\n") == 0) break;
    }
    if (response != "errno=0\n\n") throw Error("WireGuard rejected the unlocked tunnel key.");
}

std::wstring serviceName(const std::string& tunnelName) { return L"WireGuardTunnel$" + Widen(tunnelName); }

std::wstring tunnelFolder() { return KnownFolder(FOLDERID_ProgramFiles) + L"\\TELIPHONES\\Tunnels"; }

std::wstring stagingFolder() {
    std::wstring sddl = L"D:P(A;OICI;FA;;;" + Widen(CurrentUserSid()) + L")(A;OICI;FA;;;SY)(A;OICI;FR;;;BA)";
    std::wstring base = EnsureDirectory(KnownFolder(FOLDERID_LocalAppData) + L"\\TELIPHONES");
    return EnsureDirectory(base + L"\\Staging", sddl.c_str());
}

bool verifySignature(const std::wstring& path, std::string& signer) {
    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = path.c_str();
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    if (status == ERROR_SUCCESS) {
        CRYPT_PROVIDER_DATA* provider = WTHelperProvDataFromStateData(data.hWVTStateData);
        CRYPT_PROVIDER_SGNR* sgnr = provider ? WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0) : nullptr;
        CRYPT_PROVIDER_CERT* cert = sgnr ? WTHelperGetProvCertFromChain(sgnr, 0) : nullptr;
        wchar_t name[256] = L"";
        if (cert && cert->pCert) CertGetNameStringW(cert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, 256);
        signer = Narrow(name);
    }
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    return status == ERROR_SUCCESS;
}

bool isElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated;
}

bool waitForState(const std::string& tunnelName, TunnelState wanted, DWORD timeoutMs) {
    ULONGLONG deadline = GetTickCount64() + timeoutMs;
    while (GetTickCount64() < deadline) {
        if (QueryTunnel(tunnelName) == wanted) return true;
        Sleep(250);
    }
    return QueryTunnel(tunnelName) == wanted;
}

void grantUserControl(SC_HANDLE service, const std::string& userSid) {
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(Widen(userSid).c_str(), &sid)) ThrowLastError("Invalid Windows user identity");
    PACL current = nullptr, updated = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    DWORD status = GetSecurityInfo(service, SE_SERVICE, DACL_SECURITY_INFORMATION, nullptr, nullptr, &current, nullptr, &descriptor);
    if (status == ERROR_SUCCESS) {
        EXPLICIT_ACCESS_W access{};
        // Lets the signed-in user stop and remove this one tunnel without another UAC prompt; it cannot start or reconfigure it.
        access.grfAccessPermissions = SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE | READ_CONTROL;
        access.grfAccessMode = GRANT_ACCESS;
        access.grfInheritance = NO_INHERITANCE;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_USER;
        access.Trustee.ptstrName = static_cast<LPWSTR>(sid);
        status = SetEntriesInAclW(1, &access, current, &updated);
        if (status == ERROR_SUCCESS) status = SetSecurityInfo(service, SE_SERVICE, DACL_SECURITY_INFORMATION, nullptr, nullptr, updated, nullptr);
    }
    if (updated) LocalFree(updated);
    if (descriptor) LocalFree(descriptor);
    LocalFree(sid);
    if (status != ERROR_SUCCESS) ThrowLastError("Unable to delegate tunnel disconnection", status);
}

DWORD elevatedUninstall(const WireGuardInstallation& wireguard, const std::string& tunnelName) {
    if (QueryTunnel(tunnelName) != TunnelState::Absent) {
        RunProcess(wireguard.wireguardExe, {"/uninstalltunnelservice", tunnelName}, "", 30000);
        if (!waitForState(tunnelName, TunnelState::Absent, 15000)) return kHelperRemoveFailed;
    }
    if (!DeleteFileW((tunnelFolder() + L"\\" + Widen(tunnelName) + L".conf").c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND &&
        GetLastError() != ERROR_PATH_NOT_FOUND) return kHelperRemoveFailed;
    return kHelperOk;
}

DWORD helperUp(const HelperCommand& command) {
    WireGuardInstallation wireguard = FindWireGuard();
    if (!wireguard.installed || !wireguard.trusted) return kHelperWireGuardUnavailable;
    std::string privateKey = receiveKey(command.keyPipe);
    WipeString privateKeyWiper(privateKey);
    std::wstring staging = Widen(command.stagingPath);
    std::string canonical;
    try {
        std::string text = ReadSmallFile(staging, 8192);
        WipeString textWiper(text);
        TunnelConfig parsed = ParseTunnelStrict(text);
        WipeTunnelKey parsedKeyWiper(parsed);
        // Legacy plaintext configurations are never a permitted helper input.
        ValidateBootstrapTunnel(parsed);
        canonical = RenderTunnel(parsed);
    } catch (const Error&) {
        DeleteFileW(staging.c_str());
        return kHelperConfigRejected;
    }
    WipeString canonicalWiper(canonical);
    DeleteFileW(staging.c_str());

    if (elevatedUninstall(wireguard, command.tunnelName) != kHelperOk) {
        return kHelperRemoveFailed;
    }
    std::wstring configPath;
    try {
        EnsureDirectory(KnownFolder(FOLDERID_ProgramFiles) + L"\\TELIPHONES", L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)");
        configPath = EnsureDirectory(tunnelFolder(), kTunnelFolderSddl) + L"\\" + Widen(command.tunnelName) + L".conf";
        std::wstring fileSddl = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;SD;;;" + Widen(command.userSid) + L")";
        WriteNewFile(configPath, canonical, fileSddl.c_str());
    } catch (const Error&) {
        return kHelperInstallFailed;
    }

    ProcessResult installed = RunProcess(wireguard.wireguardExe, {"/installtunnelservice", Narrow(configPath)}, "", 60000);
    if (installed.exitCode != 0 || QueryTunnel(command.tunnelName) == TunnelState::Absent) {
        DeleteFileW(configPath.c_str());
        return kHelperInstallFailed;
    }
    try {
        ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        ServiceHandle service(manager ? OpenServiceW(manager.get(), serviceName(command.tunnelName).c_str(),
                                                     SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_QUERY_STATUS | READ_CONTROL | WRITE_DAC)
                                      : nullptr);
        if (!service) ThrowLastError("Unable to open the tunnel service");
        // Do not reconnect automatically at boot; TELIPHONES connections are started explicitly.
        if (!ChangeServiceConfigW(service.get(), SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr,
                                  nullptr, nullptr)) {
            ThrowLastError("Unable to configure the tunnel service");
        }
        grantUserControl(service.get(), command.userSid);
        if (QueryTunnel(command.tunnelName) != TunnelState::Running && !StartServiceW(service.get(), 0, nullptr) &&
            GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            ThrowLastError("Unable to start the tunnel service");
        }
    } catch (const Error&) {
        elevatedUninstall(wireguard, command.tunnelName);
        return kHelperPermissionsFailed;
    }
    if (!waitForState(command.tunnelName, TunnelState::Running, 20000)) {
        elevatedUninstall(wireguard, command.tunnelName);
        return kHelperStartFailed;
    }
    try {
        activateKey(command.tunnelName, privateKey);
    } catch (...) {
        elevatedUninstall(wireguard, command.tunnelName);
        return kHelperStartFailed;
    }
    return kHelperOk;
}

DWORD runElevated(const std::vector<std::string>& arguments, KeyPipe* keyPipe = nullptr) {
    wchar_t self[MAX_PATH] = L"";
    DWORD length = GetModuleFileNameW(nullptr, self, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) ThrowLastError("Unable to locate TELIPHONES");
    std::wstring parameters = Widen(JoinCommandLine(arguments));
    SHELLEXECUTEINFOW execute{};
    execute.cbSize = sizeof(execute);
    execute.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    execute.lpVerb = L"runas";
    execute.lpFile = self;
    execute.lpParameters = parameters.c_str();
    execute.nShow = SW_HIDE;
    if (!ShellExecuteExW(&execute)) {
        DWORD error = GetLastError();
        if (error == ERROR_CANCELLED) return ERROR_CANCELLED;
        ThrowLastError("Windows could not start the TELIPHONES tunnel helper", error);
    }
    if (!execute.hProcess) throw Error("Windows did not start the TELIPHONES tunnel helper.");
    Handle process(execute.hProcess);
    try {
        if (keyPipe) keyPipe->deliver(process.get());
    } catch (...) {
        TerminateProcess(process.get(), kHelperStartFailed);
        WaitForSingleObject(process.get(), 10000);
        throw;
    }
    DWORD wait = WaitForSingleObject(execute.hProcess, 180000);
    DWORD exitCode = 1;
    GetExitCodeProcess(execute.hProcess, &exitCode);
    if (wait != WAIT_OBJECT_0) {
        TerminateProcess(process.get(), kHelperStartFailed);
        WaitForSingleObject(process.get(), 10000);
        throw Error("The TELIPHONES tunnel helper did not finish in time.");
    }
    return exitCode;
}

std::string helperMessage(DWORD code) {
    switch (code) {
        case kHelperConfigRejected: return "The tunnel helper rejected the connection settings. Nothing was installed.";
        case kHelperWireGuardUnavailable: return "WireGuard for Windows is not installed or its signature could not be verified.";
        case kHelperInstallFailed: return "WireGuard for Windows could not install the tunnel. Check that WireGuard for Windows is up to date.";
        case kHelperPermissionsFailed: return "The tunnel could not be configured safely and was removed.";
        case kHelperNotElevated: return "Administrative approval is required to start a WireGuard tunnel.";
        case kHelperStartFailed: return "The WireGuard tunnel did not start and was removed. Another VPN or a conflicting address may be in use.";
        case kHelperRemoveFailed: return "An earlier TELIPHONES tunnel could not be removed. Remove it in WireGuard for Windows, then try again.";
        default: return "The TELIPHONES tunnel helper failed (code " + std::to_string(code) + ").";
    }
}

}  // namespace

WireGuardInstallation FindWireGuard() {
    WireGuardInstallation result;
    std::wstring folder = KnownFolder(FOLDERID_ProgramFiles) + L"\\WireGuard";
    result.wireguardExe = folder + L"\\wireguard.exe";
    result.wgExe = folder + L"\\wg.exe";
    DWORD a = GetFileAttributesW(result.wireguardExe.c_str()), b = GetFileAttributesW(result.wgExe.c_str());
    result.installed = a != INVALID_FILE_ATTRIBUTES && b != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY) && !(b & FILE_ATTRIBUTE_DIRECTORY);
    if (!result.installed) {
        result.problem = "WireGuard for Windows is not installed. Ask a Windows administrator to install it from the official WireGuard website "
                         "(https://www.wireguard.com/install/), then restart TELIPHONES.";
        return result;
    }
    std::string wgSigner;
    result.trusted = verifySignature(result.wireguardExe, result.signer) && verifySignature(result.wgExe, wgSigner);
    if (!result.trusted) result.problem = "The installed WireGuard for Windows files do not have a valid digital signature. Reinstall WireGuard for Windows from the official website.";
    return result;
}

std::string GeneratePrivateKey(const WireGuardInstallation& wireguard) {
    if (!wireguard.installed || !wireguard.trusted) throw Error(wireguard.problem);
    ProcessResult result = RunProcess(wireguard.wgExe, {"genkey"}, "", 10000);
    std::string key = result.output.substr(0, result.output.find_first_of("\r\n"));
    SecureWipe(result.output);
    if (result.exitCode != 0 || !IsWireGuardKey(key)) {
        SecureWipe(key);
        throw Error("WireGuard could not generate a key.");
    }
    return key;
}

std::string DerivePublicKey(const WireGuardInstallation& wireguard, const std::string& privateKey) {
    if (!wireguard.installed || !wireguard.trusted) throw Error(wireguard.problem);
    std::string input = privateKey + "\n";
    WipeString inputWiper(input);
    ProcessResult result = RunProcess(wireguard.wgExe, {"pubkey"}, input, 10000);
    std::string key = result.output.substr(0, result.output.find_first_of("\r\n"));
    if (result.exitCode != 0 || !IsWireGuardKey(key)) throw Error("WireGuard could not derive the public key.");
    return key;
}

TunnelState QueryTunnel(const std::string& tunnelName) {
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager) return TunnelState::Unknown;
    ServiceHandle service(OpenServiceW(manager.get(), serviceName(tunnelName).c_str(), SERVICE_QUERY_STATUS));
    if (!service) return GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST ? TunnelState::Absent : TunnelState::Unknown;
    SERVICE_STATUS status{};
    if (!QueryServiceStatus(service.get(), &status)) return TunnelState::Unknown;
    switch (status.dwCurrentState) {
        case SERVICE_RUNNING: return TunnelState::Running;
        case SERVICE_STOPPED: return TunnelState::Stopped;
        case SERVICE_START_PENDING: return TunnelState::Starting;
        case SERVICE_STOP_PENDING: return TunnelState::Stopping;
        default: return TunnelState::Unknown;
    }
}

bool InstallTunnel(const std::string& tunnelName, const std::string& configText) {
    TunnelConfig parsed = ParseTunnelStrict(configText);
    WipeTunnelKey parsedKeyWiper(parsed);
    std::string canonical = RenderBootstrapTunnel(parsed);
    WipeString canonicalWiper(canonical);
    std::wstring path = stagingFolder() + L"\\" + Widen(tunnelName) + L".conf";
    std::wstring sddl = L"D:P(A;;FA;;;" + Widen(CurrentUserSid()) + L")(A;;FA;;;SY)(A;;FR;;;BA)";
    WriteNewFile(path, canonical, sddl.c_str());
    DWORD code = 1;
    try {
        KeyPipe pipe(parsed.privateKey);
        HelperCommand command{HelperCommand::Verb::TunnelUp, tunnelName, Narrow(path), CurrentUserSid(), pipe.token};
        code = runElevated(HelperArguments(command), &pipe);
    } catch (...) {
        DeleteFileW(path.c_str());
        RemoveTunnel(tunnelName);
        throw;
    }
    DeleteFileW(path.c_str());
    if (code == ERROR_CANCELLED) return false;
    if (code != kHelperOk) throw Error(helperMessage(code));
    return true;
}

void RemoveTunnel(const std::string& tunnelName) {
    const auto staging = KnownFolder(FOLDERID_LocalAppData) + L"\\TELIPHONES\\Staging\\" + Widen(tunnelName) + L".conf";
    if (!DeleteFileW(staging.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND)
        ThrowLastError("Unable to remove the staged tunnel configuration");
    bool removed = false;
    {
        ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        ServiceHandle service(manager ? OpenServiceW(manager.get(), serviceName(tunnelName).c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE) : nullptr);
        if (manager && !service && GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
            removed = true;
        } else if (service) {
            SERVICE_STATUS status{};
            ControlService(service.get(), SERVICE_CONTROL_STOP, &status);
            ULONGLONG deadline = GetTickCount64() + 15000;
            while (QueryServiceStatus(service.get(), &status) && status.dwCurrentState != SERVICE_STOPPED && GetTickCount64() < deadline) Sleep(250);
            removed = status.dwCurrentState == SERVICE_STOPPED && (DeleteService(service.get()) || GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE);
        }
    }
    if (removed) {
        if (DeleteFileW((tunnelFolder() + L"\\" + Widen(tunnelName) + L".conf").c_str()) || GetLastError() == ERROR_FILE_NOT_FOUND ||
            GetLastError() == ERROR_PATH_NOT_FOUND) return;
    }
    DWORD code = runElevated(HelperArguments(HelperCommand{HelperCommand::Verb::TunnelDown, tunnelName, "", "", ""}));
    if (code == ERROR_CANCELLED) throw Error("The tunnel is still connected because administrative approval was declined. Disconnect again, or stop it in WireGuard for Windows.");
    if (code != kHelperOk) throw Error(helperMessage(code));
}

bool IsHelperInvocation(const std::vector<std::string>& arguments) {
    return !arguments.empty() && (arguments[0] == "/tunnel-up" || arguments[0] == "/tunnel-down");
}

int RunTunnelHelper(const std::vector<std::string>& arguments) {
    HelperCommand command;
    try {
        command = ParseHelperArguments(arguments);
    } catch (const Error&) {
        return static_cast<int>(kHelperArguments);
    }
    if (!isElevated()) return static_cast<int>(kHelperNotElevated);
    DWORD code = kHelperOk;
    try {
        if (command.verb == HelperCommand::Verb::TunnelUp) {
            code = helperUp(command);
        } else {
            WireGuardInstallation wireguard = FindWireGuard();
            code = !wireguard.installed || !wireguard.trusted ? kHelperWireGuardUnavailable : elevatedUninstall(wireguard, command.tunnelName);
        }
    } catch (const Error&) {
        code = command.verb == HelperCommand::Verb::TunnelUp ? kHelperInstallFailed : kHelperRemoveFailed;
    }
    return static_cast<int>(code);
}

}  // namespace win
}  // namespace tlp
