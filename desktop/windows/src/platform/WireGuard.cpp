#include "WireGuard.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include "WireGuardNt.h"
#include "Win.h"
#include "TunnelStartup.h"

#include <aclapi.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <softpub.h>
#include <wintrust.h>

#include <memory>

#include "../core/CommandLine.h"
#include "../core/Json.h"
#include "../core/TunnelConfig.h"
#include "../core/TunnelLifecycle.h"
#include "../core/Validation.h"

namespace tlp {
namespace win {
namespace {

namespace lifecycle = tunnel_lifecycle;
namespace budget = tunnel_lifecycle::budget;
using lifecycle::Stage;
static_assert(static_cast<std::uint32_t>(IfOperStatusNotPresent) == lifecycle::kInterfaceOperStatusNotPresent,
              "Portable adapter classification must match the Windows interface status");

constexpr DWORD kHelperOk = 0;

DWORD helperCode(Stage stage, DWORD error = 0) {
    lifecycle::HelperResult result;
    result.stage = stage;
    result.error = error;
    return lifecycle::EncodeHelperResult(result);
}

// The caller stopped waiting for a helper that is still running. Its outcome is unknown, so the caller must
// not start a competing cleanup helper for the same tunnel.
struct HelperStillRunning : Error {
    explicit HelperStillRunning(const std::string& message) : Error(message) {}
};

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

struct PipeTransferFailure : Error {
    DWORD code;
    PipeTransferFailure(const char* message, DWORD error) : Error(message), code(error) {}
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
            const DWORD error = GetLastError();
            if (error != ERROR_IO_PENDING) throw PipeTransferFailure("Tunnel key IPC failed.", error);
            const DWORD wait = WaitForSingleObject(event.get(), 10000);
            if (wait != WAIT_OBJECT_0) {
                const DWORD waitError = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
                CancelIoEx(pipe, &operation);
                GetOverlappedResult(pipe, &operation, &count, TRUE);
                throw PipeTransferFailure("Tunnel key IPC wait failed.", waitError);
            }
            if (!GetOverlappedResult(pipe, &operation, &count, FALSE))
                throw PipeTransferFailure("Tunnel key IPC failed.", GetLastError());
        }
        if (!count) throw PipeTransferFailure("Tunnel key IPC closed unexpectedly.", ERROR_BROKEN_PIPE);
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
    // Returns false when the helper exited before connecting; it changed nothing and its exit code explains why.
    bool deliver(HANDLE helper) {
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
                if (result == WAIT_OBJECT_0 + 1) return false;
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
        return true;
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

std::wstring tunnelConfigPath(const std::string& tunnelName) { return tunnelFolder() + L"\\" + Widen(tunnelName) + L".conf"; }

lifecycle::Residual residualFor(const tunnel_startup::Status& status) {
    switch (status.state) {
        case SERVICE_STOPPED: return lifecycle::Residual::Stopped;
        case SERVICE_START_PENDING: return lifecycle::Residual::StartPending;
        case SERVICE_STOP_PENDING: return lifecycle::Residual::StopPending;
        case SERVICE_RUNNING: return lifecycle::Residual::Running;
        default: return tunnel_startup::Absent(status) ? lifecycle::Residual::None : lifecycle::Residual::Unknown;
    }
}

lifecycle::AdapterPresence awaitAdapterRelease(const std::string& tunnelName) {
    return lifecycle::AwaitAdapterRelease([&] { return TunnelAdapterPresence(tunnelName); }, [] { return GetTickCount64(); },
                                          [](std::uint32_t ms) { Sleep(ms); }, budget::kAdapterReleaseMs);
}

lifecycle::Residual adapterResidual(lifecycle::AdapterPresence presence) {
    return presence == lifecycle::AdapterPresence::Active ? lifecycle::Residual::AdapterOnly
                                                          : lifecycle::Residual::AdapterUnverified;
}

// Removes only this TELIPHONES tunnel: its official WireGuard service, its adapter and its bootstrap file.
// A service stuck in START_PENDING cannot be stopped through the SCM, so its own wireguard.exe process is
// terminated, but only after the SCM binary path and process image prove it is this tunnel's service.
lifecycle::HelperResult removeOwnedTunnel(const WireGuardInstallation& wireguard, const std::string& tunnelName) {
    lifecycle::HelperResult outcome;
    try {
        const auto service = serviceName(tunnelName);
        const auto configPath = tunnelConfigPath(tunnelName);
        auto status = tunnel_startup::ReadStatus(service);
        if (!tunnel_startup::Absent(status)) {
            try {
                RunProcess(wireguard.wireguardExe, {"/uninstalltunnelservice", tunnelName}, "", budget::kUninstallToolMs);
            } catch (const Error&) {
                // The SCM state below decides the outcome; a stuck service can also stall the official tool.
            }
            tunnel_startup::RequestRemoval(service);
            status = tunnel_startup::AwaitAbsent(service, budget::kRemovalWaitMs);
        }
        if (!tunnel_startup::Absent(status) && status.processId != 0) {
            const auto expectedExe = Narrow(wireguard.wireguardExe);
            const auto expectedConfig = Narrow(configPath);
            const auto termination = tunnel_startup::TerminateOwnedServiceProcess(
                service,
                [&](const std::wstring& binaryPath, const std::wstring& image) {
                    return lifecycle::IsOwnedTunnelServiceCommand(Narrow(binaryPath), expectedExe, expectedConfig) &&
                           lifecycle::SameWindowsPath(Narrow(image), expectedExe);
                },
                budget::kProcessExitMs);
            outcome.ownershipUnverified = termination.outcome == tunnel_startup::Termination::NotOwned;
            outcome.processSurvived = termination.outcome == tunnel_startup::Termination::Survived;
            if (termination.outcome == tunnel_startup::Termination::Failed) outcome.error = termination.error;
            tunnel_startup::RequestRemoval(service);
            status = tunnel_startup::AwaitAbsent(service, budget::kDeletionWaitMs);
        }
        if (!tunnel_startup::Absent(status)) {
            outcome.cleanupIncomplete = true;
            outcome.residual = residualFor(status);
            return outcome;
        }
        const auto adapter = awaitAdapterRelease(tunnelName);
        status = tunnel_startup::ReadStatus(service);
        if (!tunnel_startup::Absent(status)) {
            outcome.cleanupIncomplete = true;
            outcome.residual = residualFor(status);
            outcome.error = status.error;
        } else if (adapter != lifecycle::AdapterPresence::Absent) {
            outcome.cleanupIncomplete = true;
            outcome.residual = adapterResidual(adapter);
            if (adapter == lifecycle::AdapterPresence::Active) outcome.error = ERROR_TIMEOUT;
        }
        if (!DeleteFileW(configPath.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND) {
            outcome.cleanupIncomplete = true;
            outcome.configRemains = true;
        }
    } catch (const std::exception&) {
        outcome.cleanupIncomplete = true;
        outcome.residual = lifecycle::Residual::Unknown;
    }
    if (!outcome.cleanupIncomplete) return {};
    return outcome;
}

DWORD helperUp(const HelperCommand& command) {
    WireGuardInstallation wireguard = FindWireGuard();
    if (!wireguard.installed || !wireguard.trusted) return helperCode(Stage::WireGuardUnavailable);
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
        return helperCode(Stage::ConfigRejected);
    }
    WipeString canonicalWiper(canonical);
    DeleteFileW(staging.c_str());

    tunnel_startup::HelperLock lock(tunnel_startup::HelperLockName(Widen(command.tunnelName)));
    if (!lock.owned()) return helperCode(Stage::Busy);
    // An earlier instance (including one stuck in START_PENDING) must be gone, with its adapter, before reuse.
    auto earlier = removeOwnedTunnel(wireguard, command.tunnelName);
    if (earlier.cleanupIncomplete) {
        earlier.stage = Stage::ResidualTunnel;
        return lifecycle::EncodeHelperResult(earlier);
    }
    // Every later failure reports its own stage and Windows error together with the cleanup outcome.
    auto fail = [&](Stage stage, DWORD error) {
        auto result = removeOwnedTunnel(wireguard, command.tunnelName);
        result.stage = stage;
        result.error = error;
        return lifecycle::EncodeHelperResult(result);
    };
    std::wstring configPath;
    try {
        EnsureDirectory(KnownFolder(FOLDERID_ProgramFiles) + L"\\TELIPHONES", L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)");
        configPath = EnsureDirectory(tunnelFolder(), kTunnelFolderSddl) + L"\\" + Widen(command.tunnelName) + L".conf";
        std::wstring fileSddl = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;SD;;;" + Widen(command.userSid) + L")";
        WriteNewFile(configPath, canonical, fileSddl.c_str());
    } catch (const Error&) {
        return fail(Stage::InstallFailed, 0);
    }

    ProcessResult installed;
    try {
        installed = RunProcess(wireguard.wireguardExe, {"/installtunnelservice", Narrow(configPath)}, "", budget::kInstallToolMs);
    } catch (const Error&) {
        return fail(Stage::InstallFailed, 0);
    }
    if (installed.exitCode != 0) return fail(Stage::InstallFailed, 0);
    try {
        tunnel_startup::WaitForService(serviceName(command.tunnelName), false, budget::kServiceRegisteredMs);
    } catch (const tunnel_startup::Failure& error) {
        return fail(Stage::StartFailed, error.code);
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
        const auto status = tunnel_startup::ReadStatus(serviceName(command.tunnelName));
        if (status.state == 0) ThrowLastError("Cannot query the tunnel service", status.error);
        if (status.state == SERVICE_STOPPED && !StartServiceW(service.get(), 0, nullptr) &&
            GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            ThrowLastError("Unable to start the tunnel service");
        }
    } catch (const Error&) {
        return fail(Stage::PermissionsFailed, 0);
    }
    try {
        tunnel_startup::WaitForService(serviceName(command.tunnelName), true, budget::kServiceRunningMs);
    } catch (const tunnel_startup::Failure& error) {
        return fail(Stage::StartFailed, error.code);
    }
    try {
        wireguard_nt::Api api(wireguard_nt::PrepareLibrary());
        api.activateKey(Widen(command.tunnelName), privateKey);
    } catch (const wireguard_nt::Failure& error) {
        const auto stage = error.stage == wireguard_nt::Stage::Dependency ? Stage::DependencyFailed :
                           error.stage == wireguard_nt::Stage::Adapter ? Stage::AdapterFailed : Stage::KeyFailed;
        return fail(stage, error.code);
    } catch (const Error&) {
        return fail(Stage::DependencyFailed, 0);
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
        // A helper that exits before requesting the key has changed nothing; its own exit code explains why.
        if (keyPipe) keyPipe->deliver(process.get());
    } catch (...) {
        // The helper has not yet taken the tunnel lock or changed any tunnel state.
        TerminateProcess(process.get(), helperCode(Stage::InstallFailed));
        WaitForSingleObject(process.get(), 10000);
        throw;
    }
    if (WaitForSingleObject(process.get(), budget::kHelperWaitMs) != WAIT_OBJECT_0) {
        // Every helper step is bounded within this wait. Interrupting it now could orphan wireguard.exe or
        // leave a half-configured service, so it is left to finish and no competing cleanup is started.
        throw HelperStillRunning("The TELIPHONES tunnel helper is still running after " +
                                 std::to_string(budget::kHelperWaitMs / 60000) +
                                 " minutes, so the tunnel state is unknown. TELIPHONES did not interrupt it. "
                                 "Restart TELIPHONES after it finishes to check for a remaining tunnel.");
    }
    DWORD exitCode = 1;
    if (!GetExitCodeProcess(process.get(), &exitCode)) ThrowLastError("Cannot read the TELIPHONES tunnel helper result");
    return exitCode;
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
    SERVICE_STATUS_PROCESS status{};
    DWORD size = 0;
    if (!QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &size))
        return TunnelState::Unknown;
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
    } catch (const HelperStillRunning&) {
        DeleteFileW(path.c_str());
        throw;
    } catch (const std::exception& error) {
        DeleteFileW(path.c_str());
        // Report the original failure; a cleanup failure is appended rather than replacing it.
        const std::string original = error.what();
        try {
            RemoveTunnel(tunnelName);
        } catch (const std::exception& cleanup) {
            throw Error(original + " Removing the partially started tunnel also failed: " + cleanup.what());
        }
        throw;
    }
    DeleteFileW(path.c_str());
    if (code == ERROR_CANCELLED) return false;
    if (code != kHelperOk) throw Error(lifecycle::HelperMessage(code));
    return true;
}

void RemoveTunnel(const std::string& tunnelName) {
    std::unique_ptr<tunnel_startup::HelperLock> lock;
    try {
        lock = std::make_unique<tunnel_startup::HelperLock>(tunnel_startup::HelperLockName(Widen(tunnelName)));
    } catch (const tunnel_startup::Failure& failure) {
        // An existing administrator-only lock must be acquired by the elevated helper, not bypassed.
        if (failure.code != ERROR_ACCESS_DENIED) throw;
    }
    if (lock && !lock->owned()) throw Error(lifecycle::HelperMessage(helperCode(Stage::Busy)));
    if (lock) {
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
                // START_PENDING rejects SERVICE_CONTROL_STOP (Windows error 1052), so waiting here cannot succeed;
                // only the elevated helper can verify and end a stuck service process.
                if (QueryServiceStatus(service.get(), &status) && status.dwCurrentState != SERVICE_START_PENDING) {
                    ControlService(service.get(), SERVICE_CONTROL_STOP, &status);
                    ULONGLONG deadline = GetTickCount64() + 15000;
                    while (QueryServiceStatus(service.get(), &status) && status.dwCurrentState != SERVICE_STOPPED && GetTickCount64() < deadline) Sleep(250);
                    removed = status.dwCurrentState == SERVICE_STOPPED && (DeleteService(service.get()) || GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE);
                }
            }
        }
        if (removed)
            removed = tunnel_startup::Absent(tunnel_startup::AwaitAbsent(serviceName(tunnelName), budget::kDeletionWaitMs));
        if (removed) {
            if (DeleteFileW((tunnelFolder() + L"\\" + Widen(tunnelName) + L".conf").c_str()) || GetLastError() == ERROR_FILE_NOT_FOUND ||
                GetLastError() == ERROR_PATH_NOT_FOUND) {
                // A disconnect is complete only once the adapter is released too; the next connection depends on it.
                const auto adapter = awaitAdapterRelease(tunnelName);
                const auto current = tunnel_startup::ReadStatus(serviceName(tunnelName));
                if (tunnel_startup::Absent(current) && adapter == lifecycle::AdapterPresence::Absent) return;
                lifecycle::HelperResult result;
                result.stage = Stage::RemoveFailed;
                result.cleanupIncomplete = true;
                if (!tunnel_startup::Absent(current)) {
                    result.residual = residualFor(current);
                    result.error = current.error;
                } else {
                    result.residual = adapterResidual(adapter);
                    if (adapter == lifecycle::AdapterPresence::Active) result.error = ERROR_TIMEOUT;
                }
                throw Error(lifecycle::HelperMessage(lifecycle::EncodeHelperResult(result)));
            }
        }
    }
    lock.reset();
    DWORD code = runElevated(HelperArguments(HelperCommand{HelperCommand::Verb::TunnelDown, tunnelName, "", "", ""}));
    if (code == ERROR_CANCELLED) throw Error("The tunnel is still connected because administrative approval was declined. Disconnect again, or stop it in WireGuard for Windows.");
    if (code != kHelperOk) throw Error(lifecycle::HelperMessage(code));
}

lifecycle::AdapterPresence TunnelAdapterPresence(const std::string& tunnelName) {
    PMIB_IF_TABLE2 table = nullptr;
    if (GetIfTable2(&table) != NO_ERROR) return lifecycle::ClassifyTunnelAdapter(false, {}, tunnelName);
    const std::unique_ptr<MIB_IF_TABLE2, decltype(&FreeMibTable)> owned(table, &FreeMibTable);
    // The WireGuardNT adapter carries the tunnel's exact name as its interface alias.
    const auto alias = Widen(tunnelName);
    std::vector<lifecycle::InterfaceRow> rows;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        if (alias == table->Table[i].Alias) rows.push_back({tunnelName, static_cast<std::uint32_t>(table->Table[i].OperStatus)});
    }
    return lifecycle::ClassifyTunnelAdapter(true, rows, tunnelName);
}

AddressRoute RouteToAddress(const std::string& tunnelName, const std::string& ipv4Address) {
    AddressRoute result;
    std::uint32_t parsed = 0;
    if (!ParseIPv4(ipv4Address, parsed)) return result;
    // Filled byte by byte in network order; this file does not link Winsock.
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_addr.S_un.S_un_b.s_b1 = static_cast<UCHAR>(parsed >> 24);
    destination.sin_addr.S_un.S_un_b.s_b2 = static_cast<UCHAR>(parsed >> 16);
    destination.sin_addr.S_un.S_un_b.s_b3 = static_cast<UCHAR>(parsed >> 8);
    destination.sin_addr.S_un.S_un_b.s_b4 = static_cast<UCHAR>(parsed);
    DWORD index = 0;
    if (GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&destination), &index) != NO_ERROR) return result;
    MIB_IF_ROW2 row{};
    row.InterfaceIndex = index;
    if (GetIfEntry2(&row) != NO_ERROR) return result;
    const std::string alias = Narrow(row.Alias);
    if (alias == tunnelName) {
        result.route = RouteEvidence::ViaTunnel;
    } else {
        result.route = RouteEvidence::ViaOtherInterface;
        result.interfaceAlias = alias;
    }
    return result;
}

std::vector<std::string> ResidualTeliphonesTunnels(const std::vector<std::string>& installedSavedTunnels) {
    static const std::wstring servicePrefix = L"WireGuardTunnel$";
    std::vector<std::string> services;
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE));
    if (manager) {
        std::vector<BYTE> buffer;
        DWORD resume = 0;
        // Bounded: each pass either completes or grows the buffer to the size Windows reports.
        for (int pass = 0; pass < 16; ++pass) {
            DWORD needed = 0, count = 0;
            const BOOL done = EnumServicesStatusExW(manager.get(), SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                                    buffer.empty() ? nullptr : buffer.data(),
                                                    static_cast<DWORD>(buffer.size()), &needed, &count, &resume, nullptr);
            if (!done && GetLastError() != ERROR_MORE_DATA) break;
            const auto* entries = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
            for (DWORD i = 0; i < count; ++i) {
                const std::wstring name = entries[i].lpServiceName;
                if (name.compare(0, servicePrefix.size(), servicePrefix) == 0)
                    services.push_back(Narrow(name.substr(servicePrefix.size())));
            }
            if (done) break;
            if (needed > buffer.size()) buffer.resize(needed);
        }
    }
    std::vector<lifecycle::InterfaceRow> adapters;
    PMIB_IF_TABLE2 table = nullptr;
    const DWORD enumeration = GetIfTable2(&table);
    if (enumeration != NO_ERROR) ThrowLastError("Unable to enumerate residual TELIPHONES tunnel adapters", enumeration);
    {
        const std::unique_ptr<MIB_IF_TABLE2, decltype(&FreeMibTable)> owned(table, &FreeMibTable);
        for (ULONG i = 0; i < table->NumEntries; ++i) {
            const std::string alias = Narrow(table->Table[i].Alias);
            if (lifecycle::IsTeliphonesTunnelName(alias))
                adapters.push_back({alias, static_cast<std::uint32_t>(table->Table[i].OperStatus)});
        }
    }
    return lifecycle::StartupResidualTunnels(installedSavedTunnels, services, adapters);
}

bool IsHelperInvocation(const std::vector<std::string>& arguments) {
    return !arguments.empty() && (arguments[0] == "/tunnel-up" || arguments[0] == "/tunnel-down");
}

int RunTunnelHelper(const std::vector<std::string>& arguments) {
    HelperCommand command;
    try {
        command = ParseHelperArguments(arguments);
    } catch (const Error&) {
        return static_cast<int>(helperCode(Stage::Arguments));
    }
    if (!isElevated()) return static_cast<int>(helperCode(Stage::NotElevated));
    DWORD code = kHelperOk;
    try {
        if (command.verb == HelperCommand::Verb::TunnelUp) {
            code = helperUp(command);
        } else {
            WireGuardInstallation wireguard = FindWireGuard();
            if (!wireguard.installed || !wireguard.trusted) return static_cast<int>(helperCode(Stage::WireGuardUnavailable));
            tunnel_startup::HelperLock lock(tunnel_startup::HelperLockName(Widen(command.tunnelName)));
            if (!lock.owned()) return static_cast<int>(helperCode(Stage::Busy));
            auto removal = removeOwnedTunnel(wireguard, command.tunnelName);
            if (removal.cleanupIncomplete) removal.stage = Stage::RemoveFailed;
            code = lifecycle::EncodeHelperResult(removal);
        }
    } catch (const std::exception&) {
        code = helperCode(command.verb == HelperCommand::Verb::TunnelUp ? Stage::InstallFailed : Stage::RemoveFailed);
    }
    return static_cast<int>(code);
}

}  // namespace win
}  // namespace tlp
