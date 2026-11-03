#include "Ssh.h"
#include "SshAgent.h"
#include "Applications.h"
#include "Services.h"
#include "Win.h"
#include "../core/SshCrypto.h"
#include "../core/Validation.h"

#include <wincrypt.h>
#include <winhttp.h>
#include <sddl.h>
#include <filesystem>
#include <algorithm>
#include <memory>
#include <mutex>
#include <thread>

namespace tlp::win {
namespace {
class Handle {
public:
    explicit Handle(HANDLE value = nullptr) : value_(value) {}
    ~Handle() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
    HANDLE release() { const auto value = value_; value_ = nullptr; return value; }
    void reset(HANDLE value) {
        if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
        value_ = value;
    }
private:
    HANDLE value_;
};
class Internet {
public:
    explicit Internet(HINTERNET value) : value_(value) { if (!value) ThrowLastError("SSH certificate HTTP setup failed"); }
    ~Internet() { WinHttpCloseHandle(value_); }
    HINTERNET get() const { return value_; }
private:
    HINTERNET value_;
};
struct WipeString { std::string& value; ~WipeString() { SecureWipe(value); } };
struct WipeBytes { Bytes& value; ~WipeBytes() { if (!value.empty()) SecureZeroMemory(value.data(), value.size()); } };
std::wstring ownerAcl() { return L"D:P(A;;FA;;;SY)(A;;FA;;;" + Widen(CurrentUserSid()) + L")"; }
std::wstring sshRoot() {
    const auto application = EnsureDirectory(KnownFolder(FOLDERID_LocalAppData) + L"\\TELIPHONES");
    return EnsureDirectory(application + L"\\SSH", ownerAcl().c_str());
}
std::wstring executable() {
    wchar_t path[32768];
    const auto size = GetModuleFileNameW(nullptr, path, 32768);
    if (!size || size >= 32768) ThrowLastError("Unable to locate TELIPHONES executable");
    return std::wstring(path, size);
}
std::wstring consoleExecutable() {
#ifdef TELIPHONES_SSH_TESTING
    return executable();
#else
    return (std::filesystem::path(executable()).parent_path() / L"TELIPHONES-SSH.exe").wstring();
#endif
}
std::wstring controllerExecutable() {
#ifdef TELIPHONES_SSH_TESTING
    return executable();
#else
    return (std::filesystem::path(executable()).parent_path() / L"TELIPHONES.exe").wstring();
#endif
}
std::wstring processImage(HANDLE process) {
    wchar_t path[32768];
    DWORD size = 32768;
    if (!QueryFullProcessImageNameW(process, 0, path, &size)) ThrowLastError("Unable to verify SSH process image");
    return std::wstring(path, size);
}
std::wstring identityFile(const Profile& profile) {
    if (!IsProfileId(profile.id)) throw Error("Invalid SSH workstation profile.");
    return KnownFolder(FOLDERID_LocalAppData) + L"\\TELIPHONES\\SSH\\" + Widen(profile.id) + L".dpapi";
}
std::unique_ptr<SshSigningKey> loadIdentity(const Profile& profile) {
    auto encrypted = ReadSmallFile(identityFile(profile), 8192);
    DATA_BLOB input{static_cast<DWORD>(encrypted.size()), reinterpret_cast<BYTE*>(encrypted.data())}, output{};
    if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output))
        ThrowLastError("Unable to unlock the permanent workstation identity");
    struct ClearBlob {
        DATA_BLOB& blob;
        ~ClearBlob() { SecureZeroMemory(blob.pbData, blob.cbData); LocalFree(blob.pbData); }
    } clear{output};
    std::string stored(reinterpret_cast<char*>(output.pbData), output.cbData);
    WipeString wipe{stored};
    auto seed = WorkstationIdentitySeed(stored);
    WipeBytes wipeSeed{seed};
    auto key = std::make_unique<SshSigningKey>(seed);
    if (key->publicKey() != profile.pairing.sshPublicKey) throw Error("Saved workstation identity does not match the paired key.");
    return key;
}
json::Value request(const Profile& profile, const std::string& method, const std::string& path, const std::string& body = "") {
    Internet session(WinHttpOpen(L"TELIPHONES SSH", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!WinHttpSetTimeouts(session.get(), 5000, 5000, 10000, 10000)) ThrowLastError("Unable to bound SSH certificate HTTP timeouts");
    Internet connection(WinHttpConnect(session.get(), Widen(profile.pairing.pbxAddress).c_str(),
                                        static_cast<INTERNET_PORT>(profile.pairing.sshApiPort), 0));
    Internet http(WinHttpOpenRequest(connection.get(), Widen(method).c_str(), Widen(path).c_str(), nullptr,
                                   WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0));
    DWORD disable = WINHTTP_DISABLE_REDIRECTS;
    if (!WinHttpSetOption(http.get(), WINHTTP_OPTION_DISABLE_FEATURE, &disable, sizeof(disable)))
        ThrowLastError("Unable to disable SSH certificate HTTP redirects");
    if (!WinHttpSendRequest(http.get(), L"Content-Type: application/json\r\n", static_cast<DWORD>(-1L),
                            body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
                            static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0) ||
        !WinHttpReceiveResponse(http.get(), nullptr)) ThrowLastError("SSH certificate endpoint did not respond through WireGuard");
    DWORD status = 0, size = sizeof(status);
    if (!WinHttpQueryHeaders(http.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                             &status, &size, WINHTTP_NO_HEADER_INDEX)) ThrowLastError("Unable to read SSH certificate HTTP status");
    std::string response;
    for (;;) {
        char buffer[4096];
        DWORD count = 0;
        if (!WinHttpReadData(http.get(), buffer, sizeof(buffer), &count)) ThrowLastError("Unable to read SSH certificate response");
        if (!count) break;
        if (response.size() + count > 16384) throw Error("Oversized SSH certificate response.");
        response.append(buffer, count);
    }
    if (status != 200) throw Error("SSH certificate issuance was refused (HTTP " + std::to_string(status) +
                                   "). Check workstation approval, expiry and PBX readiness.");
    return json::Parse(response, 16384);
}
bool hex(const std::string& value, std::size_t size) {
    return value.size() == size && value.find_first_not_of("0123456789abcdef") == std::string::npos;
}
std::string certificate(const Profile& profile, const SshSessionPublicKey& session) {
    auto challenge = request(profile, "GET", "/ssh/challenge?workstation_id=" + profile.pairing.workstationId);
    json::RequireExactKeys(challenge, {"schema", "workstation_id", "challenge", "expires_at"}, "SSH challenge");
    const auto nonce = challenge.at("challenge").asString();
    const auto expiry = challenge.at("expires_at").asInteger();
    if (challenge.at("schema").asString() != "teliphones-ssh-challenge/1" ||
        challenge.at("workstation_id").asString() != profile.pairing.workstationId ||
        !hex(nonce, 64) || expiry <= UnixNow() || expiry > UnixNow() + 35) throw Error("Invalid SSH challenge binding.");
    auto identity = loadIdentity(profile);
    const auto message = "TELIPHONES-SSH-REQUEST-2\n" + profile.pairing.workstationId + "\n" + nonce + "\n" +
                         session.id + "\n" + session.publicKey + "\n";
    const auto signature = SignSshChallenge(*identity, message);
    identity.reset();
    const auto body = json::Serialize(json::Value::Object{
        {"schema", "teliphones-ssh-request/2"}, {"workstation_id", profile.pairing.workstationId}, {"challenge", nonce},
        {"session_id", session.id}, {"ssh_public_key", session.publicKey}, {"signature", signature}});
    const auto response = request(profile, "POST", "/ssh/certificate", body);
    json::RequireExactKeys(response, {"schema", "workstation_id", "session_id", "ssh_public_key", "certificate", "expires_at",
                                     "ssh_user", "ssh_host_key", "ssh_ca_key", "ssh_port"}, "SSH certificate response");
    if (response.at("schema").asString() != "teliphones-ssh-certificate/2" ||
        response.at("workstation_id").asString() != profile.pairing.workstationId ||
        response.at("session_id").asString() != session.id || response.at("ssh_public_key").asString() != session.publicKey ||
        response.at("ssh_user").asString() != profile.pairing.sshUser ||
        response.at("ssh_host_key").asString() != profile.pairing.sshHostKey ||
        response.at("ssh_ca_key").asString() != profile.pairing.sshCaKey ||
        response.at("ssh_port").asInteger() != profile.pairing.sshPort) throw Error("SSH response differs from the approved pairing.");
    const auto result = response.at("certificate").asString();
    ValidateSshCertificateBindings(result, profile.pairing, session, UnixNow(), response.at("expires_at").asInteger());
    VerifySshCertificateSignature(result, profile.pairing.sshCaKey);
    return result;
}
std::string quoted(const std::wstring& path) {
    std::string result = "\"";
    for (const auto c : Narrow(path)) {
        if (c == '\\' || c == '"') result += '\\';
        if (c == '\r' || c == '\n') throw Error("Invalid SSH configuration path.");
        result += c;
    }
    return result + "\"";
}
void transfer(HANDLE pipe, void* data, DWORD size, bool writing, DWORD timeout = 30000) {
    auto* bytes = static_cast<unsigned char*>(data);
    DWORD total = 0;
    while (total < size) {
        Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!event.get()) ThrowLastError("Unable to create SSH control event");
        OVERLAPPED operation{};
        operation.hEvent = event.get();
        DWORD count = 0;
        const auto ok = writing ? WriteFile(pipe, bytes + total, size - total, &count, &operation) :
                                  ReadFile(pipe, bytes + total, size - total, &count, &operation);
        if (!ok) {
            if (GetLastError() != ERROR_IO_PENDING) ThrowLastError("SSH terminal control channel failed");
            if (WaitForSingleObject(event.get(), timeout) != WAIT_OBJECT_0) {
                CancelIoEx(pipe, &operation);
                GetOverlappedResult(pipe, &operation, &count, TRUE);
                throw Error("SSH terminal control channel timed out.");
            }
            if (!GetOverlappedResult(pipe, &operation, &count, FALSE)) ThrowLastError("SSH terminal control transfer failed");
        }
        if (!count) throw Error("SSH terminal control channel closed.");
        total += count;
    }
}
void send(HANDLE pipe, const std::string& text) {
    auto frame = SshField(text);
    transfer(pipe, frame.data(), static_cast<DWORD>(frame.size()), true);
}
std::string receive(HANDLE pipe) {
    Bytes header(4);
    transfer(pipe, header.data(), 4, false);
    SshWireReader reader(header);
    const auto size = reader.number();
    if (!size || size > 16384) throw Error("Invalid SSH terminal control message size.");
    std::string body(size, '\0');
    transfer(pipe, body.data(), size, false);
    return body;
}
struct Session {
    std::string profile;
    std::string diagnosticId;
    Handle job{CreateJobObjectW(nullptr, nullptr)};
    Handle helper;
    Handle ssh;
    Handle stop{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    Handle finished{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    std::unique_ptr<SshAgent> agent;
    std::wstring directory;
    std::int64_t expiry = 0;
    void removePublicArtifacts() {
        if (directory.empty()) return;
        for (const auto* name : {L"identity.pub", L"certificate.pub", L"config", L"known_hosts"}) {
            const auto path = directory + L"\\" + name;
            if (!DeleteFileW(path.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND)
                ThrowLastError("Unable to remove a public SSH runtime file");
        }
        if (!RemoveDirectoryW(directory.c_str()) && GetLastError() != ERROR_PATH_NOT_FOUND &&
            GetLastError() != ERROR_FILE_NOT_FOUND) ThrowLastError("Unable to remove the public SSH runtime directory");
        directory.clear();
    }
    ~Session() {
        if (job.get()) TerminateJobObject(job.get(), 1);
        agent.reset();
        try { removePublicArtifacts(); }
        catch (const std::exception& failure) {
            try { WriteSessionEvent(diagnosticId, "", "ssh_cleanup_failed", "error", failure.what()); }
            catch (const std::exception& loggingFailure) { OutputDebugStringW(Widen(loggingFailure.what()).c_str()); }
        }
    }
};
struct SessionRegistry {
    std::mutex mutex;
    std::vector<std::shared_ptr<Session>> sessions;
};
SessionRegistry& sessionRegistry() {
    // Workers may finish during CRT shutdown; OS process teardown owns the final Job handles.
    static auto* registry = new SessionRegistry;
    return *registry;
}
}

std::string GenerateWorkstationSshIdentity(const Profile& profile) {
    ProtectSshProcess(GetCurrentProcess());
    SshSigningKey identity(SshSigningKey::Purpose::Workstation);
    auto seed = identity.identitySeed();
    WipeBytes wipeSeed{seed};
    std::string stored = "teliphones-ed25519-seed/2:";
    stored.append(reinterpret_cast<const char*>(seed.data()), seed.size());
    WipeString wipeStored{stored};
    DATA_BLOB input{static_cast<DWORD>(stored.size()), reinterpret_cast<BYTE*>(stored.data())}, encrypted{};
    if (!CryptProtectData(&input, L"TELIPHONES permanent SSH workstation identity", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &encrypted)) ThrowLastError("Unable to protect the workstation SSH identity");
    const std::string bytes(reinterpret_cast<char*>(encrypted.pbData), encrypted.cbData);
    LocalFree(encrypted.pbData);
    sshRoot();
    WriteNewFile(identityFile(profile), bytes, ownerAcl().c_str());
    return identity.publicKey();
}

void CloseManagedSsh(const std::string& profile) {
    auto& registry = sessionRegistry();
    std::vector<std::shared_ptr<Session>> closing;
    {
        std::lock_guard<std::mutex> guard(registry.mutex);
        for (const auto& session : registry.sessions) if (session->profile == profile) {
            SetEvent(session->stop.get());
            if (!TerminateJobObject(session->job.get(), 1)) ThrowLastError("Unable to terminate the owned SSH session");
            closing.push_back(session);
        }
    }
    for (const auto& session : closing)
        if (WaitForSingleObject(session->finished.get(), 30000) != WAIT_OBJECT_0)
            throw Error("Owned SSH credential teardown could not be verified.");
}

#ifdef TELIPHONES_SSH_TESTING
std::size_t ManagedSshSessionCount(const std::string& profile) {
    auto& registry = sessionRegistry();
    std::lock_guard<std::mutex> guard(registry.mutex);
    return static_cast<std::size_t>(std::count_if(registry.sessions.begin(), registry.sessions.end(),
        [&profile](const auto& session) { return session->profile == profile; }));
}
#endif

void StartManagedSsh(const Profile& profile, const Preferences& preferences) {
    RequireManagedSsh(profile);
    ProtectSshProcess(GetCurrentProcess());
    const auto terminal = ResolveApp(AppKind::Terminal, preferences.terminal, DetectApps(AppKind::Terminal, preferences));
    if (preferences.terminal == "putty") throw Error("Managed SSH requires an OpenSSH-backed terminal, not PuTTY.");
    const auto ssh = OpenSshClient();
    if (ssh.empty()) throw Error("Windows OpenSSH Client is required for managed SSH. Install the Windows optional feature.");
    auto state = std::make_shared<Session>();
    state->profile = profile.id;
    state->diagnosticId = "ws-" + profile.pairing.workstationId;
    state->expiry = profile.pairing.expiresAt;
    if (!state->job.get() || !state->stop.get() || !state->finished.get()) ThrowLastError("Unable to create SSH lifetime controls");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if (!SetInformationJobObject(state->job.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
        ThrowLastError("Unable to enforce SSH job lifetime");
    auto key = std::make_unique<SshSigningKey>();
    const SshSessionPublicKey session{HexEncode(RandomBytes(16)), key->publicKey()};
    const auto cert = certificate(profile, session);
    const auto id = NewProfileId();
    const auto root = EnsureDirectory(sshRoot() + L"\\" + Widen(profile.id), ownerAcl().c_str());
    state->directory = EnsureDirectory(root + L"\\" + Widen(id), ownerAcl().c_str());
    const auto pipe = L"\\\\.\\pipe\\TELIPHONES-agent-" + Widen(session.id);
    const auto alias = "teliphones-" + profile.id;
    WriteNewFile(state->directory + L"\\identity.pub", session.publicKey + "\n", ownerAcl().c_str());
    WriteNewFile(state->directory + L"\\certificate.pub", cert + "\n", ownerAcl().c_str());
    WriteNewFile(state->directory + L"\\known_hosts", alias + " " + profile.pairing.sshHostKey + "\n", ownerAcl().c_str());
    const auto configPath = state->directory + L"\\config";
    const std::string config =
        "Host *\nHostName " + profile.pairing.pbxAddress + "\nUser " + profile.pairing.sshUser +
        "\nPort " + std::to_string(profile.pairing.sshPort) + "\nHostKeyAlias " + alias +
        "\nIdentityAgent " + quoted(pipe) + "\nIdentityFile " + quoted(state->directory + L"\\identity.pub") +
        "\nCertificateFile " + quoted(state->directory + L"\\certificate.pub") +
        "\nUserKnownHostsFile " + quoted(state->directory + L"\\known_hosts") +
        "\nGlobalKnownHostsFile NUL\nStrictHostKeyChecking yes\nUpdateHostKeys no\nVerifyHostKeyDNS no\nCheckHostIP no\n"
        "HostKeyAlgorithms ssh-ed25519\nPubkeyAcceptedKeyTypes ssh-ed25519-cert-v01@openssh.com\n"
        "IdentitiesOnly yes\nBatchMode yes\nPreferredAuthentications publickey\nPasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\nGSSAPIAuthentication no\nAddKeysToAgent no\nForwardAgent no\nForwardX11 no\n"
        "ClearAllForwardings yes\nControlMaster no\nControlPath none\nPermitLocalCommand no\nProxyCommand none\n"
        "ProxyJump none\nServerAliveInterval 15\nServerAliveCountMax 2\nConnectTimeout 10\nRequestTTY force\n";
    WriteNewFile(configPath, config, ownerAcl().c_str());
    state->agent = std::make_unique<SshAgent>(pipe, ownerAcl(), std::move(key), cert, profile.sshUser, profile.pairing.sshHostKey);
    const auto controlName = L"\\\\.\\pipe\\TELIPHONES-console-" + Widen(session.id);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(ownerAcl().c_str(), SDDL_REVISION_1, &descriptor, nullptr))
        ThrowLastError("Unable to secure SSH console channel");
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    Handle control(CreateNamedPipeW(controlName.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                   PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 16384, 16384, 0, &security));
    LocalFree(descriptor);
    if (control.get() == INVALID_HANDLE_VALUE) ThrowLastError("Unable to create SSH console channel");
    const auto plan = ManagedTerminalLaunch(preferences.terminal, terminal, Narrow(consoleExecutable()), session.id);
    auto command = Widen(plan.commandLine);
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(Widen(plan.program).c_str(), command.data(), nullptr, nullptr, FALSE,
                        plan.newConsole ? CREATE_NEW_CONSOLE : 0, nullptr, nullptr, &startup, &process))
        ThrowLastError("Unable to open the selected SSH terminal");
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    OVERLAPPED connected{};
    connected.hEvent = event.get();
    if (!ConnectNamedPipe(control.get(), &connected)) {
        const auto error = GetLastError();
        if (error == ERROR_IO_PENDING) {
            DWORD count = 0;
            if (WaitForSingleObject(event.get(), 30000) != WAIT_OBJECT_0) {
                CancelIoEx(control.get(), &connected);
                GetOverlappedResult(control.get(), &connected, &count, TRUE);
                throw Error("The selected terminal did not start its SSH session helper.");
            }
            if (!GetOverlappedResult(control.get(), &connected, &count, FALSE)) ThrowLastError("SSH console connection failed");
        } else if (error != ERROR_PIPE_CONNECTED) ThrowLastError("SSH console connection failed", error);
    }
    ULONG helperId = 0;
    if (!GetNamedPipeClientProcessId(control.get(), &helperId)) ThrowLastError("Unable to identify SSH console helper");
    Handle helper(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA | PROCESS_TERMINATE | SYNCHRONIZE, FALSE, helperId));
    if (!helper.get() || _wcsicmp(processImage(helper.get()).c_str(), consoleExecutable().c_str()) != 0 ||
        !AssignProcessToJobObject(state->job.get(), helper.get())) throw Error("The SSH console helper could not be securely owned.");
    state->helper.reset(helper.release());
    send(control.get(), json::Serialize(json::Value::Object{{"ssh", ssh}, {"config", Narrow(configPath)}}));
    const auto child = json::Parse(receive(control.get()), 1024);
    json::RequireExactKeys(child, {"pid"}, "SSH child");
    const auto pid = child.at("pid").asInteger();
    if (pid <= 0 || pid > MAXDWORD) throw Error("Invalid owned SSH process ID.");
    Handle client(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | WRITE_DAC, FALSE, static_cast<DWORD>(pid)));
    BOOL owned = FALSE;
    if (!client.get() || !IsProcessInJob(client.get(), state->job.get(), &owned) || !owned ||
        _wcsicmp(processImage(client.get()).c_str(), Widen(ssh).c_str()) != 0) throw Error("The SSH client escaped session ownership.");
    state->agent->authorise(client.get());
    ProtectSshProcess(client.get());
    state->ssh.reset(client.release());
    send(control.get(), "start");
    auto& registry = sessionRegistry();
    {
        std::lock_guard<std::mutex> guard(registry.mutex);
        registry.sessions.push_back(state);
    }
    const auto authenticationDeadline = UnixNow() + 30;
    try { std::thread([state, authenticationDeadline] {
        HANDLE waits[]{state->stop.get(), state->helper.get(), state->ssh.get()};
        std::string error;
        for (;;) {
            const auto outcome = WaitForMultipleObjects(3, waits, FALSE, 250);
            if (outcome != WAIT_TIMEOUT || (state->expiry && UnixNow() >= state->expiry)) break;
            if (!state->agent->destroyed() && UnixNow() >= authenticationDeadline) {
                error = "SSH authentication deadline reached; disposable credential destroyed.";
                break;
            }
            error = state->agent->failure();
            if (!error.empty()) break;
        }
        if (!TerminateJobObject(state->job.get(), 1)) error = "Unable to terminate the owned SSH session job.";
        state->agent.reset();
        HANDLE ended[]{state->helper.get(), state->ssh.get()};
        if (WaitForMultipleObjects(2, ended, TRUE, 10000) != WAIT_OBJECT_0)
            error = "Owned SSH process termination could not be verified.";
        try { state->removePublicArtifacts(); }
        catch (const std::exception& failure) { error += std::string(error.empty() ? "" : " ") + failure.what(); }
        try {
            WriteSessionEvent(state->diagnosticId, "", error.empty() ? "ssh_ended" : "ssh_failed",
                              error.empty() ? "info" : "error",
                              error.empty() ? "Owned SSH session ended; disposable signing capability destroyed." : error);
        } catch (const std::exception& failure) {
            OutputDebugStringW(Widen(failure.what()).c_str());
        }
        auto& registry = sessionRegistry();
        std::lock_guard<std::mutex> guard(registry.mutex);
        registry.sessions.erase(std::remove(registry.sessions.begin(), registry.sessions.end(), state), registry.sessions.end());
        SetEvent(state->finished.get());
    }).detach(); }
    catch (...) {
        std::lock_guard<std::mutex> guard(registry.mutex);
        registry.sessions.erase(std::remove(registry.sessions.begin(), registry.sessions.end(), state), registry.sessions.end());
        throw;
    }
}

int RunSshConsole(const std::vector<std::string>& arguments) {
    if (arguments.size() != 2 || arguments[0] != "/ssh-console" || !hex(arguments[1], 32)) return 2;
    try {
        ProtectSshProcess(GetCurrentProcess(), true);
        const auto name = L"\\\\.\\pipe\\TELIPHONES-console-" + Widen(arguments[1]);
        if (!WaitNamedPipeW(name.c_str(), 30000)) ThrowLastError("TELIPHONES SSH controller is unavailable");
        Handle control(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                   FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
        if (control.get() == INVALID_HANDLE_VALUE) ThrowLastError("Unable to connect SSH console to TELIPHONES");
        ULONG parentId = 0;
        if (!GetNamedPipeServerProcessId(control.get(), &parentId)) ThrowLastError("Unable to identify SSH controller");
        Handle parent(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, parentId));
        if (!parent.get() || _wcsicmp(processImage(parent.get()).c_str(), controllerExecutable().c_str()) != 0)
            throw Error("Unexpected SSH controller executable.");
        const auto value = json::Parse(receive(control.get()), 16384);
        ProtectSshProcess(GetCurrentProcess());
        json::RequireExactKeys(value, {"ssh", "config"}, "SSH console launch");
        const auto ssh = OpenSshClient();
        if (ssh.empty() || value.at("ssh").asString() != ssh) throw Error("Unexpected SSH executable.");
        const auto path = value.at("config").asString();
        if (!IsShellSafeFilePath(path)) throw Error("Unsafe SSH configuration path.");
        auto command = Widen(JoinCommandLine({ssh, "-F", path, "teliphones"}));
        STARTUPINFOW startup{sizeof(startup)};
        PROCESS_INFORMATION process{};
        if (!CreateProcessW(Widen(ssh).c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED,
                            nullptr, nullptr, &startup, &process)) ThrowLastError("Unable to start owned OpenSSH client");
        Handle child(process.hProcess), thread(process.hThread);
        try {
            send(control.get(), json::Serialize(json::Value::Object{{"pid", static_cast<std::int64_t>(process.dwProcessId)}}));
            if (receive(control.get()) != "start" || ResumeThread(thread.get()) == static_cast<DWORD>(-1))
                throw Error("TELIPHONES did not approve the owned SSH client.");
        } catch (...) { TerminateProcess(child.get(), 1); throw; }
        HANDLE waits[]{parent.get(), child.get()};
        if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) != WAIT_OBJECT_0 + 1) {
            TerminateProcess(child.get(), 1);
            throw Error("TELIPHONES ended; the SSH session was terminated.");
        }
        DWORD result = 1;
        if (!GetExitCodeProcess(child.get(), &result)) ThrowLastError("Unable to read SSH client exit status");
        return static_cast<int>(result);
    } catch (const std::exception& error) {
        const auto message = "TELIPHONES SSH: " + std::string(error.what()) + "\r\n";
        DWORD count = 0;
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), message.data(), static_cast<DWORD>(message.size()), &count, nullptr);
        return 1;
    }
}
}
