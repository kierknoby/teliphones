#include "../src/platform/SshAgent.h"
#include "../src/core/CommandLine.h"
#include "../src/core/Json.h"
#include "../src/platform/Ssh.h"
#include "../src/platform/Services.h"
#include "../src/platform/Win.h"
#include <windows.h>
#include <sddl.h>
#include <iostream>
#include <memory>
#include <thread>

namespace {
std::wstring wide(const std::string& text) {
    const auto size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (!size) throw tlp::Error("Invalid UTF-8 test argument.");
    std::wstring result(size, 0);
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), size);
    return result;
}
struct Handle {
    HANDLE value;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
std::wstring acl() {
    Handle token{nullptr};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value)) throw tlp::Error("Token query failed.");
    DWORD size = 0;
    GetTokenInformation(token.value, TokenUser, nullptr, 0, &size);
    std::vector<unsigned char> data(size);
    if (!GetTokenInformation(token.value, TokenUser, data.data(), size, &size)) throw tlp::Error("Token user query failed.");
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid, &sid)) throw tlp::Error("SID query failed.");
    std::wstring result = L"D:P(A;;FA;;;SY)(A;;FA;;;" + std::wstring(sid) + L")";
    LocalFree(sid);
    return result;
}
}

int main(int argc, char** argv) {
    try {
        if (argc > 1 && std::string(argv[1]) == "/ssh-console")
            return tlp::win::RunSshConsole(std::vector<std::string>(argv + 1, argv + argc));
        tlp::win::ProtectSshProcess(GetCurrentProcess());
        if (argc == 3 && std::string(argv[1]) == "--production") {
            tlp::Profile profile;
            profile.id = argv[2];
            profile.kind = tlp::ProfileKind::Administrator;
            profile.pairing.sshPublicKey = tlp::win::GenerateWorkstationSshIdentity(profile);
            std::cout << profile.pairing.sshPublicKey << std::endl;
            std::string line;
            if (!std::getline(std::cin, line)) return 2;
            const auto fields = tlp::json::Parse(line, 8192);
            profile.pairing.workstationId = profile.id;
            profile.pairing.address = "127.0.0.1/32";
            profile.pairing.pbxAddress = "127.0.0.1";
            profile.pairing.ssh = true;
            profile.sshUser = profile.pairing.sshUser = fields.at("user").asString();
            profile.pairing.sshHostKey = fields.at("host").asString();
            profile.pairing.sshCaKey = fields.at("ca").asString();
            profile.pairing.sshPort = 22001;
            profile.pairing.sshApiPort = 8765;
            profile.pairing.expiresAt = fields.at("expires_at").asInteger();
            tlp::Preferences preferences;
            preferences.terminal = "cmd";
            try {
                tlp::win::StartManagedSsh(profile, preferences);
                std::cout << "PRODUCTION_STARTED" << std::endl;
                if (!std::getline(std::cin, line)) throw tlp::Error("Native controller input ended.");
                if (line == "wait-expiry") {
                    if (!profile.pairing.expiresAt) throw tlp::Error("Test requires a local expiry.");
                    for (int i = 0; i < 120 && tlp::win::ManagedSshSessionCount(profile.id); ++i) Sleep(250);
                    if (tlp::win::ManagedSshSessionCount(profile.id)) throw tlp::Error("Local expiry retained an owned session.");
                    if (tlp::win::UnixNow() < profile.pairing.expiresAt) throw tlp::Error("Session ended before local expiry.");
                    std::cout << "PRODUCTION_EXPIRED" << std::endl;
                } else if (line != "close") throw tlp::Error("Unexpected native controller command.");
                tlp::win::CloseManagedSsh(profile.id);
                if (tlp::win::ManagedSshSessionCount(profile.id)) throw tlp::Error("Production session teardown was incomplete.");
                const auto identityPath = tlp::win::KnownFolder(FOLDERID_LocalAppData) + L"\\TELIPHONES\\SSH\\" +
                                          wide(profile.id) + L".dpapi";
                if (GetFileAttributesW(identityPath.c_str()) == INVALID_FILE_ATTRIBUTES)
                    throw tlp::Error("Session teardown destroyed the permanent identity.");
                std::cout << "IDENTITY_RETAINED" << std::endl;
                tlp::win::RemoveSshRuntime(profile);
                tlp::win::DeleteSshPrivateKey(profile);
                std::cout << "PRODUCTION_CLOSED" << std::endl;
                return 0;
            } catch (...) {
                tlp::win::CloseManagedSsh(profile.id);
                tlp::win::DeleteSshPrivateKey(profile);
                throw;
            }
        }
        auto key = std::make_unique<tlp::SshSigningKey>();
        std::cout << key->publicKey() << std::endl;
        std::string input;
        if (!std::getline(std::cin, input)) return 2;
        const auto params = tlp::json::Parse(input, 32768);
        const auto pipe = params.at("pipe").asString();
        const auto cert = params.at("certificate").asString();
        tlp::VerifySshCertificateSignature(cert, params.at("ca").asString());
        tlp::win::SshAgent agent(wide(pipe), acl(), std::move(key), cert, params.at("user").asString(), params.at("host").asString());
        Handle job{CreateJobObjectW(nullptr, nullptr)};
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!job.value || !SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
            throw tlp::Error("Test job setup failed.");
        const auto program = params.at("ssh").asString();
        const auto command = tlp::JoinCommandLine({program, "-F", params.at("config").asString(), "fixture",
                                                 params.at("command").asString()});
        auto commandWide = wide(command);
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        PROCESS_INFORMATION process{};
        if (!CreateProcessW(wide(program).c_str(), commandWide.data(), nullptr, nullptr, TRUE, CREATE_SUSPENDED,
                            nullptr, nullptr, &startup, &process)) throw tlp::Error("Native SSH launch failed.");
        Handle child{process.hProcess}, thread{process.hThread};
        if (!AssignProcessToJobObject(job.value, child.value)) { TerminateProcess(child.value, 1); throw tlp::Error("Test job assignment failed."); }
        agent.authorise(child.value);
        tlp::win::ProtectSshProcess(child.value);
        std::cout << "SSH_PID=" << process.dwProcessId << std::endl;
        std::cout << "PIPE_READY" << std::endl;
        std::string go;
        if (!std::getline(std::cin, go) || go != "go") { TerminateJobObject(job.value, 1); return 2; }
        if (ResumeThread(thread.value) == static_cast<DWORD>(-1)) throw tlp::Error("Native SSH resume failed.");
        std::thread crash;
        if (params.has("crash") && params.at("crash").asBool())
            crash = std::thread([handle = child.value] { Sleep(2000); TerminateProcess(handle, 87); });
        if (WaitForSingleObject(child.value, 45000) != WAIT_OBJECT_0) {
            TerminateJobObject(job.value, 1);
            if (crash.joinable()) crash.join();
            throw tlp::Error("Native SSH timed out.");
        }
        if (crash.joinable()) crash.join();
        DWORD status = 1;
        if (!GetExitCodeProcess(child.value, &status)) throw tlp::Error("Native SSH exit query failed.");
        if (!agent.failure().empty()) throw tlp::Error(agent.failure());
        if (status == 0 && !agent.destroyed()) throw tlp::Error("Successful authentication retained signing capability.");
        std::cout << "KEY_DESTROYED=" << agent.destroyed() << std::endl;
        return static_cast<int>(status);
    } catch (const std::exception& error) {
        std::cerr << "NATIVE SSH TEST FAILURE: " << error.what() << std::endl;
        return 1;
    }
}
