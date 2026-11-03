#include "SshAgent.h"
#include "../core/Json.h"
#include <sddl.h>

namespace tlp::win {
void ProtectSshProcess(HANDLE process, bool allowJobAssignment) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) throw Error("Unable to inspect SSH owner token.");
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    Bytes buffer(size);
    const auto ok = GetTokenInformation(token, TokenUser, buffer.data(), size, &size);
    CloseHandle(token);
    if (!ok) throw Error("Unable to inspect SSH owner identity.");
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &sid))
        throw Error("Unable to encode SSH owner identity.");
    // OWNER RIGHTS removes the owner's implicit WRITE_DAC permission.
    const std::wstring rights = allowJobAssignment ? L"0x101101" : L"0x101001";
    const auto sddl = L"D:P(A;;GA;;;SY)(A;;" + rights + L";;;OW)(A;;" + rights + L";;;" + std::wstring(sid) + L")";
    LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
        throw Error("Unable to prepare SSH process protection.");
    const auto protectedProcess = SetKernelObjectSecurity(process, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, descriptor);
    LocalFree(descriptor);
    if (!protectedProcess) throw Error("Unable to restrict SSH process memory and handle access.");
}
namespace {
class Event {
public:
    Event() : handle(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {
        if (!handle) throw Error("Unable to create SSH agent event.");
    }
    ~Event() { CloseHandle(handle); }
    HANDLE handle;
};
Bytes certificateBlob(const std::string& certificate) {
    const auto first = certificate.find(' ');
    if (first == std::string::npos) throw Error("Invalid SSH certificate.");
    return Base64Decode(certificate.substr(first + 1, certificate.find_first_of(" \r\n", first + 1) - first - 1));
}
}
SshAgent::SshAgent(const std::wstring& name, const std::wstring& sddl, std::unique_ptr<SshSigningKey> key,
                   const std::string& certificate, const std::string& user, const std::string& hostKey)
    : key_(std::move(key)), certificate_(certificateBlob(certificate)), hostKey_(certificateBlob(hostKey)), user_(user) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
        throw Error("Unable to create SSH agent security descriptor.");
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    pipe_ = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                            1, 16384, 16384, 0, &security);
    LocalFree(descriptor);
    if (pipe_ == INVALID_HANDLE_VALUE) throw Error("Unable to create isolated SSH agent pipe.");
    stop_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stop_) { CloseHandle(pipe_); throw Error("Unable to create SSH agent stop event."); }
    try { thread_ = std::thread([this] { serve(); }); }
    catch (...) { CloseHandle(stop_); CloseHandle(pipe_); throw; }
}
SshAgent::~SshAgent() {
    SetEvent(stop_);
    CancelIoEx(pipe_, nullptr);
    if (thread_.joinable()) thread_.join();
    if (client_) CloseHandle(client_);
    CloseHandle(pipe_);
    CloseHandle(stop_);
}
void SshAgent::authorise(HANDLE process) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (client_ || !DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(), &client_,
                                   PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, 0))
        throw Error("Unable to bind isolated SSH agent to the owned client.");
}
std::string SshAgent::failure() const { std::lock_guard<std::mutex> guard(mutex_); return failure_; }
bool SshAgent::transfer(void* bytes, DWORD size, bool write) {
    auto* buffer = static_cast<unsigned char*>(bytes);
    DWORD total = 0;
    while (total < size) {
        Event event;
        OVERLAPPED operation{};
        operation.hEvent = event.handle;
        DWORD count = 0;
        const auto ok = write ? WriteFile(pipe_, buffer + total, size - total, &count, &operation) :
                                ReadFile(pipe_, buffer + total, size - total, &count, &operation);
        if (!ok) {
            if (GetLastError() != ERROR_IO_PENDING) return false;
            HANDLE waits[]{stop_, event.handle};
            if (WaitForMultipleObjects(2, waits, FALSE, 10000) != WAIT_OBJECT_0 + 1) {
                CancelIoEx(pipe_, &operation);
                GetOverlappedResult(pipe_, &operation, &count, TRUE);
                return false;
            }
            if (!GetOverlappedResult(pipe_, &operation, &count, FALSE)) return false;
        }
        if (count == 0) return false;
        total += count;
    }
    return true;
}
void SshAgent::serve() {
    try {
        while (WaitForSingleObject(stop_, 0) != WAIT_OBJECT_0) {
            Event event;
            OVERLAPPED connection{};
            connection.hEvent = event.handle;
            const auto connected = ConnectNamedPipe(pipe_, &connection);
            const auto error = connected ? ERROR_SUCCESS : GetLastError();
            if (error == ERROR_IO_PENDING) {
                HANDLE waits[]{stop_, event.handle};
                if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) != WAIT_OBJECT_0 + 1) {
                    CancelIoEx(pipe_, &connection);
                    DWORD count = 0;
                    GetOverlappedResult(pipe_, &connection, &count, TRUE);
                    break;
                }
                DWORD count = 0;
                if (!GetOverlappedResult(pipe_, &connection, &count, FALSE)) throw Error("SSH agent connection failed.");
            } else if (error != ERROR_SUCCESS && error != ERROR_PIPE_CONNECTED) {
                throw Error("SSH agent pipe connection failed.");
            }
            ULONG pid = 0;
            bool permitted = false;
            {
                std::lock_guard<std::mutex> guard(mutex_);
                permitted = GetNamedPipeClientProcessId(pipe_, &pid) && client_ &&
                            GetProcessId(client_) == pid && WaitForSingleObject(client_, 0) == WAIT_TIMEOUT;
            }
            if (permitted) {
                for (;;) {
                    unsigned char header[4];
                    if (!transfer(header, 4, false)) break;
                    const auto size = (static_cast<DWORD>(header[0]) << 24) | (static_cast<DWORD>(header[1]) << 16) |
                                      (static_cast<DWORD>(header[2]) << 8) | header[3];
                    if (size == 0 || size > 16384) throw Error("Oversized SSH agent request.");
                    Bytes request(size);
                    if (!transfer(request.data(), size, false)) break;
                    Bytes reply{5}; // SSH_AGENT_FAILURE; no add/export/remove/shared-agent operations.
                    if (request.size() == 1 && request[0] == 11 && !destroyed_) {
                        reply = SshJoin({Bytes{12}, SshNumber(1), SshField(certificate_), SshField(std::string("TELIPHONES session"))});
                    } else if (request[0] == 13 && !destroyed_) {
                        Bytes body(request.begin() + 1, request.end());
                        SshWireReader reader(body);
                        const auto key = reader.field(), message = reader.field();
                        const auto flags = reader.number();
                        if (!reader.done() || flags != 0 || key != certificate_) throw Error("SSH agent signing key mismatch.");
                        ValidateSshAuthentication(message, user_, certificate_, hostKey_);
                        const auto signature = key_->sign(message);
                        key_->destroy();
                        destroyed_ = true;
                        reply = SshJoin({Bytes{14}, SshField(signature)});
                    }
                    auto frame = SshField(reply);
                    if (!transfer(frame.data(), static_cast<DWORD>(frame.size()), true)) break;
                }
            }
            DisconnectNamedPipe(pipe_);
        }
    } catch (const std::exception& error) {
        std::lock_guard<std::mutex> guard(mutex_);
        failure_ = error.what();
    }
    key_->destroy();
    destroyed_ = true;
}
}
