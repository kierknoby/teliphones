#pragma once
#include "../core/SshCrypto.h"
#include <windows.h>
#include <atomic>
#include <mutex>
#include <thread>

namespace tlp::win {
void ProtectSshProcess(HANDLE process, bool allowJobAssignment = false);
class SshAgent {
public:
    SshAgent(const std::wstring& pipe, const std::wstring& sddl, std::unique_ptr<SshSigningKey> key,
             const std::string& certificate, const std::string& user, const std::string& hostKey);
    ~SshAgent();
    SshAgent(const SshAgent&) = delete;
    SshAgent& operator=(const SshAgent&) = delete;
    void authorise(HANDLE process);
    bool destroyed() const { return destroyed_.load(); }
    std::string failure() const;
private:
    void serve();
    bool transfer(void* bytes, DWORD size, bool write);
    HANDLE pipe_ = INVALID_HANDLE_VALUE;
    HANDLE stop_ = nullptr;
    HANDLE client_ = nullptr;
    SshAgentProtocol protocol_;
    mutable std::mutex mutex_;
    std::string failure_;
    std::atomic<bool> destroyed_{false};
    std::thread thread_;
};
}
