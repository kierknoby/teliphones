#pragma once
#include "../core/Profiles.h"
#include "../core/Launchers.h"

#include <memory>

namespace tlp::win {
class ManagedSshConsole {
public:
    virtual ~ManagedSshConsole() = default;
    virtual std::string ReadAvailable() = 0;
    virtual void WriteInput(const std::string& text) = 0;
    virtual void Resize(int columns, int rows) = 0;
    virtual bool IsAuthenticated() = 0;
    virtual bool IsAlive() = 0;
    virtual void Disconnect() = 0;
};

std::string GenerateWorkstationSshIdentity(const Profile& profile);
void RequireManagedSsh(const Profile& profile);
void StartManagedSsh(const Profile& profile, const Preferences& preferences);
std::shared_ptr<ManagedSshConsole> StartManagedSshConsole(const Profile& profile);
void CloseManagedSsh(const std::string& profile);
int RunSshConsole(const std::vector<std::string>& arguments);
#ifdef TELIPHONES_SSH_TESTING
std::size_t ManagedSshSessionCount(const std::string& profile);
#endif
// Closes owned sessions and deletes known runtime artifacts; file deletion is not secure erasure.
void RemoveSshRuntime(const Profile& profile);
}
