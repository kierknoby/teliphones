#pragma once
#include "../core/Profiles.h"
#include "../core/Launchers.h"

namespace tlp::win {
std::string GenerateWorkstationSshIdentity(const Profile& profile);
void RequireManagedSsh(const Profile& profile);
void StartManagedSsh(const Profile& profile, const Preferences& preferences);
void CloseManagedSsh(const std::string& profile);
int RunSshConsole(const std::vector<std::string>& arguments);
#ifdef TELIPHONES_SSH_TESTING
std::size_t ManagedSshSessionCount(const std::string& profile);
#endif
// Closes owned sessions and deletes known runtime artifacts; file deletion is not secure erasure.
void RemoveSshRuntime(const Profile& profile);
}
