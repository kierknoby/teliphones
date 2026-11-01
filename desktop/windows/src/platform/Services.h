// Credential Manager (DPAPI-protected) storage for WireGuard private keys, the per-user profile store,
// tunnel reachability probes and launchers for the FreePBX GUI and SSH.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "../core/Profiles.h"

namespace tlp {
namespace win {

void SavePrivateKey(const std::string& target, const std::string& privateKey);
// Empty when no key is stored for the target.
std::string LoadPrivateKey(const std::string& target);
void DeletePrivateKey(const std::string& target);

std::vector<Profile> LoadProfiles();
void SaveProfiles(const std::vector<Profile>& profiles);
std::string NewProfileId();

// TCP connection to the PBX tunnel address; succeeds only when the PBX answers through the tunnel.
bool ProbeTcp(const std::string& ipv4, unsigned short port, unsigned timeoutMs);

void OpenFreePbx(const Profile& profile, const std::string& sessionId);
// Opens the Windows OpenSSH client in a new console window. Throws with installation guidance if absent.
void OpenSsh(const Profile& profile, const std::string& sessionId);

}  // namespace win
}  // namespace tlp
