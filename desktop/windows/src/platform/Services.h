// Credential Manager (DPAPI-protected) storage for WireGuard private keys, the per-user profile store,
// and tunnel reachability probes. The FreePBX GUI and SSH launchers are in Applications.h.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "../core/Profiles.h"
#include "../core/ConnectionHealth.h"

namespace tlp {
namespace win {

void SavePrivateKey(const std::string& target, const std::string& privateKey);
// Empty when no key is stored for the target.
std::string LoadPrivateKey(const std::string& target);
void DeletePrivateKey(const std::string& target);
void DeleteSshPrivateKey(const Profile& profile);

std::vector<Profile> LoadProfiles();
void SaveProfiles(const std::vector<Profile>& profiles);
std::string NewProfileId();

// Exact correlation IDs only: application, ws-<16hex>, support-<16hex>; attempt is empty or <16hex>.
// Throws on storage failure; the UI is responsible for making that failure visible.
void WriteSessionEvent(const std::string& sessionId, const std::string& attemptId, const std::string& event,
                       const std::string& severity, const std::string& detail);
std::string ReadSessionEvents(const std::string& sessionId);

// TCP connection to the PBX tunnel address; succeeds only when the PBX answers through the tunnel.
bool ProbeTcp(const std::string& ipv4, unsigned short port, unsigned timeoutMs);
struct TcpProbeMeasurement {
    bool known = false;
    bool succeeded = false;
    std::optional<double> latencyMs;
    std::string error;
};
TcpProbeMeasurement MeasureTcpProbe(const std::string& ipv4, unsigned short port, unsigned timeoutMs);
WireGuardCounters ReadWireGuardCounters(const std::wstring& wgExecutable, const std::string& tunnelName, const std::string& peerPublicKey);
// IP-layer interface octets, not encrypted per-peer counters; handshake remains unknown.
WireGuardCounters ReadTunnelInterfaceCounters(const std::string& tunnelName);
std::optional<HealthPreferences> LoadHealthPreferences();
void SaveHealthPreferences(const HealthPreferences& preferences);

}  // namespace win
}  // namespace tlp
