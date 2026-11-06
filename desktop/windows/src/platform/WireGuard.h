// Uses separately installed official WireGuard tunnel services and key tools, plus
// the pinned official WireGuardNT API DLL for in-memory adapter configuration.
#pragma once

#include "../core/TunnelLifecycle.h"

#include <string>
#include <vector>

namespace tlp {
namespace win {

struct WireGuardInstallation {
    bool installed = false;
    bool trusted = false;       // Authenticode signature verified by WinVerifyTrust
    std::wstring wireguardExe;
    std::wstring wgExe;
    std::string signer;         // certificate display name, shown to the user
    std::string problem;        // user-facing explanation when not usable
};

WireGuardInstallation FindWireGuard();
std::string GeneratePrivateKey(const WireGuardInstallation& wireguard);
std::string DerivePublicKey(const WireGuardInstallation& wireguard, const std::string& privateKey);

enum class TunnelState { Absent, Stopped, Starting, Running, Stopping, Unknown };
TunnelState QueryTunnel(const std::string& tunnelName);

// Only a public bootstrap identity goes to disk. The enrolled private key passes over a PID-bound pipe
// to the UAC helper, then into the existing WireGuardNT adapter through its native API. A restarted stored config
// cannot authenticate as this workstation. Returns false if the user declined the UAC prompt.
bool InstallTunnel(const std::string& tunnelName, const std::string& configText);
// Stops and removes the tunnel service. Uses the rights granted at installation; falls back to an elevated helper.
// Returns only after the service, its bootstrap configuration and its active network adapter are gone.
void RemoveTunnel(const std::string& tunnelName);
// Whether an active network adapter with this tunnel's exact name exists (read-only interface table snapshot).
tunnel_lifecycle::AdapterPresence TunnelAdapterPresence(const std::string& tunnelName);

// Entry point when the executable is started elevated with /tunnel-up or /tunnel-down. Returns the process exit code.
int RunTunnelHelper(const std::vector<std::string>& arguments);
bool IsHelperInvocation(const std::vector<std::string>& arguments);

}  // namespace win
}  // namespace tlp
