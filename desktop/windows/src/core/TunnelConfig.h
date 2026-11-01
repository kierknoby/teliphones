// WireGuard tunnel configuration: renderer and the strict validator used by the elevated helper.
#pragma once

#include <string>
#include <vector>

namespace tlp {

struct TunnelConfig {
    std::string privateKey;
    std::string address;                 // a.b.c.d/32
    std::string peerPublicKey;
    std::string endpoint;                // host:port
    std::vector<std::string> allowedIps; // a.b.c.d/32 each; never a default or broad route
    int persistentKeepalive = 25;
};

// Throws tlp::Error when the configuration is outside the TELIPHONES policy.
void ValidateTunnel(const TunnelConfig& config);
// Renders the same shape as gateway/engineer_config.py: no DNS, no scripts, no ListenPort, host routes only.
std::string RenderTunnel(const TunnelConfig& config);
// Accepts only text that RenderTunnel could have produced; anything else (PostUp, DNS, Table, broad routes...) is rejected.
TunnelConfig ParseTunnelStrict(const std::string& text);

}  // namespace tlp
