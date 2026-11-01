// Connection health decisions. Platform code supplies observations; this decides what to tell the user and when to disconnect.
#pragma once

#include <cstdint>
#include <string>

namespace tlp {

enum class LinkState { Connecting, Connected, NotResponding, NoResponse, Lost, Expired, Stopped };

struct MonitorDecision {
    LinkState state = LinkState::Connecting;
    std::string summary;
    std::string guidance;
    bool disconnect = false;
};

class ConnectionMonitor {
public:
    static constexpr std::int64_t kFirstResponseSeconds = 30;
    static constexpr int kLostAfterFailures = 3;

    // expiresAt is 0 for persistent administrator pairings. viaGateway selects Remote Support guidance.
    ConnectionMonitor(std::int64_t startedAt, std::int64_t expiresAt, std::string endpoint, bool viaGateway);

    // serviceRunning: the WireGuard tunnel service is running. probeSucceeded: a TCP connection to the PBX
    // tunnel address succeeded. WireGuard handshake state is not readable without administrative rights.
    MonitorDecision Observe(std::int64_t now, bool serviceRunning, bool probeSucceeded);
    bool everConnected() const { return everConnected_; }

private:
    std::int64_t startedAt_;
    std::int64_t expiresAt_;
    std::string endpoint_;
    bool viaGateway_;
    bool everConnected_ = false;
    int failures_ = 0;
};

}  // namespace tlp
