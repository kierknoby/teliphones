#include "Monitor.h"

#include "Profiles.h"

namespace tlp {

ConnectionMonitor::ConnectionMonitor(std::int64_t startedAt, std::int64_t expiresAt, std::string endpoint, bool viaGateway)
    : startedAt_(startedAt), expiresAt_(expiresAt), endpoint_(std::move(endpoint)), viaGateway_(viaGateway) {}

MonitorDecision ConnectionMonitor::Observe(std::int64_t now, bool serviceRunning, bool probeSucceeded) {
    MonitorDecision decision;
    if (expiresAt_ > 0 && now >= expiresAt_) {
        decision.state = LinkState::Expired;
        decision.summary = viaGateway_ ? "Support authorisation expired" : "Temporary access expired";
        decision.guidance = viaGateway_ ? "The customer's support authorisation has ended. The tunnel has been disconnected."
                                        : "The temporary workstation access granted on the PBX has ended. Pair this workstation again from the FreePBX TELIPHONES page to reconnect.";
        decision.disconnect = true;
        return decision;
    }
    if (!serviceRunning) {
        decision.state = LinkState::Stopped;
        decision.summary = "Tunnel stopped";
        decision.guidance = "The WireGuard tunnel service is no longer running. Connect again to restart it.";
        return decision;
    }
    std::string remaining = expiresAt_ > 0 ? " (" + FormatRemaining(expiresAt_ - now) + " remaining)" : "";
    if (probeSucceeded) {
        everConnected_ = true;
        failures_ = 0;
        decision.state = LinkState::Connected;
        decision.summary = "Connected" + remaining;
        decision.guidance = "The PBX is answering through the encrypted WireGuard tunnel.";
        return decision;
    }
    ++failures_;
    if (!everConnected_) {
        if (now - startedAt_ < kFirstResponseSeconds) {
            decision.state = LinkState::Connecting;
            decision.summary = "Waiting for the PBX to answer…";
            decision.guidance = "The tunnel is running. TELIPHONES is checking that the PBX answers through it.";
            return decision;
        }
        decision.state = LinkState::NoResponse;
        decision.summary = "PBX did not answer through the tunnel";
        decision.guidance = viaGateway_
            ? "The tunnel started, but the PBX did not answer through the gateway at " + endpoint_ +
                  ". Check that this network allows outbound UDP to the gateway, that the customer's session is still authorised, and that you imported a current grant."
            : "The tunnel started, but the PBX did not answer. Check that UDP traffic to " + endpoint_ +
                  " reaches the PBX (router port forwarding and the FreePBX Firewall), that this workstation has not been revoked or expired on the PBX, "
                  "and that this network permits outbound UDP. TELIPHONES connects directly and does not relay traffic, so restrictive NAT or firewalls can prevent a connection.";
        return decision;
    }
    if (failures_ < kLostAfterFailures) {
        decision.state = LinkState::NotResponding;
        decision.summary = "PBX not responding — rechecking" + remaining;
        decision.guidance = "The last status check did not reach the PBX. TELIPHONES will keep checking; new SSH launches stay unavailable until reachability is verified. Existing terminal windows are not closed.";
        return decision;
    }
    decision.state = LinkState::Lost;
    decision.summary = "Connection lost";
    decision.guidance = viaGateway_
        ? "The PBX stopped answering. The support session may have been revoked or ended, or the network changed. The tunnel remains available for manual recovery; existing terminal windows are not closed."
        : "The PBX stopped answering. Workstation access may have been revoked or expired on the PBX, or the network changed. The tunnel remains available for manual recovery; existing terminal windows are not closed.";
    return decision;
}

}  // namespace tlp
