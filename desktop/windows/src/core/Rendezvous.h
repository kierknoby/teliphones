// Provider-neutral rendezvous/relay interface. Only direct connectivity is implemented; see docs/RENDEZVOUS.md.
#pragma once

#include <string>

namespace tlp {

struct EndpointPlan {
    std::string endpoint;   // WireGuard Endpoint the tunnel will use
    std::string provider;   // "direct" for the built-in provider
    bool relayed = false;   // true only if traffic would traverse a third-party relay
    std::string limitation; // shown to the user when the connection does not answer
};

// A future provider may resolve a PBX identity to a reachable endpoint (rendezvous) or a relay. It must never
// receive private keys, must not alter AllowedIPs, and the PBX remains the only authority for workstation access.
class IRendezvousProvider {
public:
    virtual ~IRendezvousProvider() = default;
    virtual std::string Name() const = 0;
    virtual EndpointPlan Plan(const std::string& pairedEndpoint) const = 0;
};

class DirectProvider final : public IRendezvousProvider {
public:
    std::string Name() const override { return "direct"; }
    EndpointPlan Plan(const std::string& pairedEndpoint) const override {
        return {pairedEndpoint, "direct", false,
                "Direct WireGuard only: the PBX's UDP port must be reachable from this network. No relay is configured, so restrictive NAT or "
                "firewalls on either side can prevent a connection."};
    }
};

}  // namespace tlp
