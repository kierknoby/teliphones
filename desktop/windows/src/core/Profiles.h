// Saved PBX profiles (no secrets), Remote Support grants and tunnel construction.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "Pairing.h"
#include "TunnelConfig.h"

namespace tlp {

struct SupportSession {
    std::string sessionId;
    std::string pbxAddress;
    std::int64_t expiresAt = 0;
};

// teliphones-engineer-grant/1, issued by the reference gateway's `engineer-grant` operator command.
struct SupportGrant {
    std::string engineerId;
    std::string engineerAddress;
    std::string engineerPublicKey;
    std::string gatewayPublicKey;
    std::string endpoint;
    std::vector<SupportSession> sessions;
};

SupportGrant ParseEngineerGrant(const std::string& text);
// Parses a grant and requires it to be issued for the given engineer public key.
SupportGrant ParseEngineerGrantFor(const std::string& text, const std::string& engineerPublicKey);

enum class ProfileKind { Administrator, Support };

struct Profile {
    std::string id;  // 16 lowercase hex characters; also names the Credential Manager entry
    ProfileKind kind = ProfileKind::Administrator;
    std::string name;
    std::int64_t createdAt = 0;
    // Administrator ("My PBXs") profiles
    std::string workstationName;
    PairResponse pairing;
    std::string sshUser;
    // Remote Support profiles: the engineer key is created first and enrolled by the gateway operator,
    // who then issues a grant for it.
    std::string engineerPublicKey;
    bool hasGrant = false;
    SupportGrant grant;
};

std::string SerializeProfiles(const std::vector<Profile>& profiles);
std::vector<Profile> ParseProfiles(const std::string& text);

// Tunnel name used for the WireGuard for Windows service (WireGuardTunnel$<name>).
std::string TunnelNameFor(const Profile& profile);
std::string CredentialTargetFor(const Profile& profile);

// Administrator tunnel: routes only the PBX's workstation address.
TunnelConfig AdministratorTunnel(const Profile& profile, const std::string& privateKey);
// Remote Support tunnel: routes only the selected, unexpired session's PBX address through the gateway.
TunnelConfig SupportTunnel(const Profile& profile, const std::string& privateKey, const std::string& sessionId, std::int64_t now);
// Expiry that ends a connection, or 0 when the PBX-side pairing is persistent.
std::int64_t ConnectionExpiry(const Profile& profile, const std::string& sessionId);
std::string ConnectionAddress(const Profile& profile, const std::string& sessionId);

std::string FormatRemaining(std::int64_t seconds);

}  // namespace tlp
