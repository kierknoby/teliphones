#include "Profiles.h"

#include <set>

#include "Json.h"
#include "Validation.h"

namespace tlp {
namespace {

using json::Value;

std::string requireString(const Value& object, const char* key) { return object.at(key).asString(); }

Value grantToJson(const SupportGrant& grant) {
    Value::Array sessions;
    for (const SupportSession& session : grant.sessions) {
        sessions.push_back(Value(Value::Object{{"session_id", session.sessionId}, {"pbx_address", session.pbxAddress}, {"expires_at", session.expiresAt}}));
    }
    return Value(Value::Object{{"schema", "teliphones-engineer-grant/1"},
                               {"engineer_id", grant.engineerId},
                               {"engineer_address", grant.engineerAddress},
                               {"engineer_public_key", grant.engineerPublicKey},
                               {"gateway_public_key", grant.gatewayPublicKey},
                               {"endpoint", grant.endpoint},
                               {"sessions", Value(sessions)}});
}

SupportGrant grantFromJson(const Value& value) {
    json::RequireExactKeys(value, {"schema", "engineer_id", "engineer_address", "engineer_public_key", "gateway_public_key", "endpoint", "sessions"},
                           "The Remote Support grant");
    if (value.at("schema").asString() != "teliphones-engineer-grant/1") throw Error("This is not a TELIPHONES engineer grant (teliphones-engineer-grant/1).");
    SupportGrant grant;
    grant.engineerId = requireString(value, "engineer_id");
    grant.engineerAddress = requireString(value, "engineer_address");
    grant.engineerPublicKey = requireString(value, "engineer_public_key");
    grant.gatewayPublicKey = requireString(value, "gateway_public_key");
    grant.endpoint = requireString(value, "endpoint");
    std::uint32_t address = 0;
    if (grant.engineerId.empty() || grant.engineerId.size() > 64 || !IsSessionId(grant.engineerId)) throw Error("The grant has an invalid engineer identifier.");
    if (!ParseHostRoute(grant.engineerAddress, address)) throw Error("The grant engineer address must be a single /32 address.");
    if (!IsWireGuardKey(grant.engineerPublicKey) || !IsWireGuardKey(grant.gatewayPublicKey)) throw Error("The grant contains an invalid WireGuard key.");
    if (!IsEndpoint(grant.endpoint)) throw Error("The grant contains an invalid gateway endpoint.");
    std::set<std::string> ids;
    for (const Value& item : value.at("sessions").asArray()) {
        json::RequireExactKeys(item, {"session_id", "pbx_address", "expires_at"}, "A grant session");
        SupportSession session{requireString(item, "session_id"), requireString(item, "pbx_address"), item.at("expires_at").asInteger()};
        std::uint32_t pbx = 0;
        if (!IsSessionId(session.sessionId) || !ids.insert(session.sessionId).second || !ParseIPv4(session.pbxAddress, pbx) ||
            !ParseHostRoute(session.pbxAddress + "/32", pbx) || pbx == address) {
            throw Error("The grant contains an invalid support session.");
        }
        grant.sessions.push_back(session);
    }
    if (grant.sessions.size() > 64) throw Error("The grant lists too many sessions.");
    return grant;
}

Value pairingToJson(const PairResponse& p) {
    Value expires = p.mode == "persistent" ? Value(nullptr) : Value(p.expiresAt);
    Value::Object result{{"workstation_id", p.workstationId}, {"workstation_public_key", p.workstationPublicKey}, {"address", p.address},
                               {"pbx_address", p.pbxAddress}, {"pbx_name", p.pbxName}, {"pbx_public_key", p.pbxPublicKey},
                               {"endpoint", p.endpoint}, {"mode", p.mode}, {"expires_at", expires}, {"ssh", p.ssh}, {"gui_url", p.guiUrl}};
    if (p.sshPort != 0) {
        result.insert({{"ssh_user", p.sshUser}, {"ssh_public_key", p.sshPublicKey}, {"ssh_host_key", p.sshHostKey},
                       {"ssh_ca_key", p.sshCaKey}, {"ssh_port", p.sshPort}, {"ssh_api_port", p.sshApiPort}});
    }
    return Value(result);
}

PairResponse pairingFromJson(const Value& value) {
    std::vector<std::string> keys{"workstation_id", "workstation_public_key", "address", "pbx_address", "pbx_name", "pbx_public_key", "endpoint",
                                   "mode", "expires_at", "ssh", "gui_url"};
    if (value.has("ssh_port")) for (const char* key : {"ssh_user", "ssh_public_key", "ssh_host_key", "ssh_ca_key", "ssh_port", "ssh_api_port"})
        keys.emplace_back(key);
    json::RequireExactKeys(value, keys, "A saved pairing");
    PairResponse p;
    p.workstationId = requireString(value, "workstation_id");
    p.workstationPublicKey = requireString(value, "workstation_public_key");
    p.address = requireString(value, "address");
    p.pbxAddress = requireString(value, "pbx_address");
    p.pbxName = requireString(value, "pbx_name");
    p.pbxPublicKey = requireString(value, "pbx_public_key");
    p.endpoint = requireString(value, "endpoint");
    p.mode = requireString(value, "mode");
    const Value& expires = value.at("expires_at");
    if (p.mode == "temporary") {
        p.expiresAt = expires.asInteger();
        if (p.expiresAt <= 0) throw Error("A temporary pairing has an invalid expiry.");
    } else if (p.mode == "persistent") {
        if (!expires.isNull()) throw Error("A persistent pairing must not have an expiry.");
        p.expiresAt = 0;
    }
    p.ssh = value.at("ssh").asBool();
    p.guiUrl = requireString(value, "gui_url");
    if (value.has("ssh_port")) {
        p.sshUser = requireString(value, "ssh_user");
        p.sshPublicKey = requireString(value, "ssh_public_key");
        p.sshHostKey = requireString(value, "ssh_host_key");
        p.sshCaKey = requireString(value, "ssh_ca_key");
        auto port = value.at("ssh_port").asInteger(), api = value.at("ssh_api_port").asInteger();
        if (port <= 0 || port > 65535 || api <= 0 || api > 65535) throw Error("Invalid saved SSH ports.");
        p.sshPort = static_cast<int>(port);
        p.sshApiPort = static_cast<int>(api);
        ValidateManagedPairing(p);
    }
    std::uint32_t address = 0, pbx = 0;
    if (!IsWorkstationId(p.workstationId) || !IsWireGuardKey(p.workstationPublicKey) || !IsWireGuardKey(p.pbxPublicKey) ||
        !ParseHostRoute(p.address, address) || !ParseIPv4(p.pbxAddress, pbx) || !IsEndpoint(p.endpoint) || !IsPbxName(p.pbxName) ||
        (p.mode != "temporary" && p.mode != "persistent") ||
        (address & 0xFFC00000u) != 0x64400000u || (address & 0xFFFFFF00u) != (pbx & 0xFFFFFF00u) || address == pbx ||
        (pbx & 255) != 1 || !IsManagementUrl(p.guiUrl, p.pbxAddress)) {
        throw Error("A saved pairing is invalid.");
    }
    return p;
}

}  // namespace

SupportGrant ParseEngineerGrant(const std::string& text) { return grantFromJson(json::Parse(text, 256 * 1024)); }

SupportGrant ParseEngineerGrantFor(const std::string& text, const std::string& engineerPublicKey) {
    SupportGrant grant = ParseEngineerGrant(text);
    if (grant.engineerPublicKey != engineerPublicKey) {
        throw Error("This grant was issued for a different engineer key. Ask the gateway operator for a grant for the public key shown in TELIPHONES.");
    }
    return grant;
}

std::string SerializeProfiles(const std::vector<Profile>& profiles) {
    Value::Array items;
    for (const Profile& profile : profiles) {
        Value::Object item{{"id", profile.id}, {"name", profile.name}, {"created_at", profile.createdAt}};
        if (profile.kind == ProfileKind::Administrator) {
            item["kind"] = "administrator";
            item["workstation_name"] = profile.workstationName;
            item["ssh_user"] = profile.sshUser;
            item["pairing"] = pairingToJson(profile.pairing);
        } else {
            item["kind"] = "support";
            item["engineer_public_key"] = profile.engineerPublicKey;
            item["grant"] = profile.hasGrant ? grantToJson(profile.grant) : Value(nullptr);
        }
        items.push_back(Value(item));
    }
    return json::Serialize(Value(Value::Object{{"schema", "teliphones-desktop-profiles/1"}, {"profiles", Value(items)}})) + "\n";
}

std::vector<Profile> ParseProfiles(const std::string& text) {
    Value root = json::Parse(text, 4 * 1024 * 1024);
    json::RequireExactKeys(root, {"schema", "profiles"}, "The profile store");
    if (root.at("schema").asString() != "teliphones-desktop-profiles/1") throw Error("Unsupported TELIPHONES profile store version.");
    std::vector<Profile> profiles;
    std::set<std::string> ids;
    for (const Value& item : root.at("profiles").asArray()) {
        Profile profile;
        profile.id = requireString(item, "id");
        profile.name = requireString(item, "name");
        profile.createdAt = item.at("created_at").asInteger();
        std::string kind = requireString(item, "kind");
        if (!IsProfileId(profile.id) || !ids.insert(profile.id).second || profile.name.empty() || profile.name.size() > 128) {
            throw Error("The profile store contains an invalid profile.");
        }
        if (kind == "administrator") {
            json::RequireExactKeys(item, {"id", "name", "created_at", "kind", "workstation_name", "ssh_user", "pairing"}, "An administrator profile");
            profile.kind = ProfileKind::Administrator;
            profile.workstationName = requireString(item, "workstation_name");
            profile.sshUser = requireString(item, "ssh_user");
            profile.pairing = pairingFromJson(item.at("pairing"));
            if (!IsWorkstationName(profile.workstationName) ||
                (profile.pairing.ssh ? !IsLinuxUser(profile.sshUser) : !profile.sshUser.empty()) ||
                (profile.pairing.sshPort != 0 && profile.sshUser != profile.pairing.sshUser)) {
                throw Error("An administrator profile is invalid.");
            }
        } else if (kind == "support") {
            json::RequireExactKeys(item, {"id", "name", "created_at", "kind", "engineer_public_key", "grant"}, "A Remote Support profile");
            profile.kind = ProfileKind::Support;
            profile.engineerPublicKey = requireString(item, "engineer_public_key");
            profile.hasGrant = !item.at("grant").isNull();
            if (profile.hasGrant) profile.grant = grantFromJson(item.at("grant"));
            if (!IsWireGuardKey(profile.engineerPublicKey) || (profile.hasGrant && profile.grant.engineerPublicKey != profile.engineerPublicKey)) {
                throw Error("A Remote Support profile is invalid.");
            }
        } else {
            throw Error("The profile store contains an unknown profile type.");
        }
        profiles.push_back(profile);
    }
    return profiles;
}

std::string TunnelNameFor(const Profile& profile) {
    if (!IsProfileId(profile.id)) throw Error("Invalid profile identifier.");
    return "TELIPHONES-" + profile.id.substr(0, 12);
}

std::string CredentialTargetFor(const Profile& profile) {
    if (!IsProfileId(profile.id)) throw Error("Invalid profile identifier.");
    return "TELIPHONES/workstation/" + profile.id;
}

TunnelConfig AdministratorTunnel(const Profile& profile, const std::string& privateKey) {
    if (profile.kind != ProfileKind::Administrator) throw Error("Not an administrator profile.");
    TunnelConfig config;
    config.privateKey = privateKey;
    config.address = profile.pairing.address;
    config.peerPublicKey = profile.pairing.pbxPublicKey;
    config.endpoint = profile.pairing.endpoint;
    config.allowedIps = {profile.pairing.pbxAddress + "/32"};
    ValidateTunnel(config);
    return config;
}

TunnelConfig SupportTunnel(const Profile& profile, const std::string& privateKey, const std::string& sessionId, std::int64_t now) {
    if (profile.kind != ProfileKind::Support) throw Error("Not a Remote Support profile.");
    if (!profile.hasGrant) throw Error("Import a grant from your gateway operator before connecting.");
    for (const SupportSession& session : profile.grant.sessions) {
        if (session.sessionId != sessionId) continue;
        if (session.expiresAt <= now) throw Error("This support authorisation has expired. Ask the customer to authorise a new session and import a current grant.");
        TunnelConfig config;
        config.privateKey = privateKey;
        config.address = profile.grant.engineerAddress;
        config.peerPublicKey = profile.grant.gatewayPublicKey;
        config.endpoint = profile.grant.endpoint;
        config.allowedIps = {session.pbxAddress + "/32"};
        ValidateTunnel(config);
        return config;
    }
    throw Error("The selected support session is not in the current grant.");
}

std::int64_t ConnectionExpiry(const Profile& profile, const std::string& sessionId) {
    if (profile.kind == ProfileKind::Administrator) return profile.pairing.mode == "temporary" ? profile.pairing.expiresAt : 0;
    for (const SupportSession& session : profile.grant.sessions) {
        if (session.sessionId == sessionId) return session.expiresAt;
    }
    throw Error("The selected support session is not in the current grant.");
}

std::string ConnectionAddress(const Profile& profile, const std::string& sessionId) {
    if (profile.kind == ProfileKind::Administrator) return profile.pairing.pbxAddress;
    for (const SupportSession& session : profile.grant.sessions) {
        if (session.sessionId == sessionId) return session.pbxAddress;
    }
    throw Error("The selected support session is not in the current grant.");
}

std::string FormatRemaining(std::int64_t seconds) {
    if (seconds <= 0) return "expired";
    std::int64_t hours = seconds / 3600, minutes = (seconds % 3600) / 60;
    if (hours > 0) return std::to_string(hours) + " h " + std::to_string(minutes) + " min";
    if (minutes > 0) return std::to_string(minutes) + " min " + std::to_string(seconds % 60) + " s";
    return std::to_string(seconds) + " s";
}

}  // namespace tlp
