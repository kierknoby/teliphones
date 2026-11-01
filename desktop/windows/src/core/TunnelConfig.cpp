#include "TunnelConfig.h"

#include <set>

#include "Json.h"
#include "Validation.h"

namespace tlp {

void ValidateTunnel(const TunnelConfig& config) {
    std::uint32_t address = 0;
    if (!IsWireGuardKey(config.privateKey)) throw Error("Invalid WireGuard private key.");
    if (!IsWireGuardKey(config.peerPublicKey)) throw Error("Invalid PBX or gateway WireGuard public key.");
    if (!ParseHostRoute(config.address, address)) throw Error("The tunnel address must be a single IPv4 /32 address.");
    if (!IsEndpoint(config.endpoint)) throw Error("Invalid WireGuard endpoint.");
    if (config.allowedIps.empty() || config.allowedIps.size() > 16) throw Error("A tunnel must route between 1 and 16 PBX addresses.");
    std::set<std::string> seen;
    for (const std::string& route : config.allowedIps) {
        std::uint32_t destination = 0;
        if (!ParseHostRoute(route, destination)) throw Error("Only single-host /32 routes are permitted through a TELIPHONES tunnel.");
        if (destination == address || !seen.insert(route).second) throw Error("Invalid or duplicate tunnel route.");
    }
    if (config.persistentKeepalive != 25) throw Error("Unexpected keepalive interval.");
}

std::string RenderTunnel(const TunnelConfig& config) {
    ValidateTunnel(config);
    std::string allowed;
    for (const std::string& route : config.allowedIps) {
        if (!allowed.empty()) allowed += ", ";
        allowed += route;
    }
    return "[Interface]\r\nPrivateKey = " + config.privateKey + "\r\nAddress = " + config.address + "\r\n\r\n[Peer]\r\nPublicKey = " +
           config.peerPublicKey + "\r\nEndpoint = " + config.endpoint + "\r\nAllowedIPs = " + allowed + "\r\nPersistentKeepalive = 25\r\n";
}

TunnelConfig ParseTunnelStrict(const std::string& text) {
    if (text.size() > 8192) throw Error("Tunnel configuration is too large.");
    TunnelConfig config;
    config.persistentKeepalive = 0;
    std::string section;
    std::set<std::string> seen;
    std::size_t start = 0;
    while (start <= text.size()) {
        std::size_t end = text.find('\n', start);
        std::string line = text.substr(start, end == std::string::npos ? std::string::npos : end - start);
        start = end == std::string::npos ? text.size() + 1 : end + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (line == "[Interface]" || line == "[Peer]") {
            if (!seen.insert(line).second || (line == "[Peer]" && section != "[Interface]")) throw Error("Unexpected tunnel configuration section.");
            section = line;
            continue;
        }
        std::size_t equals = line.find(" = ");
        if (equals == std::string::npos || section.empty()) throw Error("Unexpected tunnel configuration line.");
        std::string key = line.substr(0, equals);
        std::string value = line.substr(equals + 3);
        if (!seen.insert(section + key).second) throw Error("Duplicate tunnel configuration setting.");
        if (section == "[Interface]" && key == "PrivateKey") config.privateKey = value;
        else if (section == "[Interface]" && key == "Address") config.address = value;
        else if (section == "[Peer]" && key == "PublicKey") config.peerPublicKey = value;
        else if (section == "[Peer]" && key == "Endpoint") config.endpoint = value;
        else if (section == "[Peer]" && key == "AllowedIPs") {
            std::size_t from = 0;
            while (true) {
                std::size_t comma = value.find(", ", from);
                config.allowedIps.push_back(value.substr(from, comma == std::string::npos ? std::string::npos : comma - from));
                if (comma == std::string::npos) break;
                from = comma + 2;
            }
        } else if (section == "[Peer]" && key == "PersistentKeepalive" && value == "25") config.persistentKeepalive = 25;
        else throw Error("Tunnel configuration setting is not permitted: " + key);
    }
    if (seen.size() != 8) throw Error("Tunnel configuration is incomplete.");
    ValidateTunnel(config);
    return config;
}

}  // namespace tlp
