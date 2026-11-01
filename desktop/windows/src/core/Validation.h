// Input validators shared by the unelevated application and the elevated tunnel helper.
#pragma once

#include <cstdint>
#include <string>

namespace tlp {

// WireGuard Curve25519 key in canonical base64 (44 characters, 32 bytes, not all zero).
bool IsWireGuardKey(const std::string& text);
// Matches the broker's WORKSTATION_NAME pattern.
bool IsWorkstationName(const std::string& text);
bool IsWorkstationId(const std::string& text);
bool IsProfileId(const std::string& text);
// WireGuard for Windows tunnel names: [A-Za-z0-9_=+.-]{1,32}.
bool IsTunnelName(const std::string& text);
bool IsHostname(const std::string& text);
bool IsLinuxUser(const std::string& text);
bool IsSessionId(const std::string& text);
bool IsPbxName(const std::string& text);

bool ParseIPv4(const std::string& text, std::uint32_t& address);
std::string FormatIPv4(std::uint32_t address);
// "a.b.c.d/32" only.
bool ParseHostRoute(const std::string& text, std::uint32_t& address);
// "host:port" or "[ipv6]:port", the forms accepted by gateway/engineer_config.py.
bool IsEndpoint(const std::string& text);

}  // namespace tlp
