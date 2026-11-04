#include "Validation.h"

#include "Encoding.h"
#include "Json.h"

namespace tlp {
namespace {

bool alnum(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); }
bool lowerHex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }

bool allOf(const std::string& text, std::size_t minLength, std::size_t maxLength, bool (*allowed)(char)) {
    if (text.size() < minLength || text.size() > maxLength) return false;
    for (char c : text) {
        if (!allowed(c)) return false;
    }
    return true;
}

}  // namespace

bool IsWireGuardKey(const std::string& text) {
    if (text.size() != 44 || text[43] != '=') return false;
    try {
        Bytes raw = Base64Decode(text);
        if (raw.size() != 32) return false;
        for (std::uint8_t b : raw) {
            if (b != 0) return true;
        }
    } catch (const Error&) {
    }
    return false;
}

bool IsWorkstationName(const std::string& text) {
    if (text.empty() || text.size() > 64 || !alnum(text[0])) return false;
    for (char c : text) {
        if (!alnum(c) && c != ' ' && c != '.' && c != '_' && c != '(' && c != ')' && c != '-') return false;
    }
    return true;
}

bool IsWorkstationId(const std::string& text) { return allOf(text, 16, 16, lowerHex); }
bool IsProfileId(const std::string& text) { return allOf(text, 16, 16, lowerHex); }

bool IsTunnelName(const std::string& text) {
    return allOf(text, 1, 32, [](char c) { return alnum(c) || c == '_' || c == '=' || c == '+' || c == '.' || c == '-'; });
}

bool IsHostname(const std::string& text) {
    if (text.empty() || text.size() > 253) return false;
    std::size_t start = 0;
    bool digitsAndDots = true;
    while (true) {
        std::size_t end = text.find('.', start);
        std::string label = text.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (label.empty() || label.size() > 63 || !alnum(label.front()) || !alnum(label.back())) return false;
        for (char c : label) {
            if (!alnum(c) && c != '-') return false;
            if (!(c >= '0' && c <= '9')) digitsAndDots = false;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return !digitsAndDots;
}

bool IsLinuxUser(const std::string& text) {
    if (text.empty() || text.size() > 32) return false;
    if (!((text[0] >= 'a' && text[0] <= 'z') || text[0] == '_')) return false;
    for (char c : text) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-')) return false;
    }
    return true;
}

bool IsSessionId(const std::string& text) {
    return allOf(text, 1, 128, [](char c) { return alnum(c) || c == '_' || c == '-'; });
}

bool IsPbxName(const std::string& text) {
    return allOf(text, 1, 64, [](char c) { return alnum(c) || c == '.' || c == '_' || c == '-'; });
}

bool ParseIPv4(const std::string& text, std::uint32_t& address) {
    std::uint32_t result = 0;
    int parts = 0;
    std::size_t i = 0;
    while (parts < 4) {
        if (i >= text.size() || text[i] < '0' || text[i] > '9') return false;
        std::size_t start = i;
        unsigned value = 0;
        while (i < text.size() && text[i] >= '0' && text[i] <= '9') {
            value = value * 10 + static_cast<unsigned>(text[i] - '0');
            if (i - start >= 3 || value > 255) return false;
            ++i;
        }
        if (i - start > 1 && text[start] == '0') return false;
        result = (result << 8) | value;
        ++parts;
        if (parts < 4) {
            if (i >= text.size() || text[i] != '.') return false;
            ++i;
        }
    }
    if (i != text.size()) return false;
    address = result;
    return true;
}

std::string FormatIPv4(std::uint32_t address) {
    return std::to_string(address >> 24) + "." + std::to_string((address >> 16) & 255) + "." + std::to_string((address >> 8) & 255) + "." +
           std::to_string(address & 255);
}

bool ParseHostRoute(const std::string& text, std::uint32_t& address) {
    if (text.size() < 3 || text.compare(text.size() - 3, 3, "/32") != 0) return false;
    if (!ParseIPv4(text.substr(0, text.size() - 3), address)) return false;
    return address != 0 && (address >> 24) != 127 && (address >> 28) < 14;
}

bool IsEndpoint(const std::string& text) {
    std::size_t colon = text.rfind(':');
    if (colon == std::string::npos || colon == 0) return false;
    std::string host = text.substr(0, colon);
    std::string port = text.substr(colon + 1);
    if (port.empty() || port.size() > 5 || port[0] == '0') return false;
    unsigned value = 0;
    for (char c : port) {
        if (c < '0' || c > '9') return false;
        value = value * 10 + static_cast<unsigned>(c - '0');
    }
    if (value < 1 || value > 65535) return false;
    if (host.front() == '[') {
        if (host.size() < 4 || host.back() != ']') return false;
        for (std::size_t i = 1; i + 1 < host.size(); ++i) {
            char c = host[i];
            if (!(lowerHex(c) || (c >= 'A' && c <= 'F') || c == ':')) return false;
        }
        return true;
    }
    std::uint32_t ipv4 = 0;
    return ParseIPv4(host, ipv4) || IsHostname(host);
}

bool IsManagementUrl(const std::string& text, const std::string& expectedAddress) {
    std::size_t start = text.rfind("http://", 0) == 0 ? 7 : (text.rfind("https://", 0) == 0 ? 8 : 0);
    const std::string suffix = "/admin/";
    if (start == 0 || text.size() <= start + suffix.size() ||
        text.compare(text.size() - suffix.size(), suffix.size(), suffix) != 0) return false;
    std::string authority = text.substr(start, text.size() - start - suffix.size());
    std::size_t colon = authority.find(':');
    std::string address = authority.substr(0, colon);
    std::uint32_t parsed = 0;
    if (!ParseIPv4(address, parsed) || (!expectedAddress.empty() && address != expectedAddress)) return false;
    return colon == std::string::npos || IsEndpoint(authority);
}

}  // namespace tlp
