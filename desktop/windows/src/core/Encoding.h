// Base64, base64url, hexadecimal and SHA-256 helpers with strict decoding.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace tlp {

using Bytes = std::vector<std::uint8_t>;

std::string Base64Encode(const Bytes& data);
// Canonical padded standard base64 only; throws tlp::Error otherwise.
Bytes Base64Decode(const std::string& text);
std::string Base64UrlEncode(const Bytes& data);
// Unpadded base64url only (the form produced by the TELIPHONES broker); throws tlp::Error otherwise.
Bytes Base64UrlDecode(const std::string& text);

std::string HexEncode(const Bytes& data);

std::array<std::uint8_t, 32> Sha256(const Bytes& data);

}  // namespace tlp
