// Workstation pairing codec for the TELIPHONES broker contract (teliphones-pair-request/1, teliphones-pair-response/1).
#pragma once

#include <cstdint>
#include <string>

#include "Encoding.h"

namespace tlp {

extern const char kPairRequestPrefix[];
extern const char kPairResponsePrefix[];

// 16 random bytes -> 22 base64url characters, as required by the broker.
std::string MakeNonce(const Bytes& randomBytes);
std::string BuildPairRequest(const std::string& workstation, const std::string& publicKey, const std::string& nonce);

struct PairResponse {
    std::string workstationId;
    std::string workstationPublicKey;
    std::string address;      // workstation tunnel address, a.b.c.d/32
    std::string pbxAddress;   // PBX tunnel address, a.b.c.d
    std::string pbxName;
    std::string pbxPublicKey;
    std::string endpoint;     // host:port
    std::string mode;         // temporary | persistent
    std::int64_t expiresAt = 0;  // 0 for persistent pairings
    bool ssh = false;
    std::string guiUrl;
};

// Verifies the response is bound to this workstation's request before any value is trusted.
PairResponse ParsePairResponse(const std::string& code, const std::string& expectedNonce, const std::string& expectedPublicKey);

// Same fingerprint as the broker and the FreePBX page: "SHA256:" + first 16 base64 characters of SHA-256(raw key).
std::string KeyFingerprint(const std::string& publicKey);

}  // namespace tlp
