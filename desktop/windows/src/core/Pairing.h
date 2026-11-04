// Versioned TELIPHONES workstation pairing and managed SSH certificate bindings.
#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "Encoding.h"

namespace tlp {

extern const char kPairRequestPrefix[];
extern const char kPairResponsePrefix[];

// 16 random bytes -> 22 base64url characters, as required by the broker.
std::string MakeNonce(const Bytes& randomBytes);
std::string BuildPairRequest(const std::string& workstation, const std::string& publicKey, const std::string& nonce);
std::string BuildSshPairRequest(const std::string& workstation, const std::string& publicKey, const std::string& nonce,
                                const std::string& sshPublicKey);
struct WorkstationPairRequest {
    std::string code;
    std::string sshPublicKey;
};
WorkstationPairRequest CreatePairRequest(const std::string& workstation, const std::string& publicKey,
                                        const std::string& nonce, bool requestSsh,
                                        const std::function<std::string()>& generateSshKey);
bool IsSshPublicKey(const std::string& key);

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
    std::string sshUser;
    std::string sshPublicKey;
    std::string sshRequestPublicKey;
    std::string sshHostKey;
    std::string sshCaKey;
    int sshPort = 0;
    int sshApiPort = 0;
};

// Verifies the response is bound to this workstation's request before any value is trusted.
PairResponse ParsePairResponse(const std::string& code, const std::string& expectedNonce, const std::string& expectedPublicKey,
                               const std::string& sshPublicKey = "");
PairResponse ApplyWorkstationMigration(const PairResponse& current, const std::string& migrationJson);
void ValidateManagedPairing(const PairResponse& pairing);
struct SshSessionPublicKey {
    std::string id;
    std::string publicKey;
};
// Structural/trust binding only. SshCrypto verifies the certificate signature separately.
void ValidateSshCertificateBindings(const std::string& certificate, const PairResponse& pairing,
                                   const SshSessionPublicKey& session, std::int64_t now, std::int64_t expiresAt);

// Same fingerprint as the broker and the FreePBX page: "SHA256:" + first 16 base64 characters of SHA-256(raw key).
std::string KeyFingerprint(const std::string& publicKey);

}  // namespace tlp
