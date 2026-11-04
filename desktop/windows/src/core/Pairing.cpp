#include "Pairing.h"

#include "Json.h"
#include "Validation.h"
#include <limits>
#include <sstream>

namespace tlp {

const char kPairRequestPrefix[] = "TELIPHONES-PAIR-REQUEST-1:";
const char kPairResponsePrefix[] = "TELIPHONES-PAIR-RESPONSE-1:";

namespace {

bool isNonce(const std::string& nonce) {
    if (nonce.size() != 22) return false;
    for (char c : nonce) {
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
        if (!ok) return false;
    }
    return true;
}

std::string trim(const std::string& text) {
    const char* space = " \t\r\n";
    std::size_t start = text.find_first_not_of(space);
    if (start == std::string::npos) return std::string();
    return text.substr(start, text.find_last_not_of(space) - start + 1);
}

}  // namespace

namespace {
class SshReader {
public:
    explicit SshReader(Bytes bytes) : bytes_(std::move(bytes)) {}
    std::uint64_t number(unsigned count) {
        if (count > bytes_.size() - position_) throw Error("Truncated SSH key.");
        std::uint64_t value = 0;
        while (count-- != 0) value = (value << 8) | bytes_[position_++];
        return value;
    }
    Bytes field() {
        auto count = number(4);
        if (count > bytes_.size() - position_) throw Error("Truncated SSH key field.");
        Bytes value(bytes_.begin() + position_, bytes_.begin() + position_ + static_cast<std::size_t>(count));
        position_ += static_cast<std::size_t>(count);
        return value;
    }
    std::string text() {
        auto value = field();
        return std::string(value.begin(), value.end());
    }
    bool done() const { return position_ == bytes_.size(); }
private:
    Bytes bytes_;
    std::size_t position_ = 0;
};

Bytes keyBlob(const std::string& key, const std::string& kind) {
    std::istringstream input(key);
    std::string type, encoded, extra;
    if (!(input >> type >> encoded) || type != kind) throw Error("Unexpected SSH key format.");
    if (kind == "ssh-ed25519" && (input >> extra)) throw Error("Unexpected SSH public-key comment.");
    if (kind != "ssh-ed25519") {
        const auto newline = key.find('\n');
        if (newline != std::string::npos && newline != key.size() - 1) throw Error("Multiple SSH certificate lines are not allowed.");
    }
    return Base64Decode(encoded);
}
}  // namespace

bool IsSshPublicKey(const std::string& key) {
    try {
        if (key.size() > 128) return false;
        auto blob = keyBlob(key, "ssh-ed25519");
        SshReader reader(blob);
        if (reader.text() != "ssh-ed25519" || reader.field().size() != 32 || !reader.done()) return false;
        return key == "ssh-ed25519 " + Base64Encode(blob);
    } catch (const Error&) {
        return false;
    }
}

void ValidateManagedPairing(const PairResponse& p) {
    if (p.sshPort == 0) {
        if (!p.sshUser.empty() || !p.sshHostKey.empty() || !p.sshCaKey.empty() || p.sshApiPort != 0)
            throw Error("Incomplete managed SSH pairing.");
        return;
    }
    std::uint32_t address = 0;
    bool validSource = ParseHostRoute(p.address, address);
#ifdef TELIPHONES_SSH_LOOPBACK_FIXTURE
    // The isolated native sshd fixture must not bind a deployable network address.
    if (p.address == "127.0.0.1/32") { validSource = true; address = 0x7f000001; }
#endif
    if (!p.ssh || !IsLinuxUser(p.sshUser) || !IsSshPublicKey(p.sshPublicKey) || !IsSshPublicKey(p.sshHostKey) ||
        !IsSshPublicKey(p.sshCaKey) || !validSource || p.sshPort != 22000 + static_cast<int>(address & 255) ||
        p.sshApiPort != 8765) throw Error("Invalid managed SSH account, keys or endpoint.");
}

void ValidateSshCertificateBindings(const std::string& certificate, const PairResponse& p,
                                   const SshSessionPublicKey& session, std::int64_t now, std::int64_t expiresAt) {
    ValidateManagedPairing(p);
    if (session.id.size() != 32 || session.id.find_first_not_of("0123456789abcdef") != std::string::npos ||
        !IsSshPublicKey(session.publicKey) || session.publicKey == p.sshPublicKey)
        throw Error("A separate ephemeral SSH session identity and public key are required.");
    if (p.sshPort == 0 || certificate.size() > 8192 || expiresAt <= now || expiresAt > now + 330 ||
        (p.expiresAt != 0 && expiresAt > p.expiresAt)) throw Error("SSH certificate validity exceeds its authorisation.");
    SshReader cert(keyBlob(certificate, "ssh-ed25519-cert-v01@openssh.com"));
    if (cert.text() != "ssh-ed25519-cert-v01@openssh.com") throw Error("Unexpected SSH certificate type.");
    cert.field(); // nonce
    SshReader publicKey(keyBlob(session.publicKey, "ssh-ed25519"));
    publicKey.text();
    if (cert.field() != publicKey.field()) throw Error("The SSH certificate belongs to a different ephemeral session key.");
    cert.number(8); // serial
    if (cert.number(4) != 1 || cert.text() != "ws-" + p.workstationId + "/" + session.id) throw Error("Unexpected SSH certificate identity.");
    SshReader principals(cert.field());
    auto digest = Sha256(Bytes(p.sshPublicKey.begin(), p.sshPublicKey.end()));
    const std::string principal = "tlp-eph-" + p.workstationId + "-" + HexEncode(Bytes(digest.begin(), digest.end())).substr(0, 16);
    if (principals.text() != principal || !principals.done()) throw Error("Unexpected SSH certificate principal.");
    auto from = cert.number(8), until = cert.number(8);
    if (from > static_cast<std::uint64_t>(now + 30) || until != static_cast<std::uint64_t>(expiresAt) || until < from || until - from > 300)
        throw Error("SSH certificate has invalid validity bounds.");
    SshReader critical(cert.field());
    if (critical.text() != "source-address") throw Error("SSH certificate lacks workstation source binding.");
    SshReader source(critical.field());
    if (source.text() != p.address || !source.done() || !critical.done()) throw Error("SSH certificate has unexpected critical options.");
    SshReader extensions(cert.field());
    if (extensions.text() != "permit-pty" || !extensions.field().empty() || !extensions.done())
        throw Error("SSH certificate has unexpected shell permissions.");
    if (!cert.field().empty() || cert.field() != keyBlob(p.sshCaKey, "ssh-ed25519"))
        throw Error("SSH certificate was not issued by the paired authority.");
    if (cert.field().empty() || !cert.done()) throw Error("SSH certificate signature is missing or malformed.");
}

std::string MakeNonce(const Bytes& randomBytes) {
    if (randomBytes.size() != 16) throw Error("A pairing nonce requires 16 random bytes.");
    return Base64UrlEncode(randomBytes);
}

std::string BuildPairRequest(const std::string& workstation, const std::string& publicKey, const std::string& nonce) {
    if (!IsWorkstationName(workstation)) {
        throw Error("Workstation names must start with a letter or digit and use only letters, digits, spaces, '.', '_', '(', ')' or '-' (64 characters maximum).");
    }
    if (!IsWireGuardKey(publicKey)) throw Error("The workstation WireGuard public key is invalid.");
    if (!isNonce(nonce)) throw Error("The pairing nonce is invalid.");
    json::Value::Object request{{"schema", "teliphones-pair-request/1"}, {"workstation", workstation}, {"public_key", publicKey}, {"nonce", nonce}};
    std::string body = json::Serialize(json::Value(request));
    return kPairRequestPrefix + Base64UrlEncode(Bytes(body.begin(), body.end()));
}

std::string BuildSshPairRequest(const std::string& workstation, const std::string& publicKey, const std::string& nonce,
                                const std::string& sshPublicKey) {
    BuildPairRequest(workstation, publicKey, nonce);
    if (!IsSshPublicKey(sshPublicKey)) throw Error("Invalid workstation SSH public key.");
    std::string body = json::Serialize(json::Value::Object{{"schema", "teliphones-pair-request/2"}, {"workstation", workstation},
        {"public_key", publicKey}, {"nonce", nonce}, {"ssh_public_key", sshPublicKey}});
    return "TELIPHONES-PAIR-REQUEST-2:" + Base64UrlEncode(Bytes(body.begin(), body.end()));
}

WorkstationPairRequest CreatePairRequest(const std::string& workstation, const std::string& publicKey,
                                        const std::string& nonce, bool requestSsh,
                                        const std::function<std::string()>& generateSshKey) {
    const auto webRequest = BuildPairRequest(workstation, publicKey, nonce);
    if (!requestSsh) return {webRequest, ""};
    if (!generateSshKey) throw Error("SSH capability requires an OpenSSH key generator.");
    const auto key = generateSshKey();
    return {BuildSshPairRequest(workstation, publicKey, nonce, key), key};
}

PairResponse ParsePairResponse(const std::string& input, const std::string& expectedNonce, const std::string& expectedPublicKey,
                               const std::string& sshPublicKey) {
    std::string code = trim(input);
    const bool managed = code.rfind("TELIPHONES-PAIR-RESPONSE-2:", 0) == 0;
    const std::string prefix = managed ? "TELIPHONES-PAIR-RESPONSE-2:" : kPairResponsePrefix;
    if (code.size() > 16000 || code.compare(0, prefix.size(), prefix) != 0) {
        throw Error("This is not a TELIPHONES pairing response. Copy the complete response shown on the FreePBX TELIPHONES page.");
    }
    json::Value value;
    try {
        Bytes raw = Base64UrlDecode(code.substr(prefix.size()));
        value = json::Parse(std::string(raw.begin(), raw.end()), 16000);
    } catch (const Error&) {
        throw Error("The pairing response is damaged or incomplete. Copy it again from the FreePBX TELIPHONES page.");
    }
    std::vector<std::string> keys{"schema", "nonce", "workstation_id", "workstation_public_key", "address", "pbx_address", "pbx_name",
                                   "pbx_public_key", "endpoint", "mode", "expires_at", "ssh", "gui_url"};
    if (managed) for (const char* key : {"ssh_user", "ssh_host_key", "ssh_ca_key", "ssh_port", "ssh_api_port"}) keys.emplace_back(key);
    json::RequireExactKeys(value, keys, "The pairing response");
    if (value.at("schema").asString() != (managed ? "teliphones-pair-response/2" : "teliphones-pair-response/1"))
        throw Error("Unsupported pairing response version.");
    if (value.at("nonce").asString() != expectedNonce || value.at("workstation_public_key").asString() != expectedPublicKey) {
        throw Error("This pairing response was issued for a different pairing request. Paste the response generated for the request shown in this window.");
    }

    PairResponse result;
    result.workstationId = value.at("workstation_id").asString();
    result.workstationPublicKey = expectedPublicKey;
    result.address = value.at("address").asString();
    result.pbxAddress = value.at("pbx_address").asString();
    result.pbxName = value.at("pbx_name").asString();
    result.pbxPublicKey = value.at("pbx_public_key").asString();
    result.endpoint = value.at("endpoint").asString();
    result.mode = value.at("mode").asString();
    result.ssh = value.at("ssh").asBool();
    result.guiUrl = value.at("gui_url").asString();
    if (managed) {
        result.sshUser = value.at("ssh_user").asString();
        result.sshPublicKey = sshPublicKey;
        result.sshHostKey = value.at("ssh_host_key").asString();
        result.sshCaKey = value.at("ssh_ca_key").asString();
        auto sshPort = value.at("ssh_port").asInteger(), apiPort = value.at("ssh_api_port").asInteger();
        if (sshPort < 0 || sshPort > 65535 || apiPort < 0 || apiPort > 65535) throw Error("Invalid SSH ports.");
        result.sshPort = static_cast<int>(sshPort);
        result.sshApiPort = static_cast<int>(apiPort);
        if (result.ssh != (result.sshPort != 0)) throw Error("Inconsistent managed SSH permission.");
        ValidateManagedPairing(result);
    }

    std::uint32_t address = 0, pbx = 0;
    if (!IsWorkstationId(result.workstationId) || !IsPbxName(result.pbxName) || !IsWireGuardKey(result.pbxPublicKey) ||
        !IsEndpoint(result.endpoint) || !ParseHostRoute(result.address, address) || !ParseIPv4(result.pbxAddress, pbx)) {
        throw Error("The pairing response contains invalid values.");
    }
    // The broker allocates a /24 from 100.64.0.0/10; the PBX and the workstation must share it.
    if ((address & 0xFFC00000u) != 0x64400000u || (address & 0xFFFFFF00u) != (pbx & 0xFFFFFF00u) || address == pbx || (pbx & 255) != 1) {
        throw Error("The pairing response addresses are outside the TELIPHONES workstation range.");
    }
    if (!IsManagementUrl(result.guiUrl, result.pbxAddress)) throw Error("The pairing response contains an unexpected GUI address.");
    const json::Value& expires = value.at("expires_at");
    if (result.mode == "temporary") {
        result.expiresAt = expires.asInteger();
        if (result.expiresAt <= 0) throw Error("The pairing response has an invalid expiry.");
    } else if (result.mode == "persistent") {
        if (!expires.isNull()) throw Error("A persistent pairing must not carry an expiry.");
    } else {
        throw Error("The pairing response has an unknown access mode.");
    }
    return result;
}

std::string KeyFingerprint(const std::string& publicKey) {
    auto digest = Sha256(Base64Decode(publicKey));
    std::string encoded = Base64Encode(Bytes(digest.begin(), digest.end()));
    return "SHA256:" + encoded.substr(0, 16);
}

}  // namespace tlp
