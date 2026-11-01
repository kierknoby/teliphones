#include "Pairing.h"

#include "Json.h"
#include "Validation.h"

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

PairResponse ParsePairResponse(const std::string& input, const std::string& expectedNonce, const std::string& expectedPublicKey) {
    std::string code = trim(input);
    const std::string prefix = kPairResponsePrefix;
    if (code.size() > 4096 || code.compare(0, prefix.size(), prefix) != 0) {
        throw Error("This is not a TELIPHONES pairing response. Copy the complete response shown on the FreePBX TELIPHONES page.");
    }
    json::Value value;
    try {
        Bytes raw = Base64UrlDecode(code.substr(prefix.size()));
        value = json::Parse(std::string(raw.begin(), raw.end()), 4096);
    } catch (const Error&) {
        throw Error("The pairing response is damaged or incomplete. Copy it again from the FreePBX TELIPHONES page.");
    }
    json::RequireExactKeys(value, {"schema", "nonce", "workstation_id", "workstation_public_key", "address", "pbx_address", "pbx_name",
                                   "pbx_public_key", "endpoint", "mode", "expires_at", "ssh", "gui_url"},
                           "The pairing response");
    if (value.at("schema").asString() != "teliphones-pair-response/1") throw Error("Unsupported pairing response version.");
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

    std::uint32_t address = 0, pbx = 0;
    if (!IsWorkstationId(result.workstationId) || !IsPbxName(result.pbxName) || !IsWireGuardKey(result.pbxPublicKey) ||
        !IsEndpoint(result.endpoint) || !ParseHostRoute(result.address, address) || !ParseIPv4(result.pbxAddress, pbx)) {
        throw Error("The pairing response contains invalid values.");
    }
    // The broker allocates a /24 from 100.64.0.0/10; the PBX and the workstation must share it.
    if ((address & 0xFFC00000u) != 0x64400000u || (address & 0xFFFFFF00u) != (pbx & 0xFFFFFF00u) || address == pbx || (pbx & 255) != 1) {
        throw Error("The pairing response addresses are outside the TELIPHONES workstation range.");
    }
    if (result.guiUrl != "http://" + result.pbxAddress + "/admin/") throw Error("The pairing response contains an unexpected GUI address.");
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
