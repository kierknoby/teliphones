// Portable unit tests for the TELIPHONES desktop core. Build with CMake or any C++17 compiler; no dependencies.
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

#include "../src/core/CommandLine.h"
#include "../src/core/Encoding.h"
#include "../src/core/Json.h"
#include "../src/core/Monitor.h"
#include "../src/core/Pairing.h"
#include "../src/core/Profiles.h"
#include "../src/core/Rendezvous.h"
#include "../src/core/TunnelConfig.h"
#include "../src/core/Validation.h"

using namespace tlp;

namespace {

int failures = 0;
int checks = 0;

void check(bool condition, const char* message) {
    ++checks;
    if (!condition) {
        ++failures;
        std::printf("FAIL: %s\n", message);
    }
}

bool throws(const std::function<void()>& action) {
    try {
        action();
    } catch (const Error&) {
        return true;
    }
    return false;
}

const std::string kWorkstationKey = std::string(42, 'A') + "E=";
const std::string kPbxKey = std::string(42, 'B') + "E=";
const std::string kPrivateKey = std::string(42, 'C') + "E=";
const std::string kNonce = "abcdefghijklmnopqrstuv";

std::string response(json::Value::Object fields) {
    json::Value::Object base{{"schema", "teliphones-pair-response/1"}, {"nonce", kNonce}, {"workstation_id", "0123456789abcdef"},
                             {"workstation_public_key", kWorkstationKey}, {"address", "100.70.1.2/32"}, {"pbx_address", "100.70.1.1"},
                             {"pbx_name", "pbx1"}, {"pbx_public_key", kPbxKey}, {"endpoint", "pbx.example.net:51821"}, {"mode", "temporary"},
                             {"expires_at", std::int64_t(2000000000)}, {"ssh", true}, {"gui_url", "http://100.70.1.1/admin/"}};
    for (auto& field : fields) {
        if (field.second.isString() && field.second.asString() == "<remove>") base.erase(field.first);
        else base[field.first] = field.second;
    }
    std::string body = json::Serialize(json::Value(base));
    return kPairResponsePrefix + Base64UrlEncode(Bytes(body.begin(), body.end()));
}

Profile adminProfile() {
    Profile profile;
    profile.id = "0011223344556677";
    profile.name = "Head office PBX";
    profile.createdAt = 1;
    profile.workstationName = "ADMIN-PC";
    profile.sshUser = "admin";
    profile.pairing = ParsePairResponse(response({}), kNonce, kWorkstationKey);
    return profile;
}

Profile webOnlyPersistentProfile() {
    Profile profile = adminProfile();
    profile.id = "1122334455667788";
    profile.name = "Web only PBX";
    profile.sshUser.clear();
    profile.pairing.mode = "persistent";
    profile.pairing.expiresAt = 0;
    profile.pairing.ssh = false;
    return profile;
}

Profile supportProfile() {
    Profile profile;
    profile.id = "8899aabbccddeeff";
    profile.kind = ProfileKind::Support;
    profile.name = "MSP gateway";
    profile.engineerPublicKey = kWorkstationKey;
    profile.hasGrant = true;
    profile.grant = ParseEngineerGrantFor(
        "{\"schema\":\"teliphones-engineer-grant/1\",\"engineer_id\":\"engineer-a\",\"engineer_address\":\"10.99.0.2/32\","
        "\"engineer_public_key\":\"" + kWorkstationKey + "\",\"gateway_public_key\":\"" + kPbxKey + "\",\"endpoint\":\"gw.example.net:51820\","
        "\"sessions\":[{\"session_id\":\"s-1\",\"pbx_address\":\"10.20.4.2\",\"expires_at\":2000},{\"session_id\":\"s-2\",\"pbx_address\":\"10.20.5.2\",\"expires_at\":900}]}", kWorkstationKey);
    return profile;
}

void testEncoding() {
    auto digest = Sha256(Bytes{'a', 'b', 'c'});
    check(HexEncode(Bytes(digest.begin(), digest.end())) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 of abc");
    auto empty = Sha256(Bytes{});
    check(HexEncode(Bytes(empty.begin(), empty.end())) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256 of empty input");
    std::string block(1000, 'x');
    auto longDigest = Sha256(Bytes(block.begin(), block.end()));
    check(HexEncode(Bytes(longDigest.begin(), longDigest.end())).size() == 64, "SHA-256 multi-block input");
    check(Base64Encode(Bytes{'f', 'o', 'o', 'b'}) == "Zm9vYg==", "base64 padding");
    check(Base64UrlEncode(Bytes{0xfb, 0xff}) == "-_8", "base64url alphabet without padding");
    check(Base64UrlDecode("-_8") == Bytes({0xfb, 0xff}), "base64url decode");
    check(throws([] { Base64Decode("Zm9vYh=="); }), "non-canonical base64 rejected");
    check(throws([] { Base64Decode("Zm9v Yg=="); }), "base64 with spaces rejected");
    check(throws([] { Base64UrlDecode("ab+c"); }), "standard alphabet rejected in base64url");
}

void testJson() {
    json::Value value = json::Parse("{\"a\":[1,true,null,\"x\\u00e9\\ud83d\\ude00\"],\"b\":-5}");
    check(value.at("a").asArray().size() == 4 && value.at("b").asInteger() == -5, "JSON parse");
    check(value.at("a").asArray()[3].asString() == "x\xc3\xa9\xf0\x9f\x98\x80", "JSON unicode escapes");
    check(json::Serialize(json::Parse("{\"b\":1,\"a\":\"q\\\"\"}")) == "{\"a\":\"q\\\"\",\"b\":1}", "JSON serialise sorted and escaped");
    check(throws([] { json::Parse("{\"a\":1,\"a\":2}"); }), "duplicate keys rejected");
    check(throws([] { json::Parse(std::string(40, '[') + std::string(40, ']')); }), "deep nesting rejected");
    check(throws([] { json::Parse("{\"a\":1} x"); }), "trailing data rejected");
    check(throws([] { json::Parse("\"\x01\""); }), "control characters rejected");
    check(throws([] { json::Parse("01"); }), "leading zero rejected");
    check(!json::Parse("1.5").isInteger() && !json::Parse("99999999999999999999").isInteger(), "fractions and overflow are not integers");
    check(throws([] { json::Parse("\"\\ud800\""); }), "unpaired surrogate rejected");
}

void testValidation() {
    check(IsWireGuardKey(kWorkstationKey), "valid WireGuard key");
    check(!IsWireGuardKey(std::string(43, 'A') + "="), "all-zero key rejected");
    check(!IsWireGuardKey(std::string(42, 'A') + "B="), "non-canonical key rejected");
    check(IsWorkstationName("ADMIN-PC (Office) 2") && !IsWorkstationName(" bad") && !IsWorkstationName("a\"b") && !IsWorkstationName(std::string(65, 'a')),
          "workstation names follow the broker pattern");
    std::uint32_t address = 0;
    check(ParseIPv4("100.64.0.1", address) && address == 0x64400001u, "IPv4 parse");
    check(!ParseIPv4("1.2.3", address) && !ParseIPv4("1.2.3.256", address) && !ParseIPv4("01.2.3.4", address) && !ParseIPv4("1.2.3.4 ", address),
          "malformed IPv4 rejected");
    check(ParseHostRoute("10.20.1.2/32", address) && !ParseHostRoute("0.0.0.0/32", address) && !ParseHostRoute("10.0.0.0/8", address) &&
              !ParseHostRoute("127.0.0.1/32", address) && !ParseHostRoute("224.0.0.1/32", address),
          "only unicast /32 host routes accepted");
    check(IsEndpoint("pbx.example.net:51821") && IsEndpoint("203.0.113.5:1") && IsEndpoint("[2001:db8::1]:51821"), "endpoints accepted");
    check(!IsEndpoint("pbx:0") && !IsEndpoint("pbx:65536") && !IsEndpoint(":51821") && !IsEndpoint("1.2.3:51821") && !IsEndpoint("a b:1") &&
              !IsEndpoint("[zz]:1"),
          "malformed endpoints rejected");
    check(IsLinuxUser("admin") && IsLinuxUser("root") && !IsLinuxUser("Admin") && !IsLinuxUser("-x") && !IsLinuxUser("a b"), "SSH user names");
}

void testPairing() {
    std::string request = BuildPairRequest("ADMIN-PC", kWorkstationKey, kNonce);
    check(request.compare(0, 26, kPairRequestPrefix) == 0, "request prefix");
    Bytes body = Base64UrlDecode(request.substr(26));
    json::Value parsed = json::Parse(std::string(body.begin(), body.end()));
    check(parsed.at("schema").asString() == "teliphones-pair-request/1" && parsed.at("public_key").asString() == kWorkstationKey &&
              parsed.asObject().size() == 4,
          "request contains only schema, workstation, public key and nonce");
    check(MakeNonce(Bytes(16, 7)).size() == 22, "nonce length");
    check(throws([] { BuildPairRequest("bad\"name", kWorkstationKey, kNonce); }), "invalid workstation name rejected");
    check(throws([] { BuildPairRequest("PC", "not-a-key", kNonce); }), "invalid key rejected");
    check(throws([] { MakeNonce(Bytes(8, 1)); }), "short nonce rejected");

    PairResponse ok = ParsePairResponse("  " + response({}) + "\r\n", kNonce, kWorkstationKey);
    check(ok.workstationId == "0123456789abcdef" && ok.pbxAddress == "100.70.1.1" && ok.expiresAt == 2000000000 && ok.ssh, "valid response parsed");
    PairResponse persistent = ParsePairResponse(response({{"mode", "persistent"}, {"expires_at", nullptr}}), kNonce, kWorkstationKey);
    check(persistent.mode == "persistent" && persistent.expiresAt == 0, "persistent response parsed");

    struct Case {
        json::Value::Object fields;
        const char* message;
    };
    std::vector<Case> invalid = {
        {{{"nonce", "bcdefghijklmnopqrstuvw"}}, "response for another request rejected"},
        {{{"workstation_public_key", kPbxKey}}, "response for another key rejected"},
        {{{"gui_url", "https://evil.example/"}}, "arbitrary GUI URL rejected"},
        {{{"address", "100.70.2.2/32"}}, "workstation outside PBX subnet rejected"},
        {{{"address", "10.0.0.2/32"}, {"pbx_address", "10.0.0.1"}, {"gui_url", "http://10.0.0.1/admin/"}}, "addresses outside 100.64.0.0/10 rejected"},
        {{{"address", "100.70.1.0/24"}}, "broad workstation address rejected"},
        {{{"pbx_address", "100.70.1.9"}, {"gui_url", "http://100.70.1.9/admin/"}}, "PBX must be the subnet's first host"},
        {{{"mode", "persistent"}}, "persistent response with expiry rejected"},
        {{{"mode", "forever"}}, "unknown mode rejected"},
        {{{"expires_at", "2000000000"}}, "string expiry rejected"},
        {{{"ssh", "yes"}}, "non-boolean SSH flag rejected"},
        {{{"extra", 1}}, "unexpected field rejected"},
        {{{"pbx_name", "<remove>"}}, "missing field rejected"},
        {{{"endpoint", "pbx.example.net"}}, "endpoint without port rejected"},
        {{{"pbx_public_key", "x"}}, "invalid PBX key rejected"},
        {{{"schema", "teliphones-pair-response/2"}}, "unknown schema rejected"},
    };
    for (const Case& item : invalid) check(throws([&] { ParsePairResponse(response(item.fields), kNonce, kWorkstationKey); }), item.message);
    check(throws([] { ParsePairResponse("TELIPHONES-PAIR-REQUEST-1:abc", kNonce, kWorkstationKey); }), "request pasted as response rejected");
    check(throws([] { ParsePairResponse(response({}).substr(0, 60), kNonce, kWorkstationKey); }), "truncated response rejected");
    check(KeyFingerprint(kWorkstationKey).size() == 23 && KeyFingerprint(kWorkstationKey).compare(0, 7, "SHA256:") == 0, "fingerprint format");
}

void testTunnels() {
    Profile admin = adminProfile();
    std::string text = RenderTunnel(AdministratorTunnel(admin, kPrivateKey));
    check(text == "[Interface]\r\nPrivateKey = " + kPrivateKey + "\r\nAddress = 100.70.1.2/32\r\n\r\n[Peer]\r\nPublicKey = " + kPbxKey +
                      "\r\nEndpoint = pbx.example.net:51821\r\nAllowedIPs = 100.70.1.1/32\r\nPersistentKeepalive = 25\r\n",
          "administrator tunnel routes only the PBX address");
    TunnelConfig parsed = ParseTunnelStrict(text);
    check(parsed.allowedIps == std::vector<std::string>{"100.70.1.1/32"} && parsed.privateKey == kPrivateKey, "strict parser round trip");
    std::string lfOnly = text;
    for (std::size_t at; (at = lfOnly.find('\r')) != std::string::npos;) lfOnly.erase(at, 1);
    check(ParseTunnelStrict(lfOnly).endpoint == "pbx.example.net:51821", "LF line endings accepted");
    auto replace = [&](const std::string& from, const std::string& to) {
        std::string copy = text;
        copy.replace(copy.find(from), from.size(), to);
        return copy;
    };
    std::vector<std::pair<std::string, const char*>> hostile = {
        {replace("AllowedIPs = 100.70.1.1/32", "AllowedIPs = 0.0.0.0/0"), "default route rejected"},
        {replace("AllowedIPs = 100.70.1.1/32", "AllowedIPs = 100.70.1.1/32, 10.0.0.0/8"), "broad route rejected"},
        {replace("AllowedIPs = 100.70.1.1/32", "AllowedIPs = 100.70.1.1/32,100.70.1.3/32"), "unexpected route list format rejected"},
        {replace("Address = 100.70.1.2/32", "Address = 100.70.1.2/32\r\nPostUp = cmd /c calc"), "PostUp script rejected"},
        {replace("Address = 100.70.1.2/32", "Address = 100.70.1.2/32\r\nDNS = 1.1.1.1"), "DNS change rejected"},
        {replace("Address = 100.70.1.2/32", "Address = 100.70.1.2/32\r\nTable = off"), "routing table override rejected"},
        {replace("Address = 100.70.1.2/32", "Address = 100.70.1.2/32\r\nAddress = 100.70.1.3/32"), "duplicate setting rejected"},
        {replace("PersistentKeepalive = 25", "PersistentKeepalive = 1"), "unexpected keepalive rejected"},
        {replace("PersistentKeepalive = 25\r\n", ""), "incomplete configuration rejected"},
        {text + "[Peer]\r\n", "second peer rejected"},
        {"# comment\r\n" + text, "comments rejected"},
        {replace("PrivateKey = ", "PrivateKey="), "non-canonical formatting rejected"},
    };
    for (const auto& item : hostile) check(throws([&] { ParseTunnelStrict(item.first); }), item.second);

    Profile support = supportProfile();
    TunnelConfig session = SupportTunnel(support, kPrivateKey, "s-1", 1000);
    check(session.allowedIps == std::vector<std::string>{"10.20.4.2/32"} && session.endpoint == "gw.example.net:51820" && session.address == "10.99.0.2/32",
          "support tunnel routes only the selected session");
    check(throws([&] { SupportTunnel(support, kPrivateKey, "s-2", 1000); }), "expired support session refused");
    check(throws([&] { SupportTunnel(support, kPrivateKey, "missing", 1000); }), "unknown support session refused");
    check(throws([&] { SupportTunnel(admin, kPrivateKey, "s-1", 1000); }), "profile kind enforced");
    Profile awaiting = support;
    awaiting.hasGrant = false;
    check(throws([&] { SupportTunnel(awaiting, kPrivateKey, "s-1", 1000); }), "support profile without a grant cannot connect");
    check(ConnectionExpiry(support, "s-1") == 2000 && ConnectionExpiry(admin, "") == 2000000000, "connection expiry");
}

void testGrants() {
    auto grant = [](const std::string& patch) {
        std::string base = "{\"schema\":\"teliphones-engineer-grant/1\",\"engineer_id\":\"engineer-a\",\"engineer_address\":\"10.99.0.2/32\","
                           "\"engineer_public_key\":\"" + kWorkstationKey + "\",\"gateway_public_key\":\"" + kPbxKey + "\",\"endpoint\":\"gw.example.net:51820\","
                           "\"sessions\":[{\"session_id\":\"s-1\",\"pbx_address\":\"10.20.4.2\",\"expires_at\":2000}]" + patch + "}";
        return ParseEngineerGrant(base);
    };
    check(grant("").sessions.size() == 1, "engineer grant parsed");
    check(throws([] { ParseEngineerGrantFor("{\"schema\":\"teliphones-engineer-grant/1\",\"engineer_id\":\"e\",\"engineer_address\":\"10.99.0.2/32\","
                                            "\"engineer_public_key\":\"" + kPbxKey + "\",\"gateway_public_key\":\"" + kPbxKey +
                                            "\",\"endpoint\":\"gw:1\",\"sessions\":[]}", kWorkstationKey); }),
          "grant for another engineer key rejected");
    check(throws([&] { grant(",\"private_key\":\"x\""); }), "grant with extra fields rejected");
    check(throws([] { ParseEngineerGrant("{\"schema\":\"teliphones-checker-grant/1\"}"); }), "checker grant rejected");
    check(throws([] {
              ParseEngineerGrant("{\"schema\":\"teliphones-engineer-grant/1\",\"engineer_id\":\"e\",\"engineer_address\":\"10.99.0.0/24\","
                                 "\"engineer_public_key\":\"" + kWorkstationKey + "\",\"gateway_public_key\":\"" + kPbxKey +
                                 "\",\"endpoint\":\"gw:1\",\"sessions\":[]}");
          }),
          "broad engineer address rejected");
    check(throws([] {
              ParseEngineerGrant("{\"schema\":\"teliphones-engineer-grant/1\",\"engineer_id\":\"e\",\"engineer_address\":\"10.99.0.2/32\","
                                 "\"engineer_public_key\":\"" + kWorkstationKey + "\",\"gateway_public_key\":\"" + kPbxKey +
                                 "\",\"endpoint\":\"gw:1\",\"sessions\":[{\"session_id\":\"a\",\"pbx_address\":\"0.0.0.0\",\"expires_at\":1}]}");
          }),
          "invalid session address rejected");
}

void testProfiles() {
    Profile awaiting = supportProfile();
    awaiting.id = "aaaaaaaaaaaaaaaa";
    awaiting.hasGrant = false;
    awaiting.grant = SupportGrant();
    std::vector<Profile> profiles{adminProfile(), supportProfile(), awaiting, webOnlyPersistentProfile()};
    std::string stored = SerializeProfiles(profiles);
    check(stored.find(kPrivateKey) == std::string::npos && stored.find("private") == std::string::npos, "profile store contains no private keys");
    std::vector<Profile> loaded = ParseProfiles(stored);
    check(loaded.size() == 4 && loaded[0].pairing.pbxAddress == "100.70.1.1" && loaded[1].grant.sessions.size() == 2 && !loaded[2].hasGrant &&
              loaded[2].engineerPublicKey == kWorkstationKey && loaded[3].pairing.mode == "persistent" &&
              loaded[3].pairing.expiresAt == 0 && !loaded[3].pairing.ssh && loaded[3].sshUser.empty() && SerializeProfiles(loaded) == stored,
          "profile store round trip");
    check(TunnelNameFor(loaded[0]) == "TELIPHONES-001122334455" && IsTunnelName(TunnelNameFor(loaded[0])), "tunnel name");
    check(CredentialTargetFor(loaded[1]) == "TELIPHONES/workstation/8899aabbccddeeff", "credential target");
    std::string duplicate = stored;
    duplicate.replace(duplicate.find("8899aabbccddeeff"), 16, "0011223344556677");
    check(throws([&] { ParseProfiles(duplicate); }), "duplicate profile ids rejected");
    std::string tampered = stored;
    tampered.replace(tampered.find("http://100.70.1.1/admin/"), 24, "https://evil.example/x/");
    check(throws([&] { ParseProfiles(tampered); }), "tampered GUI URL rejected on load");
    std::string mismatched = stored;
    mismatched.replace(mismatched.find("\"engineer_public_key\":\"" + kWorkstationKey), 23 + 44, "\"engineer_public_key\":\"" + kPbxKey);
    check(throws([&] { ParseProfiles(mismatched); }), "grant not matching the stored engineer key rejected on load");
    std::string badPersistentExpiry = stored;
    std::size_t expiry = badPersistentExpiry.find("\"expires_at\":null");
    if (expiry != std::string::npos) {
        badPersistentExpiry.replace(expiry, std::string("\"expires_at\":null").size(), "\"expires_at\":1");
    }
    check(expiry != std::string::npos && throws([&] { ParseProfiles(badPersistentExpiry); }), "persistent pairing rejects an unexpected expiry");
    check(FormatRemaining(3725) == "1 h 2 min" && FormatRemaining(125) == "2 min 5 s" && FormatRemaining(9) == "9 s" && FormatRemaining(0) == "expired",
          "remaining time format");
}

void testCommandLine() {
    check(QuoteArgument("plain") == "plain" && QuoteArgument("") == "\"\"", "simple quoting");
    check(QuoteArgument("C:\\Program Files\\x\\") == "\"C:\\Program Files\\x\\\\\"", "trailing backslash quoting");
    check(QuoteArgument("a\"b c") == "\"a\\\"b c\"", "embedded quote quoting");
    Profile admin = adminProfile();
    auto ssh = SshArguments(admin, "");
    check(ssh.back() == "admin@100.70.1.1" && ssh[5] == "22" && ssh[3] == "HostKeyAlias=teliphones-0011223344556677", "administrator SSH arguments");
    admin.pairing.ssh = false;
    check(throws([&] { SshArguments(admin, ""); }), "SSH refused when not approved on the PBX");
    admin.pairing.ssh = true;
    admin.sshUser = "x; calc";
    check(throws([&] { SshArguments(admin, ""); }), "unsafe SSH user rejected");
    auto support = SshArguments(supportProfile(), "s-1");
    check(support.back() == "root@10.20.4.2" && support[5] == "22222", "Remote Support SSH uses the temporary support service");

    HelperCommand up{HelperCommand::Verb::TunnelUp, "TELIPHONES-001122334455", "C:\\Users\\a\\AppData\\Local\\TELIPHONES\\Staging\\TELIPHONES-001122334455.conf",
                     "S-1-5-21-1-2-3-1001"};
    HelperCommand parsed = ParseHelperArguments(HelperArguments(up));
    check(parsed.verb == HelperCommand::Verb::TunnelUp && parsed.stagingPath == up.stagingPath && parsed.userSid == up.userSid, "helper arguments round trip");
    check(ParseHelperArguments({"/tunnel-down", "TELIPHONES-001122334455"}).verb == HelperCommand::Verb::TunnelDown, "tunnel-down arguments");
    std::vector<std::vector<std::string>> bad = {
        {"/tunnel-down", "OtherTunnel"},
        {"/tunnel-down", "TELIPHONES-a b"},
        {"/tunnel-up", "TELIPHONES-001122334455", "C:\\x\\other.conf", "S-1-5-21-1"},
        {"/tunnel-up", "TELIPHONES-001122334455", "relative\\TELIPHONES-001122334455.conf", "S-1-5-21-1"},
        {"/tunnel-up", "TELIPHONES-001122334455", "C:\\x\\..\\TELIPHONES-001122334455.conf", "S-1-5-21-1"},
        {"/tunnel-up", "TELIPHONES-001122334455", "C:\\x\\TELIPHONES-001122334455.conf", "S-1-5--1"},
        {"/tunnel-up", "TELIPHONES-001122334455", "C:\\x\\TELIPHONES-001122334455.conf"},
        {"/install", "x"},
    };
    for (const auto& arguments : bad) check(throws([&] { ParseHelperArguments(arguments); }), "invalid helper arguments rejected");
}

void testMonitor() {
    ConnectionMonitor monitor(1000, 1300, "pbx.example.net:51821", false);
    check(monitor.Observe(1005, true, false).state == LinkState::Connecting, "connecting while waiting for the first answer");
    MonitorDecision connected = monitor.Observe(1010, true, true);
    check(connected.state == LinkState::Connected && !connected.disconnect && connected.summary.find("remaining") != std::string::npos, "connected");
    check(monitor.Observe(1015, true, false).state == LinkState::NotResponding, "single failure is not yet a loss");
    check(monitor.Observe(1020, true, true).state == LinkState::Connected, "recovery after a transient failure");
    monitor.Observe(1025, true, false);
    monitor.Observe(1030, true, false);
    MonitorDecision lost = monitor.Observe(1035, true, false);
    check(lost.state == LinkState::Lost && lost.disconnect && lost.guidance.find("revoked") != std::string::npos, "revocation or loss disconnects");

    ConnectionMonitor never(1000, 0, "pbx.example.net:51821", false);
    check(!never.Observe(1029, true, false).disconnect, "no disconnect before the first-answer window");
    MonitorDecision unreachable = never.Observe(1031, true, false);
    check(unreachable.state == LinkState::NoResponse && unreachable.disconnect && unreachable.guidance.find("UDP traffic to pbx.example.net:51821") != std::string::npos &&
              unreachable.guidance.find("does not relay") != std::string::npos,
          "direct connectivity failure is reported honestly");
    ConnectionMonitor expiring(1000, 1100, "gw:1", true);
    MonitorDecision expired = expiring.Observe(1100, true, true);
    check(expired.state == LinkState::Expired && expired.disconnect, "expiry disconnects even while reachable");
    check(ConnectionMonitor(1000, 0, "x:1", false).Observe(1001, false, false).state == LinkState::Stopped, "stopped service detected");
    DirectProvider direct;
    EndpointPlan plan = direct.Plan("pbx.example.net:51821");
    check(plan.endpoint == "pbx.example.net:51821" && !plan.relayed && plan.provider == "direct", "direct provider does not alter the endpoint");
}

}  // namespace

int main() {
    testEncoding();
    testJson();
    testValidation();
    testPairing();
    testTunnels();
    testGrants();
    testProfiles();
    testCommandLine();
    testMonitor();
    if (failures) {
        std::printf("Desktop core tests: FAIL (%d of %d checks failed)\n", failures, checks);
        return 1;
    }
    std::printf("Desktop core tests: PASS (%d checks: encoding, JSON, validation, pairing, tunnels, grants, profiles, command lines, monitor)\n", checks);
    return 0;
}
