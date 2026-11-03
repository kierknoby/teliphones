// Portable unit tests for the TELIPHONES desktop core. Build with CMake or any C++17 compiler; no dependencies.
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <functional>
#include <iterator>
#include <string>
#include <vector>

#include "../src/core/CommandLine.h"
#include "../src/core/ConnectionHealth.h"
#include "../src/core/DesktopLayout.h"
#include "../src/core/Encoding.h"
#include "../src/core/Json.h"
#include "../src/core/Launchers.h"
#include "../src/core/Monitor.h"
#include "../src/core/Pairing.h"
#include "../src/core/Profiles.h"
#include "../src/core/Rendezvous.h"
#include "../src/core/TunnelConfig.h"
#include "../src/core/Validation.h"
#include "../src/core/WireGuardSetup.h"
#include "../src/app/Version.h"

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
    check(connected.state == LinkState::Connected && !connected.disconnect && connected.summary == "Connected",
          "connection status does not embed an authorization countdown");
    check(monitor.Observe(1015, true, false).state == LinkState::NotResponding, "single failure is not yet a loss");
    check(monitor.Observe(1020, true, true).state == LinkState::Connected, "recovery after a transient failure");
    monitor.Observe(1025, true, false);
    monitor.Observe(1030, true, false);
    MonitorDecision lost = monitor.Observe(1035, true, false);
    check(lost.state == LinkState::Lost && !lost.disconnect && lost.guidance.find("revoked") != std::string::npos,
          "reachability loss is reported without automatically removing the tunnel");

    ConnectionMonitor never(1000, 0, "pbx.example.net:51821", false);
    check(!never.Observe(1029, true, false).disconnect, "no disconnect before the first-answer window");
    MonitorDecision unreachable = never.Observe(1031, true, false);
    check(unreachable.state == LinkState::NoResponse && !unreachable.disconnect && unreachable.guidance.find("UDP traffic to pbx.example.net:51821") != std::string::npos &&
              unreachable.guidance.find("does not relay") != std::string::npos,
          "direct connectivity failure is reported honestly");
    ConnectionMonitor expiring(1000, 1100, "gw:1", true);
    MonitorDecision expired = expiring.Observe(1100, true, true);
    check(expired.state == LinkState::Expired && expired.disconnect, "expiry disconnects even while reachable");
    MonitorDecision stopped = ConnectionMonitor(1000, 0, "x:1", false).Observe(1001, false, false);
    check(stopped.state == LinkState::Stopped && !stopped.disconnect, "stopped service is reported without an extra removal attempt");
    DirectProvider direct;
    EndpointPlan plan = direct.Plan("pbx.example.net:51821");
    check(plan.endpoint == "pbx.example.net:51821" && !plan.relayed && plan.provider == "direct", "direct provider does not alter the endpoint");
}

void testConnectionHealth() {
    const int screens[][2] = {{1024, 728}, {1366, 728}, {1920, 1040}};
    const int scales[] = {100, 125, 150, 200};
    for (const auto& screen : screens) {
        for (int scale : scales) {
            const int width = screen[0] * 100 / scale;
            const int height = screen[1] * 100 / scale;
            const auto layout = ArrangeDesktop(width, height);
            for (const auto& action : layout.actions) {
                check(action.x >= 0 && action.y >= 0 && action.x + action.width <= width &&
                          action.bottom() <= height && action.width > 0 && action.height > 0,
                      "primary actions fit screen/DPI matrix without scrolling");
            }
            for (std::size_t i = 0; i < layout.content.size(); ++i) {
                const auto& control = layout.content[i];
                check(control.x >= 0 && control.y >= 0 && control.x + control.width <= width &&
                          control.bottom() <= layout.contentHeight && control.height > 0 && control.width > 0,
                      "responsive content is within the bounded scroll extent");
                for (std::size_t j = i + 1; j < layout.content.size(); ++j) {
                    const auto& other = layout.content[j];
                    check(control.x + control.width <= other.x || other.x + other.width <= control.x ||
                              control.bottom() <= other.y || other.bottom() <= control.y,
                          "responsive controls never overlap");
                }
            }
            check(layout.viewport.bottom() <= layout.actions[0].y,
                  "scroll viewport cannot obscure fixed connection controls");
        }
    }
    const auto normal = ArrangeDesktop(1034, 580);
    check(normal.contentHeight <= normal.viewport.height,
          "landscape default client fits without vertical scrolling");
    const auto compact = ArrangeDesktop(500, 350);
    check(compact.contentHeight > compact.viewport.height &&
              compact.content[static_cast<int>(DesktopSlot::ConnectionHeading)].y >
                  compact.content[static_cast<int>(DesktopSlot::Details)].bottom(),
          "small/high-DPI work areas stack panels within a scrollable extent");
    const auto larger = ArrangeDesktop(1600, 900);
    check(larger.content[static_cast<int>(DesktopSlot::Profiles)].height > normal.content[static_cast<int>(DesktopSlot::Profiles)].height &&
              larger.content[static_cast<int>(DesktopSlot::Graph)].height > normal.content[static_cast<int>(DesktopSlot::Graph)].height &&
              larger.content[static_cast<int>(DesktopSlot::Graph)].width > normal.content[static_cast<int>(DesktopSlot::Graph)].width,
          "list and graph expand in both dimensions on larger windows");
    HealthSnapshot graphHistory;
    for (int i = 0; i <= 6; ++i) {
        HealthSample sample;
        sample.timestampMs = 1000 + i * 2000;
        sample.tunnelKnown = true;
        sample.tunnelRunning = true;
        if (i % 3 == 0) {
            sample.wireGuardTelemetryAttempted = true;
            sample.receivedBytes = static_cast<std::uint64_t>(i) * 1000;
            sample.transmittedBytes = static_cast<std::uint64_t>(i) * 2000;
            sample.trafficSource = "Windows tunnel interface IP bytes";
        }
        graphHistory.samples.push_back(sample);
    }
    auto traffic = HealthTrafficHistory(graphHistory);
    check(traffic.size() == 2 && traffic[0].rx == 500 && traffic[0].tx == 1000 &&
              !traffic[0].join && traffic[1].join,
          "traffic graph joins six-second counter samples across ordinary two-second probe samples");
    graphHistory.samples[3].receivedBytes.reset();
    graphHistory.samples[3].transmittedBytes.reset();
    check(HealthTrafficHistory(graphHistory).empty(),
          "unavailable telemetry breaks the graph baseline instead of inventing data");

    HealthPreferences preferences;
    preferences.historySeconds = 300;
    preferences.alwaysOnTop = true;
    preferences.windowX = -120;
    preferences.windowY = 240;
    preferences.windowWidth = 420;
    preferences.windowHeight = 300;
    preferences.thresholds.warningLatencyMs = 500;
    preferences.thresholds.warningJitterMs = 200;
    preferences.thresholds.consecutiveFailures = 4;
    HealthPreferences restored = ParseHealthPreferences(SerializeHealthPreferences(preferences));
    check(restored.historySeconds == 300 && restored.alwaysOnTop && restored.windowX == -120 && restored.windowY == 240 &&
              restored.windowWidth == 420 && restored.windowHeight == 300 &&
              restored.thresholds.warningLatencyMs == 500 && restored.thresholds.warningJitterMs == 200 &&
              restored.thresholds.consecutiveFailures == 4,
          "connection health preferences persist history, position, topmost and configurable thresholds");
    check(throws([] { HealthPreferences invalid; invalid.thresholds.warningLatencyMs = 20; SerializeHealthPreferences(invalid); }),
          "invalid health thresholds rejected");
    const HealthWindowBounds desktop{0, 40, 1920, 1040};
    auto placement = FitHealthWindow({200, 150, 800, 600}, desktop, 640, 480);
    check(placement.x == 200 && placement.y == 150 && placement.width == 800 && placement.height == 600,
          "visible saved health window retains its position and size");
    placement = FitHealthWindow({90000, -90000, 800, 600}, desktop, 640, 480);
    check(placement.x == 560 && placement.y == 260,
          "off-screen health window is centered in the fallback monitor work area");
    placement = FitHealthWindow({1800, 1000, 800, 600}, desktop, 640, 480);
    check(placement.x == 1120 && placement.y == 480,
          "partially visible health window is fully clamped inside the work area");
    placement = FitHealthWindow({-1800, 100, 800, 600}, {-1920, 0, 1920, 1080}, 640, 480);
    check(placement.x == -1800 && placement.y == 100,
          "valid negative coordinates on secondary monitors are preserved");
    placement = FitHealthWindow({-1800, 100, 800, 600}, desktop, 640, 480);
    check(placement.x == 560 && placement.y == 260,
          "unplugging a monitor recovers to the remaining monitor");
    placement = FitHealthWindow({0, 0, 10000, 10000}, {0, 30, 800, 570}, 900, 650);
    check(placement.x == 0 && placement.y == 30 && placement.width == 800 && placement.height == 570,
          "oversized health window fits small work areas even below its normal minimum size");
    placement = FitHealthWindow({0, 0, 0, 0}, desktop, 640, 480);
    check(placement.width == 640 && placement.height == 480 && placement.x == 640 && placement.y == 320,
          "invalid saved dimensions recover to centered minimum dimensions");
    check(throws([&] { FitHealthWindow({0, 0, 800, 600}, {0, 0, 0, 0}, 640, 480); }),
          "missing display work area is reported instead of silently opening invisibly");

    WireGuardCounters counters = ParseWireGuardCounters(kPbxKey + "\t2000\t1000\n", kPbxKey + "\t1700000000\n", kPbxKey);
    check(counters.receivedBytes == 2000 && counters.transmittedBytes == 1000 && counters.handshakeUnixSeconds == 1700000000,
          "WireGuard byte counters and handshake parse from local CLI telemetry");
    WireGuardCounters absent = ParseWireGuardCounters("", "", kPbxKey);
    check(!absent.receivedBytes && !absent.transmittedBytes && !absent.handshakeUnixSeconds, "missing WireGuard telemetry remains unavailable");
    check(throws([] { ParseWireGuardCounters("bad\t1\t2\n", "", kPbxKey); }), "malformed WireGuard telemetry rejected");

    ConnectionHealthMonitor monitor;
    for (int i = 0; i < 5; ++i) {
        HealthSample sample;
        sample.timestampMs = 1000 + i * 2000;
        sample.utcUnixSeconds = 1700000000 + i * 2;
        sample.tunnelKnown = true;
        sample.tunnelRunning = true;
        sample.probeKnown = true;
        sample.probeSucceeded = true;
        sample.latencyMs = 100.0 + i * 10;
        sample.receivedBytes = static_cast<std::uint64_t>(i) * 1000;
        sample.transmittedBytes = static_cast<std::uint64_t>(i) * 500;
        sample.handshakeUnixSeconds = 1700000000;
        sample.wireGuardTelemetryAttempted = true;
        monitor.AddSample(sample);
    }
    HealthSnapshot stable = monitor.Snapshot(9000, 60);
    check(stable.state == HealthState::Stable && stable.continuouslyHealthySeconds == 0,
          "connection is not declared stable until consecutive consistent measurements");
    check(stable.latencyMs && std::abs(*stable.latencyMs - 140.0) < 0.01 &&
              stable.jitterMs && std::abs(*stable.jitterMs - 10.0) < 0.01,
          "current latency and recent absolute-difference jitter are calculated from successful probes");
    check(stable.probeSuccessPercent == 100.0 && stable.probeFailurePercent == 0.0,
          "application probe success and failure percentages are reported");
    check(stable.receiveBytesPerSecond == 500.0 && stable.transmitBytesPerSecond == 250.0,
          "actual WireGuard byte-counter deltas produce receive and transmit rates");
    check(stable.handshakeAgeSeconds == 8, "handshake age uses local WireGuard timestamp");
    check(stable.connectedSeconds == 8 && stable.continuouslyHealthySeconds == 0,
          "connection duration starts at first successful probe, independently of becoming healthy");

    HealthSample missingTelemetry;
    missingTelemetry.timestampMs = 11000;
    missingTelemetry.tunnelKnown = true;
    missingTelemetry.tunnelRunning = true;
    missingTelemetry.probeKnown = true;
    missingTelemetry.probeSucceeded = true;
    missingTelemetry.latencyMs = 100;
    missingTelemetry.wireGuardTelemetryAttempted = true;
    monitor.AddSample(missingTelemetry);
    HealthSnapshot telemetryUnavailable = monitor.Snapshot(11000, 60);
    check(!telemetryUnavailable.receiveBytesPerSecond && !telemetryUnavailable.transmitBytesPerSecond &&
              !telemetryUnavailable.handshakeAgeSeconds,
          "failed latest WireGuard telemetry attempt displays rates and handshake as Unknown");

    HealthSample failure;
    failure.timestampMs = 13000;
    failure.tunnelKnown = true;
    failure.tunnelRunning = true;
    failure.probeKnown = true;
    monitor.AddSample(failure);
    HealthSnapshot degraded = monitor.Snapshot(13000, 60);
    check(degraded.state == HealthState::Degraded && degraded.consecutiveFailures == 1 &&
              degraded.probeFailurePercent && *degraded.probeFailurePercent > 0 &&
              degraded.deterioration,
          "failed application probes are reported as probe failures and degrade health, not packet loss");
    check(!degraded.samples.back().probeSucceeded && !degraded.samples.back().latencyMs,
          "failed probe has no fabricated successful latency measurement");

    for (int i = 0; i < 2; ++i) {
        failure.timestampMs += 2000;
        monitor.AddSample(failure);
    }
    check(monitor.Snapshot(17000, 60).state == HealthState::Unstable &&
              monitor.Snapshot(17000, 60).consecutiveFailures == 3,
          "repeated application-probe failures escalate health to Unstable");

    HealthSample unknown;
    unknown.timestampMs = 19000;
    unknown.tunnelKnown = true;
    unknown.tunnelRunning = true;
    monitor.AddSample(unknown);
    check(monitor.Snapshot(19000, 60).state == HealthState::Unknown,
          "unavailable application probe is Unknown, not a fabricated failure");

    HealthSample down;
    down.timestampMs = 21000;
    down.tunnelKnown = true;
    down.tunnelRunning = false;
    down.probeKnown = true;
    monitor.AddSample(down);
    check(monitor.Snapshot(21000, 60).state == HealthState::Disconnected, "stopped tunnel is immediately Disconnected");

    ConnectionHealthMonitor expiredAuthorization;
    HealthSample expired;
    expired.timestampMs = 1000;
    expired.utcUnixSeconds = 1;
    expired.authorizationKnown = true;
    expired.tunnelKnown = true;
    expired.tunnelRunning = true;
    expired.probeKnown = true;
    expired.probeSucceeded = true;
    expired.latencyMs = 40;
    expired.authorizationExpiresAt = 5;
    expiredAuthorization.AddSample(expired);
    HealthSnapshot expiredSnapshot = expiredAuthorization.Snapshot(5000, 60);
    check(expiredSnapshot.state == HealthState::Disconnected && expiredSnapshot.authorizationRemainingSeconds == 0,
          "expired authorization is separate from reachability and reports Disconnected");

    ConnectionHealthMonitor utcAuthorization;
    HealthSample authorized = expired;
    authorized.utcUnixSeconds = 1793646000;
    authorized.authorizationExpiresAt = 1793649600;
    utcAuthorization.AddSample(authorized);
    auto temporary = utcAuthorization.Snapshot(3000, 60);
    check(temporary.authorizationRemainingSeconds == 3598 && temporary.authorizationExpiresAt == 1793649600,
          "temporary authorization uses UTC expiry, never machine uptime");
    authorized.timestampMs = 4000;
    authorized.authorizationPersistent = true;
    authorized.authorizationExpiresAt = 0;
    utcAuthorization.AddSample(authorized);
    auto persistent = utcAuthorization.Snapshot(4000, 60);
    check(persistent.authorizationKnown && persistent.authorizationPersistent && !persistent.authorizationRemainingSeconds,
          "persistent authorization has no fabricated remaining duration");
    check(utcAuthorization.Snapshot(20000, 60).state == HealthState::Unknown,
          "stale local measurements cannot claim current Stable connectivity");

    ConnectionHealthMonitor bounded;
    for (int i = 0; i < 350; ++i) {
        HealthSample sample;
        sample.timestampMs = 1000 + i * 2000;
        sample.tunnelKnown = true;
        sample.tunnelRunning = true;
        sample.probeKnown = true;
        sample.probeSucceeded = true;
        sample.latencyMs = 50;
        bounded.AddSample(sample);
    }
    check(bounded.Snapshot(699000, 60).samples.size() == 31 &&
              bounded.Snapshot(699000, 300).samples.size() == 151 &&
              bounded.Snapshot(699000, 300).samples.size() <= ConnectionHealthMonitor::kMaximumSamples,
          "60-second and 5-minute graphs use bounded sample histories");
    check(throws([&] { bounded.Snapshot(699000, 30); }), "unsupported history duration rejected");

    ConnectionHealthMonitor recovery;
    std::int64_t tick = 1000;
    auto addRecoverySample = [&](bool success) {
        HealthSample sample;
        sample.timestampMs = tick;
        tick += 2000;
        sample.tunnelKnown = true;
        sample.tunnelRunning = true;
        sample.probeKnown = true;
        sample.probeSucceeded = success;
        if (success) sample.latencyMs = 80;
        recovery.AddSample(sample);
    };
    for (int i = 0; i < 5; ++i) addRecoverySample(true);
    for (int i = 0; i < 3; ++i) addRecoverySample(false);
    check(recovery.Snapshot(tick - 2000, 60).state == HealthState::Unstable,
          "health transitions from Stable to Unstable during an interruption");
    for (int i = 0; i < 5; ++i) addRecoverySample(true);
    check(recovery.Snapshot(tick - 2000, 60).state == HealthState::Stable,
          "five fresh successful probes restore Stable after a network interruption");
    for (int i = 0; i < 200; ++i) addRecoverySample(true);
    check(recovery.Snapshot(tick - 2000, 60).continuouslyHealthySeconds == 400,
          "continuous healthy duration is not capped by the graph history window");

    ConnectionHealthMonitor sources;
    HealthSample sourceSample;
    sourceSample.timestampMs = 1000;
    sourceSample.telemetryTimestampMs = 1000;
    sourceSample.tunnelKnown = true;
    sourceSample.tunnelRunning = true;
    sourceSample.probeKnown = true;
    sourceSample.probeSucceeded = true;
    sourceSample.latencyMs = 20;
    sourceSample.wireGuardTelemetryAttempted = true;
    sourceSample.trafficSource = "WireGuard peer transport bytes";
    sourceSample.receivedBytes = 100;
    sourceSample.transmittedBytes = 200;
    sources.AddSample(sourceSample);
    sourceSample.timestampMs += 6000;
    sourceSample.telemetryTimestampMs += 6000;
    sourceSample.receivedBytes = 3100;
    sourceSample.transmittedBytes = 6200;
    sources.AddSample(sourceSample);
    check(sources.Snapshot(sourceSample.timestampMs, 60).receiveBytesPerSecond == 500,
          "current counter rate uses the latest measured interval");
    sourceSample.timestampMs += 6000;
    sourceSample.telemetryTimestampMs += 6000;
    sourceSample.trafficSource = "Windows tunnel interface IP bytes";
    sourceSample.receivedBytes = 9100;
    sourceSample.transmittedBytes = 18200;
    sources.AddSample(sourceSample);
    check(!sources.Snapshot(sourceSample.timestampMs, 60).receiveBytesPerSecond,
          "changing telemetry source resets the baseline instead of retaining the old current rate");
    sourceSample.timestampMs += 6000;
    sourceSample.telemetryTimestampMs += 6000;
    sourceSample.receivedBytes = 10300;
    sourceSample.transmittedBytes = 20600;
    sources.AddSample(sourceSample);
    check(sources.Snapshot(sourceSample.timestampMs, 60).receiveBytesPerSecond == 200,
          "new telemetry source gets its own byte-counter baseline");
    sourceSample.timestampMs += 6000;
    sourceSample.telemetryTimestampMs += 6000;
    sourceSample.receivedBytes = 10;
    sourceSample.transmittedBytes = 20;
    sources.AddSample(sourceSample);
    check(!sources.Snapshot(sourceSample.timestampMs, 60).receiveBytesPerSecond,
          "counter reset cannot retain an earlier current rate");
    sourceSample.timestampMs += 6000;
    sourceSample.telemetryTimestampMs += 6000;
    sourceSample.receivedBytes = 1210;
    sourceSample.transmittedBytes = 2420;
    sourceSample.probeKnown = false;
    sourceSample.probeSucceeded = false;
    sourceSample.latencyMs.reset();
    sources.AddSample(sourceSample);
    auto unknownProbe = sources.Snapshot(sourceSample.timestampMs, 60);
    check(unknownProbe.state == HealthState::Unknown && !unknownProbe.latencyMs &&
              unknownProbe.receiveBytesPerSecond == 200,
          "unavailable application probe does not hide independently measured current traffic");
    ConnectionHealthMonitor initialFailure;
    sourceSample.probeKnown = true;
    sourceSample.probeSucceeded = false;
    sourceSample.latencyMs.reset();
    initialFailure.AddSample(sourceSample);
    check(initialFailure.Snapshot(sourceSample.timestampMs, 60).state == HealthState::Degraded,
          "one initial failed application check is not immediately unstable or disconnected");

    ConnectionHealthMonitor noTunnelTelemetry;
    HealthSample noProbe;
    noProbe.timestampMs = 1000;
    noProbe.tunnelKnown = true;
    noProbe.tunnelRunning = true;
    noTunnelTelemetry.AddSample(noProbe);
    HealthSnapshot unknownMeasurements = noTunnelTelemetry.Snapshot(1000, 60);
    check(unknownMeasurements.state == HealthState::Unknown && !unknownMeasurements.latencyMs &&
              !unknownMeasurements.receiveBytesPerSecond && !unknownMeasurements.probeSuccessPercent,
          "unavailable probe and counter measurements remain Unknown");

    ConnectionHealthMonitor durations;
    HealthSample timing;
    timing.timestampMs = 1000;
    timing.utcUnixSeconds = 1793646000;
    timing.authorizationKnown = true;
    timing.authorizationExpiresAt = 1793649600;
    timing.tunnelKnown = true;
    timing.tunnelRunning = true;
    timing.probeKnown = true;
    durations.AddSample(timing);
    check(!durations.Snapshot(1000, 60).connectedSeconds,
          "waiting for initial reachability is not counted as connected duration");
    timing.timestampMs = 3000;
    timing.utcUnixSeconds += 2;
    timing.probeSucceeded = true;
    timing.latencyMs = 20;
    durations.AddSample(timing);
    auto beginning = durations.Snapshot(3000, 60);
    check(beginning.connectedSeconds == 0 && !beginning.continuouslyHealthySeconds &&
              beginning.authorizationRemainingSeconds == 3598,
          "successful connection starts at zero without restarting authorization expiry");
    for (int i = 0; i < 4; ++i) {
        timing.timestampMs += 2000;
        timing.utcUnixSeconds += 2;
        durations.AddSample(timing);
    }
    auto healthy = durations.Snapshot(timing.timestampMs, 60);
    check(healthy.connectedSeconds == 8 && healthy.continuouslyHealthySeconds == 0,
          "continuously healthy duration starts later than connection duration");
    check(HealthyDurationText(healthy).find("Continuously healthy for: 0 s") != std::string::npos,
          "zero healthy duration is not formatted as expired");
    timing.timestampMs += 2000;
    timing.utcUnixSeconds -= 120;
    durations.AddSample(timing);
    check(durations.Snapshot(timing.timestampMs, 60).connectedSeconds == 10,
          "wall-clock changes cannot change monotonic connected duration");
    timing.probeSucceeded = false;
    timing.latencyMs.reset();
    timing.timestampMs += 2000;
    durations.AddSample(timing);
    auto transient = durations.Snapshot(timing.timestampMs, 60);
    check(transient.connectedSeconds == 12 && !transient.continuouslyHealthySeconds,
          "brief probe failure resets health duration, not the current connection");
    for (int i = 0; i < 2; ++i) {
        timing.timestampMs += 2000;
        durations.AddSample(timing);
    }
    check(!durations.Snapshot(timing.timestampMs, 60).connectedSeconds &&
              !durations.Snapshot(timing.timestampMs + 2000, 60).connectedSeconds,
          "declared connection loss stops connected duration even while tunnel remains installed");
    timing.timestampMs += 2000;
    timing.probeSucceeded = true;
    timing.latencyMs = 20;
    durations.AddSample(timing);
    auto reconnected = durations.Snapshot(timing.timestampMs, 60);
    check(reconnected.connectedSeconds == 0 &&
              reconnected.authorizationExpiresAt == 1793649600 &&
              !reconnected.continuouslyHealthySeconds,
          "reconnection starts new duration and preserves original authorization expiry");
    check(ConnectedDurationText(reconnected) == "Connected for: 0 s" &&
              HealthyDurationText(reconnected).find("Continuously healthy for: Not currently healthy") != std::string::npos,
          "shared UI duration text distinguishes connected and healthy time");
    timing.timestampMs += 2000;
    timing.tunnelRunning = false;
    durations.AddSample(timing);
    auto disconnected = durations.Snapshot(timing.timestampMs, 60);
    check(!disconnected.connectedSeconds && ConnectedDurationText(disconnected) == "Connected for: Not connected",
          "stopped tunnel never displays an advancing connected duration");
    check(disconnected.authorizationExpiresAt == reconnected.authorizationExpiresAt &&
              disconnected.authorizationRemainingSeconds == reconnected.authorizationRemainingSeconds,
          "stopping the tunnel does not reset or extend authorization");
    ConnectionHealthMonitor newAttempt;
    timing.timestampMs += 2000;
    timing.tunnelRunning = true;
    newAttempt.AddSample(timing);
    auto restarted = newAttempt.Snapshot(timing.timestampMs, 60);
    check(restarted.connectedSeconds == 0 &&
              restarted.authorizationExpiresAt == reconnected.authorizationExpiresAt &&
              restarted.authorizationRemainingSeconds == reconnected.authorizationRemainingSeconds,
          "manual reconnect uses a fresh connected timer and the same original expiry");
    check(!newAttempt.Snapshot(timing.timestampMs + 11000, 60).connectedSeconds,
          "missing fresh samples cannot present an advancing connected duration");
    HealthSample expirySample = timing;
    expirySample.timestampMs += 2000;
    expirySample.utcUnixSeconds = expirySample.authorizationExpiresAt;
    newAttempt.AddSample(expirySample);
    auto expiry = newAttempt.Snapshot(expirySample.timestampMs, 60);
    check(!expiry.connectedSeconds && expiry.state == HealthState::Disconnected &&
              AuthorizationRemainingText(expiry) == "Expired",
          "authorization expiry stops the connected timer even when a probe succeeds");
    ConnectionHealthMonitor persistentDuration;
    timing.timestampMs += 2000;
    timing.tunnelRunning = true;
    timing.authorizationPersistent = true;
    timing.authorizationExpiresAt = 0;
    persistentDuration.AddSample(timing);
    auto persistentConnection = persistentDuration.Snapshot(timing.timestampMs, 60);
    check(persistentConnection.connectedSeconds == 0 && persistentConnection.authorizationPersistent &&
              !persistentConnection.authorizationRemainingSeconds &&
              AuthorizationRemainingText(persistentConnection) == "Until revoked" &&
              AuthorizationRemainingText(beginning) == "59 min 58 s",
          "persistent authorization and connected duration remain independent");
}

const std::string kSsh = "C:\\Windows\\System32\\OpenSSH\\ssh.exe";
const std::string kPowerShell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const std::string kChrome = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const std::string kPutty = "C:\\Program Files\\PuTTY\\putty.exe";

bool unavailable(const std::function<void()>& action, AppKind kind, const std::string& id) {
    try {
        action();
    } catch (const AppUnavailable& e) {
        return e.kind == kind && e.id == id && std::string(e.what()).find("could not be found") != std::string::npos;
    } catch (const Error&) {
    }
    return false;
}

void testLaunchers() {
    // Catalogue and detection-driven choices.
    check(KnownApps(AppKind::Browser).front().id == kWindowsDefaultBrowser, "Windows default browser listed first");
    for (const char* id : {"chrome", "edge", "firefox", "brave"}) check(FindApp(AppKind::Browser, id) != nullptr, "required browser catalogued");
    for (const char* id : {"powershell", "windows-terminal", "putty", "cmd"}) check(FindApp(AppKind::Terminal, id) != nullptr, "required terminal catalogued");
    check(!FindApp(AppKind::Terminal, "putty")->needsOpenSsh && FindApp(AppKind::Terminal, "cmd")->needsOpenSsh, "only PuTTY works without OpenSSH");
    DetectedApps noBrowsers;
    DetectedApps browsers{{"chrome", kChrome}, {"firefox", "C:\\Program Files\\Mozilla Firefox\\firefox.exe"}};
    DetectedApps terminals{{"powershell", kPowerShell}, {"cmd", "C:\\Windows\\System32\\cmd.exe"}, {"putty", kPutty}};
    check(AvailableApps(AppKind::Browser, noBrowsers) == std::vector<std::string>{kWindowsDefaultBrowser}, "Windows default browser always offered");
    check(AvailableApps(AppKind::Browser, browsers) == std::vector<std::string>({kWindowsDefaultBrowser, "chrome", "firefox"}),
          "only detected browsers offered, in catalogue order");
    check(AvailableApps(AppKind::Terminal, terminals) == std::vector<std::string>({"powershell", "putty", "cmd"}), "only detected terminals offered");
    check(AvailableApps(AppKind::Terminal, {}).empty(), "no terminal offered when none is installed");
    check(DefaultBrowser(browsers) == "chrome" && DefaultBrowser(noBrowsers) == kWindowsDefaultBrowser, "Chrome preselected when installed");
    check(DefaultTerminal(terminals) == "powershell", "PowerShell preselected when installed");
    check(DefaultTerminal({{"cmd", "C:\\Windows\\System32\\cmd.exe"}, {"putty", kPutty}}) == "cmd", "Command Prompt fallback");
    check(DefaultTerminal({{"putty", kPutty}}) == "putty" && DefaultTerminal({}).empty(), "other terminal fallback");

    // First run: saved, skipped and cancelled.
    check(NeedsFirstRun(std::nullopt), "first run without preferences");
    auto cancelled = PreferencesAfterFirstRun(FirstRunOutcome::Cancelled, "firefox", "putty", browsers, terminals, std::nullopt);
    check(!cancelled, "cancelling first run stores nothing");
    auto skipped = PreferencesAfterFirstRun(FirstRunOutcome::Skipped, "", "", browsers, terminals, std::nullopt);
    check(skipped && skipped->browser == "chrome" && skipped->terminal == "powershell" && skipped->setup == "skipped" && !NeedsFirstRun(skipped),
          "skipping first run stores the defaults and is not asked again");
    auto saved = PreferencesAfterFirstRun(FirstRunOutcome::Saved, "firefox", "putty", browsers, terminals, std::nullopt);
    check(saved && saved->browser == "firefox" && saved->terminal == "putty" && saved->setup == "completed" && !NeedsFirstRun(saved), "first-run choices saved");
    check(throws([&] { PreferencesAfterFirstRun(FirstRunOutcome::Saved, "edge", "putty", browsers, terminals, std::nullopt); }),
          "uninstalled browser cannot be saved");
    check(throws([&] { PreferencesAfterFirstRun(FirstRunOutcome::Saved, "chrome", "windows-terminal", browsers, terminals, std::nullopt); }),
          "uninstalled terminal cannot be saved");
    Preferences unfinished;
    unfinished.browser = "chrome";
    check(NeedsFirstRun(unfinished), "welcome shown again until completed or skipped");

    // Changing preferences later keeps user-located executables.
    Preferences located = *saved;
    located.locations["putty"] = "D:\\Tools\\PuTTY Portable\\putty.exe";
    auto changed = PreferencesAfterFirstRun(FirstRunOutcome::Saved, kWindowsDefaultBrowser, "cmd", browsers, terminals, located);
    check(changed && changed->browser == kWindowsDefaultBrowser && changed->terminal == "cmd" && changed->locations.at("putty") == located.locations.at("putty"),
          "changing preferences keeps located applications");

    // Persistence: exact round trip and strict parsing.
    Preferences restored = ParsePreferences(SerializePreferences(located));
    check(restored.browser == "firefox" && restored.terminal == "putty" && restored.setup == "completed" && restored.locations == located.locations,
          "preferences round trip");
    check(ParsePreferences(SerializePreferences(Preferences())).browser.empty(), "empty preferences round trip");
    check(ParsePreferences("{\"schema\":\"teliphones-desktop-preferences/1\",\"browser\":\"future-browser\",\"terminal\":\"cmd\",\"locations\":{},"
                           "\"setup\":\"completed\"}")
                  .browser == "future-browser",
          "unknown application kept so it is reported rather than replaced");
    std::vector<std::string> badPreferences = {
        "",
        "{\"schema\":\"teliphones-desktop-preferences/2\",\"browser\":\"\",\"terminal\":\"\",\"locations\":{},\"setup\":\"\"}",
        "{\"schema\":\"teliphones-desktop-preferences/1\",\"browser\":\"\",\"terminal\":\"\",\"locations\":{},\"setup\":\"\",\"pbx\":\"x\"}",
        "{\"schema\":\"teliphones-desktop-preferences/1\",\"browser\":\"Chrome.exe\",\"terminal\":\"\",\"locations\":{},\"setup\":\"\"}",
        "{\"schema\":\"teliphones-desktop-preferences/1\",\"browser\":\"\",\"terminal\":\"\",\"locations\":{},\"setup\":\"later\"}",
        "{\"schema\":\"teliphones-desktop-preferences/1\",\"browser\":\"\",\"terminal\":\"\",\"locations\":{\"putty\":\"C:\\\\x\\\\calc.exe\"},\"setup\":\"\"}",
        "{\"schema\":\"teliphones-desktop-preferences/1\",\"browser\":\"\",\"terminal\":\"\",\"locations\":{\"putty\":\"putty.exe\"},\"setup\":\"\"}",
        "{\"schema\":\"teliphones-desktop-preferences/1\",\"browser\":\"\",\"terminal\":\"\",\"locations\":{\"evil\":\"C:\\\\x\\\\putty.exe\"},\"setup\":\"\"}",
    };
    for (const auto& text : badPreferences) check(throws([&] { ParsePreferences(text); }), "invalid preferences rejected");

    // Effective preferences never substitute another application for a missing one.
    check(EffectivePreferences(std::nullopt, browsers, terminals).browser == "chrome", "defaults apply before first run");
    Preferences edge;
    edge.browser = "edge";
    edge.terminal = "windows-terminal";
    Preferences effective = EffectivePreferences(edge, browsers, terminals);
    check(effective.browser == "edge" && effective.terminal == "windows-terminal", "missing selections are kept, not replaced");
    check(unavailable([&] { ResolveApp(AppKind::Browser, "edge", browsers); }, AppKind::Browser, "edge"), "uninstalled browser reported");
    check(unavailable([&] { ResolveApp(AppKind::Terminal, "windows-terminal", terminals); }, AppKind::Terminal, "windows-terminal"),
          "uninstalled terminal reported");
    check(unavailable([&] { ResolveApp(AppKind::Browser, "future-browser", browsers); }, AppKind::Browser, "future-browser"), "unknown browser reported");
    check(ResolveApp(AppKind::Browser, kWindowsDefaultBrowser, noBrowsers).empty(), "Windows default browser needs no executable");
    check(ResolveApp(AppKind::Browser, "chrome", browsers) == kChrome, "installed browser resolved");
    check(unavailable([&] { ResolveApp(AppKind::Terminal, "putty", {{"putty", "C:\\Temp\\calc.exe"}}); }, AppKind::Terminal, "putty"),
          "wrong executable is not launched");

    // Executable and argument validation.
    const AppInfo& putty = *FindApp(AppKind::Terminal, "putty");
    check(IsExpectedExecutable(putty, kPutty) && IsExpectedExecutable(putty, "D:\\Tools\\PUTTY.EXE"), "expected executable accepted");
    for (const char* path : {"putty.exe", "C:\\Tools\\..\\putty.exe", "C:\\Tools\\\"putty.exe", "C:/Tools/putty.exe", "C:\\Tools\\putty.exe:stream",
                             "\\\\server\\share\\putty.exe", "C:\\Tools\\putty.exe.lnk", "C:\\Tools\\plink.exe"}) {
        check(!IsExpectedExecutable(putty, path), "unexpected executable rejected");
    }
    check(IsShellSafePath(kSsh) && IsShellSafePath("C:\\Program Files (x86)\\OpenSSH\\ssh.exe"), "OpenSSH paths with spaces accepted");
    check(!IsShellSafePath("C:\\Users\\a&b\\ssh.exe") && !IsShellSafePath("C:\\Users\\a'b\\ssh.exe") && !IsShellSafePath("C:\\Users\\%x%\\ssh.exe"),
          "shell metacharacters rejected in the OpenSSH path");
    check(!IsShellSafeToken("a;b") && !IsShellSafeToken("a b") && !IsShellSafeToken("$(x)") && !IsShellSafeToken(""), "unsafe tokens rejected");

    // Browser launching.
    Profile admin = adminProfile();
    std::string url = FreePbxUrl(admin, "");
    check(url == "http://100.70.1.1/admin/", "FreePBX URL unchanged");
    check(FreePbxUrl(supportProfile(), "s-1") == "http://10.20.4.2/admin/", "Remote Support FreePBX URL unchanged");
    LaunchPlan system = BrowserLaunch(kWindowsDefaultBrowser, "", url);
    check(system.shellOpen && system.target == url && system.program.empty(), "Windows default browser uses the registered URL handler");
    LaunchPlan chrome = BrowserLaunch("chrome", kChrome, url);
    check(!chrome.shellOpen && chrome.program == kChrome && chrome.commandLine == "\"" + kChrome + "\" " + url, "selected browser opens the PBX URL");
    check(BrowserLaunch("firefox", "D:\\Firefox\\firefox.exe", url).commandLine == "D:\\Firefox\\firefox.exe " + url, "browser path quoting");
    check(unavailable([&] { BrowserLaunch("chrome", "C:\\x\\msedge.exe", url); }, AppKind::Browser, "chrome"), "mismatched browser executable refused");
    for (const char* bad : {"http://100.70.1.1/admin/ --incognito", "https://evil.example/admin/", "http://100.70.1.1/admin/?x", "--disable-web-security",
                            "http://pbx.example.net/admin/"}) {
        check(throws([&] { BrowserLaunch(kWindowsDefaultBrowser, "", bad); }), "unexpected browser URL refused");
    }

    // Terminal launching.
    SshTarget target = SshTargetFor(admin, "");
    check(target.user == "admin" && target.address == "100.70.1.1" && target.port == 22 && target.hostKeyAlias == "teliphones-0011223344556677",
          "administrator SSH target");
    const std::string sshArgs = "-o ServerAliveInterval=15 -o HostKeyAlias=teliphones-0011223344556677 -p 22 admin@100.70.1.1";
    LaunchPlan powershell = TerminalLaunch("powershell", kPowerShell, kSsh, target);
    check(powershell.program == kPowerShell && powershell.newConsole &&
              powershell.commandLine == kPowerShell + " -NoLogo -NoExit -Command \"& '" + kSsh +
                                            "' '-o' 'ServerAliveInterval=15' '-o' 'HostKeyAlias=teliphones-0011223344556677' '-p' '22' 'admin@100.70.1.1'\"",
          "PowerShell runs OpenSSH with literal arguments");
    const std::string pwsh = "C:\\Program Files\\PowerShell\\7\\pwsh.exe";
    check(TerminalLaunch("pwsh", pwsh, kSsh, target).commandLine.rfind("\"" + pwsh + "\" -NoLogo -NoExit -Command \"& '", 0) == 0, "PowerShell 7 path quoted");
    const std::string wt = "C:\\Users\\Ann Smith\\AppData\\Local\\Microsoft\\WindowsApps\\wt.exe";
    LaunchPlan terminal = TerminalLaunch("windows-terminal", wt, kSsh, target);
    check(!terminal.newConsole && terminal.commandLine == "\"" + wt + "\" new-tab --title \"TELIPHONES SSH\" -- " + kSsh + " " + sshArgs,
          "Windows Terminal opens a tab running OpenSSH");
    const std::string cmd = "C:\\Windows\\System32\\cmd.exe";
    check(TerminalLaunch("cmd", cmd, kSsh, target).commandLine == cmd + " /s /k \"\"" + kSsh + "\" " + sshArgs + "\"", "Command Prompt runs OpenSSH");
    LaunchPlan puttyPlan = TerminalLaunch("putty", kPutty, "", target);
    check(!puttyPlan.newConsole && puttyPlan.program == kPutty &&
              puttyPlan.commandLine == "\"" + kPutty + "\" -ssh -P 22 -l admin -loghost teliphones-0011223344556677 100.70.1.1",
          "PuTTY receives address, port and user as separate options without OpenSSH");
    SshTarget support = SshTargetFor(supportProfile(), "s-1");
    check(TerminalLaunch("putty", kPutty, "", support).commandLine.find("-P 22222 -l root ") != std::string::npos, "Remote Support uses the support SSH service");
    check(throws([&] { TerminalLaunch("powershell", kPowerShell, "", target); }), "OpenSSH required for PowerShell");
    check(throws([&] { TerminalLaunch("cmd", cmd, "C:\\Users\\a&calc\\ssh.exe", target); }), "unsafe OpenSSH path refused");
    check(unavailable([&] { TerminalLaunch("putty", "C:\\x\\cmd.exe", "", target); }, AppKind::Terminal, "putty"), "mismatched terminal executable refused");
    check(unavailable([&] { TerminalLaunch("future-terminal", kPutty, kSsh, target); }, AppKind::Terminal, "future-terminal"), "unknown terminal refused");
    SshTarget unsafe = target;
    unsafe.user = "admin -oProxyCommand=calc";
    check(throws([&] { TerminalLaunch("putty", kPutty, "", unsafe); }), "unsafe SSH user refused for every terminal");
    unsafe = target;
    unsafe.address = "100.70.1.1;calc";
    check(throws([&] { TerminalLaunch("powershell", kPowerShell, kSsh, unsafe); }), "unsafe SSH address refused");
    unsafe = target;
    unsafe.hostKeyAlias = "x' ; calc ; '";
    check(throws([&] { TerminalLaunch("powershell", kPowerShell, kSsh, unsafe); }), "unsafe host key alias refused");
    unsafe = target;
    unsafe.port = 0;
    check(throws([&] { TerminalLaunch("putty", kPutty, "", unsafe); }), "invalid SSH port refused");

    // Choosing a terminal never authorises SSH.
    Profile webOnly = webOnlyPersistentProfile();
    check(throws([&] { SshTargetFor(webOnly, ""); }), "SSH refused when not authorised, whatever the terminal");
    check(throws([&] { SshTargetFor(supportProfile(), "s-2-missing"); }), "SSH refused for an unknown support session");
}

void testWireGuardSetup() {
    std::vector<std::string> calls;
    ConnectivityState detection = ConnectivityState::Missing;
    std::uint32_t exitCode = 0;
    std::string failAt;
    bool becomeReady = true;
    auto action = [&](const std::string& stage) {
        calls.push_back(stage);
        if (failAt == stage) throw Error(stage + " simulated failure");
    };
    SetupOperations op{
        [&] { action("detect"); return detection; },
        [&] { action("download"); },
        [&] { action("verify"); },
        [&] {
            action("install");
            if (becomeReady && (exitCode == 0 || exitCode == 3010)) detection = ConnectivityState::Ready;
            return exitCode;
        },
        [&] { action("cleanup"); },
        [&](const std::string& message) { check(!message.empty(), "installer progress is visible"); }
    };
    auto run = [&] {
        calls.clear();
        return RunWireGuardSetup(true, op);
    };
    check(RunWireGuardSetup(false, op).state == SetupState::NotNow && calls.empty(), "Not Now never retrieves or installs software");
    detection = ConnectivityState::Ready;
    check(run().state == SetupState::Installed && calls == std::vector<std::string>{"detect"}, "existing verified installation is not changed");
    detection = ConnectivityState::Untrusted;
    check(run().state == SetupState::Failed && calls == std::vector<std::string>{"detect"}, "untrusted or partial installation is not overwritten");
    detection = ConnectivityState::Missing;
    check(run().state == SetupState::Installed && detection == ConnectivityState::Ready &&
          calls == std::vector<std::string>({"detect", "download", "verify", "install", "detect", "cleanup"}),
          "fresh installation requires verification before elevation and detection before success");
    for (const char* stage : {"download", "verify", "install"}) {
        detection = ConnectivityState::Missing;
        failAt = stage;
        SetupResult result = run();
        check(result.state == SetupState::Failed && result.message.find(stage) != std::string::npos && calls.back() == "cleanup",
              "download, invalid signature and launch failures are reported and cleaned");
        if (failAt != "install") check(std::find(calls.begin(), calls.end(), "install") == calls.end(), "failed retrieval or signature never executes");
    }
    failAt.clear();
    for (std::uint32_t code : {1223u, 1602u}) {
        detection = ConnectivityState::Missing;
        exitCode = code;
        check(run().state == SetupState::Cancelled && calls.back() == "cleanup", "UAC refusal and MSI cancellation allow retry");
    }
    detection = ConnectivityState::Missing;
    exitCode = 1603;
    check(run().state == SetupState::Failed, "Windows Installer failure is not success-shaped");
    exitCode = 0;
    becomeReady = false;
    check(run().state == SetupState::Failed && detection == ConnectivityState::Missing, "zero exit code without verified detection is failure");
    exitCode = 3010;
    check(run().state == SetupState::RestartRequired, "restart is reported only when installer requests it");
    becomeReady = true;
    check(run().state == SetupState::Installed && detection == ConnectivityState::Ready, "verified components can be used after installation requesting restart");
    exitCode = 0;
    detection = ConnectivityState::Missing;
    failAt = "cleanup";
    check(run().message.find("cleanup failed") != std::string::npos, "cleanup failures are reported");
    failAt.clear();
    detection = ConnectivityState::Missing;
    check(run().state == SetupState::Installed, "retry after cancellation or failure recovers");
}

double contrast(Colour first, Colour second) {
    auto luminance = [](Colour colour) {
        auto channel = [](unsigned value) {
            double c = value / 255.0;
            return c <= 0.04045 ? c / 12.92 : std::pow((c + 0.055) / 1.055, 2.4);
        };
        return 0.2126 * channel(colour & 255) + 0.7152 * channel((colour >> 8) & 255) + 0.0722 * channel((colour >> 16) & 255);
    };
    const double a = luminance(first), b = luminance(second);
    return (std::max(a, b) + 0.05) / (std::min(a, b) + 0.05);
}

void testAppearance() {
    const std::string legacy = "{\"schema\":\"teliphones-desktop-preferences/1\",\"browser\":\"firefox\",\"terminal\":\"putty\","
        "\"locations\":{},\"setup\":\"completed\"}";
    check(ParsePreferences(legacy).appearance == Appearance::System, "legacy preferences default to System");
    check(Preferences().appearance == Appearance::System, "new preferences default to System");
    for (auto mode : {Appearance::System, Appearance::Light, Appearance::Dark}) {
        auto preferences = ParsePreferences(legacy);
        preferences.appearance = mode;
        const auto restored = ParsePreferences(SerializePreferences(preferences));
        check(restored.appearance == mode && restored.browser == "firefox" && restored.terminal == "putty" &&
            restored.setup == "completed", "all appearance modes persist without changing other preferences");
        check(ParseAppearance(AppearanceName(mode)) == mode, "appearance names round trip");
        auto skipped = PreferencesAfterFirstRun(FirstRunOutcome::Skipped, "", "", {}, {}, preferences);
        check(skipped && skipped->appearance == mode, "welcome Skip preserves appearance");
        check(EffectivePreferences(preferences, {}, {}).appearance == mode, "effective settings retain appearance");
        for (bool systemDark : {false, true}) {
            check(UseDarkAppearance(mode, systemDark, false) ==
                (mode == Appearance::Dark || (mode == Appearance::System && systemDark)), "system change/forced mode policy");
            check(!UseDarkAppearance(mode, systemDark, true), "high contrast overrides every appearance mode");
        }
    }
    for (const auto& invalid : {json::Value("auto"), json::Value("Dark"), json::Value(""), json::Value(true), json::Value(2)}) {
        auto fields = json::Parse(legacy).asObject();
        fields["appearance"] = invalid;
        check(throws([&] { ParsePreferences(json::Serialize(json::Value(fields))); }), "invalid appearance is explicitly rejected");
    }
    check(throws([] { AppearanceName(static_cast<Appearance>(99)); }), "invalid appearance enum rejected on serialization");
    for (bool dark : {false, true}) {
        const auto p = PaletteFor(dark);
        for (auto background : {p.background, p.surface, p.button, p.hover}) {
            check(contrast(p.text, background) >= 4.5, "normal control text meets 4.5:1 contrast");
            check(contrast(p.disabled, background) >= 3, "disabled control text remains readable");
        }
        check(contrast(p.selectedText, p.selection) >= 4.5, "selected PBX text meets 4.5:1 contrast");
        for (auto signal : {p.latency, p.success, p.warning, p.error, p.download, p.upload})
            check(contrast(signal, p.graph) >= 3, "every graph series meets 3:1 contrast");
        for (auto signal : {p.success, p.warning, p.error})
            check(contrast(signal, p.background) >= 4.5, "health status text meets 4.5:1 contrast");
        check(p.download != p.upload && p.latency != p.success && p.success != p.error, "graph series remain distinguishable");
    }
}

}  // namespace

int main() {
    const unsigned versionParts[] = {TELIPHONES_VERSION_NUMERIC};
    std::string versionBase = std::to_string(versionParts[0]) + "." + std::to_string(versionParts[1]) + "." + std::to_string(versionParts[2]);
    check(std::size(versionParts) == 4, "Windows numeric version contains four components");
    for (unsigned part : versionParts) check(part <= 65535, "Windows version component fits the resource WORD");
    check(TELIPHONES_VERSION_FILE_STRING == versionBase + "." + std::to_string(versionParts[3]), "file version expands consistently");
    check(TELIPHONES_VERSION_STRING == versionBase, "product version expands without a development suffix");
    check(std::string(TELIPHONES_VERSION_STRING) == "0.6.0", "Windows application version is independent of the module");
    check(std::string(TELIPHONES_VERSION_FILE_STRING) == "0.6.0.0", "Windows file version is 0.6.0.0");
    testEncoding();
    testJson();
    testValidation();
    testPairing();
    testTunnels();
    testGrants();
    testProfiles();
    testCommandLine();
    testMonitor();
    testConnectionHealth();
    testLaunchers();
    testWireGuardSetup();
    testAppearance();
    if (failures) {
        std::printf("Desktop core tests: FAIL (%d of %d checks failed)\n", failures, checks);
        return 1;
    }
    std::printf("Desktop core tests: PASS (%d checks: encoding, JSON, validation, pairing, tunnels, grants, profiles, command lines, monitor, application preferences, launchers and WireGuard setup)\n", checks);
    return 0;
}
