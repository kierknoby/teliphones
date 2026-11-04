#include "../src/core/ConnectProtection.h"
#include "../src/core/Encoding.h"
#include "../src/core/TunnelConfig.h"
#include "../src/core/Json.h"

#include <iostream>
#include <stdexcept>

namespace {
void check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
template<class F> void rejects(F operation, const char* message) {
    bool rejected = false;
    try { operation(); } catch (const tlp::Error&) { rejected = true; }
    check(rejected, message);
}
}

int main() {
    try {
        const std::string target = "TELIPHONES/workstation/0011223344556677";
        const std::string key = tlp::Base64Encode(tlp::Bytes(32, 23));
        const std::string password = "local connect password";
        // Independently generated with libargon2 20190702 and libsodium AES-256-GCM, not this implementation.
        const std::string reference =
            "TELIPHONES-CONNECT/1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaG7gx17SqtRICzKptuixGy5s9abM3XUf0ekIBU4RS2m2WYc60C1vn3MUmXA5WjCBXKqWUID1lYT6FMTl7Mw==";
        check(tlp::OpenConnectKey(target, key, "") == key, "DPAPI-only credential behavior changed");
        check(!tlp::IsProtectedConnectKey(key), "raw WireGuard key misclassified");
        check(tlp::IsProtectedConnectKey("corrupt"), "damaged credential downgraded");
        rejects([&] { tlp::OpenConnectKey(target, "corrupt", ""); }, "damaged credential accepted");

        tlp::TunnelConfig config;
        config.privateKey = key;
        config.peerPublicKey = tlp::Base64Encode(tlp::Bytes(32, 42));
        config.address = "10.20.1.3/32";
        config.allowedIps = {"10.20.1.2/32"};
        config.endpoint = "example.com:51820";
        const auto diskConfig = tlp::RenderBootstrapTunnel(config);
        const auto boot = tlp::ParseTunnelStrict(diskConfig);
        check(diskConfig.find(key) == std::string::npos, "stored bootstrap contains the enrolled secret");
        check(tlp::IsBootstrapTunnel(boot) && boot.privateKey != key, "bootstrap can authenticate as the enrolled workstation");
        check(!tlp::IsBootstrapTunnel(config), "legacy plaintext config accepted as bootstrap");
        tlp::ValidateBootstrapTunnel(boot);
        rejects([&] { tlp::ValidateBootstrapTunnel(tlp::ParseTunnelStrict(tlp::RenderTunnel(config))); },
                "helper policy accepted a stored plaintext enrolled-key config");
        check(tlp::RenderBootstrapTunnel(boot) == diskConfig, "restarting the stored config recovered the enrolled secret");

        if (!tlp::ConnectProtectionAvailable()) {
            rejects([&] { tlp::ProtectConnectKey(target, key, password); }, "missing Argon2id silently substituted");
            rejects([&] { tlp::OpenConnectKey(target, reference, password); }, "missing Argon2id permitted decrypt fallback");
            std::cout << "DPAPI/bootstrap and missing-provider fail-closed checks passed; Argon2id unavailable.\n";
            return 0;
        }
        check(tlp::OpenConnectKey(target, reference, password) == key, "independent Argon2id/AES-GCM vector failed");
        const auto stored = tlp::ProtectConnectKey(target, key, password);
        check(tlp::IsProtectedConnectKey(stored), "protected key misclassified");
        check(stored.find(key) == std::string::npos, "protected credential contains plaintext");
        check(stored != tlp::ProtectConnectKey(target, key, password), "salt/nonce reused");
        check(tlp::OpenConnectKey(target, stored, password) == key, "authenticated round trip failed");
        // Settings/profile flags are deliberately absent from the credential-opening API.
        rejects([&] { tlp::OpenConnectKey(target, stored, ""); }, "empty password bypassed authentication");
        rejects([&] { tlp::OpenConnectKey(target, stored, "wrong connect password"); }, "wrong password accepted");
        rejects([&] { tlp::OpenConnectKey(target + "other", stored, password); }, "credential transplant accepted");
        rejects([&] { tlp::ProtectConnectKey(target, key, "short"); }, "short password accepted");
        rejects([&] { tlp::OpenConnectKey(target, stored.substr(1), password); }, "missing header downgraded to DPAPI");
        rejects([&] { tlp::OpenConnectKey(target, stored + "A", password); }, "oversized envelope accepted");
        const auto separator = stored.find(':') + 1;
        const auto original = tlp::Base64Decode(stored.substr(separator));
        for (std::size_t offset : {std::size_t(0), std::size_t(16), std::size_t(28), original.size() - 1}) {
            auto bytes = original;
            bytes[offset] ^= 1;
            const auto damaged = stored.substr(0, separator) + tlp::Base64Encode(bytes);
            rejects([&] { tlp::OpenConnectKey(target, damaged, password); }, "salt/nonce/ciphertext/tag tampering authenticated");
        }
        auto wrongVersion = stored;
        wrongVersion[wrongVersion.find("/1") + 1] = '2';
        rejects([&] { tlp::OpenConnectKey(target, wrongVersion, password); }, "unknown envelope version accepted");
        std::cout << "Argon2id/AES-256-GCM authentication, tamper rejection, DPAPI and secret-free bootstrap checks passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
