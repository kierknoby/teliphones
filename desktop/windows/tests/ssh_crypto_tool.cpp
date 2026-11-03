#include "SshCrypto.h"
#include "Json.h"
#include <iostream>
#include <iterator>

int main(int argc, char** argv) {
    try {
        if (argc != 2) return 2;
        const std::string mode = argv[1];
        if (mode == "identity") {
            std::string stored(std::istreambuf_iterator<char>(std::cin), {});
            auto seed = tlp::WorkstationIdentitySeed(stored);
            tlp::SshSigningKey key(seed);
            std::cout << key.publicKey() << '\n';
        } else if (mode == "signature") {
            tlp::SshSigningKey key;
            const auto signature = tlp::SignSshChallenge(key, "test challenge");
            std::cout << tlp::json::Serialize(tlp::json::Value::Object{{"public", key.publicKey()}, {"signature", signature}}) << '\n';
        } else if (mode == "certificate") {
            std::string input(std::istreambuf_iterator<char>(std::cin), {});
            auto fields = tlp::json::Parse(input);
            tlp::VerifySshCertificateSignature(fields.at("certificate").asString(), fields.at("ca").asString());
        } else if (mode == "authentication") {
            std::string input(std::istreambuf_iterator<char>(std::cin), {});
            const auto fields = tlp::json::Parse(input);
            tlp::ValidateSshAuthentication(tlp::Base64Decode(fields.at("message").asString()), "approved",
                                          tlp::Bytes{1, 2, 3}, tlp::Bytes{4, 5, 6});
        } else if (mode == "lifetime") {
            tlp::SshSigningKey first, second;
            if (first.publicKey() == second.publicKey()) return 1;
            const auto pub = first.publicKey();
            try { first.identitySeed(); return 1; } catch (const tlp::Error&) {}
            first.destroy();
            try { first.sign({1, 2, 3}); return 1; } catch (const tlp::Error&) {}
            try { first.identitySeed(); return 1; } catch (const tlp::Error&) {}
            if (second.publicKey() == pub) return 1;
            std::cout << "fresh keys; destroyed signing/export denied; other session unaffected\n";
        } else return 2;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
