// Contract helper used by tests/contract_check.py to compare the C++ core against the Python broker and gateway tools.
#include <cstdio>
#include <iostream>
#include <iterator>
#include <string>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#include "../src/core/Json.h"
#include "../src/core/Pairing.h"
#include "../src/core/Profiles.h"
#include "../src/core/TunnelConfig.h"

int main(int argc, char** argv) {
    try {
#ifdef _WIN32
        // RenderTunnel already emits CRLF; CRT text mode would turn it into CRCRLF.
        if (_setmode(_fileno(stdout), _O_BINARY) == -1) throw tlp::Error("Unable to set binary contract output.");
#endif
        std::string mode = argc > 1 ? argv[1] : "";
        if (mode == "request" && argc == 5) {
            std::cout << tlp::BuildPairRequest(argv[2], argv[3], argv[4]) << "\n";
        } else if (mode == "request2" && argc == 6) {
            std::cout << tlp::BuildSshPairRequest(argv[2], argv[3], argv[4], argv[5]) << "\n";
        } else if (mode == "certificate" && argc == 10) {
            tlp::PairResponse pairing = tlp::ParsePairResponse(argv[2], argv[3], argv[4], argv[5]);
            tlp::Profile profile;
            profile.id = "0011223344556677";
            profile.name = "PBX";
            profile.workstationName = "ADMIN-PC";
            profile.pairing = pairing;
            profile.sshUser = pairing.sshUser;
            const auto saved = tlp::ParseProfiles(tlp::SerializeProfiles({profile}));
            std::string certificate((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
            tlp::ValidateSshCertificateBindings(certificate, saved.at(0).pairing, {argv[6], argv[7]}, std::stoll(argv[8]), std::stoll(argv[9]));
            std::cout << "validated\n";
        } else if (mode == "response" && (argc == 5 || argc == 6)) {
            tlp::PairResponse r = tlp::ParsePairResponse(argv[2], argv[3], argv[4], argc == 6 ? argv[5] : "");
            std::cout << r.workstationId << " " << r.address << " " << r.pbxAddress << " " << r.endpoint << " " << r.mode << " " << r.expiresAt << " "
                      << (r.ssh ? "ssh" : "nossh") << "\n";
        } else if (mode == "fingerprint" && argc == 3) {
            std::cout << tlp::KeyFingerprint(argv[2]) << "\n";
        } else if (mode == "administrator" && (argc == 6 || argc == 7)) {
            tlp::Profile profile;
            profile.id = "0011223344556677";
            profile.kind = tlp::ProfileKind::Administrator;
            profile.name = "PBX";
            profile.workstationName = "ADMIN-PC";
            profile.pairing = tlp::ParsePairResponse(argv[2], argv[3], argv[4], argc == 7 ? argv[5] : "");
            profile.sshUser = profile.pairing.sshUser;
            auto saved = tlp::ParseProfiles(tlp::SerializeProfiles({profile}));
            std::cout << tlp::RenderTunnel(tlp::AdministratorTunnel(saved.at(0), argv[argc == 7 ? 6 : 5]));
        } else if (mode == "support" && argc == 5) {
            std::string grant((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
            tlp::Profile profile;
            profile.id = "0011223344556677";
            profile.kind = tlp::ProfileKind::Support;
            profile.grant = tlp::ParseEngineerGrant(grant);
            profile.engineerPublicKey = profile.grant.engineerPublicKey;
            profile.hasGrant = true;
            std::cout << tlp::RenderTunnel(tlp::SupportTunnel(profile, argv[2], argv[3], std::stoll(argv[4])));
        } else {
            std::cerr << "usage: contract_tool request|response|fingerprint|administrator|support ...\n";
            return 2;
        }
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << "\n";
        return 1;
    }
    return 0;
}
