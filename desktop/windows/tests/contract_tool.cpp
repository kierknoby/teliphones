// Contract helper used by tests/contract_check.py to compare the C++ core against the Python broker and gateway tools.
#include <cstdio>
#include <iostream>
#include <iterator>
#include <string>

#include "../src/core/Json.h"
#include "../src/core/Pairing.h"
#include "../src/core/Profiles.h"
#include "../src/core/TunnelConfig.h"

int main(int argc, char** argv) {
    try {
        std::string mode = argc > 1 ? argv[1] : "";
        if (mode == "request" && argc == 5) {
            std::cout << tlp::BuildPairRequest(argv[2], argv[3], argv[4]) << "\n";
        } else if (mode == "response" && argc == 5) {
            tlp::PairResponse r = tlp::ParsePairResponse(argv[2], argv[3], argv[4]);
            std::cout << r.workstationId << " " << r.address << " " << r.pbxAddress << " " << r.endpoint << " " << r.mode << " " << r.expiresAt << " "
                      << (r.ssh ? "ssh" : "nossh") << "\n";
        } else if (mode == "fingerprint" && argc == 3) {
            std::cout << tlp::KeyFingerprint(argv[2]) << "\n";
        } else if (mode == "administrator" && argc == 6) {
            tlp::Profile profile;
            profile.id = "0011223344556677";
            profile.kind = tlp::ProfileKind::Administrator;
            profile.name = "PBX";
            profile.workstationName = "ADMIN-PC";
            profile.pairing = tlp::ParsePairResponse(argv[2], argv[3], argv[4]);
            profile.sshUser = profile.pairing.ssh ? "administrator" : "";
            auto saved = tlp::ParseProfiles(tlp::SerializeProfiles({profile}));
            std::cout << tlp::RenderTunnel(tlp::AdministratorTunnel(saved.at(0), argv[5]));
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
