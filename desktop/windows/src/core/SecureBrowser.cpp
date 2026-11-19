#include "SecureBrowser.h"

#include <algorithm>

#include "CommandLine.h"
#include "Json.h"
#include "Validation.h"

namespace tlp {
namespace {

std::string lowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : static_cast<char>(c);
    });
    return value;
}

}  // namespace

ManagementScheme PrimaryManagementScheme(const std::string& url, const std::string& expectedTunnelAddress) {
    if (!IsManagementUrl(url, expectedTunnelAddress)) throw Error("The paired primary management URL is invalid.");
    return url.rfind("https://", 0) == 0 ? ManagementScheme::Https : ManagementScheme::Http;
}

SecureManagementTarget BuildSecureManagementTarget(const std::string& primaryUrl, const std::string& tunnelAddress,
                                                    const std::string& managementHostname) {
    if (PrimaryManagementScheme(primaryUrl, tunnelAddress) != ManagementScheme::Https) {
        throw Error("The paired primary management service is HTTP, not HTTPS. TELIPHONES will not reorder the PBX's configured services or change this pairing. Ask a FreePBX administrator to explicitly approve configuring a certificate-validated HTTPS management service as the primary service, with a certificate valid for the configured hostname. After an approved change, explicitly pair again to receive the new primary URL. No pairing or firewall permission is changed by this action.");
    }
    if (!IsHostname(managementHostname))
        throw Error("Enter the HTTPS certificate hostname supplied or confirmed by the PBX administrator. TELIPHONES will not infer it from the public WireGuard endpoint.");
    std::uint32_t address = 0;
    if (!ParseIPv4(tunnelAddress, address) || address == 0 || (address >> 24) == 127)
        throw Error("The paired tunnel address is invalid.");

    const std::size_t authorityStart = 8;
    const std::size_t portSeparator = primaryUrl.find(':', authorityStart);
    unsigned short port = 443;
    if (portSeparator != std::string::npos) {
        const std::size_t path = primaryUrl.find('/', authorityStart);
        const std::string text = primaryUrl.substr(portSeparator + 1, path - portSeparator - 1);
        unsigned parsedPort = 0;
        for (char c : text) parsedPort = parsedPort * 10 + static_cast<unsigned>(c - '0');
        if (parsedPort == 0 || parsedPort > 65535) throw Error("The paired HTTPS management port is invalid.");
        port = static_cast<unsigned short>(parsedPort);
    }

    SecureManagementTarget target;
    target.hostname = lowerAscii(managementHostname);
    target.tunnelAddress = tunnelAddress;
    target.port = port;
    target.url = "https://" + target.hostname + (port == 443 ? "" : ":" + std::to_string(port)) + "/admin/";
    target.resolverRules = "MAP " + target.hostname + " " + tunnelAddress + ", MAP * ~NOTFOUND";
    return target;
}

LaunchPlan SecureEdgeLaunch(const std::string& edgeExecutable, const SecureManagementTarget& target,
                            const std::string& isolatedUserDataDirectory) {
        if (edgeExecutable.size() < 11 || isolatedUserDataDirectory.size() < 4 ||
                !((isolatedUserDataDirectory[0] >= 'A' && isolatedUserDataDirectory[0] <= 'Z') ||
                    (isolatedUserDataDirectory[0] >= 'a' && isolatedUserDataDirectory[0] <= 'z')) ||
                isolatedUserDataDirectory[1] != ':' || isolatedUserDataDirectory[2] != '\\' ||
                isolatedUserDataDirectory.find_first_of("\"*?<>|\r\n") != std::string::npos)
                throw Error("A Microsoft Edge executable and absolute isolated profile directory are required.");
    const SecureManagementTarget checked = BuildSecureManagementTarget(
        "https://" + target.tunnelAddress + (target.port == 443 ? "" : ":" + std::to_string(target.port)) + "/admin/",
        target.tunnelAddress, target.hostname);
    if (target.url != checked.url || target.resolverRules != checked.resolverRules)
        throw Error("Refusing an invalid secure Edge launch plan.");
    const bool edgeName = edgeExecutable.size() >= 10 &&
        std::equal(edgeExecutable.end() - 10, edgeExecutable.end(), "msedge.exe", [](char a, char b) {
            return (a >= 'A' && a <= 'Z' ? a + ('a' - 'A') : a) == b;
        });
    if (!edgeName) throw Error("Secure management hostname mapping requires Microsoft Edge.");
    LaunchPlan plan;
    plan.program = edgeExecutable;
    plan.commandLine = JoinCommandLine({edgeExecutable, "--user-data-dir=" + isolatedUserDataDirectory,
        "--host-resolver-rules=" + target.resolverRules, "--no-proxy-server", "--no-first-run", "--inprivate", target.url});
    return plan;
}

bool SecureResolverAllowsHost(const SecureManagementTarget& target, const std::string& hostname) {
    return lowerAscii(hostname) == target.hostname;
}

bool SecureBrowserMayLaunch(bool tunnelVerified, bool managementProbeKnown, bool managementProbeSucceeded) {
    return tunnelVerified && managementProbeKnown && managementProbeSucceeded;
}

bool SecureBrowserMustClose(bool tunnelDisconnected) { return tunnelDisconnected; }

}  // namespace tlp
