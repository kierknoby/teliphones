// Policy for certificate-validated HTTPS access to the paired primary FreePBX service.
#pragma once

#include <string>

#include "Launchers.h"

namespace tlp {

enum class ManagementScheme { Http, Https };
ManagementScheme PrimaryManagementScheme(const std::string& url, const std::string& expectedTunnelAddress);

struct SecureManagementTarget {
    std::string hostname;
    std::string tunnelAddress;
    unsigned short port = 443;
    std::string url;
    std::string resolverRules;
};

// Maps an explicitly configured certificate hostname to the paired tunnel address in an isolated Edge instance.
// HTTP primaries fail closed; no hostname is inferred from the public WireGuard endpoint.
SecureManagementTarget BuildSecureManagementTarget(const std::string& primaryUrl, const std::string& tunnelAddress,
                                                    const std::string& managementHostname);
LaunchPlan SecureEdgeLaunch(const std::string& edgeExecutable, const SecureManagementTarget& target,
                            const std::string& isolatedUserDataDirectory);
bool SecureResolverAllowsHost(const SecureManagementTarget& target, const std::string& hostname);
bool SecureBrowserMayLaunch(bool tunnelVerified, bool managementProbeKnown, bool managementProbeSucceeded);
bool SecureBrowserMustClose(bool tunnelDisconnected);

}  // namespace tlp
