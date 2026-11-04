// Process argument construction (Windows quoting rules), SSH launch arguments and elevated-helper arguments.
#pragma once

#include <string>
#include <vector>

#include "Profiles.h"

namespace tlp {

// Quotes one argument so CommandLineToArgvW / the MSVC runtime recover it exactly.
std::string QuoteArgument(const std::string& argument);
std::string JoinCommandLine(const std::vector<std::string>& arguments);

// Basic destination arguments only, not a complete managed authentication plan. New administrator pairings use
// their isolated SSH port; legacy pairings retain port 22 metadata but the GUI requires re-pairing before SSH.
// Remote Support remains on port 22222 as root. The platform supplies pinned, certificate-only configuration.
std::vector<std::string> SshArguments(const Profile& profile, const std::string& sessionId);

// The authorised SSH destination behind SshArguments, for terminals that do not use the OpenSSH client (PuTTY).
// Throws unless SSH is permitted for the profile and every field is validated.
struct SshTarget {
    std::string user;
    std::string address;
    int port = 22;
    std::string hostKeyAlias;
};
SshTarget SshTargetFor(const Profile& profile, const std::string& sessionId);

struct HelperCommand {
    enum class Verb { TunnelUp, TunnelDown } verb = Verb::TunnelDown;
    std::string tunnelName;
    std::string stagingPath;  // TunnelUp only
    std::string userSid;      // TunnelUp only: the interactive user allowed to stop and remove this tunnel
    std::string keyPipe;      // TunnelUp only: random 32-hex token, never the secret
};

std::vector<std::string> HelperArguments(const HelperCommand& command);
// Throws tlp::Error unless the arguments are exactly a well-formed helper command.
HelperCommand ParseHelperArguments(const std::vector<std::string>& arguments);
bool IsSid(const std::string& text);

}  // namespace tlp
