// Process argument construction (Windows quoting rules), SSH launch arguments and elevated-helper arguments.
#pragma once

#include <string>
#include <vector>

#include "Profiles.h"

namespace tlp {

// Quotes one argument so CommandLineToArgvW / the MSVC runtime recover it exactly.
std::string QuoteArgument(const std::string& argument);
std::string JoinCommandLine(const std::vector<std::string>& arguments);

// Arguments for the Windows OpenSSH client (excluding the program). Administrator profiles use the PBX's ordinary
// SSH service on port 22 with the administrator's own account; Remote Support uses the temporary support SSH
// service on port 22222 as root. HostKeyAlias keeps reused tunnel addresses from mixing host keys between PBXs.
std::vector<std::string> SshArguments(const Profile& profile, const std::string& sessionId);

struct HelperCommand {
    enum class Verb { TunnelUp, TunnelDown } verb = Verb::TunnelDown;
    std::string tunnelName;
    std::string stagingPath;  // TunnelUp only
    std::string userSid;      // TunnelUp only: the interactive user allowed to stop and remove this tunnel
};

std::vector<std::string> HelperArguments(const HelperCommand& command);
// Throws tlp::Error unless the arguments are exactly a well-formed helper command.
HelperCommand ParseHelperArguments(const std::vector<std::string>& arguments);
bool IsSid(const std::string& text);

}  // namespace tlp
