#include "CommandLine.h"

#include "Json.h"
#include "Validation.h"

namespace tlp {

std::string QuoteArgument(const std::string& argument) {
    if (!argument.empty() && argument.find_first_of(" \t\n\v\"") == std::string::npos) return argument;
    std::string out = "\"";
    std::size_t backslashes = 0;
    for (char c : argument) {
        if (c == '\\') {
            ++backslashes;
            continue;
        }
        if (c == '"') {
            out.append(backslashes * 2 + 1, '\\');
        } else {
            out.append(backslashes, '\\');
        }
        backslashes = 0;
        out += c;
    }
    out.append(backslashes * 2, '\\');
    out += '"';
    return out;
}

std::string JoinCommandLine(const std::vector<std::string>& arguments) {
    std::string out;
    for (const std::string& argument : arguments) {
        if (!out.empty()) out += ' ';
        out += QuoteArgument(argument);
    }
    return out;
}

std::vector<std::string> SshArguments(const Profile& profile, const std::string& sessionId) {
    std::string address = ConnectionAddress(profile, sessionId);
    std::uint32_t parsed = 0;
    if (!ParseIPv4(address, parsed)) throw Error("Invalid PBX tunnel address.");
    if (profile.kind == ProfileKind::Administrator) {
        if (!profile.pairing.ssh) throw Error("SSH was not approved for this workstation. Pair again on the PBX with SSH enabled.");
        if (!IsLinuxUser(profile.sshUser)) throw Error("Set a valid PBX SSH user name for this PBX first.");
        return {"-o", "ServerAliveInterval=15", "-o", "HostKeyAlias=teliphones-" + profile.id, "-p", "22", profile.sshUser + "@" + address};
    }
    if (!IsSessionId(sessionId)) throw Error("Invalid support session.");
    return {"-o", "ServerAliveInterval=15", "-o", "HostKeyAlias=teliphones-support-" + sessionId, "-p", "22222", "root@" + address};
}

bool IsSid(const std::string& text) {
    if (text.size() < 5 || text.size() > 184 || text.compare(0, 4, "S-1-") != 0) return false;
    bool previousDash = true;
    for (std::size_t i = 4; i < text.size(); ++i) {
        char c = text[i];
        if (c == '-') {
            if (previousDash) return false;
            previousDash = true;
        } else if (c >= '0' && c <= '9') {
            previousDash = false;
        } else {
            return false;
        }
    }
    return !previousDash;
}

std::vector<std::string> HelperArguments(const HelperCommand& command) {
    if (command.verb == HelperCommand::Verb::TunnelUp) return {"/tunnel-up", command.tunnelName, command.stagingPath, command.userSid};
    return {"/tunnel-down", command.tunnelName};
}

HelperCommand ParseHelperArguments(const std::vector<std::string>& arguments) {
    HelperCommand command;
    if (arguments.size() == 4 && arguments[0] == "/tunnel-up") {
        command.verb = HelperCommand::Verb::TunnelUp;
        command.tunnelName = arguments[1];
        command.stagingPath = arguments[2];
        command.userSid = arguments[3];
        std::string expectedName = "\\" + command.tunnelName + ".conf";
        const std::string& path = command.stagingPath;
        bool absolute = path.size() > 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' && path[2] == '\\';
        if (!absolute || path.size() > 260 || path.find("..") != std::string::npos || path.size() < expectedName.size() ||
            path.compare(path.size() - expectedName.size(), expectedName.size(), expectedName) != 0 || !IsSid(command.userSid)) {
            throw Error("Invalid tunnel helper arguments.");
        }
    } else if (arguments.size() == 2 && arguments[0] == "/tunnel-down") {
        command.verb = HelperCommand::Verb::TunnelDown;
        command.tunnelName = arguments[1];
    } else {
        throw Error("Invalid tunnel helper arguments.");
    }
    if (command.tunnelName.compare(0, 11, "TELIPHONES-") != 0 || !IsTunnelName(command.tunnelName)) throw Error("Invalid tunnel name.");
    return command;
}

}  // namespace tlp
