#include "CommandLine.h"

#include "Json.h"
#include "Validation.h"

#include <limits>

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

SshTarget SshTargetFor(const Profile& profile, const std::string& sessionId) {
    std::string address = ConnectionAddress(profile, sessionId);
    std::uint32_t parsed = 0;
    if (!ParseIPv4(address, parsed)) throw Error("Invalid PBX tunnel address.");
    if (profile.kind == ProfileKind::Administrator) {
        if (!profile.pairing.ssh) throw Error("SSH was not approved for this workstation. Pair again on the PBX with SSH enabled.");
        if (!IsLinuxUser(profile.sshUser)) throw Error("Set a valid PBX SSH user name for this PBX first.");
        if (!IsProfileId(profile.id)) throw Error("Invalid saved connection.");
        return {profile.sshUser, address, profile.pairing.sshPort != 0 ? profile.pairing.sshPort : 22, "teliphones-" + profile.id};
    }
    if (!IsSessionId(sessionId)) throw Error("Invalid support session.");
    return {"root", address, 22222, "teliphones-support-" + sessionId};
}

std::vector<std::string> SshArguments(const Profile& profile, const std::string& sessionId) {
    SshTarget target = SshTargetFor(profile, sessionId);
    return {"-o", "ServerAliveInterval=15", "-o", "HostKeyAlias=" + target.hostKeyAlias, "-p", std::to_string(target.port), target.user + "@" + target.address};
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
    if (command.verb == HelperCommand::Verb::TunnelUp)
        return {"/tunnel-up", command.tunnelName, command.stagingPath, command.userSid, command.keyPipe,
                command.profileId, command.workstationId, command.operationId, command.generation, command.cancelToken};
    return {"/tunnel-down", command.tunnelName};
}

HelperCommand ParseHelperArguments(const std::vector<std::string>& arguments) {
    HelperCommand command;
    if (arguments.size() == 10 && arguments[0] == "/tunnel-up") {
        command.verb = HelperCommand::Verb::TunnelUp;
        command.tunnelName = arguments[1];
        command.stagingPath = arguments[2];
        command.userSid = arguments[3];
        command.keyPipe = arguments[4];
        command.profileId = arguments[5];
        command.workstationId = arguments[6];
        command.operationId = arguments[7];
        command.generation = arguments[8];
        command.cancelToken = arguments[9];
        const auto hex32 = [](const std::string& value) {
            return value.size() == 32 && value.find_first_not_of("0123456789abcdef") == std::string::npos;
        };
        const auto validGeneration = [](const std::string& value) {
            if (value.empty() || value.size() > 20 || value.find_first_not_of("0123456789") != std::string::npos || value == "0")
                return false;
            std::uint64_t parsed = 0;
            for (const char digit : value) {
                const auto number = static_cast<std::uint64_t>(digit - '0');
                if (parsed > (std::numeric_limits<std::uint64_t>::max() - number) / 10) return false;
                parsed = parsed * 10 + number;
            }
            return parsed != 0;
        };
        if (!hex32(command.keyPipe) || !hex32(command.operationId) || !hex32(command.cancelToken))
            throw Error("Invalid tunnel key pipe.");
        if (!IsProfileId(command.profileId) || command.workstationId.empty() || command.workstationId.size() > 96 ||
            command.workstationId.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != std::string::npos ||
            !validGeneration(command.generation))
            throw Error("Invalid tunnel ownership arguments.");
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
