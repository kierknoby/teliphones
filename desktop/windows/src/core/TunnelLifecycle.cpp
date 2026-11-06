#include "TunnelLifecycle.h"

#include <set>

namespace tlp {
namespace tunnel_lifecycle {
namespace {

constexpr std::uint32_t kCleanupIncomplete = 0x100;
constexpr std::uint32_t kProcessSurvived = 0x200;
constexpr std::uint32_t kOwnershipUnverified = 0x400;
constexpr std::uint32_t kConfigRemains = 0x800;

bool knownStage(std::uint32_t value) {
    return value == 0 || (value >= 2 && value <= static_cast<std::uint32_t>(Stage::ResidualTunnel));
}

std::string stageText(Stage stage) {
    switch (stage) {
        case Stage::Ok: return "The tunnel operation completed.";
        case Stage::Arguments: return "The tunnel helper received invalid arguments. Nothing was changed.";
        case Stage::ConfigRejected: return "The tunnel helper rejected the connection settings. Nothing was installed.";
        case Stage::WireGuardUnavailable: return "WireGuard for Windows is not installed or its signature could not be verified.";
        case Stage::InstallFailed:
            return "WireGuard for Windows could not install the tunnel. Check that WireGuard for Windows is up to date.";
        case Stage::PermissionsFailed: return "The tunnel could not be configured safely.";
        case Stage::NotElevated: return "Administrative approval is required to start a WireGuard tunnel.";
        case Stage::StartFailed:
            return "The WireGuard tunnel service did not reach Running or stopped during startup. "
                   "Check the WireGuard diagnostic log and Windows Service Control Manager events.";
        case Stage::RemoveFailed: return "The TELIPHONES tunnel could not be removed completely.";
        case Stage::DependencyFailed:
            return "The pinned WireGuardNT API DLL is missing, modified, or could not be loaded from its protected location. "
                   "Keep wireguard.dll from this exact TELIPHONES bundle beside the application.";
        case Stage::AdapterFailed:
            return "WireGuard service startup completed, but its existing WireGuardNT adapter could not be opened.";
        case Stage::KeyFailed:
            return "WireGuard service startup completed, but the WireGuardNT in-memory private-key update failed. "
                   "Check the WireGuard diagnostic log; this is not a peer-handshake timeout.";
        case Stage::Busy:
            return "Another TELIPHONES tunnel operation for this connection is still in progress. Nothing was changed; "
                   "wait for it to finish, then try again.";
        case Stage::ResidualTunnel:
            return "An earlier instance of this TELIPHONES tunnel is still installed and could not be removed, "
                   "so no new tunnel was started.";
    }
    return "The TELIPHONES tunnel helper failed.";
}

bool installsTunnel(Stage stage) {
    switch (stage) {
        case Stage::InstallFailed:
        case Stage::PermissionsFailed:
        case Stage::StartFailed:
        case Stage::DependencyFailed:
        case Stage::AdapterFailed:
        case Stage::KeyFailed: return true;
        default: return false;
    }
}

std::string residualText(const HelperResult& result) {
    switch (result.residual) {
        case Residual::StartPending:
            return " The WireGuard tunnel service is stuck in START_PENDING, where Windows does not accept a stop "
                   "request (Windows error 1052).";
        case Residual::StopPending: return " The WireGuard tunnel service is stuck in STOP_PENDING.";
        case Residual::Running: return " The WireGuard tunnel service is still running.";
        case Residual::Stopped: return " The WireGuard tunnel service is stopped but could not be deleted.";
        case Residual::AdapterOnly:
            return " The WireGuard tunnel service was removed, but an active network adapter with the tunnel's name "
                   "still exists.";
        case Residual::AdapterUnverified:
            return " The WireGuard tunnel service was removed, but Windows could not report whether its network "
                   "adapter was released.";
        case Residual::Unknown: return " The state of the WireGuard tunnel service could not be read.";
        case Residual::None: break;
    }
    return result.configRemains ? " The tunnel service was removed, but its configuration file could not be deleted." : "";
}

std::string cleanupText(const HelperResult& result) {
    if (!result.cleanupIncomplete) {
        return installsTunnel(result.stage) ? " TELIPHONES removed the tunnel." : "";
    }
    std::string text = " Cleanup is incomplete." + residualText(result);
    if (result.processSurvived) {
        text += " Its wireguard.exe process did not exit after TELIPHONES terminated it, which means it is blocked inside "
                "Windows networking or a driver. The service is marked for deletion; restart Windows to clear it, then "
                "connect again.";
    } else if (result.ownershipUnverified) {
        text += " TELIPHONES did not force it to stop because the service could not be verified as this TELIPHONES "
                "tunnel. Check it with sc.exe qc before removing it.";
    } else if (result.residual == Residual::AdapterOnly) {
        text += " Restart Windows to release the adapter, then connect again.";
    } else {
        text += " Disconnect again; if the tunnel remains, restart Windows before connecting again.";
    }
    return text + " Other WireGuard tunnels were not changed.";
}

char foldAscii(char value) { return value >= 'A' && value <= 'Z' ? static_cast<char>(value - 'A' + 'a') : value; }

}  // namespace

AdapterPresence ClassifyTunnelAdapter(bool enumerated, const std::vector<InterfaceRow>& rows, const std::string& tunnelName) {
    if (!enumerated) return AdapterPresence::Unverified;
    for (const auto& row : rows) {
        if (row.alias == tunnelName && row.operStatus != kInterfaceOperStatusNotPresent) return AdapterPresence::Active;
    }
    return AdapterPresence::Absent;
}

bool IsTeliphonesTunnelName(const std::string& name) {
    static const std::string prefix = "TELIPHONES-";
    if (name.size() != prefix.size() + 12 || name.compare(0, prefix.size(), prefix) != 0) return false;
    for (std::size_t i = prefix.size(); i < name.size(); ++i) {
        const char c = name[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

std::vector<std::string> StartupResidualTunnels(const std::vector<std::string>& installedSavedTunnels,
                                                const std::vector<std::string>& serviceTunnelNames,
                                                const std::vector<InterfaceRow>& adapters) {
    std::set<std::string> names;
    for (const auto& name : installedSavedTunnels)
        if (IsTeliphonesTunnelName(name)) names.insert(name);
    for (const auto& name : serviceTunnelNames)
        if (IsTeliphonesTunnelName(name)) names.insert(name);
    for (const auto& row : adapters)
        if (IsTeliphonesTunnelName(row.alias) && row.operStatus != kInterfaceOperStatusNotPresent) names.insert(row.alias);
    return {names.begin(), names.end()};
}

std::uint32_t EncodeHelperResult(const HelperResult& result) {
    std::uint32_t code = static_cast<std::uint32_t>(result.stage) & 0xffu;
    if (result.cleanupIncomplete) code |= kCleanupIncomplete;
    if (result.processSurvived) code |= kProcessSurvived;
    if (result.ownershipUnverified) code |= kOwnershipUnverified;
    if (result.configRemains) code |= kConfigRemains;
    code |= (static_cast<std::uint32_t>(result.residual) & 0xfu) << 12;
    const std::uint32_t error = result.error > kMaxEncodedError ? kMaxEncodedError : result.error;
    return code | (error << 16);
}

bool DecodeHelperResult(std::uint32_t code, HelperResult& result) {
    if (code & 0xc0000000u) return false;
    const std::uint32_t stage = code & 0xffu;
    const std::uint32_t residual = (code >> 12) & 0xfu;
    if (!knownStage(stage) || residual > static_cast<std::uint32_t>(Residual::AdapterUnverified)) return false;
    result = HelperResult{};
    result.stage = static_cast<Stage>(stage);
    result.cleanupIncomplete = (code & kCleanupIncomplete) != 0;
    result.processSurvived = (code & kProcessSurvived) != 0;
    result.ownershipUnverified = (code & kOwnershipUnverified) != 0;
    result.configRemains = (code & kConfigRemains) != 0;
    result.residual = static_cast<Residual>(residual);
    result.error = code >> 16;
    return true;
}

std::string HelperMessage(std::uint32_t code) {
    HelperResult result;
    if (!DecodeHelperResult(code, result)) {
        return "The TELIPHONES tunnel helper ended abnormally (exit code " + std::to_string(code) +
               "). The tunnel state is unknown; restart TELIPHONES to check for a remaining tunnel.";
    }
    std::string text = stageText(result.stage);
    if (result.error) text += " Windows error " + std::to_string(result.error) + ".";
    return text + cleanupText(result);
}

std::vector<std::string> SplitServiceCommandLine(const std::string& commandLine) {
    std::vector<std::string> arguments;
    std::size_t i = 0;
    const std::size_t n = commandLine.size();
    auto blank = [](char c) { return c == ' ' || c == '\t'; };
    while (i < n && blank(commandLine[i])) ++i;
    if (i >= n) return arguments;
    std::string program;
    if (commandLine[i] == '"') {
        const auto close = commandLine.find('"', i + 1);
        program = commandLine.substr(i + 1, close == std::string::npos ? std::string::npos : close - i - 1);
        i = close == std::string::npos ? n : close + 1;
    } else {
        while (i < n && !blank(commandLine[i])) program += commandLine[i++];
    }
    arguments.push_back(program);
    for (;;) {
        while (i < n && blank(commandLine[i])) ++i;
        if (i >= n) break;
        std::string argument;
        bool quoted = false;
        while (i < n && (quoted || !blank(commandLine[i]))) {
            std::size_t slashes = 0;
            while (i < n && commandLine[i] == '\\') {
                ++slashes;
                ++i;
            }
            if (i < n && commandLine[i] == '"') {
                argument.append(slashes / 2, '\\');
                if (slashes % 2) {
                    argument += '"';
                } else if (quoted && i + 1 < n && commandLine[i + 1] == '"') {
                    argument += '"';
                    ++i;
                } else {
                    quoted = !quoted;
                }
                ++i;
            } else {
                argument.append(slashes, '\\');
                if (i < n && (quoted || !blank(commandLine[i]))) argument += commandLine[i++];
            }
        }
        arguments.push_back(argument);
    }
    return arguments;
}

bool SameWindowsPath(const std::string& left, const std::string& right) {
    if (left.empty() || left.size() != right.size()) return false;
    for (std::size_t i = 0; i < left.size(); ++i) {
        const char a = left[i] == '/' ? '\\' : left[i];
        const char b = right[i] == '/' ? '\\' : right[i];
        if (foldAscii(a) != foldAscii(b)) return false;
    }
    return true;
}

bool IsOwnedTunnelServiceCommand(const std::string& commandLine, const std::string& wireguardExe,
                                 const std::string& configPath) {
    const auto arguments = SplitServiceCommandLine(commandLine);
    return arguments.size() == 3 && SameWindowsPath(arguments[0], wireguardExe) &&
           arguments[1] == "/tunnelservice" && SameWindowsPath(arguments[2], configPath);
}

}  // namespace tunnel_lifecycle
}  // namespace tlp
