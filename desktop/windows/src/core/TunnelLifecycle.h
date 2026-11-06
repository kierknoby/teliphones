// Portable rules for the elevated tunnel helper: its exit-code encoding, administrator messages,
// verification that a tunnel service belongs to TELIPHONES, and the helper/UI time budget.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tlp {
namespace tunnel_lifecycle {

enum class Stage : std::uint32_t {
    Ok = 0,
    Arguments = 2,
    ConfigRejected = 3,
    WireGuardUnavailable = 4,
    InstallFailed = 5,
    PermissionsFailed = 6,
    NotElevated = 7,
    StartFailed = 8,
    RemoveFailed = 9,
    DependencyFailed = 10,
    KeyFailed = 11,
    AdapterFailed = 12,
    Busy = 13,            // another elevated helper holds this tunnel's machine-wide lock
    ResidualTunnel = 14,  // an earlier instance of this tunnel could not be removed; nothing new was installed
};

// What remained after cleanup. Independent of Win32 numeric service states.
enum class Residual : std::uint32_t {
    None = 0,
    Stopped = 1,
    StartPending = 2,
    StopPending = 3,
    Running = 4,
    Unknown = 5,
    AdapterOnly = 6,        // the service is gone but an active adapter with the tunnel's exact alias still exists
    AdapterUnverified = 7,  // the service is gone but Windows could not enumerate network interfaces
};

struct HelperResult {
    Stage stage = Stage::Ok;
    std::uint32_t error = 0;           // Win32 error of the original failure; 0 when none applies
    bool cleanupIncomplete = false;    // some part of this tunnel is still installed
    bool processSurvived = false;      // the service's own process did not exit after verified termination
    bool ownershipUnverified = false;  // forced termination was refused: not provably this TELIPHONES tunnel
    bool configRemains = false;        // the service is gone but its bootstrap configuration file is not
    Residual residual = Residual::None;
};

// Bits 0-7 stage, 8-11 cleanup flags, 12-15 residual, 16-29 Win32 error (system errors are below 16000).
// Bits 30-31 are always clear, so NTSTATUS-style process termination codes are never mistaken for a result.
constexpr std::uint32_t kMaxEncodedError = 0x3fff;
std::uint32_t EncodeHelperResult(const HelperResult& result);
// False when the exit code is not a helper result (for example a crash or forced termination code).
bool DecodeHelperResult(std::uint32_t code, HelperResult& result);
std::string HelperMessage(std::uint32_t code);

// CommandLineToArgvW rules: the program name ends at its closing quote, later arguments use backslash escaping.
std::vector<std::string> SplitServiceCommandLine(const std::string& commandLine);
// True only when the SCM binary path is exactly the trusted wireguard.exe running "/tunnelservice" for this
// TELIPHONES tunnel's protected configuration file. Paths compare ASCII case-insensitively.
bool IsOwnedTunnelServiceCommand(const std::string& commandLine, const std::string& wireguardExe,
                                 const std::string& configPath);
bool SameWindowsPath(const std::string& left, const std::string& right);

// Whether this tunnel's WireGuardNT adapter still exists, from Windows' interface table (GetIfTable2).
// The table can also hold a row for a device that is no longer present, reported with operational status
// IfOperStatusNotPresent. Such a row carries no traffic, holds no handle and cannot be reused, so it is not a
// remaining adapter. Any other row with the exact alias is. A failed enumeration is never taken as absence.
constexpr std::uint32_t kInterfaceOperStatusNotPresent = 6;  // IF_OPER_STATUS::IfOperStatusNotPresent
struct InterfaceRow {
    std::string alias;
    std::uint32_t operStatus = 0;
};
enum class AdapterPresence { Absent, Active, Unverified };
AdapterPresence ClassifyTunnelAdapter(bool enumerated, const std::vector<InterfaceRow>& rows, const std::string& tunnelName);

// TELIPHONES' own tunnel namespace: exactly "TELIPHONES-" plus 12 lowercase hexadecimal characters (TunnelNameFor).
bool IsTeliphonesTunnelName(const std::string& name);
// Tunnels to clean up at startup, when no TELIPHONES connection can be active: those of saved profiles that are
// installed, plus any other name in the TELIPHONES namespace still registered as a WireGuard tunnel service or
// present as an adapter, such as one left by a removed or re-paired profile. Other names are never returned.
std::vector<std::string> StartupResidualTunnels(const std::vector<std::string>& installedSavedTunnels,
                                                const std::vector<std::string>& serviceTunnelNames,
                                                const std::vector<InterfaceRow>& adapters);

// Polls until the adapter is absent or the budget ends, returning the last observation. Windows may finish
// removing the device shortly after its service stops; an adapter that stays active is reported, never ignored.
template <class Probe, class Now, class Pause>
AdapterPresence AwaitAdapterRelease(Probe probe, Now now, Pause pause, std::uint32_t budgetMs) {
    const auto deadline = now() + budgetMs;
    for (;;) {
        const AdapterPresence presence = probe();
        if (presence == AdapterPresence::Absent) return presence;
        const auto current = now();
        if (current >= deadline) return presence;
        const auto remaining = deadline - current;
        pause(static_cast<std::uint32_t>(remaining < 100 ? remaining : 100));
    }
}

// Every bounded wait the elevated helper performs. The interactive caller waits longer than the helper's
// worst case so it never abandons a helper that is still changing Windows state.
namespace budget {
constexpr std::uint32_t kKeyDeliveryMs = 20000;  // WaitNamedPipe plus one bounded transfer
constexpr std::uint32_t kInstallToolMs = 60000;
constexpr std::uint32_t kUninstallToolMs = 30000;
constexpr std::uint32_t kServiceRegisteredMs = 20000;
constexpr std::uint32_t kServiceRunningMs = 20000;
constexpr std::uint32_t kActivationMs = 15000;  // pinned DLL verification and one private-key driver call
constexpr std::uint32_t kRemovalWaitMs = 15000;
constexpr std::uint32_t kProcessExitMs = 10000;
constexpr std::uint32_t kDeletionWaitMs = 5000;
constexpr std::uint32_t kAdapterReleaseMs = 5000;
constexpr std::uint32_t kCallerMarginMs = 30000;

constexpr std::uint32_t RemovalWorstCaseMs() {
    return kUninstallToolMs + kRemovalWaitMs + kProcessExitMs + kDeletionWaitMs + kAdapterReleaseMs;
}
constexpr std::uint32_t HelperUpWorstCaseMs() {
    // Earlier-instance removal, installation and startup, then removal again on failure.
    return kKeyDeliveryMs + RemovalWorstCaseMs() + kInstallToolMs + kServiceRegisteredMs + kServiceRunningMs +
           kActivationMs + RemovalWorstCaseMs();
}
constexpr std::uint32_t kHelperWaitMs = 330000;
static_assert(kHelperWaitMs >= HelperUpWorstCaseMs() + kCallerMarginMs,
              "The caller must outlast every bounded helper step");
}  // namespace budget

}  // namespace tunnel_lifecycle
}  // namespace tlp
