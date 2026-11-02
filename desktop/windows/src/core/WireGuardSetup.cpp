#include "WireGuardSetup.h"

#include <exception>

namespace tlp {

SetupResult RunWireGuardSetup(bool approved, const SetupOperations& op) {
    if (!approved) return {SetupState::NotNow, "Installation deferred. You can install WireGuard later from Settings > Connectivity."};
    bool cleanupNeeded = false;
    SetupResult result;
    try {
        ConnectivityState before = op.detect();
        if (before == ConnectivityState::Ready) return {SetupState::Installed, "WireGuard is already installed and verified. Nothing was changed."};
        if (before == ConnectivityState::Untrusted) {
            return {SetupState::Failed, "Existing WireGuard files could not be verified. TELIPHONES will not overwrite or repair them automatically."};
        }
        cleanupNeeded = true;
        op.progress("Downloading the official WireGuard installer...");
        op.download();
        op.progress("Verifying installer SHA-256, Authenticode signature and publisher...");
        op.verify();
        op.progress("Waiting for administrator approval and Windows Installer. Follow the installer progress window.");
        std::uint32_t code = op.install();
        if (code == 1223 || code == 1602) {
            result = {SetupState::Cancelled, "Installation cancelled or administrator approval declined. Choose Install WireGuard to retry."};
        } else if (code != 0 && code != 3010) {
            result = {SetupState::Failed, "Windows Installer failed (code " + std::to_string(code) +
                                        "). Check your organisation's installation policy, then retry."};
        } else {
            op.progress("Checking the installed WireGuard executables and signatures...");
            ConnectivityState after = op.detect();
            if (after == ConnectivityState::Ready) {
                result = {SetupState::Installed, code == 3010
                    ? "WireGuard is installed and verified. Windows Installer also requested a restart; restart Windows if connectivity is unavailable."
                    : "WireGuard is installed and verified. You can continue without restarting TELIPHONES."};
            } else if (code == 3010) {
                result = {SetupState::RestartRequired, "Windows Installer requested a Windows restart. WireGuard is not ready yet. Restart Windows, then choose Check Again."};
            } else {
                result = {SetupState::Failed, "The installer finished, but the required WireGuard executables could not be verified. Connection controls remain disabled. Choose Check Again or retry."};
            }
        }
    } catch (const std::exception& e) {
        result = {SetupState::Failed, std::string("WireGuard installation failed: ") + e.what() + " Choose Install WireGuard to retry."};
    }
    if (cleanupNeeded) {
        try {
            op.cleanup();
        } catch (const std::exception& e) {
            result.message += std::string(" Installer file cleanup failed: ") + e.what();
            if (result.state != SetupState::Installed) result.state = SetupState::Failed;
        }
    }
    return result;
}

}  // namespace tlp
