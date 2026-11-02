#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace tlp {

enum class ConnectivityState { Missing, Ready, Untrusted };
enum class SetupState { NotNow, Installed, Cancelled, Failed, RestartRequired };

struct SetupResult {
    SetupState state = SetupState::NotNow;
    std::string message;
};

struct SetupOperations {
    std::function<ConnectivityState()> detect;
    std::function<void()> download;
    std::function<void()> verify;
    std::function<std::uint32_t()> install;
    std::function<void()> cleanup;
    std::function<void(const std::string&)> progress;
};

// Execution is permitted only after explicit approval and successful verification.
SetupResult RunWireGuardSetup(bool approved, const SetupOperations& operations);

}  // namespace tlp
