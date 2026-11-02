// Detection, per-user storage and launching of the preferred web browser and SSH terminal.
#pragma once

#include <optional>
#include <string>

#include "../core/Launchers.h"
#include "../core/Profiles.h"

namespace tlp {
namespace win {

// Applications installed for this user or computer, plus user-located executables that still exist.
// Uses registered locations (App Paths, StartMenuInternet) and Windows known folders rather than fixed paths.
DetectedApps DetectApps(AppKind kind, const Preferences& preferences);

// %LOCALAPPDATA%\TELIPHONES\preferences.json. Empty when not yet created; throws if the file is unreadable or invalid.
std::optional<Preferences> LoadPreferences();
void SavePreferences(const Preferences& preferences);

// The Windows OpenSSH client, or empty when it is not installed.
std::string OpenSshClient();

// Open the FreePBX GUI / SSH with the preferred application. Throw tlp::AppUnavailable when the selected application
// is missing, and never fall back to a different application.
void OpenFreePbx(const Profile& profile, const std::string& sessionId, const Preferences& preferences);
void OpenSsh(const Profile& profile, const std::string& sessionId, const Preferences& preferences);

}  // namespace win
}  // namespace tlp
