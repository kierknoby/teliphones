// Preferred browser and SSH terminal: catalogue, per-user preference store, selection rules and launch command lines.
// Portable and free of Win32 calls so the rules can be tested anywhere; detection and process creation live in
// platform/Applications.cpp.
#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

#include "CommandLine.h"
#include "Json.h"
#include "Profiles.h"

namespace tlp {

enum class AppKind { Browser, Terminal };

struct AppInfo {
    std::string id;
    std::string name;
    AppKind kind;
    std::vector<std::string> executables;  // accepted file names (lower case); empty for the Windows default browser
    bool needsOpenSsh = false;             // terminals that host the Windows OpenSSH client
};

constexpr const char* kWindowsDefaultBrowser = "windows-default";
constexpr const char* kPreferencesSchema = "teliphones-desktop-preferences/1";

// Catalogue in display order. The Windows default browser is always first and always available.
const std::vector<AppInfo>& KnownApps(AppKind kind);
const AppInfo* FindApp(AppKind kind, const std::string& id);
std::string AppName(AppKind kind, const std::string& id);
bool IsAppId(const std::string& text);

// Executable paths discovered on this computer, keyed by catalogue id. A user-located executable that still exists
// takes precedence over an automatically detected copy of the same application.
using DetectedApps = std::map<std::string, std::string>;

// Absolute local path to an .exe whose file name is one this catalogue entry accepts.
bool IsExpectedExecutable(const AppInfo& app, const std::string& path);
// Stricter: safe to embed inside a PowerShell or Command Prompt command (only the OpenSSH client path is embedded).
bool IsShellSafePath(const std::string& path);
// Characters that cannot alter PowerShell, Command Prompt or Windows Terminal parsing.
bool IsShellSafeToken(const std::string& text);

struct Preferences {
    std::string browser;    // catalogue id; empty when never chosen
    std::string terminal;   // catalogue id; empty when never chosen
    std::map<std::string, std::string> locations;  // user-located executables (for example portable PuTTY), by id
    std::string setup;      // "completed" or "skipped"; empty when the welcome dialog has not been finished
};

std::string SerializePreferences(const Preferences& preferences);
// Strict: throws tlp::Error for malformed or unexpected content. Unknown application ids are kept (they resolve as
// unavailable) so a preference written by a newer TELIPHONES is reported rather than silently replaced.
Preferences ParsePreferences(const std::string& text);

// Ids available on this computer, in catalogue order. Browsers always include the Windows default browser.
std::vector<std::string> AvailableApps(AppKind kind, const DetectedApps& detected);
// Pre-selection: Google Chrome, else the Windows default browser; Windows PowerShell, else Command Prompt, else any
// detected terminal, else empty.
std::string DefaultBrowser(const DetectedApps& browsers);
std::string DefaultTerminal(const DetectedApps& terminals);

// The welcome dialog appears until it is completed or explicitly skipped.
bool NeedsFirstRun(const std::optional<Preferences>& stored);
enum class FirstRunOutcome { Saved, Skipped, Cancelled };
// Saved stores the chosen applications; Skipped stores the defaults; Cancelled stores nothing, so the welcome dialog
// is offered again at the next start. Throws if a chosen application is not available.
std::optional<Preferences> PreferencesAfterFirstRun(FirstRunOutcome outcome, const std::string& browser, const std::string& terminal,
                                                    const DetectedApps& browsers, const DetectedApps& terminals,
                                                    const std::optional<Preferences>& stored);
// Preferences in force: stored values where present, otherwise the defaults. Never substitutes another application
// for a stored choice that is no longer available.
Preferences EffectivePreferences(const std::optional<Preferences>& stored, const DetectedApps& browsers, const DetectedApps& terminals);

// Raised when the selected application cannot be found. The caller must ask the user; nothing else is launched.
struct AppUnavailable : Error {
    AppUnavailable(AppKind kind, std::string id);
    AppKind kind;
    std::string id;
};

// Executable path for a selection. Empty for the Windows default browser. Throws AppUnavailable when the application
// was not detected; another application is never substituted.
std::string ResolveApp(AppKind kind, const std::string& id, const DetectedApps& detected);

struct LaunchPlan {
    bool shellOpen = false;    // open `target` with the Windows registered URL handler
    std::string target;        // URL for shellOpen
    std::string program;       // absolute executable for CreateProcess
    std::string commandLine;   // complete command line, beginning with the quoted program
    bool newConsole = false;
};

// http://<validated tunnel address>/admin/ - unchanged from earlier releases.
std::string FreePbxUrl(const Profile& profile, const std::string& sessionId);
LaunchPlan BrowserLaunch(const std::string& browserId, const std::string& executable, const std::string& url);

// sshExecutable is the Windows OpenSSH client; it is required for every terminal except PuTTY.
LaunchPlan TerminalLaunch(const std::string& terminalId, const std::string& terminalExecutable, const std::string& sshExecutable,
                          const SshTarget& target);

}  // namespace tlp
