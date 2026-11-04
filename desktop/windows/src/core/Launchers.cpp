#include "Launchers.h"

#include <algorithm>
#include <cctype>

#include "Validation.h"

namespace tlp {
namespace {

std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

bool endsWithExe(const std::string& path) { return path.size() > 4 && lower(path.substr(path.size() - 4)) == ".exe"; }

bool isAbsoluteLocalPath(const std::string& path) {
    if (path.size() < 4 || path.size() > 1024) return false;
    char drive = path[0];
    if (!((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')) || path[1] != ':' || path[2] != '\\') return false;
    for (unsigned char c : path) {
        if (c < 0x20 || c == 0x7f || c == '"' || c == '/' || c == '*' || c == '?' || c == '<' || c == '>' || c == '|') return false;
    }
    if (path.find(':', 2) != std::string::npos) return false;  // no alternate data streams
    std::size_t start = 3;
    while (start <= path.size()) {
        std::size_t end = path.find('\\', start);
        std::string part = path.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (part.empty() || part == "." || part == "..") return false;
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return true;
}

std::string fileName(const std::string& path) {
    std::size_t slash = path.rfind('\\');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

// PowerShell single-quoted literal: nothing inside is expanded; a quote is written twice.
std::string powerShellLiteral(const std::string& text) {
    std::string out = "'";
    for (char c : text) {
        out += c;
        if (c == '\'') out += '\'';
    }
    return out + "'";
}

std::vector<std::string> openSshArguments(const SshTarget& target) {
    return {"-o", "ServerAliveInterval=15", "-o", "HostKeyAlias=" + target.hostKeyAlias, "-p", std::to_string(target.port), target.user + "@" + target.address};
}

void requireSafeTarget(const SshTarget& target) {
    std::uint32_t parsed = 0;
    if (!IsLinuxUser(target.user) || !ParseIPv4(target.address, parsed) || target.port < 1 || target.port > 65535 || !IsShellSafeToken(target.hostKeyAlias)) {
        throw Error("Refusing to start SSH with an invalid destination.");
    }
}

}  // namespace

const std::vector<AppInfo>& KnownApps(AppKind kind) {
    static const std::vector<AppInfo> browsers = {
        {kWindowsDefaultBrowser, "Windows default browser", AppKind::Browser, {}, false},
        {"chrome", "Google Chrome", AppKind::Browser, {"chrome.exe"}, false},
        {"edge", "Microsoft Edge", AppKind::Browser, {"msedge.exe"}, false},
        {"firefox", "Mozilla Firefox", AppKind::Browser, {"firefox.exe"}, false},
        {"brave", "Brave", AppKind::Browser, {"brave.exe"}, false},
        {"vivaldi", "Vivaldi", AppKind::Browser, {"vivaldi.exe"}, false},
    };
    static const std::vector<AppInfo> terminals = {
        {"powershell", "Windows PowerShell", AppKind::Terminal, {"powershell.exe"}, true},
        {"pwsh", "PowerShell 7", AppKind::Terminal, {"pwsh.exe"}, true},
        {"windows-terminal", "Windows Terminal", AppKind::Terminal, {"wt.exe"}, true},
        {"putty", "PuTTY", AppKind::Terminal, {"putty.exe"}, false},
        {"cmd", "Command Prompt", AppKind::Terminal, {"cmd.exe"}, true},
    };
    return kind == AppKind::Browser ? browsers : terminals;
}

const AppInfo* FindApp(AppKind kind, const std::string& id) {
    for (const AppInfo& app : KnownApps(kind)) {
        if (app.id == id) return &app;
    }
    return nullptr;
}

std::string AppName(AppKind kind, const std::string& id) {
    const AppInfo* app = FindApp(kind, id);
    if (app != nullptr) return app->name;
    return id.empty() ? std::string(kind == AppKind::Browser ? "No browser selected" : "No SSH terminal selected") : "Unrecognised application (" + id + ")";
}

bool IsAppId(const std::string& text) {
    if (text.empty() || text.size() > 32) return false;
    return std::all_of(text.begin(), text.end(), [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'; });
}

bool IsExpectedExecutable(const AppInfo& app, const std::string& path) {
    if (app.executables.empty() || !isAbsoluteLocalPath(path) || !endsWithExe(path)) return false;
    std::string name = lower(fileName(path));
    return std::find(app.executables.begin(), app.executables.end(), name) != app.executables.end();
}

bool IsShellSafePath(const std::string& path) {
    return endsWithExe(path) && IsShellSafeFilePath(path) &&
           std::all_of(path.begin(), path.end(), [](unsigned char c) { return c < 0x80; });
}

bool IsShellSafeFilePath(const std::string& path) {
    if (!isAbsoluteLocalPath(path) || path.size() > 260) return false;
    return std::all_of(path.begin(), path.end(), [](unsigned char c) {
        return c >= 0x80 || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '\\' || c == ':' || c == ' ' || c == '.' ||
               c == '_' || c == '-' || c == '(' || c == ')';
    });
}

bool IsShellSafeToken(const std::string& text) {
    if (text.empty() || text.size() > 256) return false;
    return std::all_of(text.begin(), text.end(), [](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == '@' ||
               c == '=' || c == ':';
    });
}

std::string SerializePreferences(const Preferences& preferences) {
    json::Value::Object locations;
    for (const auto& location : preferences.locations) locations[location.first] = location.second;
    json::Value::Object object{{"schema", kPreferencesSchema},
                               {"browser", preferences.browser},
                               {"terminal", preferences.terminal},
                               {"locations", json::Value(locations)},
                               {"setup", preferences.setup},
                               {"appearance", AppearanceName(preferences.appearance)}};
    return json::Serialize(json::Value(object)) + "\n";
}

Preferences ParsePreferences(const std::string& text) {
    json::Value value = json::Parse(text, 64 * 1024);
    if (value.has("appearance")) {
        json::RequireExactKeys(value, {"schema", "browser", "terminal", "locations", "setup", "appearance"}, "TELIPHONES preferences");
    } else {
        json::RequireExactKeys(value, {"schema", "browser", "terminal", "locations", "setup"}, "TELIPHONES preferences");
    }
    if (value.at("schema").asString() != kPreferencesSchema) throw Error("Unsupported TELIPHONES preferences format.");
    Preferences preferences;
    if (value.has("appearance")) preferences.appearance = ParseAppearance(value.at("appearance").asString());
    preferences.browser = value.at("browser").asString();
    preferences.terminal = value.at("terminal").asString();
    preferences.setup = value.at("setup").asString();
    for (const std::string* id : {&preferences.browser, &preferences.terminal}) {
        if (!id->empty() && !IsAppId(*id)) throw Error("Invalid application in TELIPHONES preferences.");
    }
    if (!preferences.setup.empty() && preferences.setup != "completed" && preferences.setup != "skipped") {
        throw Error("Invalid setup state in TELIPHONES preferences.");
    }
    const json::Value::Object& locations = value.at("locations").asObject();
    if (locations.size() > 16) throw Error("Too many application locations in TELIPHONES preferences.");
    for (const auto& location : locations) {
        const AppInfo* app = FindApp(AppKind::Browser, location.first);
        if (app == nullptr) app = FindApp(AppKind::Terminal, location.first);
        const std::string& path = location.second.asString();
        if (app == nullptr || !IsExpectedExecutable(*app, path)) throw Error("Invalid application location in TELIPHONES preferences.");
        preferences.locations[location.first] = path;
    }
    return preferences;
}

std::vector<std::string> AvailableApps(AppKind kind, const DetectedApps& detected) {
    std::vector<std::string> ids;
    for (const AppInfo& app : KnownApps(kind)) {
        if (app.id == kWindowsDefaultBrowser || detected.count(app.id) != 0) ids.push_back(app.id);
    }
    return ids;
}

std::string DefaultBrowser(const DetectedApps& browsers) { return browsers.count("chrome") != 0 ? "chrome" : kWindowsDefaultBrowser; }

std::string DefaultTerminal(const DetectedApps& terminals) {
    if (terminals.count("powershell") != 0) return "powershell";
    if (terminals.count("cmd") != 0) return "cmd";
    std::vector<std::string> available = AvailableApps(AppKind::Terminal, terminals);
    return available.empty() ? std::string() : available.front();
}

bool NeedsFirstRun(const std::optional<Preferences>& stored) { return !stored || stored->setup.empty(); }

std::optional<Preferences> PreferencesAfterFirstRun(FirstRunOutcome outcome, const std::string& browser, const std::string& terminal,
                                                    const DetectedApps& browsers, const DetectedApps& terminals,
                                                    const std::optional<Preferences>& stored) {
    if (outcome == FirstRunOutcome::Cancelled) return std::nullopt;
    Preferences preferences = stored.value_or(Preferences());
    if (outcome == FirstRunOutcome::Skipped) {
        preferences.browser = DefaultBrowser(browsers);
        preferences.terminal = DefaultTerminal(terminals);
        preferences.setup = "skipped";
        return preferences;
    }
    std::vector<std::string> availableBrowsers = AvailableApps(AppKind::Browser, browsers);
    std::vector<std::string> availableTerminals = AvailableApps(AppKind::Terminal, terminals);
    if (std::find(availableBrowsers.begin(), availableBrowsers.end(), browser) == availableBrowsers.end()) {
        throw Error("Choose a web browser that is installed on this computer.");
    }
    if (!terminal.empty() && std::find(availableTerminals.begin(), availableTerminals.end(), terminal) == availableTerminals.end()) {
        throw Error("Choose an SSH terminal that is installed on this computer.");
    }
    preferences.browser = browser;
    preferences.terminal = terminal;
    preferences.setup = "completed";
    return preferences;
}

Preferences EffectivePreferences(const std::optional<Preferences>& stored, const DetectedApps& browsers, const DetectedApps& terminals) {
    Preferences preferences = stored.value_or(Preferences());
    if (preferences.browser.empty()) preferences.browser = DefaultBrowser(browsers);
    if (preferences.terminal.empty()) preferences.terminal = DefaultTerminal(terminals);
    return preferences;
}

AppUnavailable::AppUnavailable(AppKind appKind, std::string appId)
    : Error(AppName(appKind, appId) + (appKind == AppKind::Browser ? ", your selected web browser," : ", your selected SSH terminal,") +
            " could not be found on this computer. It may have been uninstalled or moved."),
      kind(appKind),
      id(std::move(appId)) {}

std::string ResolveApp(AppKind kind, const std::string& id, const DetectedApps& detected) {
    if (kind == AppKind::Browser && id == kWindowsDefaultBrowser) return std::string();
    const AppInfo* app = FindApp(kind, id);
    if (app == nullptr) throw AppUnavailable(kind, id);
    auto found = detected.find(id);
    if (found == detected.end() || !IsExpectedExecutable(*app, found->second)) throw AppUnavailable(kind, id);
    return found->second;
}

std::string FreePbxUrl(const Profile& profile, const std::string& sessionId) {
    std::string address = ConnectionAddress(profile, sessionId);
    std::uint32_t parsed = 0;
    if (!ParseIPv4(address, parsed)) throw Error("Invalid PBX tunnel address.");
    if (profile.kind == ProfileKind::Administrator) {
        if (!IsManagementUrl(profile.pairing.guiUrl, address)) throw Error("Invalid PBX management address.");
        return profile.pairing.guiUrl;
    }
    return "http://" + address + "/admin/";
}

int ManagementProbePort(const std::string& url) {
    if (!IsManagementUrl(url)) throw Error("Invalid PBX management address.");
    const std::size_t start = url.find("://") + 3;
    const std::size_t colon = url.find(':', start);
    if (colon == std::string::npos) return url.rfind("https://", 0) == 0 ? 443 : 80;
    return std::stoi(url.substr(colon + 1, url.find('/', colon) - colon - 1));
}

LaunchPlan BrowserLaunch(const std::string& browserId, const std::string& executable, const std::string& url) {
    if (!IsManagementUrl(url)) {
        throw Error("Refusing to open an unexpected FreePBX address.");
    }
    LaunchPlan plan;
    if (browserId == kWindowsDefaultBrowser) {
        plan.shellOpen = true;
        plan.target = url;
        return plan;
    }
    const AppInfo* app = FindApp(AppKind::Browser, browserId);
    if (app == nullptr || !IsExpectedExecutable(*app, executable)) throw AppUnavailable(AppKind::Browser, browserId);
    // Every supported browser opens a URL given as its only argument; the URL cannot be mistaken for a switch.
    plan.program = executable;
    plan.commandLine = JoinCommandLine({executable, url});
    return plan;
}

LaunchPlan TerminalLaunch(const std::string& terminalId, const std::string& terminalExecutable, const std::string& sshExecutable,
                          const SshTarget& target, const std::string& configuration) {
    requireSafeTarget(target);
    const AppInfo* app = FindApp(AppKind::Terminal, terminalId);
    if (app == nullptr || !IsExpectedExecutable(*app, terminalExecutable)) throw AppUnavailable(AppKind::Terminal, terminalId);
    LaunchPlan plan;
    plan.program = terminalExecutable;
    plan.newConsole = true;
    if (terminalId == "putty") {
        if (!configuration.empty()) throw Error("Managed SSH certificates require a Windows OpenSSH terminal; choose PowerShell, Command Prompt or Windows Terminal.");
        // PuTTY's own options; -loghost keeps reused tunnel addresses from sharing a cached host key between PBXs.
        plan.commandLine = JoinCommandLine({terminalExecutable, "-ssh", "-P", std::to_string(target.port), "-l", target.user, "-loghost",
                                            target.hostKeyAlias, target.address});
        plan.newConsole = false;
        return plan;
    }
    if (!IsShellSafePath(sshExecutable)) throw Error("The Windows OpenSSH client path is not safe to use.");
    std::vector<std::string> ssh = openSshArguments(target);
    for (const std::string& argument : ssh) {
        if (!IsShellSafeToken(argument)) throw Error("Refusing to start SSH with an unsafe argument.");
    }
    if (!configuration.empty()) {
        if (!IsShellSafeFilePath(configuration)) throw Error("The managed SSH configuration path is not safe for this terminal.");
        ssh.insert(ssh.begin(), {"-F", configuration});
    }
    if (terminalId == "powershell" || terminalId == "pwsh") {
        std::string command = "& " + powerShellLiteral(sshExecutable);
        for (const std::string& argument : ssh) command += " " + powerShellLiteral(argument);
        plan.commandLine = JoinCommandLine({terminalExecutable, "-NoLogo", "-NoExit", "-Command", command});
    } else if (terminalId == "windows-terminal") {
        // Everything after "--" is the command line of the new tab. Arguments never contain ';', wt's separator.
        std::vector<std::string> arguments{terminalExecutable, "new-tab", "--title", "TELIPHONES SSH", "--", sshExecutable};
        arguments.insert(arguments.end(), ssh.begin(), ssh.end());
        plan.commandLine = JoinCommandLine(arguments);
        plan.newConsole = false;
    } else if (terminalId == "cmd") {
        // /s /k "<command>": cmd removes the outer quotes and runs the rest unchanged; arguments contain no cmd metacharacters.
        plan.commandLine = QuoteArgument(terminalExecutable) + " /s /k \"\"" + sshExecutable + "\" " + JoinCommandLine(ssh) + "\"";
    } else {
        throw AppUnavailable(AppKind::Terminal, terminalId);
    }
    return plan;
}

LaunchPlan ManagedTerminalLaunch(const std::string& terminalId, const std::string& terminalExecutable,
                                 const std::string& helper, const std::string& session) {
    const auto* app = FindApp(AppKind::Terminal, terminalId);
    if (!app || !IsExpectedExecutable(*app, terminalExecutable)) throw AppUnavailable(AppKind::Terminal, terminalId);
    if (!IsShellSafeFilePath(helper) || session.size() != 32 || session.find_first_not_of("0123456789abcdef") != std::string::npos)
        throw Error("Invalid managed SSH console invocation.");
    LaunchPlan plan;
    plan.program = terminalExecutable;
    plan.newConsole = true;
    if (terminalId == "powershell" || terminalId == "pwsh")
        plan.commandLine = JoinCommandLine({terminalExecutable, "-NoLogo", "-NoProfile", "-Command",
            "& " + powerShellLiteral(helper) + " '/ssh-console' '" + session + "'; exit $LASTEXITCODE"});
    else if (terminalId == "windows-terminal") {
        plan.commandLine = JoinCommandLine({terminalExecutable, "new-tab", "--title", "TELIPHONES SSH", "--",
                                           helper, "/ssh-console", session});
        plan.newConsole = false;
    } else if (terminalId == "cmd")
        plan.commandLine = QuoteArgument(terminalExecutable) + " /d /s /c \"\"" + helper + "\" /ssh-console " + session + "\"";
    else
        throw Error("Managed SSH requires PowerShell, Command Prompt or Windows Terminal; PuTTY is unsupported.");
    return plan;
}

}  // namespace tlp
