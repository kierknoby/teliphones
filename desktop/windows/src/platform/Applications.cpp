#include "Applications.h"
#include "Win.h"
#include "Ssh.h"

#include <shellapi.h>

#include <cctype>
#include <cwchar>
#include <iterator>
#include <vector>

#include "../core/Validation.h"

namespace tlp {
namespace win {
namespace {

std::wstring preferencesFile() { return EnsureDirectory(KnownFolder(FOLDERID_LocalAppData) + L"\\TELIPHONES") + L"\\preferences.json"; }

bool isFile(const std::string& path) {
    DWORD attributes = GetFileAttributesW(Widen(path).c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

std::string expand(const std::wstring& text) {
    DWORD needed = ExpandEnvironmentStringsW(text.c_str(), nullptr, 0);
    if (needed == 0 || needed > 4096) return std::string();
    std::wstring out(needed, L'\0');
    if (ExpandEnvironmentStringsW(text.c_str(), &out[0], needed) == 0) return std::string();
    out.resize(std::wcslen(out.c_str()));
    return Narrow(out);
}

std::string readString(HKEY root, const std::wstring& subkey, const wchar_t* value, REGSAM view) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_QUERY_VALUE | view, &key) != ERROR_SUCCESS) return std::string();
    wchar_t buffer[2048]{};
    DWORD bytes = sizeof(buffer) - sizeof(wchar_t);
    LSTATUS status = RegGetValueW(key, nullptr, value, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, nullptr, buffer, &bytes);
    RegCloseKey(key);
    return status == ERROR_SUCCESS ? expand(buffer) : std::string();
}

// The executable named by a registered command such as "C:\Program Files\App\app.exe" --flag.
std::string commandExecutable(const std::string& command) {
    std::size_t start = command.find_first_not_of(' ');
    if (start == std::string::npos) return std::string();
    if (command[start] == '"') {
        std::size_t end = command.find('"', start + 1);
        return end == std::string::npos ? std::string() : command.substr(start + 1, end - start - 1);
    }
    std::string lowered = command;
    for (char& c : lowered) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    std::size_t exe = lowered.find(".exe", start);
    return exe == std::string::npos ? std::string() : command.substr(start, exe + 4 - start);
}

const HKEY kRoots[] = {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
const REGSAM kViews[] = {KEY_WOW64_64KEY, KEY_WOW64_32KEY};

// HKCU/HKLM ...\App Paths\<executable>, the documented registration for launching an application by name.
std::vector<std::string> appPathCandidates(const AppInfo& app) {
    std::vector<std::string> out;
    for (const std::string& executable : app.executables) {
        std::wstring subkey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + Widen(executable);
        for (HKEY root : kRoots) {
            for (REGSAM view : kViews) {
                std::string path = commandExecutable(readString(root, subkey, nullptr, view));
                if (!path.empty()) out.push_back(path);
            }
        }
    }
    return out;
}

// Browsers registered with Windows Default Apps (HKCU/HKLM\SOFTWARE\Clients\StartMenuInternet\<name>\shell\open\command).
std::vector<std::string> registeredBrowsers() {
    std::vector<std::string> out;
    for (HKEY root : kRoots) {
        for (REGSAM view : kViews) {
            HKEY key = nullptr;
            if (RegOpenKeyExW(root, L"SOFTWARE\\Clients\\StartMenuInternet", 0, KEY_ENUMERATE_SUB_KEYS | view, &key) != ERROR_SUCCESS) continue;
            for (DWORD index = 0; index < 64; ++index) {
                wchar_t name[256]{};
                DWORD length = static_cast<DWORD>(std::size(name));
                if (RegEnumKeyExW(key, index, name, &length, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                std::wstring subkey = L"SOFTWARE\\Clients\\StartMenuInternet\\" + std::wstring(name) + L"\\shell\\open\\command";
                std::string path = commandExecutable(readString(root, subkey, nullptr, view));
                if (!path.empty()) out.push_back(path);
            }
            RegCloseKey(key);
        }
    }
    return out;
}

std::string systemDirectory() {
    wchar_t system[MAX_PATH] = L"";
    UINT length = GetSystemDirectoryW(system, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) ThrowLastError("Unable to locate Windows");
    return Narrow(system);
}

std::string knownFolder(const KNOWNFOLDERID& id) {
    try {
        return Narrow(KnownFolder(id));
    } catch (const std::exception&) {
        return std::string();
    }
}

// Standard install locations relative to Windows known folders, used when an application has no registration.
std::vector<std::string> folderCandidates(const std::string& id) {
    std::string system = systemDirectory();
    std::string programFiles = knownFolder(FOLDERID_ProgramFiles);
    std::string programFilesX86 = knownFolder(FOLDERID_ProgramFilesX86);
    std::string localAppData = knownFolder(FOLDERID_LocalAppData);
    std::vector<std::string> out;
    auto add = [&](const std::string& base, const char* rest) {
        if (!base.empty()) out.push_back(base + rest);
    };
    if (id == "powershell") add(system, "\\WindowsPowerShell\\v1.0\\powershell.exe");
    if (id == "cmd") add(system, "\\cmd.exe");
    if (id == "pwsh") add(programFiles, "\\PowerShell\\7\\pwsh.exe");
    if (id == "windows-terminal") add(localAppData, "\\Microsoft\\WindowsApps\\wt.exe");  // Windows Terminal execution alias
    if (id == "putty") {
        add(programFiles, "\\PuTTY\\putty.exe");
        add(programFilesX86, "\\PuTTY\\putty.exe");
    }
    return out;
}

void launch(const LaunchPlan& plan, AppKind kind, const std::string& id) {
    if (plan.shellOpen) {
        HINSTANCE result = ShellExecuteW(nullptr, L"open", Widen(plan.target).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        if (reinterpret_cast<INT_PTR>(result) <= 32) {
            throw Error("Windows could not open the Windows default browser. Check Settings > Apps > Default apps, or choose a specific browser in TELIPHONES Settings.");
        }
        return;
    }
    std::wstring program = Widen(plan.program);
    std::wstring commandLine = Widen(plan.commandLine);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(program.c_str(), &commandLine[0], nullptr, nullptr, FALSE, plan.newConsole ? CREATE_NEW_CONSOLE : 0, nullptr, nullptr,
                        &startup, &process)) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) throw AppUnavailable(kind, id);
        ThrowLastError(("Unable to start " + AppName(kind, id)).c_str(), error);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
}

}  // namespace

DetectedApps DetectApps(AppKind kind, const Preferences& preferences) {
    DetectedApps detected;
    std::vector<std::string> browsers = kind == AppKind::Browser ? registeredBrowsers() : std::vector<std::string>();
    for (const AppInfo& app : KnownApps(kind)) {
        if (app.executables.empty()) continue;
        std::vector<std::string> candidates;
        auto located = preferences.locations.find(app.id);
        if (located != preferences.locations.end()) candidates.push_back(located->second);
        for (const std::string& path : appPathCandidates(app)) candidates.push_back(path);
        for (const std::string& path : browsers) candidates.push_back(path);
        for (const std::string& path : folderCandidates(app.id)) candidates.push_back(path);
        for (const std::string& path : candidates) {
            if (IsExpectedExecutable(app, path) && isFile(path)) {
                detected[app.id] = path;
                break;
            }
        }
    }
    return detected;
}

std::optional<Preferences> LoadPreferences() {
    std::wstring path = preferencesFile();
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) return std::nullopt;
    return ParsePreferences(ReadSmallFile(path, 64 * 1024));
}

void SavePreferences(const Preferences& preferences) {
    std::string text = SerializePreferences(preferences);
    ParsePreferences(text);
    ReplaceUserFile(preferencesFile(), text);
}

std::string OpenSshClient() {
    std::string ssh = systemDirectory() + "\\OpenSSH\\ssh.exe";
    return isFile(ssh) ? ssh : std::string();
}

void OpenFreePbx(const Profile& profile, const std::string& sessionId, const Preferences& preferences) {
    // Only a URL built from the validated tunnel address is opened; never a URL supplied by a remote party.
    std::string url = FreePbxUrl(profile, sessionId);
    std::string executable = ResolveApp(AppKind::Browser, preferences.browser, DetectApps(AppKind::Browser, preferences));
    launch(BrowserLaunch(preferences.browser, executable, url), AppKind::Browser, preferences.browser);
}

void OpenSsh(const Profile& profile, const std::string& sessionId, const Preferences& preferences) {
    if (profile.kind == ProfileKind::Administrator) {
        StartManagedSsh(profile, preferences);
        return;
    }
    SshTarget target = SshTargetFor(profile, sessionId);
    std::string executable = ResolveApp(AppKind::Terminal, preferences.terminal, DetectApps(AppKind::Terminal, preferences));
    std::string ssh;
    if (FindApp(AppKind::Terminal, preferences.terminal)->needsOpenSsh) {
        ssh = OpenSshClient();
        if (ssh.empty()) {
            throw Error("The Windows OpenSSH client is not installed. Install it from Settings > System > Optional features > OpenSSH Client, "
                        "or choose PuTTY as your SSH terminal in TELIPHONES Settings.");
        }
    }
    launch(TerminalLaunch(preferences.terminal, executable, ssh, target), AppKind::Terminal, preferences.terminal);
}

}  // namespace win
}  // namespace tlp
