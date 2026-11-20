#if !defined(TELIPHONES_SSH_ONLY_BUILD)
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "Applications.h"
#include "Win.h"
#include "Ssh.h"
#include "Services.h"
#if !defined(TELIPHONES_SSH_ONLY_BUILD)
#include "WireGuard.h"
#include "../core/SecureBrowser.h"
#endif
#include "../core/Encoding.h"

#include <shellapi.h>
#if !defined(TELIPHONES_SSH_ONLY_BUILD)
#include <iphlpapi.h>
#include <netioapi.h>
#endif
#include <objbase.h>

#include <cctype>
#include <cstring>
#include <cwchar>
#include <iterator>
#include <map>
#include <vector>
#if !defined(TELIPHONES_SSH_ONLY_BUILD)
#include <memory>
#include <mutex>
#include <set>
#endif

#include "../core/Validation.h"

namespace tlp {
namespace win {
namespace {

#if !defined(TELIPHONES_SSH_ONLY_BUILD)
struct SecureBrowserSession {
    std::string profileId;
    std::wstring tunnelName;
    std::wstring pnpInstanceId;
    HANDLE job = nullptr;
    HANDLE process = nullptr;
    HANDLE profileLock = nullptr;
    std::wstring userDataDirectory;
    ~SecureBrowserSession() {
        if (job) CloseHandle(job);
        if (process) CloseHandle(process);
        if (profileLock) CloseHandle(profileLock);
    }
};

std::mutex secureBrowserMutex;
std::vector<std::unique_ptr<SecureBrowserSession>> secureBrowserSessions;
std::set<std::string> disconnectedSecureBrowserProfiles;
#endif

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

#if !defined(TELIPHONES_SSH_ONLY_BUILD)
class ProcessHandle {
public:
    explicit ProcessHandle(HANDLE value) : value_(value) {}
    ~ProcessHandle() { if (value_) CloseHandle(value_); }
    ProcessHandle(const ProcessHandle&) = delete;
    ProcessHandle& operator=(const ProcessHandle&) = delete;
    HANDLE get() const { return value_; }
private:
    HANDLE value_;
};
#endif

#if !defined(TELIPHONES_SSH_ONLY_BUILD)
bool isSecureProfileLeaf(const std::wstring& leaf) {
    if (leaf.size() != 32) return false;
    for (wchar_t c : leaf) {
        if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'))) return false;
    }
    return true;
}

bool plainDirectory(const std::wstring& path);

std::wstring secureBrowserRoot() {
    const std::wstring base = EnsureDirectory(KnownFolder(FOLDERID_LocalAppData) + L"\\TELIPHONES");
    return EnsureDirectory(base + L"\\SecureBrowser");
}

std::wstring createSecureProfileDirectory(HANDLE& profileLock) {
    const std::wstring folder = secureBrowserRoot();
    for (int attempt = 0; attempt < 8; ++attempt) {
        const std::wstring leaf = Widen(HexEncode(RandomBytes(16)));
        const std::wstring path = folder + L"\\" + leaf;
        if (CreateDirectoryW(path.c_str(), nullptr)) {
            HANDLE marker = INVALID_HANDLE_VALUE;
            try {
                static constexpr char kMarker[] = "TELIPHONES-SECURE-EDGE-PROFILE/1\n";
                marker = CreateFileW((path + L"\\.teliphones-profile-owner").c_str(), GENERIC_WRITE, 0, nullptr,
                                     CREATE_NEW, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, nullptr);
                if (marker == INVALID_HANDLE_VALUE) ThrowLastError("Unable to mark the isolated Edge profile as TELIPHONES-owned");
                DWORD written = 0;
                const BOOL markerWritten = WriteFile(marker, kMarker, sizeof(kMarker) - 1, &written, nullptr) && written == sizeof(kMarker) - 1;
                CloseHandle(marker);
                marker = INVALID_HANDLE_VALUE;
                if (!markerWritten) ThrowLastError("Unable to write the isolated Edge profile ownership marker");
                profileLock = CreateFileW((path + L"\\.teliphones-profile-lock").c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                                          nullptr, CREATE_NEW, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, nullptr);
                if (profileLock == INVALID_HANDLE_VALUE) ThrowLastError("Unable to lock the isolated Edge profile");
                return path;
            } catch (...) {
                if (marker != INVALID_HANDLE_VALUE) CloseHandle(marker);
                if (profileLock && profileLock != INVALID_HANDLE_VALUE) {
                    CloseHandle(profileLock);
                    profileLock = nullptr;
                }
                if (plainDirectory(path)) {
                    WIN32_FIND_DATAW entry{};
                    HANDLE cleanup = FindFirstFileW((path + L"\\*").c_str(), &entry);
                    if (cleanup != INVALID_HANDLE_VALUE) {
                        do {
                            const std::wstring child(entry.cFileName);
                            if (child == L"." || child == L"..") continue;
                            if ((entry.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0)
                                DeleteFileW((path + L"\\" + child).c_str());
                        } while (FindNextFileW(cleanup, &entry));
                        FindClose(cleanup);
                    }
                    RemoveDirectoryW(path.c_str());
                }
                throw;
            }
        }
        if (GetLastError() != ERROR_ALREADY_EXISTS) ThrowLastError("Unable to create an isolated Edge profile");
        continue;
    }
    throw Error("Unable to create a unique isolated Edge profile.");
}

bool plainDirectory(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
           (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}

bool removeProfileContents(const std::wstring& path, bool topLevel) {
    WIN32_FIND_DATAW item{};
    HANDLE search = FindFirstFileW((path + L"\\*").c_str(), &item);
    if (search == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND;
    bool ok = true;
    do {
        const std::wstring name(item.cFileName);
        if (name == L"." || name == L".." || (topLevel && (name == L".teliphones-profile-owner" || name == L".teliphones-profile-lock"))) continue;
        const std::wstring child = path + L"\\" + name;
        const DWORD attributes = GetFileAttributesW(child.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            ok = false;  // Never traverse or delete reparse points from an Edge profile.
            break;
        }
        if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if (!removeProfileContents(child, false) || !RemoveDirectoryW(child.c_str())) {
                ok = false;
                break;
            }
        } else if (!DeleteFileW(child.c_str())) {
            ok = false;
            break;
        }
    } while (FindNextFileW(search, &item));
    const DWORD enumerationError = GetLastError();
    FindClose(search);
    return ok && (enumerationError == ERROR_NO_MORE_FILES || enumerationError == ERROR_SUCCESS);
}

bool removeOwnedSecureProfileDirectory(const std::wstring& path) {
    if (!plainDirectory(secureBrowserRoot()) || !plainDirectory(path)) return false;
    const std::wstring root = secureBrowserRoot();
    if (path.compare(0, root.size() + 1, root + L"\\") != 0 || !isSecureProfileLeaf(path.substr(root.size() + 1))) return false;
    const DWORD markerAttributes = GetFileAttributesW((path + L"\\.teliphones-profile-owner").c_str());
    const DWORD lockAttributes = GetFileAttributesW((path + L"\\.teliphones-profile-lock").c_str());
    if (markerAttributes == INVALID_FILE_ATTRIBUTES || lockAttributes == INVALID_FILE_ATTRIBUTES ||
        (markerAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        (lockAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) return false;
    HANDLE lock = CreateFileW((path + L"\\.teliphones-profile-lock").c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (lock == INVALID_HANDLE_VALUE) return false;  // Missing or actively held locks are not removable.
    const std::wstring marker = path + L"\\.teliphones-profile-owner";
    HANDLE file = CreateFileW(marker.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        CloseHandle(lock);
        return false;
    }
    char contents[40]{};
    DWORD read = 0;
    const BOOL readOk = ReadFile(file, contents, sizeof(contents), &read, nullptr);
    CloseHandle(file);
    static constexpr char kMarker[] = "TELIPHONES-SECURE-EDGE-PROFILE/1\n";
    if (!readOk || read != sizeof(kMarker) - 1 || memcmp(contents, kMarker, sizeof(kMarker) - 1) != 0) {
        CloseHandle(lock);
        return false;
    }
    const bool contentsRemoved = removeProfileContents(path, true);
    CloseHandle(lock);
    if (!contentsRemoved || !DeleteFileW(marker.c_str())) return false;
    if (!DeleteFileW((path + L"\\.teliphones-profile-lock").c_str())) return false;
    return RemoveDirectoryW(path.c_str()) != FALSE;
}

bool cleanupCompletedSecureProfiles() {
    const std::wstring root = KnownFolder(FOLDERID_LocalAppData) + L"\\TELIPHONES\\SecureBrowser";
    const DWORD rootAttributes = GetFileAttributesW(root.c_str());
    if (rootAttributes == INVALID_FILE_ATTRIBUTES) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return true;
        return false;
    }
    if ((rootAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || (rootAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        return false;
    bool complete = true;
    std::set<std::wstring> trackedProfiles;
    {
        std::lock_guard<std::mutex> lock(secureBrowserMutex);
        for (const auto& session : secureBrowserSessions) trackedProfiles.insert(session->userDataDirectory);
    }
    WIN32_FIND_DATAW item{};
    HANDLE search = FindFirstFileW((root + L"\\*").c_str(), &item);
    if (search == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND;
    do {
        const std::wstring leaf(item.cFileName);
        const std::wstring profilePath = root + L"\\" + leaf;
        if (trackedProfiles.find(profilePath) == trackedProfiles.end() && isSecureProfileLeaf(leaf) &&
            (item.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
            (item.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0)
                if (!removeOwnedSecureProfileDirectory(profilePath)) complete = false;
    } while (FindNextFileW(search, &item));
    const DWORD enumerationError = GetLastError();
    FindClose(search);
    return complete && enumerationError == ERROR_NO_MORE_FILES;
}

void removeEmptySecureProfileDirectory(const std::wstring& path) {
    if (path.empty()) return;
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) return;
    WIN32_FIND_DATAW entry{};
    HANDLE search = FindFirstFileW((path + L"\\*").c_str(), &entry);
    if (search == INVALID_HANDLE_VALUE) return;
    bool onlyMarkers = true;
    do {
        const std::wstring name(entry.cFileName);
        if (name == L"." || name == L".." || name == L".teliphones-profile-owner" || name == L".teliphones-profile-lock") continue;
        onlyMarkers = false;
        break;
    } while (FindNextFileW(search, &entry));
    FindClose(search);
    if (onlyMarkers) (void)removeOwnedSecureProfileDirectory(path);
}

std::wstring adapterPnpInstance(const std::string& tunnelName) {
    PMIB_IF_TABLE2 table = nullptr;
    if (GetIfTable2(&table) != NO_ERROR) throw Error("Windows could not verify the WireGuard tunnel interface.");
    std::unique_ptr<MIB_IF_TABLE2, decltype(&FreeMibTable)> owned(table, &FreeMibTable);
    const std::wstring alias = Widen(tunnelName);
    std::wstring pnp;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto& row = table->Table[i];
        if (row.Alias != alias || row.OperStatus == IfOperStatusNotPresent) continue;
        wchar_t guid[64]{};
        if (!StringFromGUID2(row.InterfaceGuid, guid, static_cast<int>(std::size(guid))))
            throw Error("Windows could not identify the WireGuard tunnel interface.");
        const std::wstring key = L"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\" +
                     std::wstring(guid) + L"\\Connection";
        HKEY opened = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_QUERY_VALUE, &opened) != ERROR_SUCCESS)
            throw Error("Windows could not verify the WireGuard device identity.");
        wchar_t value[512]{};
        DWORD type = 0, bytes = sizeof(value);
        const LONG result = RegQueryValueExW(opened, L"PnpInstanceID", nullptr, &type,
                                              reinterpret_cast<BYTE*>(value), &bytes);
        RegCloseKey(opened);
        if (result != ERROR_SUCCESS || type != REG_SZ || value[0] == L'\0')
            throw Error("Windows could not read the WireGuard device identity.");
        if (!pnp.empty()) throw Error("Multiple interfaces have the TELIPHONES tunnel alias; secure browser launch was refused.");
        pnp = value;
    }
    if (pnp.empty()) throw Error("The exact TELIPHONES WireGuard interface is not present.");
    return pnp;
}

bool closeBrowserSession(SecureBrowserSession& session) {
    if (session.job) {
        TerminateJobObject(session.job, ERROR_CANCELLED);
        const ULONGLONG deadline = GetTickCount64() + 5000;
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
        while (GetTickCount64() < deadline) {
            if (!QueryInformationJobObject(session.job, JobObjectBasicAccountingInformation,
                                           &accounting, sizeof(accounting), nullptr)) return false;
            if (accounting.ActiveProcesses == 0) break;
            Sleep(25);
        }
        if (!QueryInformationJobObject(session.job, JobObjectBasicAccountingInformation,
                                       &accounting, sizeof(accounting), nullptr) || accounting.ActiveProcesses != 0) return false;
        CloseHandle(session.job);  // The owned process tree is confirmed empty before profile cleanup.
        session.job = nullptr;
    } else if (session.process && WaitForSingleObject(session.process, 0) == WAIT_TIMEOUT) {
        // Process ownership is established by the retained handle and suspended CreateProcess launch.
        TerminateProcess(session.process, ERROR_CANCELLED);
        WaitForSingleObject(session.process, 5000);
    }
    if (session.process) {
        if (WaitForSingleObject(session.process, 0) == WAIT_TIMEOUT) return false;
        CloseHandle(session.process);
        session.process = nullptr;
    }
    if (session.profileLock) {
        CloseHandle(session.profileLock);
        session.profileLock = nullptr;
    }
    (void)removeOwnedSecureProfileDirectory(session.userDataDirectory);
    return true;
}

void pruneSecureBrowserSessions() {
    std::lock_guard<std::mutex> lock(secureBrowserMutex);
    for (auto it = secureBrowserSessions.begin(); it != secureBrowserSessions.end();) {
        bool remove = !(*it)->process || WaitForSingleObject((*it)->process, 0) == WAIT_OBJECT_0;
        if (remove) {
            if (closeBrowserSession(**it)) it = secureBrowserSessions.erase(it);
            else ++it;
        } else ++it;  // Tunnel-loss cleanup is driven by the main connection monitor; never infer it from lookup failure here.
    }
}

void launchSecureEdge(const std::string& profileId, const std::string& tunnelName, const std::wstring& pnpInstanceId,
                      const LaunchPlan& plan, const std::wstring& userDataDirectory, HANDLE& profileLock) {
    auto session = std::make_unique<SecureBrowserSession>();
    session->profileId = profileId;
    session->tunnelName = Widen(tunnelName);
    session->pnpInstanceId = pnpInstanceId;
    session->userDataDirectory = userDataDirectory;
    session->job = CreateJobObjectW(nullptr, nullptr);
    if (!session->job) ThrowLastError("Unable to create the secure browser process job");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(session->job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
        ThrowLastError("Unable to configure the secure browser process job");
    std::wstring program = Widen(plan.program);
    std::wstring commandLine = Widen(plan.commandLine);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(program.c_str(), &commandLine[0], nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP,
                        nullptr, nullptr, &startup, &process)) ThrowLastError("Unable to launch isolated Microsoft Edge");
    session->process = process.hProcess;
    ProcessHandle thread(process.hThread);
    if (!AssignProcessToJobObject(session->job, process.hProcess)) {
        const DWORD error = GetLastError();
        TerminateProcess(process.hProcess, ERROR_CANCELLED);
        WaitForSingleObject(process.hProcess, 5000);
        ThrowLastError("Unable to assign isolated Edge to its TELIPHONES session job", error);
    }
    DWORD resumeError = ERROR_SUCCESS;
    {
        session->profileLock = profileLock;
        try {
            std::lock_guard<std::mutex> lock(secureBrowserMutex);
            secureBrowserSessions.push_back(std::move(session));
            profileLock = nullptr;
            SecureBrowserSession& tracked = *secureBrowserSessions.back();
            if (disconnectedSecureBrowserProfiles.find(profileId) != disconnectedSecureBrowserProfiles.end()) {
                (void)closeBrowserSession(tracked);
                secureBrowserSessions.pop_back();
                resumeError = ERROR_CANCELLED;
            } else if (ResumeThread(thread.get()) == static_cast<DWORD>(-1)) {
                resumeError = GetLastError();
                (void)closeBrowserSession(tracked);
                secureBrowserSessions.pop_back();
            }
        } catch (...) {
            if (session) {
                profileLock = session->profileLock;
                session->profileLock = nullptr;
                (void)closeBrowserSession(*session);
            }
            throw;
        }
    }
    if (resumeError != ERROR_SUCCESS) ThrowLastError("Unable to start the isolated Edge process", resumeError);
}
#endif

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
    const std::string pairedUrl = FreePbxUrl(profile, sessionId);
#if defined(TELIPHONES_SSH_ONLY_BUILD)
    if (profile.kind == ProfileKind::Administrator)
        throw Error("Administrator FreePBX browsing is available only in the full TELIPHONES application.");
#else
    if (profile.kind == ProfileKind::Administrator && pairedUrl.rfind("https://", 0) == 0) {
        SecureManagementTarget target = BuildSecureManagementTarget(pairedUrl, profile.pairing.pbxAddress,
                                                                    profile.managementTlsHostname);
        const std::string tunnelName = TunnelNameFor(profile);
        const TunnelState service = QueryTunnel(tunnelName);
        const AddressRoute route = RouteToAddress(tunnelName, target.tunnelAddress);
        const auto port = target.port;
        const auto probe = MeasureTcpProbe(target.tunnelAddress, port, 2500);
        const bool tunnelVerified = service == TunnelState::Running && route.route == RouteEvidence::ViaTunnel;
        if (!SecureBrowserMayLaunch(tunnelVerified, probe.known, probe.succeeded))
            throw Error("TELIPHONES requires the exact tunnel service to be Running, the management route to select that tunnel, and the paired management TCP port to answer a fresh probe. No browser was opened.");
        const std::string executable = ResolveApp(AppKind::Browser, "edge", DetectApps(AppKind::Browser, preferences));
        const std::wstring pnp = adapterPnpInstance(tunnelName);
        pruneSecureBrowserSessions();
        {
            std::lock_guard<std::mutex> lock(secureBrowserMutex);
            disconnectedSecureBrowserProfiles.erase(profile.id);
        }
        HANDLE profileLock = nullptr;
        cleanupCompletedSecureProfiles();
        const std::wstring userDataDirectory = createSecureProfileDirectory(profileLock);
        try {
            LaunchPlan plan = SecureEdgeLaunch(executable, target, Narrow(userDataDirectory));
            launchSecureEdge(profile.id, tunnelName, pnp, plan, userDataDirectory, profileLock);
        } catch (...) {
            if (profileLock) CloseHandle(profileLock);
            removeEmptySecureProfileDirectory(userDataDirectory);
            throw;
        }
        return;
    }
#endif
    if (profile.kind == ProfileKind::Administrator)
        throw Error("The paired primary management service is HTTP. TELIPHONES will not launch it in an ordinary browser or silently change PBX service order. Ask the PBX administrator to explicitly approve HTTPS as the primary service, then explicitly pair again.");
    std::string url = pairedUrl;
    std::string executable = ResolveApp(AppKind::Browser, preferences.browser, DetectApps(AppKind::Browser, preferences));
    launch(BrowserLaunch(preferences.browser, executable, url), AppKind::Browser, preferences.browser);
}

#if !defined(TELIPHONES_SSH_ONLY_BUILD)
void CloseSecureBrowserSessions(const std::string& profileId) {
    std::lock_guard<std::mutex> lock(secureBrowserMutex);
    disconnectedSecureBrowserProfiles.insert(profileId);
    for (auto it = secureBrowserSessions.begin(); it != secureBrowserSessions.end();) {
        if ((*it)->profileId == profileId) {
            if (closeBrowserSession(**it)) it = secureBrowserSessions.erase(it);
            else {
                if ((*it)->job) TerminateJobObject((*it)->job, ERROR_CANCELLED);
                ++it;
            }
        } else ++it;
    }
}

void CloseAllSecureBrowserSessions() {
    std::lock_guard<std::mutex> lock(secureBrowserMutex);
    for (const auto& session : secureBrowserSessions) disconnectedSecureBrowserProfiles.insert(session->profileId);
    for (auto it = secureBrowserSessions.begin(); it != secureBrowserSessions.end();) {
        if (closeBrowserSession(**it)) it = secureBrowserSessions.erase(it);
        else {
            if ((*it)->job) TerminateJobObject((*it)->job, ERROR_CANCELLED);
            ++it;
        }
    }
}

bool RecoverSecureBrowserSessions() {
    CloseAllSecureBrowserSessions();
    {
        std::lock_guard<std::mutex> lock(secureBrowserMutex);
        if (!secureBrowserSessions.empty()) return false;
    }
    return cleanupCompletedSecureProfiles();
}
#endif

void OpenSsh(const Profile& profile, const std::string& sessionId, const Preferences& preferences) {
    if (profile.kind == ProfileKind::Administrator) {
        // The in-process Custom Console is intentionally disabled. Use the
        // selected external OpenSSH terminal so certificate-backed
        // administrator access keeps its pinned-host and disposable-agent
        // security boundary.
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
