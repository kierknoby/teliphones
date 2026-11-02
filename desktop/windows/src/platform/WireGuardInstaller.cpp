#include "WireGuardInstaller.h"
#include "Win.h"
#include "WireGuard.h"

#include <bcrypt.h>
#include <objbase.h>
#include <sddl.h>
#include <shellapi.h>
#include <softpub.h>
#include <winhttp.h>
#include <wintrust.h>

#include <iterator>
#include <utility>

#include "../core/CommandLine.h"
#include "../core/Json.h"
#include "../app/Version.h"

namespace tlp {
namespace win {
namespace {

constexpr wchar_t kHost[] = L"download.wireguard.com";
constexpr wchar_t kPath[] = L"/windows-client/wireguard-amd64-1.1.1.msi";
constexpr char kSha256[] = "7bfed60ad61b785c914b38b61555a975488e1d3ec472dbfb2fcdf498fca75242";
constexpr wchar_t kPublisher[] = L"WireGuard LLC";
constexpr DWORD kMaximumBytes = 32 * 1024 * 1024;

class Handle {
public:
    explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
    void reset(HANDLE value = INVALID_HANDLE_VALUE) {
        if (value_ != INVALID_HANDLE_VALUE && value_ != nullptr) CloseHandle(value_);
        value_ = value;
    }
private:
    HANDLE value_;
};

class HttpHandle {
public:
    explicit HttpHandle(HINTERNET value) : value_(value) {
        if (!value_) ThrowLastError("Unable to contact the official WireGuard distribution service");
    }
    ~HttpHandle() { WinHttpCloseHandle(value_); }
    HttpHandle(const HttpHandle&) = delete;
    HttpHandle& operator=(const HttpHandle&) = delete;
    HINTERNET get() const { return value_; }
private:
    HINTERNET value_;
};

class Download {
public:
    ~Download() {
        lock_.reset();
        directoryLock_.reset();
        // Normal paths use cleanup(), which reports errors to the UI.
        if (!path_.empty()) DeleteFileW(path_.c_str());
        if (!folder_.empty()) RemoveDirectoryW(folder_.c_str());
    }

    void retrieve(const std::function<void(const std::string&)>& progress) {
        SYSTEM_INFO system{};
        GetNativeSystemInfo(&system);
        if (system.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
            throw Error("Integrated installation supports Intel/AMD x64 Windows only, not an emulated x64 application on ARM64.");
        }
        std::wstring base = EnsureDirectory(KnownFolder(FOLDERID_LocalAppData) + L"\\TELIPHONES");
        std::wstring candidate = base + L"\\Installer-" + Widen(HexEncode(RandomBytes(16)));
        std::wstring sddl = L"D:P(A;OICI;FA;;;" + Widen(CurrentUserSid()) + L")(A;OICI;FA;;;SY)(A;OICI;GRGX;;;BA)";
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
            ThrowLastError("Unable to prepare installer directory permissions");
        }
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
        BOOL created = CreateDirectoryW(candidate.c_str(), &attributes);
        DWORD error = GetLastError();
        LocalFree(descriptor);
        if (!created) ThrowLastError("Unable to create a private installer directory", error);
        folder_ = candidate;
        directoryLock_.reset(CreateFileW(folder_.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                         OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (directoryLock_.get() == INVALID_HANDLE_VALUE) ThrowLastError("Unable to protect the installer directory");
        path_ = folder_ + L"\\wireguard.msi";
        Handle output(CreateFileW(path_.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (output.get() == INVALID_HANDLE_VALUE) ThrowLastError("Unable to create the installer file");

        std::wstring agent = Widen("TELIPHONES/" TELIPHONES_VERSION_STRING);
        HttpHandle session(WinHttpOpen(agent.c_str(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
        if (!WinHttpSetTimeouts(session.get(), 15000, 15000, 30000, 30000)) ThrowLastError("Unable to set download timeouts");
        HttpHandle connection(WinHttpConnect(session.get(), kHost, INTERNET_DEFAULT_HTTPS_PORT, 0));
        HttpHandle request(WinHttpOpenRequest(connection.get(), L"GET", kPath, nullptr, WINHTTP_NO_REFERER,
                                              WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
        DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        if (!WinHttpSetOption(request.get(), WINHTTP_OPTION_REDIRECT_POLICY, &redirect, sizeof(redirect))) ThrowLastError("Unable to restrict download redirects");
        if (!WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(request.get(), nullptr)) ThrowLastError("Official WireGuard download failed (check network, proxy and certificate policy)");
        DWORD status = 0, size = sizeof(status);
        if (!WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                                 &status, &size, WINHTTP_NO_HEADER_INDEX)) ThrowLastError("Unable to read download status");
        if (status != 200) throw Error("The official download service returned HTTP " + std::to_string(status) + ".");
        DWORD total = 0, lastShown = 0;
        ULONGLONG deadline = GetTickCount64() + 5 * 60 * 1000;
        for (;;) {
            if (GetTickCount64() > deadline) throw Error("The WireGuard download timed out.");
            BYTE buffer[32768];
            DWORD count = 0, written = 0;
            if (!WinHttpReadData(request.get(), buffer, sizeof(buffer), &count)) ThrowLastError("The WireGuard download was interrupted");
            if (!count) break;
            if (count > kMaximumBytes - total) throw Error("The installer download exceeds the permitted size.");
            if (!WriteFile(output.get(), buffer, count, &written, nullptr)) ThrowLastError("Unable to save the WireGuard installer");
            if (written != count) throw Error("The installer download could not be written completely.");
            total += count;
            if (total - lastShown >= 256 * 1024) {
                progress("Downloading official WireGuard installer: " + std::to_string(total / 1024) + " KiB received...");
                lastShown = total;
            }
        }
        if (!total) throw Error("The official installer download was empty.");
        if (!FlushFileBuffers(output.get())) ThrowLastError("Unable to flush the installer download");
        output.reset();
        // Keep this read-only handle open through Windows Installer execution: deny writes, deletion and replacement.
        lock_.reset(CreateFileW(path_.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (lock_.get() == INVALID_HANDLE_VALUE) ThrowLastError("Unable to lock the downloaded installer");
    }

    void verify() {
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(lock_.get(), &info)) ThrowLastError("Unable to inspect the downloaded installer");
        if ((info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) || info.nFileSizeHigh ||
            !info.nFileSizeLow || info.nFileSizeLow > kMaximumBytes) throw Error("The downloaded installer is not a regular file of the expected size.");
        Bytes bytes(info.nFileSizeLow);
        DWORD read = 0;
        if (!ReadFile(lock_.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr)) ThrowLastError("Unable to read the locked installer");
        if (read != bytes.size()) throw Error("The locked installer could not be read completely.");
        Bytes hash(32);
        if (!BCRYPT_SUCCESS(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, bytes.data(), static_cast<ULONG>(bytes.size()), hash.data(),
                                       static_cast<ULONG>(hash.size())))) throw Error("Unable to verify installer SHA-256.");
        if (HexEncode(hash) != kSha256) throw Error("Installer SHA-256 does not match the reviewed official x64 package. Nothing was executed.");
        LARGE_INTEGER beginning{};
        if (!SetFilePointerEx(lock_.get(), beginning, nullptr, FILE_BEGIN)) ThrowLastError("Unable to rewind the locked installer");

        WINTRUST_FILE_INFO file{};
        file.cbStruct = sizeof(file);
        file.pcwszFilePath = path_.c_str();
        file.hFile = lock_.get();
        WINTRUST_DATA data{};
        data.cbStruct = sizeof(data);
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.pFile = &file;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
        bool publisher = false;
        if (status == ERROR_SUCCESS) {
            CRYPT_PROVIDER_DATA* provider = WTHelperProvDataFromStateData(data.hWVTStateData);
            CRYPT_PROVIDER_SGNR* signer = provider ? WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0) : nullptr;
            CRYPT_PROVIDER_CERT* cert = signer ? WTHelperGetProvCertFromChain(signer, 0) : nullptr;
            wchar_t name[256]{}, organisation[256]{};
            if (cert && cert->pCert) {
                CertGetNameStringW(cert->pCert, CERT_NAME_ATTR_TYPE, 0, const_cast<char*>(szOID_COMMON_NAME), name, static_cast<DWORD>(std::size(name)));
                CertGetNameStringW(cert->pCert, CERT_NAME_ATTR_TYPE, 0, const_cast<char*>(szOID_ORGANIZATION_NAME), organisation, static_cast<DWORD>(std::size(organisation)));
                publisher = std::wstring(name) == kPublisher && std::wstring(organisation) == kPublisher;
            }
        }
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
        if (status != ERROR_SUCCESS || !publisher) throw Error("The installer signature, certificate revocation status or WireGuard LLC publisher could not be verified. Nothing was executed.");
    }

    std::uint32_t execute() {
        wchar_t system[MAX_PATH]{};
        UINT size = GetSystemDirectoryW(system, MAX_PATH);
        if (!size || size >= MAX_PATH) ThrowLastError("Unable to locate Windows Installer");
        std::wstring executable = std::wstring(system) + L"\\msiexec.exe";
        std::wstring arguments = Widen(JoinCommandLine({"/i", Narrow(path_), "/qb", "/norestart", "DO_NOT_LAUNCH=1"}));
        SHELLEXECUTEINFOW launch{};
        launch.cbSize = sizeof(launch);
        launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        launch.lpVerb = L"runas";
        launch.lpFile = executable.c_str();
        launch.lpParameters = arguments.c_str();
        launch.lpDirectory = system;
        launch.nShow = SW_SHOWNORMAL;
        if (!ShellExecuteExW(&launch)) {
            DWORD error = GetLastError();
            if (error == ERROR_CANCELLED) return ERROR_CANCELLED;
            ThrowLastError("Unable to start Windows Installer", error);
        }
        Handle process(launch.hProcess);
        if (!launch.hProcess) throw Error("Windows Installer did not provide a process handle.");
        // Do not kill MSI or delete its input while it is running; Windows Installer supplies its own Cancel UI.
        if (WaitForSingleObject(process.get(), INFINITE) != WAIT_OBJECT_0) ThrowLastError("Unable to wait for Windows Installer");
        DWORD code = 0;
        if (!GetExitCodeProcess(process.get(), &code)) ThrowLastError("Unable to read Windows Installer result");
        return code;
    }

    void cleanup() {
        lock_.reset();
        directoryLock_.reset();
        if (!path_.empty()) {
            if (!DeleteFileW(path_.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) ThrowLastError("Unable to remove the private installer file");
            path_.clear();
        }
        if (!folder_.empty()) {
            if (!RemoveDirectoryW(folder_.c_str())) ThrowLastError("Unable to remove the private installer directory");
            folder_.clear();
        }
    }

private:
    std::wstring folder_, path_;
    Handle directoryLock_, lock_;
};

}  // namespace

SetupResult InstallWireGuard(const std::function<void(const std::string&)>& progress) {
    HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(com)) return {SetupState::Failed, "Windows could not initialise the installer worker. Close Settings and retry."};
    struct ComCleanup {
        ~ComCleanup() { CoUninitialize(); }
    } comCleanup;
    Download download;
    return RunWireGuardSetup(true, {
        [] {
            WireGuardInstallation found = FindWireGuard();
            if (found.installed) return found.trusted ? ConnectivityState::Ready : ConnectivityState::Untrusted;
            for (const std::wstring* path : {&found.wireguardExe, &found.wgExe}) {
                if (GetFileAttributesW(path->c_str()) != INVALID_FILE_ATTRIBUTES) return ConnectivityState::Untrusted;
                DWORD error = GetLastError();
                if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
                    ThrowLastError("Unable to inspect the existing WireGuard installation; automatic replacement is disabled", error);
                }
            }
            return ConnectivityState::Missing;
        },
        [&] { download.retrieve(progress); },
        [&] { download.verify(); },
        [&] { return download.execute(); },
        [&] { download.cleanup(); },
        progress
    });
}

}  // namespace win
}  // namespace tlp
