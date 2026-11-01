#include "Win.h"

#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>

#include <algorithm>
#include <chrono>

#include "../core/CommandLine.h"
#include "../core/Json.h"

namespace tlp {
namespace win {
namespace {

class Handle {
public:
    Handle() = default;
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
    HANDLE* put() { reset(); return &value_; }
    bool valid() const { return value_ != nullptr && value_ != INVALID_HANDLE_VALUE; }
    void reset() {
        if (valid()) CloseHandle(value_);
        value_ = nullptr;
    }

private:
    HANDLE value_ = nullptr;
};

struct SecurityDescriptor {
    PSECURITY_DESCRIPTOR value = nullptr;
    explicit SecurityDescriptor(const wchar_t* sddl) {
        if (sddl && !ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &value, nullptr)) {
            ThrowLastError("Unable to prepare file permissions");
        }
    }
    ~SecurityDescriptor() {
        if (value) LocalFree(value);
    }
    SecurityDescriptor(const SecurityDescriptor&) = delete;
    SecurityDescriptor& operator=(const SecurityDescriptor&) = delete;
};

void writeAll(HANDLE file, const std::string& data, const char* what) {
    std::size_t offset = 0;
    while (offset < data.size()) {
        DWORD written = 0;
        DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(data.size() - offset, 1 << 20));
        if (!WriteFile(file, data.data() + offset, chunk, &written, nullptr) || written == 0) ThrowLastError(what);
        offset += written;
    }
    if (!FlushFileBuffers(file)) ThrowLastError(what);
}

}  // namespace

std::wstring Widen(const std::string& utf8) {
    if (utf8.empty()) return std::wstring();
    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (length <= 0) throw Error("Invalid UTF-8 text.");
    std::wstring wide(static_cast<std::size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), &wide[0], length);
    return wide;
}

std::string Narrow(const std::wstring& wide) {
    if (wide.empty()) return std::string();
    int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (length <= 0) throw Error("Invalid Unicode text.");
    std::string utf8(static_cast<std::size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), static_cast<int>(wide.size()), &utf8[0], length, nullptr, nullptr);
    return utf8;
}

std::wstring ErrorText(DWORD code) {
    wchar_t* buffer = nullptr;
    DWORD length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, 0,
                                  reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    std::wstring text = length && buffer ? std::wstring(buffer, length) : L"Windows error " + std::to_wstring(code);
    if (buffer) LocalFree(buffer);
    while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ' || text.back() == L'.')) text.pop_back();
    return text;
}

void ThrowLastError(const char* what, DWORD code) {
    throw Error(std::string(what) + ": " + Narrow(ErrorText(code)) + ".");
}

std::wstring KnownFolder(const KNOWNFOLDERID& id) {
    PWSTR path = nullptr;
    HRESULT result = SHGetKnownFolderPath(id, KF_FLAG_CREATE, nullptr, &path);
    if (FAILED(result)) {
        if (path) CoTaskMemFree(path);
        throw Error("Unable to locate a Windows system folder.");
    }
    std::wstring value(path);
    CoTaskMemFree(path);
    return value;
}

std::wstring EnsureDirectory(const std::wstring& path, const wchar_t* sddl) {
    SecurityDescriptor descriptor(sddl);
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor.value, FALSE};
    if (!CreateDirectoryW(path.c_str(), sddl ? &attributes : nullptr)) {
        DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS) ThrowLastError("Unable to create a TELIPHONES folder", error);
        DWORD attributesNow = GetFileAttributesW(path.c_str());
        if (attributesNow == INVALID_FILE_ATTRIBUTES || !(attributesNow & FILE_ATTRIBUTE_DIRECTORY) || (attributesNow & FILE_ATTRIBUTE_REPARSE_POINT)) {
            throw Error("A TELIPHONES folder is not a plain directory: " + Narrow(path));
        }
        if (sddl) {
            BOOL present = FALSE, defaulted = FALSE;
            PACL dacl = nullptr;
            if (!GetSecurityDescriptorDacl(descriptor.value, &present, &dacl, &defaulted)) ThrowLastError("Unable to prepare folder permissions");
            DWORD status = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
                                                 DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
            if (status != ERROR_SUCCESS) ThrowLastError("Unable to restrict a TELIPHONES folder", status);
        }
    }
    return path;
}

Bytes RandomBytes(std::size_t count) {
    Bytes bytes(count);
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        throw Error("Windows could not generate random data.");
    }
    return bytes;
}

std::int64_t UnixNow() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string CurrentUserSid() {
    Handle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token.put())) ThrowLastError("Unable to read the Windows user identity");
    DWORD size = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    if (!size || !GetTokenInformation(token.get(), TokenUser, buffer.data(), size, &size)) ThrowLastError("Unable to read the Windows user identity");
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &text)) ThrowLastError("Unable to read the Windows user identity");
    std::wstring sid(text);
    LocalFree(text);
    return Narrow(sid);
}

std::string ReadSmallFile(const std::wstring& path, std::size_t maxBytes) {
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!file.valid()) ThrowLastError("Unable to open a TELIPHONES file");
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(file.get(), &info)) ThrowLastError("Unable to inspect a TELIPHONES file");
    if (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) throw Error("A TELIPHONES file is not a regular file.");
    std::uint64_t size = (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    if (size > maxBytes) throw Error("A TELIPHONES file is unexpectedly large.");
    std::string data(static_cast<std::size_t>(size), '\0');
    DWORD read = 0;
    if (size && (!ReadFile(file.get(), &data[0], static_cast<DWORD>(size), &read, nullptr) || read != size)) ThrowLastError("Unable to read a TELIPHONES file");
    return data;
}

void WriteNewFile(const std::wstring& path, const std::string& data, const wchar_t* sddl) {
    if (!DeleteFileW(path.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) ThrowLastError("Unable to replace a TELIPHONES file");
    SecurityDescriptor descriptor(sddl);
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor.value, FALSE};
    Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) ThrowLastError("Unable to create a TELIPHONES file");
    writeAll(file.get(), data, "Unable to write a TELIPHONES file");
}

void ReplaceUserFile(const std::wstring& path, const std::string& data) {
    std::wstring temporary = path + L".tmp";
    {
        Handle file(CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!file.valid()) ThrowLastError("Unable to save TELIPHONES settings");
        writeAll(file.get(), data, "Unable to save TELIPHONES settings");
    }
    if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) ThrowLastError("Unable to save TELIPHONES settings");
}

void SecureWipe(std::string& secret) {
    if (!secret.empty()) SecureZeroMemory(&secret[0], secret.size());
    secret.clear();
}

ProcessResult RunProcess(const std::wstring& program, const std::vector<std::string>& arguments, const std::string& input, DWORD timeoutMs) {
    SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
    Handle outRead, outWrite, inRead, inWrite;
    if (!CreatePipe(outRead.put(), outWrite.put(), &inherit, 0) || !SetHandleInformation(outRead.get(), HANDLE_FLAG_INHERIT, 0) ||
        !CreatePipe(inRead.put(), inWrite.put(), &inherit, 0) || !SetHandleInformation(inWrite.get(), HANDLE_FLAG_INHERIT, 0)) {
        ThrowLastError("Unable to start a helper program");
    }
    Handle nul(CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, nullptr));
    if (!nul.valid()) ThrowLastError("Unable to start a helper program");

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = inRead.get();
    startup.hStdOutput = outWrite.get();
    startup.hStdError = nul.get();
    std::wstring commandLine = Widen(QuoteArgument(Narrow(program)) + (arguments.empty() ? "" : " " + JoinCommandLine(arguments)));
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(program.c_str(), &commandLine[0], nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
        ThrowLastError("Unable to start a helper program");
    }
    Handle processHandle(process.hProcess), threadHandle(process.hThread);
    inRead.reset();
    outWrite.reset();
    nul.reset();
    if (!input.empty()) {
        DWORD written = 0;
        WriteFile(inWrite.get(), input.data(), static_cast<DWORD>(input.size()), &written, nullptr);
    }
    inWrite.reset();

    ProcessResult result;
    ULONGLONG deadline = GetTickCount64() + timeoutMs;
    char buffer[4096];
    bool exited = false;
    while (true) {
        DWORD available = 0;
        while (PeekNamedPipe(outRead.get(), nullptr, 0, nullptr, &available, nullptr) && available > 0) {
            DWORD read = 0;
            if (!ReadFile(outRead.get(), buffer, std::min<DWORD>(available, sizeof(buffer)), &read, nullptr) || read == 0) break;
            if (result.output.size() < 65536) result.output.append(buffer, read);
        }
        if (exited) break;
        DWORD wait = WaitForSingleObject(processHandle.get(), 50);
        if (wait == WAIT_OBJECT_0) {
            exited = true;  // drain once more
        } else if (GetTickCount64() > deadline) {
            TerminateProcess(processHandle.get(), 1);
            throw Error("A helper program did not finish in time.");
        }
    }
    GetExitCodeProcess(processHandle.get(), &result.exitCode);
    return result;
}

}  // namespace win
}  // namespace tlp
