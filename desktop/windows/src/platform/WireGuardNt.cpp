#include "WireGuardNt.h"
#include "Win.h"

#include <wincrypt.h>
#include <algorithm>
#include <cstring>
#include <iterator>

namespace tlp {
namespace win {
namespace wireguard_nt {
namespace {
bool reviewed(const std::string& data) {
    const auto hash = Sha256(Bytes(data.begin(), data.end()));
    return HexEncode(Bytes(hash.begin(), hash.end())) == kDllSha256;
}

template<typename Function>
Function* resolve(HMODULE module, const char* name) {
    const auto address = GetProcAddress(module, name);
    if (!address) throw Failure(Stage::Dependency, "WireGuardNT export unavailable", GetLastError());
    // GetProcAddress returns a generic function pointer; preserve its representation.
    Function* result = nullptr;
    static_assert(sizeof(result) == sizeof(address), "Windows function pointer size");
    std::memcpy(&result, &address, sizeof(result));
    return result;
}
}  // namespace

std::wstring PrepareLibrary() {
    wchar_t self[32768]{};
    const auto length = GetModuleFileNameW(nullptr, self, static_cast<DWORD>(std::size(self)));
    if (!length || length >= std::size(self)) ThrowLastError("Cannot locate WireGuardNT dependency");
    const auto source = std::wstring(self, length);
    const auto data = ReadSmallFile(source.substr(0, source.find_last_of(L"\\/")) + L"\\wireguard.dll", 2 * 1024 * 1024);
    if (!reviewed(data)) throw Failure(Stage::Dependency, "Packaged WireGuardNT DLL hash mismatch", ERROR_INVALID_IMAGE_HASH);
    const auto root = EnsureDirectory(KnownFolder(FOLDERID_ProgramFiles) + L"\\TELIPHONES",
        L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)");
    const auto directory = EnsureDirectory(root + L"\\WireGuardNT-1.1", L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    const auto path = directory + L"\\wireguard.dll";
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        if (GetLastError() != ERROR_FILE_NOT_FOUND) ThrowLastError("Cannot inspect protected WireGuardNT dependency");
        WriteNewFile(path, data, L"D:P(A;;FA;;;SY)(A;;FA;;;BA)");
    }
    return path;
}

void PrivateKeyUpdate::decode(const std::string& base64) {
    DWORD bytes = sizeof(value.PrivateKey);
    if (base64.size() != 44 ||
        !CryptStringToBinaryA(base64.c_str(), static_cast<DWORD>(base64.size()), CRYPT_STRING_BASE64,
                             value.PrivateKey, &bytes, nullptr, nullptr) ||
        bytes != sizeof(value.PrivateKey)) {
        throw Failure(Stage::Key, "Invalid WireGuardNT private key", ERROR_INVALID_DATA);
    }
    value.Flags = WIREGUARD_INTERFACE_HAS_PRIVATE_KEY;
}

Api::Api(const std::wstring& protectedDllPath) {
    try {
        file_ = CreateFileW(protectedDllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                            FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (file_ == INVALID_HANDLE_VALUE) throw Failure(Stage::Dependency, "Cannot lock WireGuardNT DLL", GetLastError());
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(file_, &info))
            throw Failure(Stage::Dependency, "Cannot inspect WireGuardNT DLL", GetLastError());
        if ((info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
            info.nFileSizeHigh || info.nFileSizeLow != 1352800)
            throw Failure(Stage::Dependency, "Invalid WireGuardNT DLL", ERROR_INVALID_IMAGE_HASH);
        std::string data(info.nFileSizeLow, '\0');
        DWORD read = 0;
        if (!ReadFile(file_, data.data(), info.nFileSizeLow, &read, nullptr))
            throw Failure(Stage::Dependency, "Cannot read WireGuardNT DLL", GetLastError());
        if (read != info.nFileSizeLow || !reviewed(data))
            throw Failure(Stage::Dependency, "Protected WireGuardNT DLL hash mismatch", ERROR_INVALID_IMAGE_HASH);
        module_ = LoadLibraryExW(protectedDllPath.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module_) throw Failure(Stage::Dependency, "Cannot load WireGuardNT DLL", GetLastError());
        openAdapter = resolve<WIREGUARD_OPEN_ADAPTER_FUNC>(module_, "WireGuardOpenAdapter");
        closeAdapter = resolve<WIREGUARD_CLOSE_ADAPTER_FUNC>(module_, "WireGuardCloseAdapter");
        setConfiguration = resolve<WIREGUARD_SET_CONFIGURATION_FUNC>(module_, "WireGuardSetConfiguration");
        getConfiguration = resolve<WIREGUARD_GET_CONFIGURATION_FUNC>(module_, "WireGuardGetConfiguration");
    } catch (...) {
        reset();
        throw;
    }
}

void Api::reset() {
    if (module_) FreeLibrary(module_);
    if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
    module_ = nullptr;
    file_ = INVALID_HANDLE_VALUE;
}
Api::~Api() { reset(); }

void Api::activateKey(const std::wstring& name, const std::string& base64) const {
    ActivateKey(name, base64, openAdapter, closeAdapter, setConfiguration);
}

void ActivateKey(const std::wstring& name, const std::string& base64,
                 WIREGUARD_OPEN_ADAPTER_FUNC* openAdapter,
                 WIREGUARD_CLOSE_ADAPTER_FUNC* closeAdapter,
                 WIREGUARD_SET_CONFIGURATION_FUNC* setConfiguration) {
    PrivateKeyUpdate update;
    update.decode(base64);
    const auto adapter = openAdapter(name.c_str());
    if (!adapter) throw Failure(Stage::Adapter, "Cannot open the existing WireGuardNT adapter", GetLastError());
    const BOOL applied = setConfiguration(adapter, &update.value, sizeof(update.value));
    const DWORD error = applied ? ERROR_SUCCESS : GetLastError();
    closeAdapter(adapter);
    if (!applied) throw Failure(Stage::Key, "WireGuardNT private-key update failed", error);
}

}  // namespace wireguard_nt
}  // namespace win
}  // namespace tlp
