#pragma once

#include <wireguard.h>
#include <cstddef>
#include <stdexcept>
#include <string>

namespace tlp {
namespace win {
namespace wireguard_nt {

inline constexpr char kDllSha256[] = "b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3";

enum class Stage { Dependency, Adapter, Key };
struct Failure : std::runtime_error {
    Stage stage;
    DWORD code;
    Failure(Stage where, const char* message, DWORD error) : std::runtime_error(message), stage(where), code(error) {}
};

static_assert(sizeof(WIREGUARD_INTERFACE) == 80 && alignof(WIREGUARD_INTERFACE) == 8, "WireGuardNT interface ABI");
static_assert(offsetof(WIREGUARD_INTERFACE, PrivateKey) == 6 &&
              offsetof(WIREGUARD_INTERFACE, PeersCount) == 72, "WireGuardNT interface offsets");

class PrivateKeyUpdate {
public:
    WIREGUARD_INTERFACE value{};
    PrivateKeyUpdate() = default;
    ~PrivateKeyUpdate() { SecureZeroMemory(&value, sizeof(value)); }
    PrivateKeyUpdate(const PrivateKeyUpdate&) = delete;
    PrivateKeyUpdate& operator=(const PrivateKeyUpdate&) = delete;
    void decode(const std::string& base64);
};

void ActivateKey(const std::wstring& name, const std::string& base64,
                 WIREGUARD_OPEN_ADAPTER_FUNC* openAdapter,
                 WIREGUARD_CLOSE_ADAPTER_FUNC* closeAdapter,
                 WIREGUARD_SET_CONFIGURATION_FUNC* setConfiguration);

class Api {
public:
    explicit Api(const std::wstring& protectedDllPath);
    ~Api();
    Api(const Api&) = delete;
    Api& operator=(const Api&) = delete;
    WIREGUARD_OPEN_ADAPTER_FUNC* openAdapter = nullptr;
    WIREGUARD_CLOSE_ADAPTER_FUNC* closeAdapter = nullptr;
    WIREGUARD_SET_CONFIGURATION_FUNC* setConfiguration = nullptr;
    WIREGUARD_GET_CONFIGURATION_FUNC* getConfiguration = nullptr;
    void activateKey(const std::wstring& name, const std::string& base64) const;
private:
    HMODULE module_ = nullptr;
    HANDLE file_ = INVALID_HANDLE_VALUE;
    void reset();
};

// Reads but never loads code from the portable bundle. Only reviewed bytes are copied
// into the administrator-controlled application directory before the elevated load.
std::wstring PrepareLibrary();

}  // namespace wireguard_nt
}  // namespace win
}  // namespace tlp
