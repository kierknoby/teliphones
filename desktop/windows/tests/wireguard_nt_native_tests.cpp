#include <winsock2.h>
#include <ws2tcpip.h>

#include "../src/platform/WireGuardNt.h"
#include "../src/platform/WireGuard.h"
#include "../src/platform/Win.h"
#include "../src/core/Json.h"
#include "../src/core/TunnelConfig.h"

#include <iphlpapi.h>
#include <netioapi.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <iterator>
#include <new>
#include <vector>

namespace nt = tlp::win::wireguard_nt;
using namespace tlp;
using namespace tlp::win;

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

bool openFails = false, setFails = false, closed = false, configured = false;
int sentinel = 0;
const auto fakeHandle = reinterpret_cast<WIREGUARD_ADAPTER_HANDLE>(&sentinel);

WIREGUARD_ADAPTER_HANDLE WINAPI fakeOpen(LPCWSTR) {
    if (openFails) { SetLastError(ERROR_ACCESS_DENIED); return nullptr; }
    return fakeHandle;
}
void WINAPI fakeClose(WIREGUARD_ADAPTER_HANDLE handle) { closed = handle == fakeHandle; }
BOOL WINAPI fakeSet(WIREGUARD_ADAPTER_HANDLE handle, const WIREGUARD_INTERFACE* config, DWORD bytes) {
    configured = handle == fakeHandle && bytes == sizeof(*config) &&
        config->Flags == WIREGUARD_INTERFACE_HAS_PRIVATE_KEY && !config->PeersCount && !config->ListenPort &&
        std::all_of(std::begin(config->PublicKey), std::end(config->PublicKey), [](BYTE b) { return b == 0; }) &&
        std::all_of(std::begin(config->PrivateKey), std::end(config->PrivateKey), [](BYTE b) { return b == 3; });
    if (setFails) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return TRUE;
}

void unitTests() {
    const auto key = Base64Encode(Bytes(32, 3));
    nt::ActivateKey(L"test", key, fakeOpen, fakeClose, fakeSet);
    require(configured && closed, "Exact official private-only ABI update must close the adapter");
    openFails = true;
    closed = configured = false;
    try {
        nt::ActivateKey(L"test", key, fakeOpen, fakeClose, fakeSet);
        throw std::runtime_error("Adapter-open failure was accepted");
    } catch (const nt::Failure& error) {
        require(error.stage == nt::Stage::Adapter && error.code == ERROR_ACCESS_DENIED &&
                !closed && !configured, "Open failure must preserve its Win32 code and not configure");
    }
    openFails = false;
    setFails = true;
    try {
        nt::ActivateKey(L"test", key, fakeOpen, fakeClose, fakeSet);
        throw std::runtime_error("Configuration failure was accepted");
    } catch (const nt::Failure& error) {
        require(error.stage == nt::Stage::Key && error.code == ERROR_INVALID_PARAMETER && closed,
                "Set failure must close the handle and preserve the original error");
    }
    alignas(nt::PrivateKeyUpdate) unsigned char storage[sizeof(nt::PrivateKeyUpdate)]{};
    auto* update = new (storage) nt::PrivateKeyUpdate;
    update->decode(key);
    update->~PrivateKeyUpdate();
    require(std::all_of(std::begin(storage), std::end(storage), [](unsigned char b) { return b == 0; }),
            "Private-key update destructor must wipe the whole official structure");
    update = new (storage) nt::PrivateKeyUpdate;
    bool rejected = false;
    try { update->decode(std::string(44, '!')); }
    catch (const nt::Failure& error) { rejected = error.stage == nt::Stage::Key; }
    update->~PrivateKeyUpdate();
    require(rejected && std::all_of(std::begin(storage), std::end(storage), [](unsigned char b) { return b == 0; }),
            "Invalid input must fail and still wipe partially decoded data");
    wchar_t temporary[MAX_PATH]{}, path[MAX_PATH]{};
    require(GetTempPathW(MAX_PATH, temporary) != 0 && GetTempFileNameW(temporary, L"tlp", 0, path) != 0,
            "Cannot create isolated untrusted-DLL fixture");
    try {
        const auto sddl = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + Widen(CurrentUserSid()) + L")";
        WriteNewFile(path, std::string(1352800, '\0'), sddl.c_str());
        bool refused = false;
        try { nt::Api invalid(path); }
        catch (const nt::Failure& error) {
            refused = error.stage == nt::Stage::Dependency && error.code == ERROR_INVALID_IMAGE_HASH;
        }
        require(refused, "Correct-size but unreviewed DLL must be rejected before loading any code");
    } catch (...) {
        DeleteFileW(path);
        throw;
    }
    require(DeleteFileW(path) != FALSE, "Cannot remove untrusted-DLL fixture");
}

class Snapshot {
public:
    std::vector<ULONG64> storage;
    explicit Snapshot(const nt::Api& api, WIREGUARD_ADAPTER_HANDLE adapter) {
        DWORD bytes = 0;
        require(!api.getConfiguration(adapter, nullptr, &bytes) && GetLastError() == ERROR_MORE_DATA,
                "Official API must provide required configuration buffer size");
        require(bytes >= sizeof(WIREGUARD_INTERFACE) && bytes < 65536, "Unexpected test adapter buffer size");
        storage.resize((bytes + sizeof(ULONG64) - 1) / sizeof(ULONG64));
        if (!api.getConfiguration(adapter, config(), &bytes)) {
            SecureZeroMemory(storage.data(), storage.size() * sizeof(ULONG64));
            throw std::runtime_error("Cannot read official WireGuardNT configuration");
        }
    }
    ~Snapshot() { SecureZeroMemory(storage.data(), storage.size() * sizeof(ULONG64)); }
    Snapshot(const Snapshot&) = delete;
    Snapshot& operator=(const Snapshot&) = delete;
    WIREGUARD_INTERFACE* config() { return reinterpret_cast<WIREGUARD_INTERFACE*>(storage.data()); }
    const WIREGUARD_PEER* peer() {
        require(config()->PeersCount == 1, "Existing peer must remain present");
        require(storage.size() * sizeof(ULONG64) >= sizeof(WIREGUARD_INTERFACE) + sizeof(WIREGUARD_PEER) +
                sizeof(WIREGUARD_ALLOWED_IP), "Expected peer and AllowedIP buffer");
        return reinterpret_cast<const WIREGUARD_PEER*>(config() + 1);
    }
};

// Evidence for the integration log: every interface row Windows still reports under the tunnel's alias.
void logAdapterRows(const std::string& name, const char* when) {
    PMIB_IF_TABLE2 table = nullptr;
    require(GetIfTable2(&table) == NO_ERROR, "Cannot enumerate network interfaces");
    const auto alias = Widen(name);
    int rows = 0;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto& row = table->Table[i];
        if (alias != row.Alias) continue;
        ++rows;
        std::cout << "adapter row " << when << ": OperStatus=" << row.OperStatus << " MediaConnectState=" << row.MediaConnectState
                  << " HardwareInterface=" << static_cast<int>(row.InterfaceAndOperStatusFlags.HardwareInterface)
                  << " ConnectorPresent=" << static_cast<int>(row.InterfaceAndOperStatusFlags.ConnectorPresent)
                  << " NotMediaConnected=" << static_cast<int>(row.InterfaceAndOperStatusFlags.NotMediaConnected) << "\n";
    }
    FreeMibTable(table);
    std::cout << "adapter rows " << when << ": " << rows << "\n";
}

class Tunnel {
public:
    const std::string name = "TELIPHONES-NT-" + std::to_string(GetCurrentProcessId());
    Tunnel() { require(QueryTunnel(name) == TunnelState::Absent, "Fixture must never replace an existing tunnel"); }
    ~Tunnel() {
        try { RemoveTunnel(name); }
        catch (const std::exception& error) { std::cerr << "FAIL: fixture cleanup: " << error.what() << "\n"; }
    }
    void remove() {
        RemoveTunnel(name);
        require(QueryTunnel(name) == TunnelState::Absent, "Cleanup must remove the actual service");
        logAdapterRows(name, "after disconnect");
        require(TunnelAdapterPresence(name) == tunnel_lifecycle::AdapterPresence::Absent,
                "A successful disconnect must release the tunnel's network adapter");
        require(GetFileAttributesW(configPath().c_str()) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND,
                "Cleanup must delete the bootstrap disk config");
    }
    std::wstring configPath() const {
        return KnownFolder(FOLDERID_ProgramFiles) + L"\\TELIPHONES\\Tunnels\\" + Widen(name) + L".conf";
    }
};

class Adapter {
public:
    const nt::Api& api;
    WIREGUARD_ADAPTER_HANDLE handle;
    Adapter(const nt::Api& owner, const std::wstring& name) : api(owner), handle(api.openAdapter(name.c_str())) {
        require(handle != nullptr, "Cannot open actual service-owned adapter");
    }
    ~Adapter() { api.closeAdapter(handle); }
};

class HiddenDependency {
public:
    std::wstring path, hidden;
    bool restored = false;
    HiddenDependency() {
        wchar_t self[32768]{};
        const auto length = GetModuleFileNameW(nullptr, self, static_cast<DWORD>(std::size(self)));
        require(length && length < std::size(self), "Cannot locate test dependency");
        const auto executable = std::wstring(self, length);
        path = executable.substr(0, executable.find_last_of(L"\\/")) + L"\\wireguard.dll";
        hidden = path + L".test-hidden";
        require(MoveFileW(path.c_str(), hidden.c_str()) != FALSE, "Cannot isolate missing-dependency negative control");
    }
    ~HiddenDependency() {
        if (!restored && !MoveFileW(hidden.c_str(), path.c_str())) std::cerr << "FAIL: cannot restore isolated test DLL\n";
    }
    void restore() {
        require(MoveFileW(hidden.c_str(), path.c_str()) != FALSE, "Cannot restore isolated test DLL");
        restored = true;
    }
};

void integrationTests() {
    const auto installation = FindWireGuard();
    require(installation.installed && installation.trusted, "Real integration requires trusted official WireGuard for Windows");
    Tunnel tunnel;
    require(QueryTunnel(tunnel.name) == TunnelState::Absent, "Fixture must never replace an existing tunnel");
    TunnelConfig config;
    config.privateKey = GeneratePrivateKey(installation);
    config.peerPublicKey = DerivePublicKey(installation, GeneratePrivateKey(installation));
    config.address = "192.0.2.1/32";
    config.allowedIps = {"192.0.2.2/32"};
    config.endpoint = "127.0.0.1:9"; // No remote peer or external network is involved.
    config.persistentKeepalive = 25;
    require(InstallTunnel(tunnel.name, RenderTunnel(config)), "Production helper connection was cancelled");
    require(QueryTunnel(tunnel.name) == TunnelState::Running, "Real service must stay Running after key activation");
    const auto stored = ParseTunnelStrict(ReadSmallFile(tunnel.configPath(), 8192));
    require(IsBootstrapTunnel(stored) && stored.privateKey != config.privateKey,
            "Production disk config must contain only bootstrap identity");
    {
        nt::Api api(nt::PrepareLibrary());
        HANDLE writer = CreateFileW(nt::PrepareLibrary().c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr, OPEN_EXISTING, 0, nullptr);
        const DWORD writeError = writer == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
        require(writer == INVALID_HANDLE_VALUE && writeError == ERROR_SHARING_VIOLATION,
                "Loaded reviewed dependency must remain locked against writes");
        Adapter adapter(api, Widen(tunnel.name));
        Snapshot before(api, adapter.handle);
        nt::PrivateKeyUpdate expected;
        expected.decode(config.privateKey);
        require(std::memcmp(before.config()->PrivateKey, expected.value.PrivateKey, WIREGUARD_KEY_LENGTH) == 0,
                "Production helper must apply enrolled key to real driver, not just start bootstrap service");
        require(before.peer()->LastHandshake == 0, "Startup acceptance must not depend on a handshake");
        const auto replacement = GeneratePrivateKey(installation);
        api.activateKey(Widen(tunnel.name), replacement);
        Snapshot after(api, adapter.handle);
        expected.decode(replacement);
        require(std::memcmp(after.config()->PrivateKey, expected.value.PrivateKey, WIREGUARD_KEY_LENGTH) == 0,
                "Native key update must reach actual driver");
        const auto* oldPeer = before.peer();
        const auto* newPeer = after.peer();
        require(after.config()->ListenPort == before.config()->ListenPort &&
                std::memcmp(oldPeer->PublicKey, newPeer->PublicKey, WIREGUARD_KEY_LENGTH) == 0 &&
                std::memcmp(oldPeer->PresharedKey, newPeer->PresharedKey, WIREGUARD_KEY_LENGTH) == 0 &&
                oldPeer->PersistentKeepalive == newPeer->PersistentKeepalive &&
                std::memcmp(&oldPeer->Endpoint, &newPeer->Endpoint, sizeof(oldPeer->Endpoint)) == 0 &&
                oldPeer->AllowedIPsCount == 1 && newPeer->AllowedIPsCount == 1 &&
                std::memcmp(oldPeer + 1, newPeer + 1, sizeof(WIREGUARD_ALLOWED_IP)) == 0,
                "Private-only update must preserve peer, endpoint, PSK, keepalive, routes and listen port");
        DWORD bytes = sizeof(WIREGUARD_INTERFACE) - 1;
        require(!api.setConfiguration(adapter.handle, &expected.value, bytes), "Real driver must reject truncated ABI buffer");
        try {
            api.activateKey(Widen(tunnel.name) + L"-absent", replacement);
            throw std::runtime_error("Missing adapter unexpectedly opened");
        } catch (const nt::Failure& error) { require(error.stage == nt::Stage::Adapter, "Missing adapter must report correct stage"); }
        const std::wstring pipe = L"\\\\.\\pipe\\ProtectedPrefix\\Administrators\\WireGuard\\" + Widen(tunnel.name);
        require(!WaitNamedPipeW(pipe.c_str(), 0) && GetLastError() == ERROR_FILE_NOT_FOUND,
                "Real official tunnel must work without the obsolete text-UAPI pipe");
        require(QueryTunnel(tunnel.name) == TunnelState::Running, "Key update/handle close must not remove service-owned adapter");
    }
    const auto deadline = GetTickCount64() + 2000;
    do {
        require(QueryTunnel(tunnel.name) == TunnelState::Running,
                "Service must remain running beyond the reported 287ms regression after API/adapter close");
        Sleep(50);
    } while (GetTickCount64() < deadline);
    tunnel.remove();
    // Reported 0.8.4 regression: reconnecting the same pairing immediately after a normal disconnect was refused
    // because the released adapter still had an interface row with the tunnel's name.
    require(InstallTunnel(tunnel.name, RenderTunnel(config)), "Immediate reconnection was cancelled");
    require(QueryTunnel(tunnel.name) == TunnelState::Running, "Immediate reconnection must start the real service");
    require(TunnelAdapterPresence(tunnel.name) == tunnel_lifecycle::AdapterPresence::Active,
            "A running tunnel's adapter must be reported as active");
    logAdapterRows(tunnel.name, "while reconnected");
    {
        nt::Api api(nt::PrepareLibrary());
        Adapter adapter(api, Widen(tunnel.name));
        Snapshot reconnected(api, adapter.handle);
        nt::PrivateKeyUpdate expected;
        expected.decode(config.privateKey);
        require(std::memcmp(reconnected.config()->PrivateKey, expected.value.PrivateKey, WIREGUARD_KEY_LENGTH) == 0,
                "Reconnection must apply the enrolled key to the new adapter");
    }
    tunnel.remove();
    for (int cycle = 0; cycle < 2; ++cycle) {
        require(InstallTunnel(tunnel.name, RenderTunnel(config)), "Repeated reconnection was cancelled");
        require(QueryTunnel(tunnel.name) == TunnelState::Running, "Repeated reconnection must start the service");
        require(TunnelAdapterPresence(tunnel.name) == tunnel_lifecycle::AdapterPresence::Active,
                "Repeated reconnection must have a present adapter");
        tunnel.remove();
    }
    {
        HiddenDependency negativeControl;
        bool rejected = false;
        try { InstallTunnel(tunnel.name, RenderTunnel(config)); }
        catch (const Error& error) { rejected = std::string(error.what()).find("pinned WireGuardNT API DLL") != std::string::npos; }
        require(rejected, "Missing dependency must report explicit activation-stage failure");
        tunnel.remove();
        negativeControl.restore();
    }
    SecureWipe(config.privateKey);
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
    std::vector<std::string> arguments;
    for (int i = 1; i < argc; ++i) arguments.push_back(Narrow(argv[i]));
    if (IsHelperInvocation(arguments)) return RunTunnelHelper(arguments);
    try {
        require(arguments.size() == 1, "Specify --unit or --integration");
        if (arguments[0] == "--unit") unitTests();
        else if (arguments[0] == "--integration") integrationTests();
        else throw std::runtime_error("Unknown test mode");
        std::cout << "WireGuardNT " << arguments[0] << ": PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "WireGuardNT: FAIL: " << error.what() << "\n";
        return 1;
    }
}
