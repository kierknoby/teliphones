#include "Services.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Win.h"

#include <wincred.h>

#include <chrono>
#include <sstream>

#include "../core/ConnectionHealth.h"
#include "../core/Json.h"
#include "../core/Validation.h"

namespace tlp {
namespace win {
namespace {

std::wstring profileFile() { return EnsureDirectory(KnownFolder(FOLDERID_RoamingAppData) + L"\\TELIPHONES") + L"\\profiles.json"; }
std::wstring healthPreferencesFile() { return EnsureDirectory(KnownFolder(FOLDERID_LocalAppData) + L"\\TELIPHONES") + L"\\connection-health.json"; }

}  // namespace

void SavePrivateKey(const std::string& target, const std::string& privateKey) {
    if (!IsWireGuardKey(privateKey)) throw Error("Refusing to store an invalid WireGuard key.");
    std::wstring name = Widen(target);
    std::string blob = privateKey;
    CREDENTIALW credential{};
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = &name[0];
    credential.Comment = const_cast<LPWSTR>(L"TELIPHONES WireGuard workstation key");
    credential.CredentialBlobSize = static_cast<DWORD>(blob.size());
    credential.CredentialBlob = reinterpret_cast<LPBYTE>(&blob[0]);
    // Local machine persistence: the key is never roamed to other computers with the user's profile.
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    credential.UserName = const_cast<LPWSTR>(L"TELIPHONES");
    BOOL ok = CredWriteW(&credential, 0);
    DWORD error = GetLastError();
    SecureWipe(blob);
    if (!ok) ThrowLastError("Unable to store the WireGuard key in Windows Credential Manager", error);
}

std::string LoadPrivateKey(const std::string& target) {
    PCREDENTIALW credential = nullptr;
    if (!CredReadW(Widen(target).c_str(), CRED_TYPE_GENERIC, 0, &credential)) {
        if (GetLastError() == ERROR_NOT_FOUND) return std::string();
        ThrowLastError("Unable to read the WireGuard key from Windows Credential Manager");
    }
    std::string key(reinterpret_cast<const char*>(credential->CredentialBlob), credential->CredentialBlobSize);
    SecureZeroMemory(credential->CredentialBlob, credential->CredentialBlobSize);
    CredFree(credential);
    if (!IsWireGuardKey(key)) {
        SecureWipe(key);
        throw Error("The stored WireGuard key is damaged. Remove this PBX and pair the workstation again.");
    }
    return key;
}

void DeletePrivateKey(const std::string& target) {
    if (!CredDeleteW(Widen(target).c_str(), CRED_TYPE_GENERIC, 0) && GetLastError() != ERROR_NOT_FOUND) {
        ThrowLastError("Unable to remove the WireGuard key from Windows Credential Manager");
    }
}

std::vector<Profile> LoadProfiles() {
    std::wstring path = profileFile();
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) return {};
    return ParseProfiles(ReadSmallFile(path, 4 * 1024 * 1024));
}

void SaveProfiles(const std::vector<Profile>& profiles) { ReplaceUserFile(profileFile(), SerializeProfiles(profiles)); }

std::string NewProfileId() { return HexEncode(RandomBytes(8)); }

TcpProbeMeasurement MeasureTcpProbe(const std::string& ipv4, unsigned short port, unsigned timeoutMs) {
    TcpProbeMeasurement measurement;
    std::uint32_t parsed = 0;
    if (!ParseIPv4(ipv4, parsed)) return measurement;
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return measurement;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        WSACleanup();
        return measurement;
    }
    u_long nonBlocking = 1;
    if (ioctlsocket(s, FIONBIO, &nonBlocking) != 0) {
        closesocket(s);
        WSACleanup();
        return measurement;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(parsed);
    const auto started = std::chrono::steady_clock::now();
    int result = connect(s, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    if (result == 0) {
        measurement.known = true;
        measurement.succeeded = true;
    } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set writable, failed;
        FD_ZERO(&writable);
        FD_ZERO(&failed);
        FD_SET(s, &writable);
        FD_SET(s, &failed);
        timeval timeout{static_cast<long>(timeoutMs / 1000), static_cast<long>((timeoutMs % 1000) * 1000)};
        int selected = select(0, nullptr, &writable, &failed, &timeout);
        measurement.known = selected >= 0;
        if (selected > 0 && FD_ISSET(s, &writable)) {
            int error = 0;
            int length = sizeof(error);
            measurement.known = getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) == 0;
            measurement.succeeded = measurement.known && error == 0;
        }
    } else {
        // A refused or unreachable TCP connection is a failed application probe, not measured packet loss.
        measurement.known = true;
    }
    if (measurement.succeeded) {
        measurement.latencyMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
    }
    closesocket(s);
    WSACleanup();
    return measurement;
}

bool ProbeTcp(const std::string& ipv4, unsigned short port, unsigned timeoutMs) {
    TcpProbeMeasurement result = MeasureTcpProbe(ipv4, port, timeoutMs);
    return result.known && result.succeeded;
}

WireGuardCounters ReadWireGuardCounters(const std::wstring& wgExecutable, const std::string& tunnelName, const std::string& peerPublicKey) {
    if (tunnelName.empty() || !IsTunnelName(tunnelName)) throw Error("The active TELIPHONES tunnel name is invalid.");
    ProcessResult transfer = RunProcess(wgExecutable, {"show", tunnelName, "transfer"}, "", 1000);
    ProcessResult handshakes = RunProcess(wgExecutable, {"show", tunnelName, "latest-handshakes"}, "", 1000);
    if (transfer.exitCode != 0 || handshakes.exitCode != 0) throw Error("WireGuard telemetry is not available for this tunnel.");
    return ParseWireGuardCounters(transfer.output, handshakes.output, peerPublicKey);
}

std::optional<HealthPreferences> LoadHealthPreferences() {
    std::wstring path = healthPreferencesFile();
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) return std::nullopt;
    return ParseHealthPreferences(ReadSmallFile(path, 4096));
}

void SaveHealthPreferences(const HealthPreferences& preferences) {
    ReplaceUserFile(healthPreferencesFile(), SerializeHealthPreferences(preferences));
}

}  // namespace win
}  // namespace tlp
