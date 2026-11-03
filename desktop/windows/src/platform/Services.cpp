#include "Services.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Win.h"

#include <wincred.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <chrono>
#include <memory>
#include <sstream>

#include "../core/ConnectionHealth.h"
#include "../core/Json.h"
#include "../core/SessionDiagnostics.h"
#include "../core/Validation.h"

namespace tlp {
namespace win {
namespace {

std::wstring profileFile() { return EnsureDirectory(KnownFolder(FOLDERID_RoamingAppData) + L"\\TELIPHONES") + L"\\profiles.json"; }
std::wstring healthPreferencesFile() { return EnsureDirectory(KnownFolder(FOLDERID_LocalAppData) + L"\\TELIPHONES") + L"\\connection-health.json"; }

std::wstring sshSecretFile(const Profile& profile) {
    if (!IsProfileId(profile.id)) throw Error("Invalid SSH profile identity.");
    const std::wstring sddl = L"D:P(A;;FA;;;SY)(A;;FA;;;" + Widen(CurrentUserSid()) + L")";
    return EnsureDirectory(KnownFolder(FOLDERID_LocalAppData) + L"\\TELIPHONES\\SSH", sddl.c_str()) +
           L"\\" + Widen(profile.id) + L".dpapi";
}

SessionDiagnostics& sessionDiagnostics() {
    static SessionDiagnostics diagnostics(std::filesystem::path(
        EnsureDirectory(KnownFolder(FOLDERID_LocalAppData) + L"\\TELIPHONES") + L"\\Diagnostics"));
    return diagnostics;
}

std::string probeError(const char* stage, int code) {
    return SanitizeDiagnosticDetail(std::string(stage) + ": WSA error " + std::to_string(code) +
                                    " (" + Narrow(ErrorText(static_cast<DWORD>(code))) + ").");
}

ProcessResult readWgStage(const std::wstring& executable, const std::string& tunnel, const char* stage) {
    const std::string permission = " Reading WireGuard telemetry requires WireGuard admin interface permission; "
                                   "TELIPHONES does not elevate or change interface permissions.";
    ProcessResult result;
    try {
        result = RunProcess(executable, {"show", tunnel, stage}, "", 1000, true);
    } catch (const std::exception& error) {
        throw Error(std::string("WireGuard telemetry stage ") + stage + " could not complete (exit code unavailable): " +
                    SanitizeDiagnosticDetail(error.what()) + permission);
    }
    if (result.exitCode != 0) {
        throw Error(std::string("WireGuard telemetry stage ") + stage + " failed with exit code " +
                    std::to_string(result.exitCode) + ": " +
                    (result.output.empty() ? "no helper error output" : SanitizeDiagnosticDetail(result.output)) + permission);
    }
    return result;
}

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

void DeleteSshPrivateKey(const Profile& profile) {
    if (!DeleteFileW(sshSecretFile(profile).c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND)
        ThrowLastError("Unable to remove the protected SSH private key");
}

std::vector<Profile> LoadProfiles() {
    std::wstring path = profileFile();
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) return {};
    return ParseProfiles(ReadSmallFile(path, 4 * 1024 * 1024));
}

void SaveProfiles(const std::vector<Profile>& profiles) { ReplaceUserFile(profileFile(), SerializeProfiles(profiles)); }

std::string NewProfileId() { return HexEncode(RandomBytes(8)); }

void WriteSessionEvent(const std::string& sessionId, const std::string& attemptId, const std::string& event,
                       const std::string& severity, const std::string& detail) {
    sessionDiagnostics().Write(sessionId, attemptId, event, severity, detail);
}

std::string ReadSessionEvents(const std::string& sessionId) { return sessionDiagnostics().Read(sessionId); }

TcpProbeMeasurement MeasureTcpProbe(const std::string& ipv4, unsigned short port, unsigned timeoutMs) {
    TcpProbeMeasurement measurement;
    std::uint32_t parsed = 0;
    if (!ParseIPv4(ipv4, parsed)) {
        measurement.error = "TCP probe target is not a valid IPv4 address.";
        return measurement;
    }
    WSADATA wsa{};
    const int startupError = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (startupError != 0) {
        measurement.error = probeError("WSAStartup", startupError);
        return measurement;
    }
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        measurement.error = probeError("socket", WSAGetLastError());
        WSACleanup();
        return measurement;
    }
    u_long nonBlocking = 1;
    if (ioctlsocket(s, FIONBIO, &nonBlocking) != 0) {
        measurement.error = probeError("ioctlsocket", WSAGetLastError());
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
    } else {
        const int connectError = WSAGetLastError();
        if (connectError != WSAEWOULDBLOCK) {
            measurement.known = true;
            measurement.error = probeError("connect", connectError);
        } else {
            fd_set writable, failed;
            FD_ZERO(&writable);
            FD_ZERO(&failed);
            FD_SET(s, &writable);
            FD_SET(s, &failed);
            timeval timeout{static_cast<long>(timeoutMs / 1000), static_cast<long>((timeoutMs % 1000) * 1000)};
            int selected = select(0, nullptr, &writable, &failed, &timeout);
            measurement.known = selected >= 0;
            if (selected > 0) {
                int error = 0;
                int length = sizeof(error);
                measurement.known = getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) == 0;
                measurement.succeeded = measurement.known && error == 0 && FD_ISSET(s, &writable);
                if (!measurement.known) measurement.error = probeError("getsockopt", WSAGetLastError());
                else if (error != 0) measurement.error = probeError("connect", error);
                else if (!measurement.succeeded) measurement.error = probeError("connect exception", WSAECONNABORTED);
            } else if (selected == 0) {
                measurement.error = probeError("connect timeout", WSAETIMEDOUT);
            } else {
                measurement.error = probeError("select", WSAGetLastError());
            }
        }
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
    if (!IsWireGuardKey(peerPublicKey)) throw Error("The active WireGuard peer key is invalid.");
    ProcessResult transfer = readWgStage(wgExecutable, tunnelName, "transfer");
    ProcessResult handshakes = readWgStage(wgExecutable, tunnelName, "latest-handshakes");
    WireGuardCounters counters;
    try {
        counters = ParseWireGuardCounters(transfer.output, handshakes.output, peerPublicKey);
    } catch (const Error& error) {
        throw Error("WireGuard telemetry stages transfer/latest-handshakes returned exit code 0 but parsing failed: " +
                    SanitizeDiagnosticDetail(error.what()));
    }
    if (!counters.receivedBytes || !counters.transmittedBytes) {
        throw Error("WireGuard telemetry stage transfer returned exit code 0 but no counters for the active peer.");
    }
    if (!counters.handshakeUnixSeconds) {
        throw Error("WireGuard telemetry stage latest-handshakes returned exit code 0 but no handshake row for the active peer.");
    }
    return counters;
}

WireGuardCounters ReadTunnelInterfaceCounters(const std::string& tunnelName) {
    if (tunnelName.empty() || !IsTunnelName(tunnelName)) throw Error("The active TELIPHONES tunnel name is invalid.");
    PMIB_IF_TABLE2 table = nullptr;
    const auto status = GetIfTable2(&table);
    if (status != NO_ERROR) {
        throw Error("Windows tunnel interface counters: Windows error " + std::to_string(status) +
                    " (" + SanitizeDiagnosticDetail(Narrow(ErrorText(status))) + ").");
    }
    const std::unique_ptr<MIB_IF_TABLE2, decltype(&FreeMibTable)> owned(table, &FreeMibTable);
    const auto alias = Widen(tunnelName);
    const MIB_IF_ROW2* match = nullptr;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        if (alias != table->Table[i].Alias) continue;
        if (match) throw Error("Windows tunnel interface counters: more than one interface has the exact active tunnel alias.");
        match = &table->Table[i];
    }
    if (!match) throw Error("Windows tunnel interface counters: no interface has the exact active tunnel alias.");
    // WireGuardNT is an IF_TYPE_PROP_VIRTUAL adapter on supported WireGuard releases,
    // not necessarily IF_TYPE_TUNNEL. An exact, unique tunnel alias is required instead.
    WireGuardCounters counters;
    counters.receivedBytes = match->InOctets;
    counters.transmittedBytes = match->OutOctets;
    return counters;
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
