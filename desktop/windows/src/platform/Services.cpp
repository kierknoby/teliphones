#include "Services.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Win.h"

#include <wincred.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <chrono>
#include <memory>
#include <sstream>

#include "../core/ConnectionHealth.h"
#include "../core/ConnectProtection.h"
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

namespace {
void writeKeyCredential(const std::string& target, const std::string& stored) {
    std::wstring name = Widen(target);
    std::string blob = stored;
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

std::string readKeyCredential(const std::string& target) {
    PCREDENTIALW credential = nullptr;
    if (!CredReadW(Widen(target).c_str(), CRED_TYPE_GENERIC, 0, &credential)) {
        if (GetLastError() == ERROR_NOT_FOUND) return std::string();
        ThrowLastError("Unable to read the WireGuard key from Windows Credential Manager");
    }
    const auto release = [](CREDENTIALW* value) {
        SecureZeroMemory(value->CredentialBlob, value->CredentialBlobSize);
        CredFree(value);
    };
    std::unique_ptr<CREDENTIALW, decltype(release)> owned(credential, release);
    return std::string(reinterpret_cast<const char*>(credential->CredentialBlob), credential->CredentialBlobSize);
}
}  // namespace

void SavePrivateKey(const std::string& target, const std::string& privateKey) {
    if (!IsWireGuardKey(privateKey)) throw Error("Refusing to store an invalid WireGuard key.");
    std::string previous = readKeyCredential(target);
    const bool exists = !previous.empty();
    SecureWipe(previous);
    if (exists) throw Error("A key already exists for this profile. It cannot be overwritten by pairing.");
    writeKeyCredential(target, privateKey);
}

bool PrivateKeyNeedsPassword(const std::string& target) {
    std::string stored = readKeyCredential(target);
    const bool protectedKey = !stored.empty() && IsProtectedConnectKey(stored);
    SecureWipe(stored);
    return protectedKey;
}

std::string LoadPrivateKey(const std::string& target, const std::string& password) {
    std::string stored = readKeyCredential(target);
    if (stored.empty()) return {};
    try {
        std::string result = OpenConnectKey(target, stored, password);
        SecureWipe(stored);
        return result;
    } catch (...) {
        SecureWipe(stored);
        throw;
    }
}

void SetConnectPassword(const std::string& target, const std::string& oldPassword, const std::string& newPassword) {
    std::string key = LoadPrivateKey(target, oldPassword);
    std::string stored;
    try {
        if (key.empty()) throw Error("The saved WireGuard key is missing. Pair this connection again.");
        stored = newPassword.empty() ? key : ProtectConnectKey(target, key, newPassword);
        writeKeyCredential(target, stored);
    } catch (...) {
        SecureWipe(key);
        SecureWipe(stored);
        throw;
    }
    SecureWipe(key);
    SecureWipe(stored);
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

WorkstationSessionStatus MaintainWorkstationSession(const std::string& pbxAddress, bool release,
                                                    const PairResponse* pairing, const std::string& action,
                                                    const std::string& sshPublicKey,
                                                    const std::string& allowedSources) {
    std::uint32_t parsed = 0;
    if (!ParseIPv4(pbxAddress, parsed)) throw Error("The PBX session-control address is invalid.");
    struct HttpHandle {
        HINTERNET value = nullptr;
        explicit HttpHandle(HINTERNET handle) : value(handle) {
            if (!value) ThrowLastError("Unable to open the PBX workstation session-control connection");
        }
        ~HttpHandle() { if (value) WinHttpCloseHandle(value); }
        HttpHandle(const HttpHandle&) = delete;
        HttpHandle& operator=(const HttpHandle&) = delete;
    };
    HttpHandle session(WinHttpOpen(L"TELIPHONES workstation lease", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!WinHttpSetTimeouts(session.value, 3000, 3000, 5000, 5000))
        ThrowLastError("Unable to bound workstation lease HTTP timeouts");
    HttpHandle connection(WinHttpConnect(session.value, Widen(pbxAddress).c_str(), 8766, 0));
    HttpHandle request(WinHttpOpenRequest(connection.value, L"POST", L"/workstation/session", nullptr,
                                          WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0));
    DWORD disable = WINHTTP_DISABLE_REDIRECTS;
    if (!WinHttpSetOption(request.value, WINHTTP_OPTION_DISABLE_FEATURE, &disable, sizeof(disable)))
        ThrowLastError("Unable to disable workstation lease redirects");
    json::Value::Object requestBody{{"action", release ? "release" : action.empty() ? "heartbeat" : action}};
    if (!sshPublicKey.empty()) requestBody["ssh_public_key"] = sshPublicKey;
    if (!allowedSources.empty()) requestBody["sources"] = allowedSources;
    const std::string body = json::Serialize(json::Value(requestBody));
    if (!WinHttpSendRequest(request.value, L"Content-Type: application/json\r\n", static_cast<DWORD>(-1L),
                            const_cast<char*>(body.data()), static_cast<DWORD>(body.size()),
                            static_cast<DWORD>(body.size()), 0) ||
        !WinHttpReceiveResponse(request.value, nullptr))
        ThrowLastError("The PBX workstation session controller did not respond through WireGuard");
    DWORD status = 0, size = sizeof(status);
    if (!WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX))
        ThrowLastError("Unable to read the PBX workstation session response status");
    std::string response;
    for (;;) {
        char buffer[1024];
        DWORD count = 0;
        if (!WinHttpReadData(request.value, buffer, sizeof(buffer), &count))
            ThrowLastError("Unable to read the PBX workstation session response");
        if (!count) break;
        if (response.size() + count > 16384) throw Error("The PBX workstation session response is oversized.");
        response.append(buffer, count);
    }
    const json::Value value = json::Parse(response, 16384);
    if (status != 200 || !value.at("ok").asBool()) {
        const std::string error = value.has("error") ? value.at("error").asString()
                                                     : "The PBX refused the workstation session.";
        throw Error(error);
    }
    if (action == "ssh-request" && !release) {
        const std::string state = value.at("ssh_request_status").asString();
        if (state != "pending" && state != "applied")
            throw Error("The PBX returned an invalid SSH request state.");
        WorkstationSessionStatus result;
        result.sshRequestStatus = state;
        return result;
    }
    if (action == "lock-current" && !release) {
        if (value.at("workstation_change_status").asString() != "applied")
            throw Error("The PBX did not confirm the workstation restriction change.");
        WorkstationSessionStatus result;
        result.policyLocked = true;
        result.policySummary = value.at("migration_pending").asBool()
            ? "Lock to Current IP applied; secure tunnel migration is pending."
            : "Lock to Current IP applied.";
        return result;
    }
    if (action == "unlock-request" && !release) {
        const std::string state = value.at("unlock_request_status").asString();
        if (state != "pending" && state != "applied")
            throw Error("The PBX returned an invalid workstation unlock request state.");
        WorkstationSessionStatus result;
        result.unlockRequestPending = state == "pending";
        result.policySummary = state == "pending"
            ? "Unlock request: Pending Approval by a FreePBX administrator."
            : "Workstation is already unlocked.";
        return result;
    }
    if (action == "sources-request" && !release) {
        if (value.at("sources_request_status").asString() != "pending")
            throw Error("The PBX did not confirm the Allowed List request.");
        WorkstationSessionStatus result;
        result.sourcesRequestPending = true;
        result.policySummary = "Allowed List change: Pending Approval by a FreePBX administrator.";
        return result;
    }
    const auto connected = value.at("connected_workstations").asInteger();
    const auto maximum = value.at("max_sessions").asInteger();
    if (connected < 0 || connected > 128 || maximum < 1 || maximum > 128)
        throw Error("The PBX returned invalid workstation session capacity.");
    WorkstationSessionStatus result;
    result.connectedWorkstations = static_cast<int>(connected);
    result.maximumWorkstations = static_cast<int>(maximum);
    if (!release && value.has("migration")) {
        if (pairing == nullptr || !value.at("migration").isObject())
            throw Error("The PBX offered a configuration migration that cannot be bound to this saved workstation.");
        const auto& migration = value.at("migration");
        result.migration = ApplyWorkstationMigration(*pairing, json::Serialize(migration));
        result.policySummary = "PBX configuration migration pending; management access remains blocked until the new tunnel is acknowledged.";
        return result;
    }
    if (!release) {
        if (!value.at("active").asBool() ||
            (result.expiresAt = value.at("expires_at").asInteger()) <= UnixNow())
            throw Error("The PBX did not grant a valid workstation session lease.");
        if (!value.has("policy") || !value.at("policy").isObject())
            throw Error("The PBX did not return the effective workstation policy.");
        const auto& policy = value.at("policy");
        const auto& connectionState = policy.at("connection_state").asString();
        if (connectionState != "open" && connectionState != "closed" && connectionState != "frozen")
            throw Error("The PBX returned an invalid workstation connection policy.");
        const bool locked = policy.at("locked").asBool();
        result.policyLocked = locked;
        result.unlockRequestPending = policy.at("unlock_request_pending").asBool();
        result.sourcesRequestPending = policy.at("sources_request_pending").asBool();
        const auto& sources = policy.at("sources").asArray();
        const auto effectiveCount = policy.at("effective_source_count").asInteger();
        const auto& failures = policy.at("source_resolution_failures").asArray();
        if (effectiveCount < 0 || effectiveCount > 1000000)
            throw Error("The PBX returned an invalid effective source count.");
        result.policySummary = "Applied PBX policy: " + connectionState + ". " +
            (locked ? "Locked. Allowed entries: " : "Unlocked (shared listener).");
        for (std::size_t i = 0; i < sources.size(); ++i) {
            if (!sources[i].isString()) throw Error("The PBX returned an invalid allowed-source policy.");
            if (i) result.allowedSources += ", ";
            result.allowedSources += sources[i].asString();
        }
        if (locked) {
            if (sources.empty()) throw Error("The PBX returned a locked policy without any allowed entries.");
            for (std::size_t i = 0; i < sources.size(); ++i) {
                if (!sources[i].isString()) throw Error("The PBX returned an invalid allowed-source policy.");
                if (i) result.policySummary += ", ";
                result.policySummary += sources[i].asString();
            }
            result.policySummary += ". Resolved sources: " + std::to_string(effectiveCount) + ".";
            if (!failures.empty()) {
                result.policySummary += " DNS/source resolution unavailable for " + std::to_string(failures.size()) +
                    " entr" + (failures.size() == 1 ? "y" : "ies") + "; access remains restricted.";
            }
        }
        result.policySummary += policy.at("ssh_approved").asBool()
            ? " SSH access: approved." : " SSH access: not approved.";
        if (result.unlockRequestPending)
            result.policySummary += " Unlock request: Pending Approval.";
        if (result.sourcesRequestPending) {
            result.policySummary += " Allowed List change: Pending Approval";
            if (policy.has("requested_sources")) {
                const auto& requested = policy.at("requested_sources").asArray();
                if (!requested.empty()) {
                    result.policySummary += " (";
                    for (std::size_t i = 0; i < requested.size(); ++i) {
                        if (!requested[i].isString())
                            throw Error("The PBX returned an invalid requested Allowed List.");
                        if (i) result.policySummary += ", ";
                        result.policySummary += requested[i].asString();
                    }
                    result.policySummary += ")";
                }
            }
            result.policySummary += ".";
        }
        if (policy.has("current_source") && !policy.at("current_source").isNull()) {
            if (!policy.at("current_source").isString())
                throw Error("The PBX returned an invalid verified public source.");
            const auto& currentSource = policy.at("current_source").asString();
            if (currentSource.empty() || currentSource.size() > 64 ||
                currentSource.find_first_not_of("0123456789abcdefABCDEF:./") != std::string::npos)
                throw Error("The PBX returned an invalid verified public source.");
            result.policySummary += " Verified public source: " + currentSource + ".";
        } else {
            result.policySummary += " Verified public source: unavailable.";
        }
        result.sshRevoked = pairing != nullptr && pairing->sshPort != 0 && !policy.at("ssh_approved").asBool();
        result.sshRequestRejected = pairing != nullptr && pairing->sshPort == 0 &&
            !pairing->sshRequestPublicKey.empty() && !policy.at("ssh_approved").asBool() &&
            !policy.at("ssh_request_pending").asBool();
        if (pairing != nullptr && pairing->sshPort == 0 &&
            pairing->sshRequestPublicKey.size() > 0 && policy.at("ssh_approved").asBool() &&
            policy.has("ssh_configuration")) {
            const auto& configuration = policy.at("ssh_configuration");
            json::RequireExactKeys(configuration, {"ssh_user", "ssh_public_key", "ssh_host_key", "ssh_ca_key",
                                                    "ssh_port", "ssh_api_port"},
                                   "The PBX managed SSH approval");
            if (configuration.at("ssh_public_key").asString() != pairing->sshRequestPublicKey)
                throw Error("The PBX SSH approval does not match the pending workstation key.");
            PairResponse updated = *pairing;
            updated.ssh = true;
            updated.sshPublicKey = configuration.at("ssh_public_key").asString();
            updated.sshUser = configuration.at("ssh_user").asString();
            updated.sshHostKey = configuration.at("ssh_host_key").asString();
            updated.sshCaKey = configuration.at("ssh_ca_key").asString();
            updated.sshPort = static_cast<int>(configuration.at("ssh_port").asInteger());
            updated.sshApiPort = static_cast<int>(configuration.at("ssh_api_port").asInteger());
            updated.sshRequestPublicKey.clear();
            ValidateManagedPairing(updated);
            result.pairingUpdate = std::move(updated);
        }
    }
    return result;
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
