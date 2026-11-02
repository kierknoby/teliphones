#include "Services.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Win.h"

#include <wincred.h>

#include "../core/Json.h"
#include "../core/Validation.h"

namespace tlp {
namespace win {
namespace {

std::wstring profileFile() { return EnsureDirectory(KnownFolder(FOLDERID_RoamingAppData) + L"\\TELIPHONES") + L"\\profiles.json"; }

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

bool ProbeTcp(const std::string& ipv4, unsigned short port, unsigned timeoutMs) {
    std::uint32_t parsed = 0;
    if (!ParseIPv4(ipv4, parsed)) return false;
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
    bool connected = false;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s != INVALID_SOCKET) {
        u_long nonBlocking = 1;
        ioctlsocket(s, FIONBIO, &nonBlocking);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = htonl(parsed);
        int result = connect(s, reinterpret_cast<sockaddr*>(&address), sizeof(address));
        if (result == 0) {
            connected = true;
        } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set writable, failed;
            FD_ZERO(&writable);
            FD_ZERO(&failed);
            FD_SET(s, &writable);
            FD_SET(s, &failed);
            timeval timeout{static_cast<long>(timeoutMs / 1000), static_cast<long>((timeoutMs % 1000) * 1000)};
            if (select(0, nullptr, &writable, &failed, &timeout) > 0 && FD_ISSET(s, &writable)) {
                int error = 0;
                int length = sizeof(error);
                connected = getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) == 0 && error == 0;
            }
        }
        closesocket(s);
    }
    WSACleanup();
    return connected;
}

}  // namespace win
}  // namespace tlp
