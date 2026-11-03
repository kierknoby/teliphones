#include "Ssh.h"
#include "Win.h"
#include "../core/Validation.h"

#include <filesystem>

namespace tlp::win {
namespace {
bool plainDirectory(const std::wstring& directory) {
    const auto attributes = GetFileAttributesW(directory.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const auto error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return false;
        ThrowLastError("Unable to inspect a legacy SSH runtime directory", error);
    }
    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        throw Error("A legacy SSH runtime directory is not a plain owned directory.");
    return true;
}

void removeFiles(const std::wstring& directory) {
    for (const wchar_t* name : {L"identity", L"identity.pub", L"identity.sig", L"certificate.pub", L"config", L"known_hosts"}) {
        const auto path = directory + L"\\" + name;
        const auto attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            const auto error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND) continue;
            ThrowLastError("Unable to inspect a legacy SSH runtime file", error);
        }
        if (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
            throw Error("A legacy SSH runtime file is not a plain file; cleanup was stopped.");
        if (!DeleteFileW(path.c_str())) ThrowLastError("Unable to remove a legacy SSH runtime file");
    }
}
}

void RemoveSshRuntime(const Profile& profile) {
    if (!IsProfileId(profile.id)) throw Error("Invalid SSH profile.");
    CloseManagedSsh(profile.id);
    auto directory = KnownFolder(FOLDERID_LocalAppData) + L"\\TELIPHONES";
    if (!plainDirectory(directory)) return;
    directory += L"\\SSH";
    if (!plainDirectory(directory)) return;
    directory += L"\\" + Widen(profile.id);
    if (!plainDirectory(directory)) return;
    removeFiles(directory);
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (!IsProfileId(Narrow(entry.path().filename().wstring())))
            throw Error("Unexpected legacy SSH runtime artifact; inspect the protected SSH folder.");
        if (!plainDirectory(entry.path().wstring()))
            throw Error("A legacy SSH runtime attempt disappeared during cleanup.");
        removeFiles(entry.path().wstring());
        if (!RemoveDirectoryW(entry.path().c_str())) ThrowLastError("Unable to remove a legacy SSH runtime attempt directory");
    }
    if (!RemoveDirectoryW(directory.c_str())) ThrowLastError("Unable to remove a legacy SSH runtime directory");
}

void RequireManagedSsh(const Profile& profile) {
    ValidateManagedPairing(profile.pairing);
    if (profile.kind != ProfileKind::Administrator || profile.pairing.sshPort == 0 ||
        profile.sshUser != profile.pairing.sshUser)
        throw Error("This PBX has no explicit managed SSH account approval.");
    if (profile.pairing.expiresAt != 0 && profile.pairing.expiresAt <= UnixNow())
        throw Error("SSH authorisation has expired.");
}
}
