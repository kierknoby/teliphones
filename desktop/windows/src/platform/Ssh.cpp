#include "Ssh.h"
#include "Win.h"
#include "../core/SshRuntime.h"
#include "../core/Validation.h"

#include <filesystem>

namespace tlp::win {
namespace {
[[noreturn]] void residual(const std::wstring& path, const std::string& what, DWORD code) {
    throw SshRuntimeResidual(what + " (" + Narrow(path) + "): " + Narrow(ErrorText(code)) + ".");
}

// Win32 primitives for the shared cleanup: reparse points are reported as Other and never followed.
SshRuntimeFilesystem win32RuntimeFilesystem() {
    SshRuntimeFilesystem fs;
    fs.kind = [](const std::string& path) {
        const auto wide = Widen(path);
        const auto attributes = GetFileAttributesW(wide.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            const auto error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return SshRuntimeFilesystem::Kind::Missing;
            residual(wide, "Unable to inspect SSH runtime state", error);
        }
        if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) return SshRuntimeFilesystem::Kind::Other;
        return (attributes & FILE_ATTRIBUTE_DIRECTORY) ? SshRuntimeFilesystem::Kind::PlainDirectory
                                                       : SshRuntimeFilesystem::Kind::PlainFile;
    };
    fs.list = [](const std::string& directory) {
        std::vector<std::string> names;
        try {
            for (const auto& entry : std::filesystem::directory_iterator(std::filesystem::path(Widen(directory))))
                names.push_back(Narrow(entry.path().filename().wstring()));
        } catch (const std::filesystem::filesystem_error& error) {
            throw SshRuntimeResidual("Unable to list SSH runtime directory (" + directory + "): " + error.what());
        }
        return names;
    };
    fs.removeFile = [](const std::string& path) {
        const auto wide = Widen(path);
        if (!DeleteFileW(wide.c_str())) residual(wide, "Unable to remove an SSH runtime file", GetLastError());
    };
    fs.removeEmptyDirectory = [](const std::string& directory) {
        const auto wide = Widen(directory);
        if (RemoveDirectoryW(wide.c_str())) return true;
        const auto error = GetLastError();
        if (error == ERROR_DIR_NOT_EMPTY) return false;
        residual(wide, "Unable to remove an SSH runtime directory", error);
    };
    return fs;
}

bool plainAncestor(const SshRuntimeFilesystem& fs, const std::wstring& directory) {
    const auto kind = fs.kind(Narrow(directory));
    if (kind == SshRuntimeFilesystem::Kind::Missing) return false;
    if (kind != SshRuntimeFilesystem::Kind::PlainDirectory)
        throw SshRuntimeResidual("An SSH runtime directory is not a plain owned directory; it was left unchanged (" +
                                 Narrow(directory) + ").");
    return true;
}
}

void RemoveSshRuntime(const Profile& profile) {
    if (!IsProfileId(profile.id)) throw Error("Invalid SSH profile.");
    // A session whose teardown cannot be verified is a live-credential failure, not a leftover file.
    CloseManagedSsh(profile.id);
    const auto fs = win32RuntimeFilesystem();
    auto directory = KnownFolder(FOLDERID_LocalAppData) + L"\\TELIPHONES";
    if (!plainAncestor(fs, directory)) return;
    directory += L"\\SSH";
    if (!plainAncestor(fs, directory)) return;
    // The permanent <profile>.dpapi identity lives beside this directory and is never part of the tree.
    RemoveSshRuntimeTree(fs, Narrow(directory + L"\\" + Widen(profile.id)));
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
