// Lifecycle policy for per-attempt managed SSH runtime directories. They hold only public material
// (session public key, short-lived certificate, pinned host key, client config) and the client's
// diagnostic log; private keys never reach disk. Leftovers therefore must not block the application.
#pragma once

#include "Json.h"
#include "Profiles.h"
#include "Validation.h"

#include <array>
#include <functional>
#include <string>
#include <vector>

namespace tlp {

// Every file name a managed SSH attempt (current or earlier release) may create. Cleanup deletes only
// these names, never recursively, so an unexpected entry is left in place and reported.
inline constexpr std::array<const char*, 7> kSshRuntimeFiles{
    "identity", "identity.pub", "identity.sig", "certificate.pub", "config", "known_hosts", "ssh.log"};

// Release 0.8.4 deleted only these at startup; a crashed session's ssh.log then kept its directory alive.
inline constexpr std::array<const char*, 6> kSshRuntimeFiles084{
    "identity", "identity.pub", "identity.sig", "certificate.pub", "config", "known_hosts"};

template <typename Names>
bool IsKnownName(const Names& names, const std::string& name) {
    for (const char* known : names)
        if (name == known) return true;
    return false;
}

inline bool IsSshRuntimeFile(const std::string& name) { return IsKnownName(kSshRuntimeFiles, name); }

// A runtime directory or file from an earlier attempt could not be removed. Raised only after any owned
// SSH session for the profile has been verified closed, so it never stands for a live connection.
struct SshRuntimeResidual : Error {
    using Error::Error;
};

// SSH approval may since have been revoked or re-paired, so the current pairing does not decide.
inline bool MayHaveSshRuntime(const Profile& profile) { return profile.kind == ProfileKind::Administrator; }

struct SshRuntimeCleanupFailure {
    std::string profileName;
    std::string error;
};

// Runs every profile's cleanup independently: one failure neither hides the loaded profiles nor skips the others.
inline std::vector<SshRuntimeCleanupFailure> CleanSshRuntimes(const std::vector<Profile>& profiles,
                                                              const std::function<void(const Profile&)>& clean) {
    std::vector<SshRuntimeCleanupFailure> failures;
    for (const auto& profile : profiles) {
        if (!MayHaveSshRuntime(profile)) continue;
        try {
            clean(profile);
        } catch (const std::exception& error) {
            failures.push_back({profile.name, error.what()});
        }
    }
    return failures;
}

// Filesystem primitives for one profile's runtime tree. Platform code supplies them (Win32 on Windows,
// so reparse points are refused); tests supply real directories. None of them may recurse.
struct SshRuntimeFilesystem {
    enum class Kind { Missing, PlainDirectory, PlainFile, Other };
    std::function<Kind(const std::string& path)> kind;
    std::function<std::vector<std::string>(const std::string& directory)> list;
    std::function<void(const std::string& path)> removeFile;
    // Returns false only when the directory is not empty.
    std::function<bool(const std::string& directory)> removeEmptyDirectory;
    std::string separator = "\\";
};

namespace ssh_runtime_detail {
template <typename Names>
void removeKnownFiles(const SshRuntimeFilesystem& fs, const std::string& directory, const Names& names) {
    for (const char* name : names) {
        const auto path = directory + fs.separator + name;
        const auto kind = fs.kind(path);
        if (kind == SshRuntimeFilesystem::Kind::Missing) continue;
        if (kind != SshRuntimeFilesystem::Kind::PlainFile)
            throw SshRuntimeResidual("An SSH runtime file is not a plain file; cleanup was stopped (" + path + ").");
        fs.removeFile(path);
    }
}

template <typename Names>
void removeOwnedDirectory(const SshRuntimeFilesystem& fs, const std::string& directory, const Names& names) {
    removeKnownFiles(fs, directory, names);
    if (!fs.removeEmptyDirectory(directory))
        throw SshRuntimeResidual("An SSH runtime directory still contains a file TELIPHONES did not create; it was "
                                 "left for inspection (" + directory + ").");
}
}  // namespace ssh_runtime_detail

// Removes <profile>\<attempt>\ directories and the profile directory itself, deleting only known file names.
// Every attempt is tried even if an earlier one fails, and the first failure is reported naming its path.
// Anything else, including a stray *.dpapi identity, is left in place.
template <typename Names = decltype(kSshRuntimeFiles)>
void RemoveSshRuntimeTree(const SshRuntimeFilesystem& fs, const std::string& profileDirectory,
                          const Names& names = kSshRuntimeFiles) {
    using Kind = SshRuntimeFilesystem::Kind;
    const auto root = fs.kind(profileDirectory);
    if (root == Kind::Missing) return;
    if (root != Kind::PlainDirectory)
        throw SshRuntimeResidual("An SSH runtime directory is not a plain owned directory; it was left unchanged (" +
                                 profileDirectory + ").");
    std::string firstFailure;
    for (const auto& name : fs.list(profileDirectory)) {
        const auto path = profileDirectory + fs.separator + name;
        try {
            if (IsProfileId(name)) {
                const auto kind = fs.kind(path);
                if (kind == Kind::Missing) continue;
                if (kind != Kind::PlainDirectory)
                    throw SshRuntimeResidual("An SSH runtime attempt is not a plain owned directory; it was left unchanged (" +
                                             path + ").");
                ssh_runtime_detail::removeOwnedDirectory(fs, path, names);
            } else if (!IsKnownName(names, name)) {
                throw SshRuntimeResidual("Unexpected SSH runtime artifact; it was left for inspection (" + path + ").");
            }
        } catch (const SshRuntimeResidual& failure) {
            if (firstFailure.empty()) firstFailure = failure.what();
        }
    }
    if (!firstFailure.empty()) throw SshRuntimeResidual(firstFailure);
    ssh_runtime_detail::removeOwnedDirectory(fs, profileDirectory, names);
}

inline std::string DescribeSshRuntimeCleanupFailures(const std::vector<SshRuntimeCleanupFailure>& failures) {
    std::string text = "Temporary SSH files could not be removed for:";
    for (const auto& failure : failures) text += "\n- " + failure.profileName + ": " + failure.error;
    return text + "\nThese files contain no private keys. TELIPHONES will try again when the connection is next "
                  "disconnected or the application next starts.";
}

}  // namespace tlp
