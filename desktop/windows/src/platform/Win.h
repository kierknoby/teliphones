// Win32 utilities: text conversion, folders, randomness, files with restrictive DACLs, process execution.
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shlobj.h>

#include <cstdint>
#include <string>
#include <vector>

#include "../core/Encoding.h"

namespace tlp {
namespace win {

std::wstring Widen(const std::string& utf8);
std::string Narrow(const std::wstring& wide);
std::wstring ErrorText(DWORD code);
[[noreturn]] void ThrowLastError(const char* what, DWORD code = GetLastError());

// Known folders, e.g. FOLDERID_RoamingAppData; created on demand for application subdirectories.
std::wstring KnownFolder(const KNOWNFOLDERID& id);
std::wstring EnsureDirectory(const std::wstring& path, const wchar_t* sddl = nullptr);

Bytes RandomBytes(std::size_t count);
std::int64_t UnixNow();
std::string CurrentUserSid();

std::string ReadSmallFile(const std::wstring& path, std::size_t maxBytes);
// Creates a new file (removing any old one first) with an explicit protected DACL, then flushes it.
void WriteNewFile(const std::wstring& path, const std::string& data, const wchar_t* sddl);
// Replaces a user data file atomically; the file inherits the per-user folder's permissions.
void ReplaceUserFile(const std::wstring& path, const std::string& data);
void SecureWipe(std::string& secret);

struct ProcessResult {
    DWORD exitCode = 1;
    std::string output;
};
// Runs a program without a console window, optionally feeding stdin, capturing stdout. Throws on launch failure or timeout.
ProcessResult RunProcess(const std::wstring& program, const std::vector<std::string>& arguments, const std::string& input, DWORD timeoutMs);

}  // namespace win
}  // namespace tlp
