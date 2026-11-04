#pragma once

#include <string>

namespace tlp {

bool ConnectProtectionAvailable();
// The credential's format, never a preferences flag, determines whether authentication is required.
bool IsProtectedConnectKey(const std::string& stored);
std::string ProtectConnectKey(const std::string& target, const std::string& privateKey, const std::string& password);
std::string OpenConnectKey(const std::string& target, const std::string& stored, const std::string& password);

}  // namespace tlp
