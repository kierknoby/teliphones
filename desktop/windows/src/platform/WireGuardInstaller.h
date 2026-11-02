#pragma once

#include <functional>
#include <string>

#include "../core/WireGuardSetup.h"

namespace tlp {
namespace win {

// Fixed official x64 distribution; no URL, command or executable is accepted from a PBX.
SetupResult InstallWireGuard(const std::function<void(const std::string&)>& progress);

}  // namespace win
}  // namespace tlp
