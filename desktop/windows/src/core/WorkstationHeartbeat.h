// Applies authenticated workstation heartbeat updates to a saved administrator profile.
#pragma once

#include "Profiles.h"

namespace tlp {

bool ApplyWorkstationSshRevocation(Profile& profile);
bool ApplyWorkstationSshRequestRejection(Profile& profile);
bool ApplyWorkstationSshApproval(Profile& profile, const PairResponse& approval);

}  // namespace tlp
