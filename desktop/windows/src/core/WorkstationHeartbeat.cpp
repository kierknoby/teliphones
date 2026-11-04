#include "WorkstationHeartbeat.h"

namespace tlp {

bool ApplyWorkstationSshRevocation(Profile& profile) {
    if (profile.kind != ProfileKind::Administrator) return false;
    profile.pairing.ssh = false;
    profile.pairing.sshRequestPublicKey = profile.pairing.sshPublicKey;
    profile.pairing.sshPublicKey.clear();
    profile.pairing.sshUser.clear();
    profile.pairing.sshHostKey.clear();
    profile.pairing.sshCaKey.clear();
    profile.pairing.sshPort = 0;
    profile.pairing.sshApiPort = 0;
    profile.sshUser.clear();
    return true;
}

bool ApplyWorkstationSshRequestRejection(Profile& profile) {
    if (profile.kind != ProfileKind::Administrator) return false;
    profile.pairing.sshRequestPublicKey.clear();
    return true;
}

bool ApplyWorkstationSshApproval(Profile& profile, const PairResponse& approval) {
    if (profile.kind != ProfileKind::Administrator ||
        approval.workstationId != profile.pairing.workstationId ||
        approval.workstationPublicKey != profile.pairing.workstationPublicKey ||
        approval.sshPublicKey != profile.pairing.sshRequestPublicKey) {
        return false;
    }
    profile.pairing = approval;
    profile.sshUser = profile.pairing.sshUser;
    return true;
}

}  // namespace tlp
