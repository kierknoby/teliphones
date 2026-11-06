// Classifies a workstation session-admission transport failure from facts the client can observe:
// which HTTP stage failed and how old the peer's WireGuard handshake is. Only a current handshake
// proves the tunnel is authenticated; without one the failure is on the outer UDP path, not the PBX.
#pragma once

#include "ConnectionHealth.h"
#include "Json.h"

#include <cstdint>
#include <optional>
#include <string>

namespace tlp {

enum class AdmissionStage {
    Reach,     // TCP connect and request send to the session controller
    Response,  // controller accepted the request but its answer did not arrive
};

struct AdmissionTransportError : Error {
    AdmissionTransportError(AdmissionStage failedStage, unsigned long windowsError, const std::string& text)
        : Error(text), stage(failedStage), code(windowsError) {}
    AdmissionStage stage;
    unsigned long code;
};

enum class AdmissionFailure {
    NoHandshake,         // UDP path: no authenticated WireGuard session from this network
    HandshakeUnknown,    // handshake telemetry unreadable; authentication cannot be claimed
    ControllerUnreached, // tunnel authenticated, controller TCP not reachable through it
    ControllerSilent,    // tunnel authenticated, controller accepted but did not answer
};

// handshakeUnixSeconds: nullopt = unreadable, 0 = no handshake since the tunnel started.
inline AdmissionFailure ClassifyAdmissionFailure(AdmissionStage stage, std::optional<std::int64_t> handshakeUnixSeconds,
                                                 std::int64_t nowUnixSeconds) {
    if (!handshakeUnixSeconds) return AdmissionFailure::HandshakeUnknown;
    if (*handshakeUnixSeconds <= 0 ||
        nowUnixSeconds - *handshakeUnixSeconds > ConnectionHealthMonitor::kStaleHandshakeSeconds)
        return AdmissionFailure::NoHandshake;
    return stage == AdmissionStage::Reach ? AdmissionFailure::ControllerUnreached : AdmissionFailure::ControllerSilent;
}

inline const char* AdmissionFailureName(AdmissionFailure failure) {
    switch (failure) {
        case AdmissionFailure::NoHandshake: return "no-handshake";
        case AdmissionFailure::HandshakeUnknown: return "handshake-unknown";
        case AdmissionFailure::ControllerUnreached: return "controller-unreached";
        case AdmissionFailure::ControllerSilent: return "controller-silent";
    }
    return "unknown";
}

inline std::string DescribeAdmissionFailure(const AdmissionTransportError& error,
                                            std::optional<std::int64_t> handshakeUnixSeconds,
                                            std::int64_t nowUnixSeconds, const std::string& endpoint,
                                            const std::string& controller) {
    const std::string windows = " (Windows error " + std::to_string(error.code) + ")";
    const std::string retry = " TELIPHONES keeps retrying while connected and admits the session as soon as the PBX answers.";
    switch (ClassifyAdmissionFailure(error.stage, handshakeUnixSeconds, nowUnixSeconds)) {
        case AdmissionFailure::NoHandshake: {
            const std::string age = *handshakeUnixSeconds <= 0
                ? "has not completed since this tunnel started"
                : "last completed " + std::to_string(nowUnixSeconds - *handshakeUnixSeconds) + " seconds ago";
            return "The PBX session controller could not be reached" + windows + ". The WireGuard handshake with " + endpoint +
                   " " + age + ", so the tunnel is not authenticated from this network and this is not a PBX admission "
                   "decision. Check that this network permits outbound UDP to " + endpoint +
                   ". Disconnect and Connect looks up the PBX address again." + retry;
        }
        case AdmissionFailure::HandshakeUnknown:
            return "The PBX session controller could not be reached" + windows +
                   ". The WireGuard handshake could not be read, so whether the tunnel is authenticated is unknown." + retry;
        case AdmissionFailure::ControllerUnreached:
            return "The WireGuard tunnel is authenticated (handshake " +
                   std::to_string(nowUnixSeconds - *handshakeUnixSeconds) + " seconds ago), but the PBX session controller at " +
                   controller + " did not accept a connection through it" + windows +
                   ". The PBX controller listener or PBX firewall is not answering; this network is not the cause." + retry;
        case AdmissionFailure::ControllerSilent:
            return "The WireGuard tunnel is authenticated (handshake " +
                   std::to_string(nowUnixSeconds - *handshakeUnixSeconds) + " seconds ago) and the PBX session controller at " +
                   controller + " accepted the request, but did not answer in time" + windows +
                   ". The PBX broker is busy or stalled; this network is not the cause." + retry;
    }
    return error.what();
}

}  // namespace tlp
