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

inline const char* AdmissionStageName(AdmissionStage stage) {
    return stage == AdmissionStage::Reach ? "connect" : "response";
}

// Where Windows sends traffic for the PBX session-controller address (GetBestRoute2).
enum class RouteEvidence {
    Unknown,            // the route could not be read
    ViaTunnel,          // into this tunnel's WireGuard adapter
    ViaOtherInterface,  // into another interface, so admission requests never enter this tunnel
};

// Facts gathered alongside a failed admission. Interface aliases only; never addresses.
struct AdmissionContext {
    RouteEvidence route = RouteEvidence::Unknown;
    std::string routeInterface;                           // alias of the other interface for ViaOtherInterface
    bool routeInterfaceTeliphones = false;                // that alias is in TELIPHONES' own tunnel namespace
    std::optional<std::int64_t> networkChangedUnixSeconds;  // last local network change observed while connected
    std::string correlationId;                            // ws-... shared with the PBX diagnostic history
};

enum class AdmissionFailure {
    NoHandshake,         // UDP path: no authenticated WireGuard session from this network
    HandshakeUnknown,    // handshake telemetry unreadable; authentication cannot be claimed
    ControllerUnreached, // tunnel authenticated, controller TCP not reachable through it
    ControllerSilent,    // tunnel authenticated, controller accepted but did not answer
    RouteMisdirected,    // Windows routes the PBX address outside this tunnel
};

// handshakeUnixSeconds: nullopt = unreadable, 0 = no handshake since the tunnel started.
inline AdmissionFailure ClassifyAdmissionFailure(AdmissionStage stage, std::optional<std::int64_t> handshakeUnixSeconds,
                                                 std::int64_t nowUnixSeconds, RouteEvidence route = RouteEvidence::Unknown) {
    if (route == RouteEvidence::ViaOtherInterface) return AdmissionFailure::RouteMisdirected;
    if (!handshakeUnixSeconds) {
        // A response-stage failure follows a completed TCP handshake with the controller's tunnel address. Routed
        // into this tunnel, that reply can only have been delivered by the PBX's authenticated WireGuard peer.
        return stage == AdmissionStage::Response && route == RouteEvidence::ViaTunnel
            ? AdmissionFailure::ControllerSilent : AdmissionFailure::HandshakeUnknown;
    }
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
        case AdmissionFailure::RouteMisdirected: return "route-misdirected";
    }
    return "unknown";
}

inline std::string DescribeAdmissionFailure(const AdmissionTransportError& error,
                                            std::optional<std::int64_t> handshakeUnixSeconds,
                                            std::int64_t nowUnixSeconds, const std::string& endpoint,
                                            const std::string& controller, const AdmissionContext& context = {}) {
    const std::string windows = " (Windows error " + std::to_string(error.code) + ")";
    const std::string retry = " TELIPHONES keeps retrying while connected and admits the session as soon as the PBX answers.";
    std::string network;
    if (context.networkChangedUnixSeconds && nowUnixSeconds >= *context.networkChangedUnixSeconds &&
        nowUnixSeconds - *context.networkChangedUnixSeconds <= 600)
        network = " The local network changed " + std::to_string(nowUnixSeconds - *context.networkChangedUnixSeconds) +
                  " seconds ago.";
    const std::string pbx = context.correlationId.empty() ? std::string()
        : " The PBX's TELIPHONES diagnostics for " + context.correlationId +
          " record whether and when the PBX received and answered these requests.";
    const std::string stage = error.stage == AdmissionStage::Reach
        ? " did not accept a TCP connection through the tunnel"
        : " accepted the connection and request but did not answer in time";
    switch (ClassifyAdmissionFailure(error.stage, handshakeUnixSeconds, nowUnixSeconds, context.route)) {
        case AdmissionFailure::RouteMisdirected:
            return "Windows routes the PBX session controller " + controller + " through the network interface \"" +
                   context.routeInterface + "\" instead of this TELIPHONES tunnel, so admission requests never enter "
                   "the tunnel" + windows + "." +
                   (context.routeInterfaceTeliphones
                        ? " That interface is a leftover TELIPHONES tunnel. Disconnect, restart TELIPHONES and approve "
                          "removal of the leftover tunnel; other WireGuard tunnels are not changed."
                        : " That interface does not belong to TELIPHONES, which will not change it. Disconnect the other "
                          "VPN or tunnel that routes this address, then Connect again.") +
                   network + " TELIPHONES keeps retrying while connected and admits the session once the route uses this tunnel.";
        case AdmissionFailure::NoHandshake: {
            const std::string age = *handshakeUnixSeconds <= 0
                ? "has not completed since this tunnel started"
                : "last completed " + std::to_string(nowUnixSeconds - *handshakeUnixSeconds) + " seconds ago";
            return "The PBX session controller could not be reached" + windows + ". The WireGuard handshake with " + endpoint +
                   " " + age + ", so the tunnel is not authenticated from this network and this is not a PBX admission "
                   "decision. Check that this network permits outbound UDP to " + endpoint +
                   ". Disconnect and Connect looks up the PBX address again." + network + retry;
        }
        case AdmissionFailure::HandshakeUnknown:
            return "The PBX session controller at " + controller + stage + windows +
                   ". The WireGuard handshake could not be read, so whether the tunnel is authenticated is unknown" +
                   (context.route == RouteEvidence::ViaTunnel
                        ? "; Windows does route the PBX address into this tunnel."
                        : " and the route to the PBX address could not be verified.") +
                   network + pbx + retry;
        case AdmissionFailure::ControllerUnreached:
            return "The WireGuard tunnel is authenticated (handshake " +
                   std::to_string(nowUnixSeconds - *handshakeUnixSeconds) + " seconds ago), but the PBX session controller at " +
                   controller + " did not accept a connection through it" + windows +
                   ". The PBX controller listener or PBX firewall is not answering; this network is not the cause." +
                   network + pbx + retry;
        case AdmissionFailure::ControllerSilent:
            return "The WireGuard tunnel is authenticated (" +
                   (handshakeUnixSeconds ? "handshake " + std::to_string(nowUnixSeconds - *handshakeUnixSeconds) + " seconds ago"
                                         : std::string("the PBX completed a TCP connection through it")) +
                   ") and the PBX session controller at " + controller +
                   " accepted the request, but did not answer in time" + windows +
                   ". Most likely the PBX broker is busy or stalled." + network + pbx + retry;
    }
    return error.what();
}

}  // namespace tlp
