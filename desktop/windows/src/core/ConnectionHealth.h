// Bounded, local-only connection measurements and health assessment.
#pragma once

#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <vector>

#include "Json.h"

namespace tlp {

enum class HealthState { Unknown, Stable, Degraded, Unstable, Disconnected };

struct HealthThresholds {
    int warningLatencyMs = 300;
    int warningJitterMs = 100;
    int consecutiveFailures = 3;
};

struct HealthPreferences {
    int historySeconds = 60;
    bool alwaysOnTop = false;
    int windowX = -1;
    int windowY = -1;
    int windowWidth = 0;
    int windowHeight = 0;
    HealthThresholds thresholds;
};

struct HealthSample {
    std::int64_t timestampMs = 0;
    bool tunnelKnown = false;
    bool tunnelRunning = false;
    bool probeKnown = false;
    bool probeSucceeded = false;
    std::optional<double> latencyMs;
    std::optional<std::uint64_t> receivedBytes;
    std::optional<std::uint64_t> transmittedBytes;
    std::optional<std::int64_t> handshakeUnixSeconds;
    bool wireGuardTelemetryAttempted = false;
    std::int64_t telemetryTimestampMs = 0;
    std::int64_t authorizationExpiresAt = 0;
};

struct HealthSnapshot {
    HealthState state = HealthState::Unknown;
    std::optional<double> latencyMs;
    std::optional<double> jitterMs;
    std::optional<double> probeSuccessPercent;
    std::optional<double> probeFailurePercent;
    std::optional<double> receiveBytesPerSecond;
    std::optional<double> transmitBytesPerSecond;
    std::optional<std::int64_t> handshakeAgeSeconds;
    std::optional<std::int64_t> authorizationRemainingSeconds;
    int consecutiveFailures = 0;
    std::optional<std::int64_t> continuouslyHealthySeconds;
    bool deterioration = false;
    std::deque<HealthSample> samples;
};

struct WireGuardCounters {
    std::optional<std::uint64_t> receivedBytes;
    std::optional<std::uint64_t> transmittedBytes;
    std::optional<std::int64_t> handshakeUnixSeconds;
};

WireGuardCounters ParseWireGuardCounters(const std::string& transfer, const std::string& handshakes, const std::string& peerPublicKey);

constexpr const char* kHealthPreferencesSchema = "teliphones-connection-health/1";

std::string SerializeHealthPreferences(const HealthPreferences& preferences);
HealthPreferences ParseHealthPreferences(const std::string& text);
const char* HealthStateName(HealthState state);

class ConnectionHealthMonitor {
public:
    static constexpr std::size_t kMaximumSamples = 300;
    static constexpr int kSampleIntervalSeconds = 2;
    static constexpr int kTelemetryIntervalSeconds = 6;
    static constexpr int kStableSamplesRequired = 5;
    static constexpr int kDisconnectedAfterFailures = 5;
    static constexpr int kStaleHandshakeSeconds = 180;

    explicit ConnectionHealthMonitor(HealthThresholds thresholds = {});
    void AddSample(const HealthSample& sample);
    void SetThresholds(const HealthThresholds& thresholds);
    HealthSnapshot Snapshot(std::int64_t nowMs, int historySeconds) const;

private:
    HealthThresholds thresholds_;
    std::deque<HealthSample> samples_;
    int consecutiveFailures_ = 0;
};

}  // namespace tlp
