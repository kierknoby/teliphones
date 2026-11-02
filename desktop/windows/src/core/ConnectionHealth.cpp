#include "ConnectionHealth.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <sstream>
#include <exception>

#include "Validation.h"

namespace tlp {
namespace {

using json::Value;

void validateThresholds(const HealthThresholds& thresholds) {
    const bool latencySupported = thresholds.warningLatencyMs == 200 || thresholds.warningLatencyMs == 300 || thresholds.warningLatencyMs == 500;
    const bool jitterSupported = thresholds.warningJitterMs == 50 || thresholds.warningJitterMs == 100 || thresholds.warningJitterMs == 200;
    const bool failuresSupported = thresholds.consecutiveFailures >= 2 && thresholds.consecutiveFailures <= 4;
    if (!latencySupported || !jitterSupported || !failuresSupported) {
        throw Error("Connection health thresholds are outside the supported range.");
    }
}

std::optional<double> average(const std::vector<double>& values) {
    if (values.empty()) return std::nullopt;
    double sum = 0;
    for (double value : values) sum += value;
    return sum / static_cast<double>(values.size());
}

template <typename Number>
Number parseUnsigned(const std::string& text, const char* description) {
    if (text.empty() || !std::all_of(text.begin(), text.end(), [](unsigned char ch) { return ch >= '0' && ch <= '9'; })) {
        throw Error(std::string("Invalid WireGuard ") + description + ".");
    }
    try {
        unsigned long long parsed = std::stoull(text);
        if (parsed > static_cast<unsigned long long>(std::numeric_limits<Number>::max())) throw Error(std::string("WireGuard ") + description + " is out of range.");
        return static_cast<Number>(parsed);
    } catch (const Error&) {
        throw;
    } catch (const std::exception&) {
        throw Error(std::string("Invalid WireGuard ") + description + ".");
    }
}

}  // namespace

WireGuardCounters ParseWireGuardCounters(const std::string& transfer, const std::string& handshakes, const std::string& peerPublicKey) {
    if (!IsWireGuardKey(peerPublicKey)) throw Error("The active WireGuard peer key is invalid.");
    WireGuardCounters result;
    std::istringstream transferLines(transfer);
    std::string line;
    while (std::getline(transferLines, line)) {
        std::istringstream fields(line);
        std::string key, received, transmitted, extra;
        if (!(fields >> key >> received >> transmitted) || (fields >> extra) || !IsWireGuardKey(key)) {
            throw Error("WireGuard transfer telemetry is malformed.");
        }
        if (key == peerPublicKey) {
            if (result.receivedBytes || result.transmittedBytes) throw Error("WireGuard transfer telemetry contains a duplicate peer.");
            result.receivedBytes = parseUnsigned<std::uint64_t>(received, "received-byte counter");
            result.transmittedBytes = parseUnsigned<std::uint64_t>(transmitted, "transmitted-byte counter");
        }
    }
    std::istringstream handshakeLines(handshakes);
    while (std::getline(handshakeLines, line)) {
        std::istringstream fields(line);
        std::string key, timestamp, extra;
        if (!(fields >> key >> timestamp) || (fields >> extra) || !IsWireGuardKey(key)) {
            throw Error("WireGuard handshake telemetry is malformed.");
        }
        if (key == peerPublicKey) {
            if (result.handshakeUnixSeconds) throw Error("WireGuard handshake telemetry contains a duplicate peer.");
            result.handshakeUnixSeconds = parseUnsigned<std::int64_t>(timestamp, "handshake timestamp");
        }
    }
    return result;
}

std::string SerializeHealthPreferences(const HealthPreferences& preferences) {
    validateThresholds(preferences.thresholds);
    if (preferences.historySeconds != 60 && preferences.historySeconds != 300) {
        throw Error("Connection health history must be 60 or 300 seconds.");
    }
    if (preferences.windowX < -100000 || preferences.windowX > 100000 || preferences.windowY < -100000 || preferences.windowY > 100000 ||
        preferences.windowWidth < 0 || preferences.windowWidth > 10000 || preferences.windowHeight < 0 || preferences.windowHeight > 10000) {
        throw Error("Connection health window geometry is outside the supported range.");
    }
    return json::Serialize(Value(Value::Object{
        {"schema", kHealthPreferencesSchema},
        {"history_seconds", preferences.historySeconds},
        {"always_on_top", preferences.alwaysOnTop},
        {"window_x", preferences.windowX},
        {"window_y", preferences.windowY},
        {"window_width", preferences.windowWidth},
        {"window_height", preferences.windowHeight},
        {"warning_latency_ms", preferences.thresholds.warningLatencyMs},
        {"warning_jitter_ms", preferences.thresholds.warningJitterMs},
        {"consecutive_failures", preferences.thresholds.consecutiveFailures},
    })) + "\n";
}

HealthPreferences ParseHealthPreferences(const std::string& text) {
    Value value = json::Parse(text, 4096);
    json::RequireExactKeys(value, {"schema", "history_seconds", "always_on_top", "window_x", "window_y", "window_width", "window_height",
                                   "warning_latency_ms", "warning_jitter_ms", "consecutive_failures"},
                           "Connection health preferences");
    if (value.at("schema").asString() != kHealthPreferencesSchema) throw Error("Unsupported connection health preferences format.");
    HealthPreferences result;
    const std::int64_t historySeconds = value.at("history_seconds").asInteger();
    if (historySeconds < std::numeric_limits<int>::min() || historySeconds > std::numeric_limits<int>::max()) {
        throw Error("Connection health history is out of range.");
    }
    result.historySeconds = static_cast<int>(historySeconds);
    result.alwaysOnTop = value.at("always_on_top").asBool();
    const std::int64_t windowX = value.at("window_x").asInteger();
    const std::int64_t windowY = value.at("window_y").asInteger();
    const std::int64_t windowWidth = value.at("window_width").asInteger();
    const std::int64_t windowHeight = value.at("window_height").asInteger();
    const std::int64_t latency = value.at("warning_latency_ms").asInteger();
    const std::int64_t jitter = value.at("warning_jitter_ms").asInteger();
    const std::int64_t failures = value.at("consecutive_failures").asInteger();
    if (windowX < std::numeric_limits<int>::min() || windowX > std::numeric_limits<int>::max() ||
        windowY < std::numeric_limits<int>::min() || windowY > std::numeric_limits<int>::max() ||
        windowWidth < std::numeric_limits<int>::min() || windowWidth > std::numeric_limits<int>::max() ||
        windowHeight < std::numeric_limits<int>::min() || windowHeight > std::numeric_limits<int>::max() ||
        latency < std::numeric_limits<int>::min() || latency > std::numeric_limits<int>::max() ||
        jitter < std::numeric_limits<int>::min() || jitter > std::numeric_limits<int>::max() ||
        failures < std::numeric_limits<int>::min() || failures > std::numeric_limits<int>::max()) {
        throw Error("Connection health preferences contain an out-of-range value.");
    }
    result.windowX = static_cast<int>(windowX);
    result.windowY = static_cast<int>(windowY);
    result.windowWidth = static_cast<int>(windowWidth);
    result.windowHeight = static_cast<int>(windowHeight);
    result.thresholds.warningLatencyMs = static_cast<int>(latency);
    result.thresholds.warningJitterMs = static_cast<int>(jitter);
    result.thresholds.consecutiveFailures = static_cast<int>(failures);
    if (result.windowX < -100000 || result.windowX > 100000 || result.windowY < -100000 || result.windowY > 100000 ||
        result.windowWidth < 0 || result.windowWidth > 10000 || result.windowHeight < 0 || result.windowHeight > 10000) {
        throw Error("Connection health window position is invalid.");
    }
    if (result.historySeconds != 60 && result.historySeconds != 300) {
        throw Error("Connection health history must be 60 or 300 seconds.");
    }
    validateThresholds(result.thresholds);
    return result;
}

const char* HealthStateName(HealthState state) {
    switch (state) {
        case HealthState::Stable: return "Stable";
        case HealthState::Degraded: return "Degraded";
        case HealthState::Unstable: return "Unstable";
        case HealthState::Disconnected: return "Disconnected";
        case HealthState::Unknown: return "Unknown";
    }
    return "Unknown";
}

ConnectionHealthMonitor::ConnectionHealthMonitor(HealthThresholds thresholds) : thresholds_(thresholds) {
    validateThresholds(thresholds_);
}

void ConnectionHealthMonitor::AddSample(const HealthSample& sample) {
    if (sample.timestampMs <= 0 || (!samples_.empty() && sample.timestampMs <= samples_.back().timestampMs)) {
        throw Error("Connection health samples must have increasing timestamps.");
    }
    if (!sample.probeSucceeded && sample.latencyMs) throw Error("A failed application probe cannot provide a successful round-trip latency.");
    if (sample.latencyMs && (!std::isfinite(*sample.latencyMs) || *sample.latencyMs < 0)) throw Error("Connection latency is invalid.");
    if (sample.handshakeUnixSeconds && *sample.handshakeUnixSeconds < 0) throw Error("WireGuard handshake timestamp is invalid.");
    samples_.push_back(sample);
    if (samples_.size() > kMaximumSamples) samples_.pop_front();
    if (sample.probeKnown) {
        consecutiveFailures_ = sample.probeSucceeded ? 0 : consecutiveFailures_ + 1;
    }
}

void ConnectionHealthMonitor::SetThresholds(const HealthThresholds& thresholds) {
    validateThresholds(thresholds);
    thresholds_ = thresholds;
}

HealthSnapshot ConnectionHealthMonitor::Snapshot(std::int64_t nowMs, int historySeconds) const {
    if (historySeconds != 60 && historySeconds != 300) throw Error("Connection health history must be 60 or 300 seconds.");
    HealthSnapshot result;
    result.consecutiveFailures = consecutiveFailures_;
    if (samples_.empty()) return result;
    const std::int64_t cutoff = nowMs - static_cast<std::int64_t>(historySeconds) * 1000;
    for (const HealthSample& sample : samples_) {
        if (sample.timestampMs >= cutoff) result.samples.push_back(sample);
    }
    if (result.samples.empty()) return result;

    const HealthSample& latest = result.samples.back();
    if (latest.authorizationExpiresAt > 0) {
        result.authorizationRemainingSeconds = std::max<std::int64_t>(0, latest.authorizationExpiresAt - nowMs / 1000);
    }
    if (latest.tunnelKnown && !latest.tunnelRunning) {
        result.state = HealthState::Disconnected;
        return result;
    }
    if (latest.authorizationExpiresAt > 0 && latest.authorizationExpiresAt <= nowMs / 1000) {
        result.state = HealthState::Disconnected;
        result.authorizationRemainingSeconds = 0;
        return result;
    }
    if (!latest.tunnelKnown || !latest.tunnelRunning || !latest.probeKnown) {
        result.state = HealthState::Unknown;
        return result;
    }

    std::vector<double> latencies;
    std::vector<double> jitters;
    int attempts = 0;
    int successes = 0;
    int failures = 0;
    std::vector<double> receiveRates;
    std::vector<double> transmitRates;
    std::optional<std::int64_t> previousTime;
    std::optional<std::uint64_t> previousRx;
    std::optional<std::uint64_t> previousTx;
    for (const HealthSample& sample : result.samples) {
        if (sample.probeKnown) {
            ++attempts;
            if (sample.probeSucceeded) ++successes;
            else ++failures;
        }
        if (sample.probeSucceeded && sample.latencyMs) {
            if (!latencies.empty()) jitters.push_back(std::abs(*sample.latencyMs - latencies.back()));
            latencies.push_back(*sample.latencyMs);
        }
        const std::int64_t counterTime = sample.telemetryTimestampMs > 0 ? sample.telemetryTimestampMs : sample.timestampMs;
        if (sample.receivedBytes && sample.transmittedBytes && previousTime && previousRx && previousTx &&
            counterTime > *previousTime && *sample.receivedBytes >= *previousRx && *sample.transmittedBytes >= *previousTx) {
            double seconds = static_cast<double>(counterTime - *previousTime) / 1000.0;
            receiveRates.push_back(static_cast<double>(*sample.receivedBytes - *previousRx) / seconds);
            transmitRates.push_back(static_cast<double>(*sample.transmittedBytes - *previousTx) / seconds);
        }
        if (sample.receivedBytes && sample.transmittedBytes) {
            previousTime = counterTime;
            previousRx = sample.receivedBytes;
            previousTx = sample.transmittedBytes;
        }
    }
    result.latencyMs = average(latencies);
    result.jitterMs = average(jitters);
    result.receiveBytesPerSecond = average(receiveRates);
    result.transmitBytesPerSecond = average(transmitRates);
    if (attempts > 0) {
        result.probeSuccessPercent = 100.0 * successes / attempts;
        result.probeFailurePercent = 100.0 * failures / attempts;
    }
    const HealthSample* latestTelemetry = nullptr;
    for (auto sample = result.samples.rbegin(); sample != result.samples.rend(); ++sample) {
        if (sample->wireGuardTelemetryAttempted) {
            latestTelemetry = &*sample;
            break;
        }
    }
    if (latestTelemetry && latestTelemetry->handshakeUnixSeconds) {
        const std::int64_t nowSeconds = nowMs / 1000;
        if (*latestTelemetry->handshakeUnixSeconds <= nowSeconds) result.handshakeAgeSeconds = nowSeconds - *latestTelemetry->handshakeUnixSeconds;
    }
    if (!latestTelemetry || !latestTelemetry->receivedBytes || !latestTelemetry->transmittedBytes) {
        result.receiveBytesPerSecond.reset();
        result.transmitBytesPerSecond.reset();
    }
    const int unstableLatency = thresholds_.warningLatencyMs * 3;
    const int unstableJitter = thresholds_.warningJitterMs * 3;
    int recentAttempts = 0;
    int recentFailures = 0;
    for (auto sample = result.samples.rbegin(); sample != result.samples.rend() && recentAttempts < 5; ++sample) {
        if (sample->probeKnown) {
            ++recentAttempts;
            if (!sample->probeSucceeded) ++recentFailures;
        }
    }
    bool severe = consecutiveFailures_ >= thresholds_.consecutiveFailures ||
                  (latest.latencyMs && *latest.latencyMs >= unstableLatency) ||
                  (result.jitterMs && *result.jitterMs >= unstableJitter) ||
                  (recentAttempts > 0 && 100.0 * recentFailures / recentAttempts >= 60.0);
    bool elevated = consecutiveFailures_ > 0 ||
                    (latest.latencyMs && *latest.latencyMs >= thresholds_.warningLatencyMs) ||
                    (result.jitterMs && *result.jitterMs >= thresholds_.warningJitterMs) ||
                    (result.handshakeAgeSeconds && *result.handshakeAgeSeconds > kStaleHandshakeSeconds);
    std::size_t successfulStreak = 0;
    std::int64_t stableSince = latest.timestampMs;
    for (auto sample = result.samples.rbegin(); sample != result.samples.rend(); ++sample) {
        if (!sample->tunnelKnown || !sample->tunnelRunning || !sample->probeKnown || !sample->probeSucceeded ||
            (sample->latencyMs && *sample->latencyMs >= thresholds_.warningLatencyMs)) break;
        if (successfulStreak > 0 && stableSince - sample->timestampMs > kSampleIntervalSeconds * 2000LL) break;
        stableSince = sample->timestampMs;
        ++successfulStreak;
    }
    if (consecutiveFailures_ >= kDisconnectedAfterFailures) result.state = HealthState::Disconnected;
    else if (severe) result.state = HealthState::Unstable;
    else if (elevated || successfulStreak < kStableSamplesRequired) result.state = HealthState::Degraded;
    else result.state = HealthState::Stable;

    if (result.state == HealthState::Stable) {
        result.continuouslyHealthySeconds = (latest.timestampMs - stableSince) / 1000;
    } else {
        result.continuouslyHealthySeconds.reset();
    }

    if (latencies.size() >= 4) {
        const std::size_t half = latencies.size() / 2;
        std::vector<double> earlier(latencies.begin(), latencies.begin() + static_cast<std::ptrdiff_t>(half));
        std::vector<double> recent(latencies.begin() + static_cast<std::ptrdiff_t>(half), latencies.end());
        std::optional<double> first = average(earlier), last = average(recent);
        result.deterioration = first && last && *last > *first * 1.5 && *last - *first >= 50;
    }
    result.deterioration = result.deterioration || consecutiveFailures_ > 0;
    return result;
}

}  // namespace tlp
