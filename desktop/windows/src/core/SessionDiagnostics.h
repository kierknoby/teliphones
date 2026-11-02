// Bounded per-user JSON-lines diagnostics; callers must surface storage failures.
#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>

namespace tlp {

std::string SanitizeDiagnosticDetail(const std::string& detail);

class SessionDiagnostics {
public:
    static constexpr std::size_t MaxFileBytes = 1024 * 1024;
    static constexpr std::size_t MaxFiles = 3;
    static constexpr std::int64_t RetentionSeconds = 7 * 24 * 60 * 60;
    using Clock = std::function<std::int64_t()>;

    // The parent directory must exist. The final directory is created privately.
    // Cross-process/thread lock acquisition is bounded to 100 ms and throws on contention.
    explicit SessionDiagnostics(std::filesystem::path directory, Clock clock = {});
    void Write(const std::string& sessionId, const std::string& attemptId, const std::string& event,
               const std::string& severity, const std::string& detail);
    // JSON lines, exact session only; useful detail is sanitized again before viewing/export.
    std::string Read(const std::string& sessionId);

private:
    std::filesystem::path directory_;
    Clock clock_;
};

}  // namespace tlp
