#include "SessionDiagnostics.h"

#include "Json.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <memory>
#include <sstream>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace tlp {
namespace {

const auto processStarted = std::chrono::steady_clock::now();

bool hexId(const std::string& value) {
    return value.size() == 16 && value.find_first_not_of("0123456789abcdef") == std::string::npos;
}

bool sessionIdValid(const std::string& value) {
    return value == "application" || (value.compare(0, 3, "ws-") == 0 && hexId(value.substr(3))) ||
           (value.compare(0, 8, "support-") == 0 && hexId(value.substr(8)));
}

bool eventValid(const std::string& value) {
    static const std::vector<std::string> events{
        "startup", "shutdown", "pairing_saved", "profile_removed", "connection_attempt", "tunnel_started",
        "connection_failed", "disconnect_requested", "tunnel_removed", "disconnect_failed", "authorization_expired",
        "health_changed", "probe_changed", "telemetry_changed", "session_summary", "recent_measurements", "measurement_error"};
    return std::find(events.begin(), events.end(), value) != events.end();
}

bool severityValid(const std::string& value) {
    return value == "info" || value == "warning" || value == "error";
}

std::string utc(std::int64_t seconds) {
    std::time_t time = static_cast<std::time_t>(seconds);
    std::tm broken{};
#ifdef _WIN32
    if (gmtime_s(&broken, &time) != 0) throw Error("Diagnostic clock is invalid.");
#else
    if (!gmtime_r(&time, &broken)) throw Error("Diagnostic clock is invalid.");
#endif
    char text[32]{};
    if (!std::strftime(text, sizeof(text), "%Y-%m-%dT%H:%M:%SZ", &broken)) throw Error("Diagnostic clock is invalid.");
    return text;
}

bool utcValid(const std::string& value) {
    if (value.size() != 20) return false;
    std::tm broken{};
    std::istringstream input(value);
    input >> std::get_time(&broken, "%Y-%m-%dT%H:%M:%SZ");
    if (input.fail()) return false;
#ifdef _WIN32
    const auto seconds = _mkgmtime(&broken);
#else
    const auto seconds = timegm(&broken);
#endif
    return seconds >= 0 && utc(seconds) == value;
}

[[noreturn]] void storageError() { throw Error("Unable to safely access local session diagnostics."); }

#ifdef _WIN32
class Handle {
public:
    HANDLE value;
    explicit Handle(HANDLE handle) : value(handle) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};

class PrivateSecurity {
public:
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    SECURITY_ATTRIBUTES attributes{};
    std::wstring sid;
    PrivateSecurity() {
        Handle token(nullptr);
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value)) storageError();
        DWORD length = 0;
        GetTokenInformation(token.value, TokenUser, nullptr, 0, &length);
        std::vector<BYTE> data(length);
        if (!length || !GetTokenInformation(token.value, TokenUser, data.data(), length, &length)) storageError();
        LPWSTR text = nullptr;
        if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid, &text)) storageError();
        sid = text;
        LocalFree(text);
        const auto sddl = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + sid + L")";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) storageError();
        attributes = {sizeof(attributes), descriptor, FALSE};
    }
    ~PrivateSecurity() { if (descriptor) LocalFree(descriptor); }
};

class Directory {
    PrivateSecurity security_;
    std::vector<std::unique_ptr<Handle>> directories_;
    Handle mutex_{nullptr};
    bool locked_ = false;
    std::filesystem::path path_;

    void restrict(HANDLE file) {
        if (!SetKernelObjectSecurity(file, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, security_.descriptor)) storageError();
    }
    void regular(HANDLE file) {
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(file, &info) ||
            (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) || info.nNumberOfLinks != 1) storageError();
        restrict(file);
    }
public:
    explicit Directory(const std::filesystem::path& path) : path_(std::filesystem::absolute(path)) {
        if (path_ == path_.root_path()) storageError();
        const auto name = L"Global\\TELIPHONES.Diagnostics." + security_.sid;
        mutex_.value = CreateMutexW(&security_.attributes, FALSE, name.c_str());
        if (!mutex_.value) storageError();
        const DWORD wait = WaitForSingleObject(mutex_.value, 100);
        if (wait == WAIT_TIMEOUT) throw Error("Session diagnostics storage is busy (100 ms lock timeout).");
        if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) storageError();
        locked_ = true;
        try {
            std::filesystem::path current = path_.root_path();
            for (const auto& component : path_.relative_path()) {
                if (component == L".." || component == L".") storageError();
                current /= component;
                if (current == path_ && !CreateDirectoryW(current.c_str(), &security_.attributes) && GetLastError() != ERROR_ALREADY_EXISTS) storageError();
                auto handle = std::make_unique<Handle>(CreateFileW(current.c_str(),
                    FILE_READ_ATTRIBUTES | (current == path_ ? WRITE_DAC : 0), FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
                BY_HANDLE_FILE_INFORMATION info{};
                if (handle->value == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(handle->value, &info) ||
                    !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) storageError();
                if (current == path_) restrict(handle->value);
                // Denying delete sharing pins every ancestor against junction/rename replacement.
                directories_.push_back(std::move(handle));
            }
        } catch (...) {
            ReleaseMutex(mutex_.value);
            locked_ = false;
            throw;
        }
    }
    ~Directory() { if (locked_) ReleaseMutex(mutex_.value); }
    std::string Read(const std::string& name) {
        Handle file(CreateFileW((path_ / name).c_str(), GENERIC_READ | WRITE_DAC, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (file.value == INVALID_HANDLE_VALUE) {
            if (GetLastError() == ERROR_FILE_NOT_FOUND) return {};
            storageError();
        }
        regular(file.value);
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file.value, &size) || size.QuadPart < 0 || size.QuadPart > SessionDiagnostics::MaxFileBytes) storageError();
        std::string result(static_cast<std::size_t>(size.QuadPart), '\0');
        DWORD read = 0;
        if (!result.empty() && (!ReadFile(file.value, &result[0], static_cast<DWORD>(result.size()), &read, nullptr) || read != result.size())) storageError();
        return result;
    }
    void Write(const std::string& name, const std::string& data, bool append = false) {
        Handle file(CreateFileW((path_ / name).c_str(), GENERIC_WRITE | WRITE_DAC, 0, &security_.attributes,
                               OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (file.value == INVALID_HANDLE_VALUE) storageError();
        regular(file.value);
        // Inspect before truncation: never follow a reparse point or modify a hard-linked file.
        LARGE_INTEGER size{}, zero{};
        if (!GetFileSizeEx(file.value, &size) || size.QuadPart < 0 ||
            (append && static_cast<std::uint64_t>(size.QuadPart) + data.size() > SessionDiagnostics::MaxFileBytes)) storageError();
        if (append) {
            if (!SetFilePointerEx(file.value, zero, nullptr, FILE_END)) storageError();
        } else if (!SetEndOfFile(file.value)) storageError();
        DWORD written = 0;
        if ((!data.empty() && (!WriteFile(file.value, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) || written != data.size())) ||
            !FlushFileBuffers(file.value)) storageError();
    }
};
#else
class Descriptor {
public:
    int value;
    explicit Descriptor(int descriptor) : value(descriptor) {}
    ~Descriptor() { if (value >= 0) close(value); }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
};

class Directory {
    Descriptor directory_{-1};
    void regular(int file) {
        struct stat info{};
        if (fstat(file, &info) != 0 || !S_ISREG(info.st_mode) || info.st_nlink != 1 || info.st_uid != geteuid() ||
            fchmod(file, 0600) != 0) storageError();
    }
public:
    explicit Directory(const std::filesystem::path& path) {
        const auto absolute = std::filesystem::absolute(path);
        if (absolute == absolute.root_path()) storageError();
        Descriptor current(open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        if (current.value < 0) storageError();
        const auto relative = absolute.relative_path();
        for (auto it = relative.begin(); it != relative.end(); ++it) {
            if (*it == ".." || *it == ".") storageError();
            const auto next = std::next(it);
            if (next == relative.end() && mkdirat(current.value, it->c_str(), 0700) != 0 && errno != EEXIST) storageError();
            const int child = openat(current.value, it->c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0) storageError();
            close(current.value);
            current.value = child;
        }
        struct stat info{};
        if (fstat(current.value, &info) != 0 || info.st_uid != geteuid() || fchmod(current.value, 0700) != 0) storageError();
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
        while (flock(current.value, LOCK_EX | LOCK_NB) != 0) {
            if (errno != EINTR && errno != EWOULDBLOCK) storageError();
            if (std::chrono::steady_clock::now() >= deadline) {
                throw Error("Session diagnostics storage is busy (100 ms lock timeout).");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        directory_.value = current.value;
        current.value = -1;
    }
    std::string Read(const std::string& name) {
        Descriptor file(openat(directory_.value, name.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
        if (file.value < 0) {
            if (errno == ENOENT) return {};
            storageError();
        }
        regular(file.value);
        struct stat info{};
        if (fstat(file.value, &info) != 0 || info.st_size < 0 || static_cast<std::uint64_t>(info.st_size) > SessionDiagnostics::MaxFileBytes) storageError();
        std::string result(static_cast<std::size_t>(info.st_size), '\0');
        std::size_t offset = 0;
        while (offset < result.size()) {
            const auto count = read(file.value, &result[offset], result.size() - offset);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) storageError();
            offset += static_cast<std::size_t>(count);
        }
        return result;
    }
    void Write(const std::string& name, const std::string& data, bool append = false) {
        Descriptor file(openat(directory_.value, name.c_str(), O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (append ? O_APPEND : 0), 0600));
        if (file.value < 0) storageError();
        regular(file.value);
        struct stat info{};
        if (fstat(file.value, &info) != 0 || info.st_size < 0 ||
            (append && static_cast<std::uint64_t>(info.st_size) + data.size() > SessionDiagnostics::MaxFileBytes)) storageError();
        if (!append && ftruncate(file.value, 0) != 0) storageError();
        std::size_t offset = 0;
        while (offset < data.size()) {
            const auto count = write(file.value, data.data() + offset, data.size() - offset);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) storageError();
            offset += static_cast<std::size_t>(count);
        }
        if (fsync(file.value) != 0) storageError();
    }
};
#endif

std::string filename(std::size_t index) { return "events-" + std::to_string(index) + ".jsonl"; }

bool appendCurrent(Directory& directory, const std::string& line, std::int64_t now) {
    std::vector<std::string> files;
    const auto oldest = utc(now - SessionDiagnostics::RetentionSeconds);
    const auto newest = utc(now);
    const std::string marker = ",\"utc\":\"";
    const std::string suffix = "\",\"version\":1}";
    std::size_t active = 0;
    for (std::size_t i = 0; i < SessionDiagnostics::MaxFiles; ++i) {
        files.push_back(directory.Read(filename(i)));
        const auto& file = files.back();
        if (!file.empty()) active = i;
        std::size_t begin = 0;
        while (begin < file.size()) {
            const auto end = file.find('\n', begin);
            if (end == std::string::npos || end - begin > 16384 ||
                end - begin < marker.size() + 20 + suffix.size()) return false;
            const auto position = end - suffix.size() - 20 - marker.size();
            if (file.compare(position, marker.size(), marker) != 0 ||
                file.compare(end - suffix.size(), suffix.size(), suffix) != 0) return false;
            const auto time = file.substr(position + marker.size(), 20);
            // Writer-generated canonical UTC tails permit a linear retention scan without
            // parsing or re-sanitizing megabytes of history on the synchronous UI path.
            if (time <= oldest || time > newest) return false;
            begin = end + 1;
        }
    }
    if (files[active].size() + line.size() <= SessionDiagnostics::MaxFileBytes) {
        directory.Write(filename(active), line, true);
    } else if (active + 1 < SessionDiagnostics::MaxFiles) {
        directory.Write(filename(active + 1), line);
    } else {
        for (std::size_t i = 1; i < SessionDiagnostics::MaxFiles; ++i) directory.Write(filename(i - 1), files[i]);
        directory.Write(filename(SessionDiagnostics::MaxFiles - 1), line);
    }
    return true;
}

std::vector<json::Value> load(Directory& directory, std::int64_t now) {
    std::vector<json::Value> records;
    const auto oldest = utc(now - SessionDiagnostics::RetentionSeconds);
    const auto newest = utc(now);
    for (std::size_t i = 0; i < SessionDiagnostics::MaxFiles; ++i) {
        std::istringstream lines(directory.Read(filename(i)));
        std::string line;
        while (std::getline(lines, line)) {
            try {
                auto value = json::Parse(line, 16384);
                json::RequireExactKeys(value, {"version", "utc", "elapsed_ms", "session", "attempt", "event", "severity", "detail"}, "diagnostic record");
                if (value.at("version").asInteger() != 1 || value.at("elapsed_ms").asInteger() < 0 ||
                    !sessionIdValid(value.at("session").asString()) ||
                    (!value.at("attempt").asString().empty() && !hexId(value.at("attempt").asString())) ||
                    !eventValid(value.at("event").asString()) || !severityValid(value.at("severity").asString()) ||
                    !utcValid(value.at("utc").asString()) || value.at("utc").asString() <= oldest ||
                    value.at("utc").asString() > newest || value.at("detail").asString().size() > 2048) continue;
                auto object = value.asObject();
                object["detail"] = SanitizeDiagnosticDetail(value.at("detail").asString());
                records.emplace_back(std::move(object));
            } catch (const Error&) {
                // A crash-truncated or untrusted record is never copied into an export.
            }
        }
    }
    return records;
}

void save(Directory& directory, const std::vector<json::Value>& records) {
    std::vector<std::vector<std::string>> chunks(1);
    std::size_t bytes = 0;
    // Pack newest first so exceeding the limit always discards the oldest records.
    for (auto it = records.rbegin(); it != records.rend(); ++it) {
        const auto line = json::Serialize(*it) + "\n";
        if (bytes + line.size() > SessionDiagnostics::MaxFileBytes) {
            if (chunks.size() == SessionDiagnostics::MaxFiles) break;
            chunks.emplace_back();
            bytes = 0;
        }
        chunks.back().push_back(line);
        bytes += line.size();
    }
    std::reverse(chunks.begin(), chunks.end());
    for (std::size_t i = 0; i < SessionDiagnostics::MaxFiles; ++i) {
        std::string data;
        if (i < chunks.size()) {
            for (auto line = chunks[i].rbegin(); line != chunks[i].rend(); ++line) data += *line;
        }
        directory.Write(filename(i), data);
    }
}

}  // namespace

std::string SanitizeDiagnosticDetail(const std::string& detail) {
    if (detail.size() > 8192) return "[detail omitted: too long]";
    // PEM can contain whitespace, so remove the entire remainder if its terminator is missing.
    std::string value = detail;
    for (char& c : value) {
        const auto byte = static_cast<unsigned char>(c);
        // Normalize before redaction so control characters cannot split a secret label.
        if (byte < 32 || byte >= 127) c = ' ';
    }
    std::size_t begin = 0;
    while ((begin = value.find("-----BEGIN", begin)) != std::string::npos) {
        const auto endStart = value.find("-----END", begin + 10);
        const auto end = endStart == std::string::npos ? std::string::npos : value.find("-----", endStart + 8);
        value.replace(begin, end == std::string::npos ? value.size() - begin : end + 5 - begin, "[redacted]");
        begin += 10;
    }
    const auto alpha = [](char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); };
    const auto tokenCharacter = [&](char c) {
        return alpha(c) || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '+' || c == '/' || c == '.';
    };
    std::string output;
    for (std::size_t i = 0; i < value.size();) {
        if (!tokenCharacter(value[i])) { output += value[i++]; continue; }
        const auto start = i;
        while (i < value.size() && tokenCharacter(value[i])) ++i;
        const auto token = value.substr(start, i - start);
        std::string lower = token;
        for (char& c : lower) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        auto next = i;
        const bool quoted = next < value.size() && (value[next] == '"' || value[next] == '\'');
        if (quoted) ++next;
        while (next < value.size() && value[next] == ' ') ++next;
        const bool label = lower == "privatekey" || lower == "private_key" || lower == "publickey" || lower == "public_key" ||
            lower == "private-key" || lower == "public-key" || lower == "presharedkey" || lower == "preshared_key" ||
            lower == "apikey" || lower == "api_key" || lower == "access_token" ||
            lower == "password" || lower == "passwd" || lower == "secret" || lower == "token" ||
            lower == "authorization" || lower == "credential" || lower == "pair" || lower == "pairing" ||
            lower == "pairing_code" || lower == "grant" || lower == "bearer";
        const bool assignment = (alpha(token[0]) || token[0] == '_') &&
            token.find_first_of("+/") == std::string::npos && next < value.size() &&
            (value[next] == '=' || (value[next] == ':' && (label || quoted)));
        const bool metric = lower == "utc" || lower == "tick_ms" || lower == "latency_ms" ||
            lower == "rx" || lower == "tx" || lower == "hs_utc" || lower == "probe";
        if (assignment && metric && value[next] == '=') {
            auto first = next + 1;
            while (first < value.size() && value[first] == ' ') ++first;
            auto end = first;
            while (end < value.size() && value[end] != ' ' && value[end] != ',' && value[end] != ';') ++end;
            const auto measurement = value.substr(first, end - first);
            const bool number = !measurement.empty() && measurement.size() <= 20 &&
                std::all_of(measurement.begin(), measurement.end(), [&](char c) {
                    return (c >= '0' && c <= '9') || (lower == "latency_ms" && c == '.');
                }) && std::count(measurement.begin(), measurement.end(), '.') <= 1 &&
                measurement.find_first_of("0123456789") != std::string::npos;
            if (measurement == "Unknown" || measurement == "unknown" ||
                (lower == "probe" ? measurement == "ok" || measurement == "failed" : number)) {
                output += value.substr(start, end - start);
                i = end;
                continue;
            }
        }
        const bool claim = lower.compare(0, 5, "pair-") == 0 || lower.compare(0, 5, "pair_") == 0 ||
            lower.compare(0, 8, "pairing-") == 0 || lower.compare(0, 8, "pairing_") == 0 ||
            lower.compare(0, 6, "grant-") == 0 || lower.compare(0, 6, "grant_") == 0 ||
            lower.compare(0, 6, "token-") == 0 || lower.compare(0, 6, "token_") == 0;
        if (assignment || (label && i < value.size() && value[i] == ' ')) {
            while (i < value.size() && value[i] != ',' && value[i] != ';') ++i;
            output += "[redacted]";
        } else if (token.size() >= 24 || claim || std::count(token.begin(), token.end(), '.') >= 2) {
            while (i < value.size() && value[i] == '=') ++i;
            output += "[redacted]";
        } else {
            output += token;
        }
    }
    if (output.size() > 2048) output.resize(2048);
    return output;
}

SessionDiagnostics::SessionDiagnostics(std::filesystem::path directory, Clock clock)
    : directory_(std::move(directory)), clock_(std::move(clock)) {
    if (!clock_) clock_ = [] {
        return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    };
}

void SessionDiagnostics::Write(const std::string& sessionId, const std::string& attemptId, const std::string& event,
                               const std::string& severity, const std::string& detail) {
    if (!sessionIdValid(sessionId) || (!attemptId.empty() && !hexId(attemptId)) || !eventValid(event) || !severityValid(severity)) {
        throw Error("Invalid session diagnostic fields.");
    }
    Directory directory(directory_);
    const auto now = clock_();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - processStarted).count();
    const json::Value record(json::Value::Object{
        {"version", 1}, {"utc", utc(now)}, {"elapsed_ms", static_cast<std::int64_t>(elapsed)},
        {"session", sessionId}, {"attempt", attemptId}, {"event", event}, {"severity", severity},
        {"detail", SanitizeDiagnosticDetail(detail)}});
    if (appendCurrent(directory, json::Serialize(record) + "\n", now)) return;
    auto records = load(directory, now);
    records.push_back(record);
    save(directory, records);
}

std::string SessionDiagnostics::Read(const std::string& sessionId) {
    if (!sessionIdValid(sessionId)) throw Error("Invalid diagnostic session identifier.");
    Directory directory(directory_);
    const auto records = load(directory, clock_());
    save(directory, records);
    std::string output;
    for (const auto& record : records) {
        if (record.at("session").asString() != sessionId) continue;
        output += json::Serialize(record) + "\n";
    }
    return output;
}

}  // namespace tlp
