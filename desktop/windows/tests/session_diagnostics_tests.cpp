// Standalone portable test executable; no Windows APIs are required on Unix.
#include "../src/core/SessionDiagnostics.h"
#include "../src/core/Json.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using namespace tlp;

namespace {
int checks = 0;
void check(bool value, const char* message) {
    ++checks;
    if (!value) throw Error(message);
}
template<class Action> bool throws(Action action) {
    try { action(); } catch (const Error&) { return true; }
    return false;
}
std::string read(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(file), {});
}
void write(const fs::path& path, const std::string& data) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file << data;
    if (!file) throw Error("test fixture write failed");
}
std::size_t count(const std::string& text) { return std::count(text.begin(), text.end(), '\n'); }
const std::string admin = "ws-0123456789abcdef";
const std::string support = "support-0123456789abcdef";

#ifdef _WIN32
bool privateAcl(const fs::path& path) {
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (GetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                             nullptr, nullptr, &dacl, nullptr, &descriptor) != ERROR_SUCCESS) return false;
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    bool valid = GetSecurityDescriptorControl(descriptor, &control, &revision) && (control & SE_DACL_PROTECTED) && dacl && dacl->AceCount == 2;
    HANDLE token = nullptr;
    DWORD size = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) valid = false;
    if (token) GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> user(size);
    if (!token || !size || !GetTokenInformation(token, TokenUser, user.data(), size, &size)) valid = false;
    BYTE system[SECURITY_MAX_SID_SIZE]{};
    DWORD systemSize = sizeof(system);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &systemSize)) valid = false;
    bool sawUser = false, sawSystem = false;
    if (valid) for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* entry = nullptr;
        if (!GetAce(dacl, i, &entry) || static_cast<ACE_HEADER*>(entry)->AceType != ACCESS_ALLOWED_ACE_TYPE) { valid = false; break; }
        const auto ace = static_cast<ACCESS_ALLOWED_ACE*>(entry);
        const auto sid = reinterpret_cast<PSID>(&ace->SidStart);
        if ((ace->Mask & FILE_ALL_ACCESS) != FILE_ALL_ACCESS) valid = false;
        if (EqualSid(sid, reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid)) sawUser = true;
        else if (EqualSid(sid, system)) sawSystem = true;
        else valid = false;
    }
    if (token) CloseHandle(token);
    LocalFree(descriptor);
    return valid && sawUser && sawSystem;
}
#endif

void concurrentWrite(SessionDiagnostics& store, const char* event) {
    // Busy is an explicit, bounded failure. The stress harness retries it rather than
    // assuming OS mutex fairness or hiding a failed append.
    for (unsigned attempt = 0; ; ++attempt) {
        try {
            store.Write(admin, "", event, "info", "Windows error 5");
            return;
        } catch (const Error& error) {
            if (attempt >= 20 || std::string(error.what()).find("100 ms lock timeout") == std::string::npos) throw;
        }
    }
}

void tests(const fs::path& root) {
    std::int64_t now = 1760000000;
    SessionDiagnostics store(root / "basic", [&] { return now; });
    store.Write(admin, "1234567890abcdef", "startup", "info", "WSA error 10061 (Connection refused). Retry temporarily unavailable.");
    store.Write(support, "", "connection_failed", "error", "support only");
    store.Write("application", "", "startup", "info", "");
    const auto exported = store.Read(admin);
    check(count(exported) == 1, "export must contain only exact admin session");
    check(store.Read(support).find("support-") != std::string::npos, "support has separate local correlation");
    check(exported.find("WSA error 10061") != std::string::npos && exported.find("Connection refused") != std::string::npos &&
          exported.find("Retry temporarily unavailable") != std::string::npos,
          "view/export preserves actual sanitized error code, OS reason and retry context");
    const auto record = json::Parse(exported);
    check(record.at("version").asInteger() == 1 && record.at("elapsed_ms").asInteger() >= 0 &&
          record.at("utc").asString().back() == 'Z', "schema includes version, UTC and monotonic elapsed");
    check(throws([&] { store.Read("ws-0123456789abcde"); }), "reject partial session filter");
    check(throws([&] { store.Read(""); }), "reject wildcard session filter");
    check(throws([&] { store.Write("../bad", "", "startup", "info", ""); }), "reject path as ID");
    check(throws([&] { store.Write(admin, "invalid", "startup", "info", ""); }), "reject invalid attempt");
    check(throws([&] { store.Write(admin, "", "arbitrary", "info", ""); }), "reject unlisted event");
    check(throws([&] { store.Write(admin, "", "startup", "debug", ""); }), "reject unlisted severity");

    store.Write("application", "", "ssh_runtime_cleanup_incomplete", "warning",
                "Saved connections were loaded. Temporary SSH files could not be removed: ssh.log is in use.");
    check(store.Read("application").find("ssh_runtime_cleanup_incomplete") != std::string::npos &&
          store.Read("application").find("Saved connections were loaded.") != std::string::npos,
          "startup cleanup warning is accepted without triggering a second diagnostics error");

    const std::string key(43, 'A');
    const std::string secret = "password=short-secret; {\"token\":\"short-token\"}; grant abcdef; pair-code-abcd; " +
        key + "=; -----BEGIN PRIVATE KEY-----\nPEMSECRET\n-----END PRIVATE KEY-----; "
        "Bearer bearer-value; eyJhbGci.e30.signature; control\n\t\x1b";
    const auto sanitized = SanitizeDiagnosticDetail(secret);
    check(sanitized.find("short-secret") == std::string::npos && sanitized.find("short-token") == std::string::npos &&
          sanitized.find("abcdef") == std::string::npos && sanitized.find("pair-code-abcd") == std::string::npos &&
          sanitized.find(key) == std::string::npos && sanitized.find("PEMSECRET") == std::string::npos &&
          sanitized.find("bearer-value") == std::string::npos && sanitized.find("signature") == std::string::npos,
          "redact assignments, grants, pairing, keys, PEM, bearer and JWT");
    check(sanitized.find_first_of("\n\t\x1b") == std::string::npos, "strip control characters");
    check(SanitizeDiagnosticDetail("token\x01shortsecret").find("shortsecret") == std::string::npos,
          "control characters cannot bypass secret label redaction");
    check(SanitizeDiagnosticDetail(std::string(8193, 'a')).size() <= 2048, "bound oversized detail");
    check(SanitizeDiagnosticDetail(std::string(8192, 'A')).find("AAAA") == std::string::npos, "redact maximum accepted opaque token");
    check(SanitizeDiagnosticDetail("Unable to access interface: Access is denied.").find("Access is denied") != std::string::npos,
          "preserve real OS helper errors without treating prose as a secret assignment");
    store.Write(admin, "", "measurement_error", "error", secret);
    check(read(root / "basic/events-0.jsonl").find("PEMSECRET") == std::string::npos, "redaction applies before storage");
    const std::string samples = "utc=1760000000 tick_ms=2000 probe=failed latency_ms=Unknown rx=1234 tx=5678 hs_utc=0; "
                                "utc=1760000001 tick_ms=3000 probe=ok latency_ms=12.500 rx=2000 tx=6000 hs_utc=1759999990;";
    store.Write(admin, "", "recent_measurements", "info", samples);
    check(store.Read(admin).find(samples) != std::string::npos, "recent measurements survive storage, view and export");
    store.Write(admin, "", "telemetry_changed", "warning",
                "WireGuard telemetry stage transfer failed with exit code 1: Unable to access interface: Access is denied. "
                "Reading WireGuard telemetry requires WireGuard admin interface permission.");
    check(store.Read(admin).find("Unable to access interface: Access is denied") != std::string::npos &&
          store.Read(admin).find("WireGuard admin interface permission") != std::string::npos,
          "telemetry denial reason and permission requirement survive view/export");
    const std::string admission = "The PBX session controller could not be reached (Windows error 12002). "
                                  "The WireGuard handshake with pbx.example:51821 last completed 240 seconds ago.";
    store.Write(admin, "", "admission_failed", "warning", admission);
    store.Write(admin, "", "admission_recovered", "info", "The PBX session controller answered and admitted this workstation.");
    check(store.Read(admin).find("last completed 240 seconds ago") != std::string::npos &&
          store.Read(admin).find("admission_recovered") != std::string::npos,
          "admission failure classification and recovery survive view/export");
    store.Write(admin, "", "session_summary", "info", "Stable; latency 12.5 ms; received 2000 bytes; retry unavailable.");
    check(store.Read(admin).find("Stable; latency 12.5 ms; received 2000 bytes") != std::string::npos,
          "correlated summary preserves useful sanitized detail");
    // Unknown fields, malformed JSON, and a crash-truncated tail must not be re-exported.
    auto tampered = record.asObject();
    tampered["secret"] = "not exported";
    auto modified = record.asObject();
    modified["detail"] = "Access is denied; password=tampered-secret; token short-value; " + key + "=";
    write(root / "basic/events-2.jsonl", json::Serialize(json::Value(tampered)) + "\n" +
          json::Serialize(json::Value(modified)) + "\n{\"incomplete\":");
    check(store.Read(admin).find("not exported") == std::string::npos, "reject untrusted/non-whitelisted records");
    const auto reread = store.Read(admin);
    check(reread.find("Access is denied") != std::string::npos && reread.find("tampered-secret") == std::string::npos &&
          reread.find("short-value") == std::string::npos && reread.find(key) == std::string::npos,
          "sanitize externally tampered whitelisted detail again without discarding useful error context");

    now += SessionDiagnostics::RetentionSeconds;
    check(store.Read(admin).empty() && store.Read(support).empty(), "read enforces seven-day record retention");
    check(read(root / "basic/events-0.jsonl").empty(), "expired records removed from disk, not just hidden");
    store.Write(admin, "", "startup", "info", "new");
    check(count(store.Read(admin)) == 1, "write after expiry keeps current record");
    now += SessionDiagnostics::RetentionSeconds + 1;
    store.Write(admin, "", "shutdown", "info", "current");
    check(count(store.Read(admin)) == 1, "write enforces seven-day retention");

    SessionDiagnostics rotation(root / "rotation", [&] { return now; });
    rotation.Write(admin, "", "startup", "info", "");
    auto fixture = json::Parse(read(root / "rotation/events-0.jsonl")).asObject();
    fixture["detail"] = std::string(2000, ' ');
    std::int64_t serial = 0;
    std::size_t seeded = 0;
    for (unsigned i = 0; i < 3; ++i) {
        std::string contents;
        while (true) {
            fixture["elapsed_ms"] = serial++;
            const auto line = json::Serialize(json::Value(fixture)) + "\n";
            if (contents.size() + line.size() > SessionDiagnostics::MaxFileBytes - 512) break;
            contents += line;
            ++seeded;
        }
        write(root / "rotation" / ("events-" + std::to_string(i) + ".jsonl"), contents);
    }
    const auto appendStarted = std::chrono::steady_clock::now();
    rotation.Write(admin, "", "health_changed", "info", "");
    const auto appendElapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - appendStarted).count();
    std::cout << "Routine append at approximately 3 MiB retention: " << appendElapsed << " us\n";
    // Enough new data to force eviction, not just consume the last file's slack.
    const auto fullStarted = std::chrono::steady_clock::now();
    for (unsigned i = 0; i < 4; ++i) {
        rotation.Write(admin, "ffffffffffffffff", "session_summary", "info", std::string(2048, ' '));
    }
    const auto fullElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - fullStarted).count();
    std::cout << "Four writes at full 3 MiB retention (including rotation): " << fullElapsed << " ms\n";
    const auto rotated = rotation.Read(admin);
    check(count(rotated) < seeded + 5 && rotated.find("ffffffffffffffff") != std::string::npos,
          "rotation evicts oldest records and retains newest");
    check(rotated.find("\"elapsed_ms\":0,") == std::string::npos, "oldest record was evicted");
    std::size_t files = 0;
    for (const auto& entry : fs::directory_iterator(root / "rotation")) {
        ++files;
        check(entry.file_size() <= SessionDiagnostics::MaxFileBytes, "each actual file is at most 1 MiB");
    }
    check(files == 3, "at most three storage files (no sidecar lock file)");

    SessionDiagnostics concurrent(root / "concurrent", [&] { return now; });
    std::atomic<bool> failed{false};
    std::vector<std::thread> writers;
    for (unsigned i = 0; i < 6; ++i) {
        writers.emplace_back([&] {
            try {
                SessionDiagnostics independent(root / "concurrent", [&] { return now; });
                for (unsigned j = 0; j < 15; ++j) concurrentWrite(independent, "health_changed");
            } catch (...) { failed = true; }
        });
    }
    for (auto& writer : writers) writer.join();
    check(!failed && count(concurrent.Read(admin)) == 90, "independent instances serialize threads without lost records");
#ifndef _WIN32
    std::vector<pid_t> children;
    for (unsigned i = 0; i < 3; ++i) {
        const auto pid = fork();
        if (pid < 0) throw Error("fork failed");
        if (!pid) {
            try {
                SessionDiagnostics child(root / "concurrent", [&] { return now; });
                for (unsigned j = 0; j < 10; ++j) concurrentWrite(child, "probe_changed");
                _exit(0);
            } catch (...) { _exit(1); }
        }
        children.push_back(pid);
    }
    for (auto pid : children) {
        int status = 0;
        check(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0, "child writer succeeds");
    }
    check(count(concurrent.Read(admin)) == 120, "cross-process writes do not lose/interleave records");
    const int held = open((root / "concurrent").c_str(), O_RDONLY | O_DIRECTORY);
    check(held >= 0 && flock(held, LOCK_EX) == 0, "hold storage lock for timeout test");
    const auto started = std::chrono::steady_clock::now();
    const bool timedOut = throws([&] { concurrent.Write(admin, "", "startup", "info", "must not silently drop"); });
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
    close(held);
    check(timedOut && elapsed >= 80 && elapsed < 1000, "contention fails visibly in about 100 ms, not seconds");
    struct stat mode{};
    check(stat((root / "concurrent").c_str(), &mode) == 0 && (mode.st_mode & 0777) == 0700, "directory restricted to current user");
    check(stat((root / "concurrent/events-0.jsonl").c_str(), &mode) == 0 && (mode.st_mode & 0777) == 0600, "file restricted to current user");
    fs::create_directory_symlink(root / "basic", root / "linked");
    SessionDiagnostics linked(root / "linked");
    check(throws([&] { linked.Read(admin); }), "reject directory symlink");
    fs::remove(root / "concurrent/events-0.jsonl");
    write(root / "sentinel", "unchanged");
    fs::create_symlink(root / "sentinel", root / "concurrent/events-0.jsonl");
    check(throws([&] { concurrent.Write(admin, "", "startup", "info", ""); }), "reject file symlink");
    check(read(root / "sentinel") == "unchanged", "symlink target not modified");
    fs::remove(root / "concurrent/events-0.jsonl");
    fs::create_hard_link(root / "sentinel", root / "concurrent/events-0.jsonl");
    check(throws([&] { concurrent.Read(admin); }), "reject hard-linked file");
    fs::remove(root / "concurrent/events-0.jsonl");
    check(mkfifo((root / "concurrent/events-0.jsonl").c_str(), 0600) == 0, "create FIFO fixture");
    check(throws([&] { concurrent.Read(admin); }), "reject nonregular file without blocking");
#else
    check(privateAcl(root / "concurrent") && privateAcl(root / "concurrent/events-0.jsonl"),
          "Windows directory and logfile use protected current-user/SYSTEM-only full-control ACLs");
    fs::remove(root / "concurrent/events-0.jsonl");
    write(root / "sentinel", "unchanged");
    std::error_code linkError;
    fs::create_hard_link(root / "sentinel", root / "concurrent/events-0.jsonl", linkError);
    if (!linkError) {
        check(throws([&] { concurrent.Read(admin); }), "Windows rejects hard-linked logfile");
        check(read(root / "sentinel") == "unchanged", "Windows hard-link target not modified");
        fs::remove(root / "concurrent/events-0.jsonl");
    } else {
        std::cout << "SKIP: test volume does not support hard links.\n";
    }
    fs::create_directory(root / "concurrent/events-0.jsonl");
    check(throws([&] { concurrent.Read(admin); }), "Windows rejects nonregular logfile");
    std::cout << "SKIP: Unix-only fork/flock/symlink/FIFO checks; Windows tests do not require symlink privilege.\n";
#endif
}
}  // namespace

int main() {
    // Scratch data stays under the test working directory, never in a system temporary directory.
    const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path root = fs::absolute("session-diagnostics-test-" + std::to_string(suffix));
    try {
        fs::create_directory(root);
        tests(root);
        fs::remove_all(root);
        std::cout << checks << " session diagnostics checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        fs::remove_all(root);
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
