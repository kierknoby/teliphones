#include "fixture_security.h"
#include "../src/core/Json.h"
#include "../src/platform/Win.h"
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <taskschd.h>
#include <wrl/client.h>
#include <algorithm>
#include <cstddef>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>

void FixtureWin32Error(const char* operation, DWORD error) {
    throw tlp::Error(std::string(operation) + ": expected API success; actual Win32=" +
                     std::to_string(error) + " (" + tlp::win::Narrow(tlp::win::ErrorText(error)) + ")");
}

namespace {
using Microsoft::WRL::ComPtr;
using tlp::json::Value;
using Object = Value::Object;
using Array = Value::Array;

struct LocalDelete {
    void operator()(void* value) const { if (value) LocalFree(value); }
};
using LocalMemory = std::unique_ptr<void, LocalDelete>;

struct Bstr {
    BSTR value = nullptr;
    Bstr() = default;
    explicit Bstr(const std::wstring& text) : value(SysAllocString(text.c_str())) {
        if (!value) throw tlp::Error("SysAllocString: allocation failed.");
    }
    Bstr(const Bstr&) = delete;
    Bstr& operator=(const Bstr&) = delete;
    ~Bstr() { SysFreeString(value); }
};

void check(HRESULT result, const char* operation) {
    if (FAILED(result)) {
        std::ostringstream error;
        error << operation << ": expected successful HRESULT; actual=0x"
              << std::hex << static_cast<unsigned long>(result)
              << " (" << tlp::win::Narrow(tlp::win::ErrorText(static_cast<DWORD>(result))) << ")";
        throw tlp::Error(error.str());
    }
}

std::string sidText(PSID sid) {
    if (!sid || !IsValidSid(sid)) throw tlp::Error("Security descriptor contains a missing/invalid SID.");
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(sid, &text)) FixtureWin32Error("ConvertSidToStringSidW");
    LocalMemory memory(text);
    return tlp::win::Narrow(text);
}

Object describe(PSECURITY_DESCRIPTOR descriptor) {
    if (!IsValidSecurityDescriptor(descriptor)) throw tlp::Error("IsValidSecurityDescriptor: invalid descriptor.");
    PSID owner = nullptr;
    BOOL defaulted = FALSE, present = FALSE;
    PACL dacl = nullptr;
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    if (!GetSecurityDescriptorOwner(descriptor, &owner, &defaulted))
        FixtureWin32Error("GetSecurityDescriptorOwner");
    if (!GetSecurityDescriptorControl(descriptor, &control, &revision))
        FixtureWin32Error("GetSecurityDescriptorControl");
    if (!GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted))
        FixtureWin32Error("GetSecurityDescriptorDacl");
    if (!present || !dacl || !IsValidAcl(dacl)) throw tlp::Error("Expected present, non-NULL, valid DACL.");
    LPWSTR text = nullptr;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &text, nullptr))
        FixtureWin32Error("ConvertSecurityDescriptorToStringSecurityDescriptorW");
    LocalMemory memory(text);
    Array rules;
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* raw = nullptr;
        if (!GetAce(dacl, i, &raw)) FixtureWin32Error("GetAce");
        const auto header = static_cast<ACE_HEADER*>(raw);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE && header->AceType != ACCESS_DENIED_ACE_TYPE)
            throw tlp::Error("Expected ordinary allow/deny ACE; actual ACE type=" +
                             std::to_string(header->AceType) + "; observed SDDL=" + tlp::win::Narrow(text));
        const auto ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        auto* sid = &ace->SidStart;
        constexpr auto offset = static_cast<DWORD>(offsetof(ACCESS_ALLOWED_ACE, SidStart));
        if (header->AceSize < offset + GetSidLengthRequired(0) || !IsValidSid(sid) ||
            GetLengthSid(sid) > static_cast<DWORD>(header->AceSize) - offset)
            throw tlp::Error("Expected well-formed SID within ACE bounds.");
        rules.emplace_back(Object{
            {"sid", sidText(sid)}, {"allow", header->AceType == ACCESS_ALLOWED_ACE_TYPE},
            {"inherited", (header->AceFlags & INHERITED_ACE) != 0},
            {"mask", static_cast<std::int64_t>(ace->Mask)},
            {"inheritance", header->AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)},
            {"propagation", header->AceFlags & (NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE)},
            {"unsupported_flags", header->AceFlags & ~(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE |
                                                       NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE | INHERITED_ACE)}});
    }
    return {{"owner", sidText(owner)}, {"protected", (control & SE_DACL_PROTECTED) != 0},
            {"sddl", tlp::win::Narrow(text)}, {"rules", rules}};
}

struct Scheduler {
    bool initialized = false;
    ComPtr<ITaskService> service;
    ComPtr<ITaskFolder> folder;
    Scheduler() {
        check(CoInitializeEx(nullptr, COINIT_MULTITHREADED), "CoInitializeEx");
        initialized = true;
        try {
            check(CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                                       RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr),
                  "CoInitializeSecurity(local Task Scheduler)");
            check(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                   IID_PPV_ARGS(service.GetAddressOf())), "CoCreateInstance(TaskScheduler)");
            VARIANT empty;
            VariantInit(&empty);
            check(service->Connect(empty, empty, empty, empty), "ITaskService::Connect(local)");
            Bstr root(L"\\");
            check(service->GetFolder(root.value, folder.GetAddressOf()), "ITaskService::GetFolder(root)");
        } catch (...) {
            folder.Reset();
            service.Reset();
            CoUninitialize();
            throw;
        }
    }
    ~Scheduler() {
        folder.Reset();
        service.Reset();
        if (initialized) CoUninitialize();
    }
};

void validateTaskName(const std::wstring& name) {
    const std::wstring prefix = L"TELIPHONES-sshd-test-";
    if (name.size() != prefix.size() + 16 || name.compare(0, prefix.size(), prefix) != 0 ||
        !std::all_of(name.begin() + prefix.size(), name.end(),
                     [](wchar_t c) { return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'); }))
        throw tlp::Error("Refusing task outside the unique fixture namespace.");
}

Value taskCommand(const std::wstring& kind, const std::wstring& target, const std::wstring& userSid) {
    validateTaskName(target);
    Scheduler scheduler;
    Bstr name(target);
    ComPtr<IRegisteredTask> task;
    const auto found = scheduler.folder->GetTask(name.value, task.GetAddressOf());
    if (kind == L"TaskState" && found == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) return nullptr;
    check(found, "ITaskFolder::GetTask");
    if (kind == L"TaskState") {
        TASK_STATE state{};
        check(task->get_State(&state), "IRegisteredTask::get_State");
        return static_cast<int>(state);
    }
    PSID parsedSid = nullptr;
    if (!ConvertStringSidToSidW(userSid.c_str(), &parsedSid))
        FixtureWin32Error("ConvertStringSidToSidW(task runner)");
    LocalMemory sidMemory(parsedSid);
    // The caller must be the same user whose task grant is being installed.
    if (sidText(parsedSid) != tlp::win::CurrentUserSid())
        throw tlp::Error("Task runner SID differs from the current token.");
    Bstr expected(L"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + userSid + L")");
    const auto changed = task->SetSecurityDescriptor(expected.value, TASK_DONT_ADD_PRINCIPAL_ACE);
    Bstr observed;
    const auto inspected = task->GetSecurityDescriptor(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                                     DACL_SECURITY_INFORMATION, &observed.value);
    if (FAILED(changed)) {
        std::cerr << "Expected task SDDL: " << tlp::win::Narrow(expected.value) << "\n";
        if (SUCCEEDED(inspected)) std::cerr << "Observed task SDDL: " << tlp::win::Narrow(observed.value) << "\n";
        else std::cerr << "Task descriptor inspection also failed: HRESULT=0x" << std::hex
                       << static_cast<unsigned long>(inspected) << "\n";
        check(changed, "IRegisteredTask::SetSecurityDescriptor");
    }
    check(inspected, "IRegisteredTask::GetSecurityDescriptor");
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(observed.value, SDDL_REVISION_1, &descriptor, nullptr))
        FixtureWin32Error("ConvertStringSecurityDescriptorToSecurityDescriptorW(task)");
    LocalMemory memory(descriptor);
    auto result = describe(descriptor);
    ComPtr<ITaskDefinition> definition;
    ComPtr<IPrincipal> principal;
    check(task->get_Definition(definition.GetAddressOf()), "IRegisteredTask::get_Definition");
    check(definition->get_Principal(principal.GetAddressOf()), "ITaskDefinition::get_Principal");
    Bstr user;
    check(principal->get_UserId(&user.value), "IPrincipal::get_UserId");
    // Resolve account names through LSA, not localised text comparison.
    PSID principalSid = nullptr;
    if (ConvertStringSidToSidW(user.value, &principalSid)) {
        LocalMemory principalMemory(principalSid);
        result["principal"] = sidText(principalSid);
    } else {
        DWORD sidSize = 0, domainSize = 0;
        SID_NAME_USE use{};
        LookupAccountNameW(nullptr, user.value, nullptr, &sidSize, nullptr, &domainSize, &use);
        const auto error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER) FixtureWin32Error("LookupAccountNameW(size)", error);
        std::vector<BYTE> sid(sidSize);
        std::vector<wchar_t> domain(domainSize);
        if (!LookupAccountNameW(nullptr, user.value, sid.data(), &sidSize, domain.data(), &domainSize, &use))
            FixtureWin32Error("LookupAccountNameW(task principal)");
        result["principal"] = sidText(sid.data());
    }
    TASK_LOGON_TYPE logon{};
    TASK_RUNLEVEL_TYPE level{};
    check(principal->get_LogonType(&logon), "IPrincipal::get_LogonType");
    check(principal->get_RunLevel(&level), "IPrincipal::get_RunLevel");
    result["logon_type"] = static_cast<int>(logon);
    result["run_level"] = static_cast<int>(level);
    return result;
}

Value fileState(std::wstring path) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const auto error = GetNamedSecurityInfoW(path.data(), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr, &descriptor);
    if (error != ERROR_SUCCESS) FixtureWin32Error("GetNamedSecurityInfoW(file owner/DACL)", error);
    LocalMemory memory(descriptor);
    std::vector<wchar_t> volume(MAX_PATH);
    if (!GetVolumePathNameW(path.c_str(), volume.data(), static_cast<DWORD>(volume.size())))
        FixtureWin32Error("GetVolumePathNameW(fixture)");
    DWORD flags = 0;
    if (!GetVolumeInformationW(volume.data(), nullptr, 0, nullptr, nullptr, &flags, nullptr, 0))
        FixtureWin32Error("GetVolumeInformationW(fixture)");
    if (!(flags & FS_PERSISTENT_ACLS)) throw tlp::Error("Fixture filesystem must support persistent Windows ACLs.");
    return describe(descriptor);
}

Value restrictFile(std::wstring path, const std::string& policy) {
    if (policy != "directory" && policy != "file" && policy != "host")
        throw tlp::Error("Expected fixture file ACL policy: directory, file or host.");
    const auto flags = policy == "directory" ? L"OICI" : L"";
    std::wstring sddl = L"D:P(A;" + std::wstring(flags) + L";FA;;;SY)(A;" + flags + L";FA;;;BA)";
    if (policy != "host")
        sddl += L"(A;" + std::wstring(flags) + L";FA;;;" + tlp::win::Widen(tlp::win::CurrentUserSid()) + L")";
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
        FixtureWin32Error("ConvertStringSecurityDescriptorToSecurityDescriptorW(exact fixture DACL)");
    LocalMemory memory(descriptor);
    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = nullptr;
    if (!GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted))
        FixtureWin32Error("GetSecurityDescriptorDacl(exact fixture DACL)");
    if (!present || !dacl) throw tlp::Error("Expected a non-NULL replacement fixture DACL.");
    const auto error = SetNamedSecurityInfoW(path.data(), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
    if (error != ERROR_SUCCESS) {
        std::cerr << "Expected complete replacement DACL: " << tlp::win::Narrow(sddl) << "\n";
        FixtureWin32Error("SetNamedSecurityInfoW(replace protected fixture DACL)", error);
    }
    return fileState(path);
}

Value identity() {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) FixtureWin32Error("OpenProcessToken");
    struct Token { HANDLE value; ~Token() { CloseHandle(value); } } token{raw};
    TOKEN_ELEVATION elevation{};
    DWORD bytes = 0;
    if (!GetTokenInformation(token.value, TokenElevation, &elevation, sizeof(elevation), &bytes))
        FixtureWin32Error("GetTokenInformation(TokenElevation)");
    const auto sid = tlp::win::CurrentUserSid();
    PSID rawSid = nullptr;
    if (!ConvertStringSidToSidW(tlp::win::Widen(sid).c_str(), &rawSid))
        FixtureWin32Error("ConvertStringSidToSidW(identity)");
    LocalMemory memory(rawSid);
    DWORD userSize = 0, domainSize = 0;
    SID_NAME_USE use{};
    LookupAccountSidW(nullptr, rawSid, nullptr, &userSize, nullptr, &domainSize, &use);
    const auto error = GetLastError();
    if (error != ERROR_INSUFFICIENT_BUFFER) FixtureWin32Error("LookupAccountSidW(size)", error);
    std::vector<wchar_t> user(userSize), domain(domainSize);
    if (!LookupAccountSidW(nullptr, rawSid, user.data(), &userSize, domain.data(), &domainSize, &use))
        FixtureWin32Error("LookupAccountSidW(identity)");
    wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD length = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(computer, &length)) FixtureWin32Error("GetComputerNameW");
    return Object{{"sid", sid}, {"user", tlp::win::Narrow(user.data())},
                  {"local_account", _wcsicmp(computer, domain.data()) == 0},
                  {"elevated", elevation.TokenIsElevated != 0}};
}
}

int FixtureSecurityCommand(int argc, char** argv) {
    if (argc < 3) throw tlp::Error("Expected --security Identity|File|Task|TaskState arguments.");
    const auto kind = tlp::win::Widen(argv[2]);
    Value result;
    if (kind == L"Identity" && argc == 3) result = identity();
    else if (kind == L"File" && argc == 4) result = fileState(tlp::win::Widen(argv[3]));
    else if (kind == L"RestrictFile" && argc == 5) result = restrictFile(tlp::win::Widen(argv[3]), argv[4]);
    else if ((kind == L"Task" && argc == 5) || (kind == L"TaskState" && argc == 4))
        result = taskCommand(kind, tlp::win::Widen(argv[3]), argc == 5 ? tlp::win::Widen(argv[4]) : L"");
    else throw tlp::Error("Invalid native fixture-security command/argument count.");
    std::cout << tlp::json::Serialize(result) << std::endl;
    return 0;
}
