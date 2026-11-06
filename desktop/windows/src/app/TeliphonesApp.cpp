#include "TeliphonesApp.h"

#include <shellapi.h>

#include <iterator>
#include <string>
#include <vector>

#include "../platform/Win.h"
#include "../platform/WireGuard.h"
#include "MainDlg.h"

CTeliphonesApp theApp;

namespace {

std::wstring ProcessImage(DWORD processId) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (process == nullptr) return {};
    wchar_t path[MAX_PATH * 4];
    DWORD size = static_cast<DWORD>(std::size(path));
    const bool read = QueryFullProcessImageNameW(process, 0, path, &size) != FALSE;
    CloseHandle(process);
    return read ? std::wstring(path, size) : std::wstring();
}

struct ExistingInstance {
    DWORD self = GetCurrentProcessId();
    std::wstring image = ProcessImage(GetCurrentProcessId());
    HWND window = nullptr;
    DWORD processId = 0;
};

BOOL CALLBACK FindExistingWindow(HWND window, LPARAM context) {
    auto* search = reinterpret_cast<ExistingInstance*>(context);
    DWORD processId = 0;
    GetWindowThreadProcessId(window, &processId);
    if (processId == 0 || processId == search->self || search->image.empty() ||
        _wcsicmp(ProcessImage(processId).c_str(), search->image.c_str()) != 0)
        return TRUE;
    search->processId = processId;
    if (!IsWindowVisible(window)) return TRUE;
    search->window = window;
    return FALSE;
}

// Brings an existing instance forward, or explains why it cannot. Never ends the other process.
void ActivateExistingInstance() {
    ExistingInstance search;
    EnumWindows(FindExistingWindow, reinterpret_cast<LPARAM>(&search));
    if (search.window != nullptr) {
        HWND owner = GetAncestor(search.window, GA_ROOTOWNER);
        if (owner == nullptr) owner = search.window;
        if (IsIconic(owner)) ShowWindow(owner, SW_RESTORE);
        HWND target = GetLastActivePopup(owner);
        SetForegroundWindow(target != nullptr && IsWindowVisible(target) ? target : search.window);
        return;
    }
    std::wstring text = L"TELIPHONES is already running";
    if (search.processId != 0) text += L" (process ID " + std::to_wstring(search.processId) + L")";
    text += L", but it has no open window. It may still be closing connections or recovering from an error. "
            L"Wait a moment and start TELIPHONES again. If it remains without a window, end that TELIPHONES "
            L"process in Task Manager. The next start removes any tunnel or temporary SSH files it left; "
            L"saved connections, credentials and pairings are not affected.";
    AfxMessageBox(text.c_str(), MB_ICONINFORMATION);
}

}  // namespace

BOOL CTeliphonesApp::InitInstance() {
    std::vector<std::string> arguments;
    int argumentCount = 0;
    LPWSTR* argumentValues = CommandLineToArgvW(GetCommandLineW(), &argumentCount);
    if (argumentValues == nullptr) {
        AfxMessageBox(L"Windows could not read the TELIPHONES command line.", MB_ICONERROR);
        return FALSE;
    }
    for (int i = 1; i < argumentCount; ++i) arguments.push_back(tlp::win::Narrow(argumentValues[i]));
    LocalFree(argumentValues);
    // Elevated tunnel helper invocations never create a window.
    if (tlp::win::IsHelperInvocation(arguments)) {
        ExitProcess(static_cast<UINT>(tlp::win::RunTunnelHelper(arguments)));
    }

    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_WIN95_CLASSES};
    InitCommonControlsEx(&controls);
    CWinApp::InitInstance();

    HANDLE instance = CreateMutexW(nullptr, TRUE, L"Local\\TELIPHONES-Desktop");
    if (instance != nullptr && GetLastError() == ERROR_ALREADY_EXISTS) {
        ActivateExistingInstance();
        return FALSE;
    }

    CMainDlg dialog;
    m_pMainWnd = &dialog;
    dialog.DoModal();
    return FALSE;
}
