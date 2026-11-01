#include "TeliphonesApp.h"

#include <shellapi.h>

#include <string>
#include <vector>

#include "../platform/Win.h"
#include "../platform/WireGuard.h"
#include "MainDlg.h"

CTeliphonesApp theApp;

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
        AfxMessageBox(L"TELIPHONES is already running.", MB_ICONINFORMATION);
        return FALSE;
    }

    CMainDlg dialog;
    m_pMainWnd = &dialog;
    dialog.DoModal();
    return FALSE;
}
