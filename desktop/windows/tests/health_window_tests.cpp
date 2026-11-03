#include "../src/app/ConnectionHealthDlg.h"
#include "../src/app/resource.h"

#include <cstdio>
#include <stdexcept>

namespace {

class CWindowLifecycleTest : public CDialogEx {
public:
    CWindowLifecycleTest() : CDialogEx(IDD_MAIN), health_(this) {}
    int result = 1;

protected:
    BOOL OnInitDialog() override {
        CDialogEx::OnInitDialog();
        ShowWindow(SW_SHOW);
        PostMessage(WM_APP + 100);
        return TRUE;
    }

    LRESULT WindowTests(WPARAM, LPARAM) {
        try {
            tlp::HealthPreferences preferences;
            preferences.windowX = 90000;
            preferences.windowY = -90000;
            preferences.windowWidth = 10000;
            preferences.windowHeight = 10000;
            health_.SetPreferences(preferences);
            health_.preferencesChanged = [&](const tlp::HealthPreferences& value) { preferences = value; };
            const HWND mainWindow = GetSafeHwnd();
            for (int attempt = 0; attempt < 3; ++attempt) {
                health_.ShowMonitor();
                const HWND popup = health_.GetSafeHwnd();
                check(::IsWindowVisible(mainWindow) && ::IsWindowEnabled(mainWindow), "main window remains visible and enabled");
                check(AfxGetMainWnd()->GetSafeHwnd() == mainWindow, "application main window remains unchanged");
                check(::IsWindowVisible(popup) && !health_.IsIconic(), "pop-out is visible and restored");
                check(::GetWindow(popup, GW_OWNER) == mainWindow, "explicit main-window owner");
                check((health_.GetStyle() & WS_CHILD) == 0 && (health_.GetStyle() & WS_THICKFRAME) != 0, "resizable top-level window");
                check((health_.GetExStyle() & WS_EX_APPWINDOW) != 0 && (health_.GetExStyle() & WS_EX_TOOLWINDOW) == 0, "task switcher style");
                preferences.alwaysOnTop = attempt == 1;
                health_.SetPreferences(preferences);
                check(((health_.GetExStyle() & WS_EX_TOPMOST) != 0) == preferences.alwaysOnTop, "optional topmost preference");
                CRect rectangle;
                health_.GetWindowRect(&rectangle);
                MONITORINFO monitor{};
                monitor.cbSize = sizeof(monitor);
                check(GetMonitorInfo(MonitorFromWindow(popup, MONITOR_DEFAULTTONEAREST), &monitor) != FALSE, "monitor query");
                check(rectangle.left >= monitor.rcWork.left && rectangle.top >= monitor.rcWork.top &&
                      rectangle.right <= monitor.rcWork.right && rectangle.bottom <= monitor.rcWork.bottom, "entire pop-out inside current work area");
                health_.ShowMonitor();
                check(health_.GetSafeHwnd() == popup, "repeat opening reuses one window");
                health_.ShowWindow(SW_MINIMIZE);
                health_.ShowMonitor();
                check(!health_.IsIconic() && health_.IsWindowVisible(), "reopen restores minimized window");
                health_.SendMessage(WM_CLOSE);
                check(::IsWindow(popup) && !::IsWindowVisible(popup), "close hides without destroying reusable window");
                check(::IsWindowVisible(mainWindow) && ::IsWindowEnabled(mainWindow), "close leaves main usable");
                tlp::HealthSnapshot snapshot;
                snapshot.connectedSeconds = attempt;
                health_.UpdateSnapshot(snapshot);
                check(!health_.IsWindowVisible(), "hidden monitoring update does not reopen window");
                preferences.windowX = -90000;
                preferences.windowY = 90000;
                health_.SetPreferences(preferences);
            }
            const UINT commands[] = {IDOK, IDCANCEL};
            for (UINT command : commands) {
                health_.ShowMonitor();
                health_.SendMessage(WM_COMMAND, command);
                check(!health_.IsWindowVisible() && IsWindowVisible() && IsWindowEnabled(), "Enter/Escape only hide pop-out");
            }
            check(health_.DestroyWindow() != FALSE, "explicit destruction");
            health_.ShowMonitor();
            check(health_.IsWindowVisible() && IsWindowVisible() && IsWindowEnabled(), "safe recreation after destruction");
            health_.DestroyWindow();
            std::puts("Native Connection Health window lifecycle tests: PASS");
            result = 0;
        } catch (const std::exception& error) {
            std::fprintf(stderr, "Native Connection Health window lifecycle tests: FAIL: %s\n", error.what());
        } catch (CException* error) {
            error->Delete();
            std::fputs("Native Connection Health window lifecycle tests: FAIL: MFC exception\n", stderr);
        }
        EndDialog(result);
        return 0;
    }

    DECLARE_MESSAGE_MAP()

private:
    static void check(bool passed, const char* message) {
        if (!passed) throw std::runtime_error(message);
    }
    CConnectionHealthDlg health_;
};

BEGIN_MESSAGE_MAP(CWindowLifecycleTest, CDialogEx)
    ON_MESSAGE(WM_APP + 100, &CWindowLifecycleTest::WindowTests)
END_MESSAGE_MAP()

class CWindowTestApp : public CWinApp {
public:
    BOOL InitInstance() override {
        INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_WIN95_CLASSES};
        InitCommonControlsEx(&controls);
        CWinApp::InitInstance();
        CWindowLifecycleTest dialog;
        m_pMainWnd = &dialog;
        if (dialog.DoModal() != -1) result_ = dialog.result;
        m_pMainWnd = nullptr;
        return FALSE;
    }
    int ExitInstance() override {
        CWinApp::ExitInstance();
        return result_;
    }
private:
    int result_ = 1;
};

CWindowTestApp app;

}  // namespace
