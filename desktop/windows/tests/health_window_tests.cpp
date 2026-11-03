#include "../src/app/ConnectionHealthDlg.h"
#include "../src/app/resource.h"
#include "../src/app/DesktopLayout.h"

#include <cstdio>
#include <stdexcept>

namespace {

class CWindowLifecycleTest : public CDialogEx {
public:
    CWindowLifecycleTest() : CDialogEx(IDD_MAIN), health_(this) {}
    int result = 1;

protected:
    BOOL PreTranslateMessage(MSG* message) override {
        const BOOL handled = CDialogEx::PreTranslateMessage(message);
        if (message->message == WM_KEYDOWN) layout_.RevealFocus();
        return handled;
    }

    BOOL OnCommand(WPARAM wparam, LPARAM lparam) override {
        if (lparam != 0 && HIWORD(wparam) == BN_CLICKED && LOWORD(wparam) != IDCANCEL) {
            lastAction_ = LOWORD(wparam);
            return TRUE;
        }
        return CDialogEx::OnCommand(wparam, lparam);
    }

    BOOL OnInitDialog() override {
        CDialogEx::OnInitDialog();
        ShowWindow(SW_SHOW);
        PostMessage(WM_APP + 100);
        return TRUE;
    }

    LRESULT WindowTests(WPARAM, LPARAM) {
        try {
            LayoutTests();
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
    afx_msg BOOL OnMouseWheel(UINT, short delta, CPoint) { return layout_.Wheel(delta); }

private:
    void LayoutTests() {
        layout_.Initialize(*this);
        const int sizes[][2] = {{1024, 728}, {1366, 728}, {1920, 1040}, {420, 300}, {2560, 1400}};
        const UINT dpis[] = {96, 120, 144, 192};
        for (UINT dpi : dpis) {
            layout_.SetDpi(dpi);
            for (const auto& size : sizes) {
                SetWindowPos(nullptr, 0, 0, size[0], size[1], SWP_NOZORDER | SWP_NOACTIVATE);
                layout_.Arrange();
                CRect client;
                GetClientRect(&client);
                const int fixed[] = {IDC_CONNECT, IDC_DISCONNECT, IDC_OPEN_GUI, IDC_OPEN_SSH, IDC_SETTINGS, IDCANCEL};
                for (int id : fixed) {
                    CRect rectangle;
                    layout_.Find(id)->GetWindowRect(&rectangle);
                    ScreenToClient(&rectangle);
                    // Extreme test sizes below the scaled minimum are not user-resizable sizes.
                    if (size[0] >= MulDiv(420, static_cast<int>(dpi), 96) &&
                        size[1] >= MulDiv(300, static_cast<int>(dpi), 96)) {
                        check(rectangle.left >= 0 && rectangle.top >= 0 && rectangle.right <= client.right &&
                            rectangle.bottom <= client.bottom, "critical actions stay inside client area");
                    }
                }
                CWnd* viewport = CDialogEx::GetDlgItem(IDC_CONTENT_VIEWPORT);
                SCROLLINFO info{sizeof(info), SIF_ALL};
                viewport->GetScrollInfo(SB_VERT, &info);
                viewport->SendMessage(WM_VSCROLL, SB_BOTTOM);
                layout_.Find(IDC_SESSION_LOG)->SetFocus();
                layout_.RevealFocus();
                CRect button, visible;
                layout_.Find(IDC_SESSION_LOG)->GetWindowRect(&button);
                viewport->GetWindowRect(&visible);
                if (visible.Height() >= button.Height()) {
                    check(button.top >= visible.top && button.bottom <= visible.bottom, "scrolled content is keyboard reachable");
                }
                viewport->SendMessage(WM_VSCROLL, SB_TOP);
                viewport->SendMessage(WM_MOUSEWHEEL, MAKEWPARAM(0, static_cast<WORD>(-WHEEL_DELTA)), 0);
                SCROLLINFO after{sizeof(after), SIF_ALL};
                viewport->GetScrollInfo(SB_VERT, &after);
                check(after.nPos >= 0 && after.nPos <= std::max(0, after.nMax - static_cast<int>(after.nPage) + 1),
                    "wheel scroll remains bounded");
            }
        }
        layout_.SetDpi(GetDpiForWindow(m_hWnd));
        layout_.InitialPosition();
        for (int id : {IDC_ADD_PBX, IDC_REMOVE, IDC_ADD_SUPPORT, IDC_UPDATE_GRANT, IDC_CONNECT,
                       IDC_DISCONNECT, IDC_OPEN_GUI, IDC_OPEN_SSH, IDC_SETTINGS, IDC_CONNECTION_HEALTH, IDC_SESSION_LOG}) {
            lastAction_ = 0;
            layout_.Find(id)->SendMessage(BM_CLICK);
            check(lastAction_ == id, "management and connection commands reach the controller after reparenting");
        }
        layout_.Find(IDC_ADD_PBX)->SetFocus();
        MSG key{};
        key.hwnd = layout_.Find(IDC_ADD_PBX)->GetSafeHwnd();
        key.message = WM_KEYDOWN;
        key.wParam = VK_TAB;
        PreTranslateMessage(&key);
        check(GetFocus() && GetFocus()->GetDlgCtrlID() == IDC_REMOVE, "native Tab navigation follows management layout");
        const wchar_t* states[] = {
            L"Not connected", L"Connected for: 0 s\r\nAuthorisation remaining: 59 min 58 s",
            L"Authorisation remaining: Until revoked", L"Authorisation remaining: Expired"
        };
        for (const auto* state : states) {
            layout_.Find(IDC_HEALTH_INLINE_TEXT)->SetWindowText(state);
            layout_.Arrange();
            check(IsWindowVisible() && IsWindowEnabled(), "authorization display does not affect layout lifecycle");
        }
        tlp::HealthSnapshot snapshot;
        const auto now = static_cast<std::int64_t>(GetTickCount64());
        snapshot.snapshotTimestampMs = now;
        for (int i = 0; i < 15; ++i) {
            tlp::HealthSample sample;
            sample.timestampMs = now - (14 - i) * 2000;
            sample.tunnelKnown = true;
            sample.tunnelRunning = i != 10;
            sample.probeKnown = i != 5;
            sample.probeSucceeded = i != 8 && i != 9;
            if (sample.probeKnown && sample.probeSucceeded) sample.latencyMs = 20 + i * 5;
            if (i % 3 == 0) {
                sample.wireGuardTelemetryAttempted = true;
                sample.receivedBytes = i * 1000;
                sample.transmittedBytes = i * 500;
            }
            snapshot.samples.push_back(sample);
        }
        CWnd* graph = layout_.Find(IDC_HEALTH_INLINE_GRAPH);
        CRect rectangle;
        graph->GetClientRect(&rectangle);
        CClientDC dc(graph);
        dc.SelectObject(graph->GetFont());
        for (int mode = 0; mode < 3; ++mode) {
            DrawConnectionHealthGraph(dc, rectangle, snapshot, 60, mode);
            DrawConnectionHealthGraph(dc, rectangle, snapshot, 300, mode);
        }
    }

    static void check(bool passed, const char* message) {
        if (!passed) throw std::runtime_error(message);
    }
    CConnectionHealthDlg health_;
    CDesktopLayout layout_;
    int lastAction_ = 0;
};

BEGIN_MESSAGE_MAP(CWindowLifecycleTest, CDialogEx)
    ON_WM_MOUSEWHEEL()
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
