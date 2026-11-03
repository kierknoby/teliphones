#include "../src/app/ConnectionHealthDlg.h"
#include "../src/app/resource.h"
#include "../src/app/DesktopLayout.h"

#include <cstdio>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {

class CWindowLifecycleTest : public CAppearanceDialog {
public:
    CWindowLifecycleTest() : CAppearanceDialog(IDD_MAIN), health_(this) {}
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
        CAppearanceDialog::OnInitDialog();
        ShowWindow(SW_SHOW);
        PostMessage(WM_APP + 100);
        return TRUE;
    }

    LRESULT WindowTests(WPARAM, LPARAM) {
        try {
            LayoutTests();
            AppearanceTests();
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
    static void PumpAppearance() {
        MSG message{};
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    static COLORREF Background(HWND window, UINT message, HWND control = nullptr) {
        HDC dc = ::GetDC(window);
        const auto brush = reinterpret_cast<HBRUSH>(::SendMessageW(window, message,
            reinterpret_cast<WPARAM>(dc), reinterpret_cast<LPARAM>(control ? control : window)));
        LOGBRUSH info{};
        const bool valid = brush && GetObjectW(brush, sizeof(info), &info) == sizeof(info);
        ::ReleaseDC(window, dc);
        check(valid, "control supplies an appearance brush");
        return info.lbColor;
    }

    void AppearanceTests() {
        using tlp::Appearance;
        std::vector<std::unique_ptr<CAppearanceDialog>> dialogs;
        for (UINT resource : {IDD_PAIR, IDD_SUPPORT, IDD_APP_SETTINGS, IDD_SESSION_LOG, IDD_HEALTH_LIMITS, IDD_APP_MESSAGE}) {
            auto dialog = std::make_unique<CAppearanceDialog>(resource, this);
            check(dialog->Create(resource, this) != FALSE, "create application dialog resource with shared appearance base");
            dialog->ShowWindow(SW_SHOWNOACTIVATE);
            dialogs.push_back(std::move(dialog));
        }
        health_.ShowMonitor();
        for (auto mode : {Appearance::System, Appearance::Light, Appearance::Dark}) {
            tlp::ui::SetAppearance(mode);
            for (bool systemDark : {false, true, false}) {
                tlp::ui::SimulateSystemAppearance(systemDark, false);
                PumpAppearance();
                const auto expected = tlp::PaletteFor(tlp::UseDarkAppearance(mode, systemDark, false));
                check(tlp::ui::Colours().Values() == expected.Values(), "live simulated system event respects selected mode");
                check(Background(m_hWnd, WM_CTLCOLORDLG) == expected.background, "main dialog background follows theme");
                const HWND list = layout_.Find(IDC_PROFILES)->GetSafeHwnd();
                check(ListView_GetBkColor(list) == expected.surface && ListView_GetTextColor(list) == expected.text,
                    "PBX list colours update immediately");
                const HWND edit = layout_.Find(IDC_DETAILS)->GetSafeHwnd();
                check(Background(m_hWnd, WM_CTLCOLORSTATIC, edit) == expected.surface, "read-only details follow theme");
                for (const auto& dialog : dialogs) {
                    check(Background(dialog->GetSafeHwnd(), WM_CTLCOLORDLG) == expected.background,
                        "every currently open application dialog follows theme");
                }
                check(Background(health_.GetSafeHwnd(), WM_CTLCOLORDLG) == expected.background,
                    "open health pop-out follows theme");
                check(IsWindowVisible() && IsWindowEnabled(), "appearance does not disable or hide main window");
                ControlAppearanceTests();
                ListAppearanceTests();
                GraphAppearanceTests();
            }
        }
        health_.SendMessage(WM_CLOSE);
        dialogs.front()->ShowWindow(SW_HIDE);
        tlp::ui::SetAppearance(Appearance::Light);
        tlp::ui::SetAppearance(Appearance::Dark);
        check(!health_.IsWindowVisible() && !dialogs.front()->IsWindowVisible(), "theme switch never reopens hidden windows");
        health_.ShowMonitor();
        check(Background(health_.GetSafeHwnd(), WM_CTLCOLORDLG) == tlp::ui::Colours().background,
            "reopened pop-out uses latest theme");
        tlp::ui::SimulateSystemAppearance(true, true);
        PumpAppearance();
        check(tlp::ui::HighContrast(), "live simulated accessibility event overrides forced Dark");
        check(tlp::ui::Colours().surface == GetSysColor(COLOR_WINDOW) &&
            tlp::ui::Colours().text == GetSysColor(COLOR_WINDOWTEXT), "high contrast uses actual Windows system colours");
        ComboHeightTests();
        GraphAppearanceTests();
        tlp::ui::SimulateSystemAppearance(false, false);
        PumpAppearance();
        tlp::ui::SetAppearance(Appearance::System);
        for (auto& dialog : dialogs) dialog->DestroyWindow();
        health_.SendMessage(WM_CLOSE);
        MessageAppearanceTests();
        std::puts("Native appearance tests: PASS (simulated Windows theme/accessibility notifications; no OS settings changed)");
    }

    static COLORREF ControlPixel(HWND window, int x, int y) {
        RECT rectangle{};
        ::GetClientRect(window, &rectangle);
        HDC screen = ::GetDC(window);
        HDC dc = CreateCompatibleDC(screen);
        HBITMAP bitmap = CreateCompatibleBitmap(screen, std::max<LONG>(1, rectangle.right), std::max<LONG>(1, rectangle.bottom));
        check(dc && bitmap, "create native control paint buffer");
        const auto previous = SelectObject(dc, bitmap);
        ::SendMessageW(window, WM_PRINTCLIENT, reinterpret_cast<WPARAM>(dc), PRF_CLIENT | PRF_ERASEBKGND);
        const COLORREF pixel = GetPixel(dc, x, y);
        SelectObject(dc, previous);
        DeleteObject(bitmap);
        DeleteDC(dc);
        ::ReleaseDC(window, screen);
        return pixel;
    }

    void ControlAppearanceTests() {
        const auto& palette = tlp::ui::Colours();
        const HWND button = layout_.Find(IDC_SETTINGS)->GetSafeHwnd();
        const auto pixel = ControlPixel(button, 6, 4);
        check(pixel == palette.button || pixel == palette.hover || pixel == palette.selection,
            "native button paint uses current palette");
        const HWND combo = layout_.Find(IDC_HEALTH_PLOT)->GetSafeHwnd();
        ::SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Appearance test"));
        ::SendMessageW(combo, CB_SETCURSEL, 0, 0);
        RECT rectangle{};
        ::GetClientRect(combo, &rectangle);
        check(ControlPixel(combo, 4, rectangle.bottom / 2) == palette.surface, "closed dropdown uses current palette");
        COMBOBOXINFO info{sizeof(info)};
        check(GetComboBoxInfo(combo, &info) != FALSE, "dropdown list is available");
        check(Background(combo, WM_CTLCOLORLISTBOX, info.hwndList) == palette.surface, "dropdown list background follows theme");
        const auto previousFocus = ::GetFocus();
        const auto previousUiState = ::SendMessageW(combo, WM_QUERYUISTATE, 0, 0);
        ::SetFocus(combo);
        ::SendMessageW(combo, WM_UPDATEUISTATE, MAKEWPARAM(UIS_SET, UISF_HIDEFOCUS), 0);
        CClientDC screen(CWnd::FromHandle(combo));
        CDC selectionDc;
        CBitmap selectionBitmap;
        check(selectionDc.CreateCompatibleDC(&screen) &&
            selectionBitmap.CreateCompatibleBitmap(&screen, rectangle.right, rectangle.bottom),
            "create combo selection paint buffer");
        CBitmap* previousBitmap = selectionDc.SelectObject(&selectionBitmap);
        selectionDc.FillSolidRect(&rectangle, palette.error);
        DRAWITEMSTRUCT selection{};
        selection.CtlType = ODT_COMBOBOX;
        selection.itemID = static_cast<UINT>(-1);
        selection.itemAction = ODA_DRAWENTIRE;
        selection.itemState = ODS_COMBOBOXEDIT | ODS_SELECTED | ODS_FOCUS;
        selection.hwndItem = combo;
        selection.hDC = selectionDc.GetSafeHdc();
        selection.rcItem = info.rcItem;
        check(::SendMessageW(::GetParent(combo), WM_DRAWITEM, ::GetDlgCtrlID(combo),
            reinterpret_cast<LPARAM>(&selection)) != 0, "native combo selection notification is handled");
        bool cleanSelection = true;
        for (int y = info.rcItem.top; y < info.rcItem.bottom; ++y)
            for (int x = info.rcItem.left; x < info.rcItem.right; ++x)
                cleanSelection = cleanSelection && selectionDc.GetPixel(x, y) == palette.surface;
        check(cleanSelection, "closed combo owner-draw preserves surface and respects hidden focus cues");
        check(selectionDc.GetPixel(0, 0) == palette.error, "combo selection painting does not overwrite its frame");
        check(ControlPixel(combo, info.rcItem.left + 1, info.rcItem.top) == palette.surface,
            "full combo repaint has no focus overlay against the selection edge");
        selection.itemState = ODS_SELECTED | ODS_NOFOCUSRECT;
        check(::SendMessageW(::GetParent(combo), WM_DRAWITEM, ::GetDlgCtrlID(combo),
            reinterpret_cast<LPARAM>(&selection)) != 0, "dropdown row selection notification is handled");
        check(selectionDc.GetPixel(info.rcItem.left + 1, info.rcItem.top + 1) == palette.selection,
            "open dropdown rows retain selection highlighting");
        selectionDc.SelectObject(previousBitmap);
        ::SendMessageW(combo, WM_UPDATEUISTATE,
            MAKEWPARAM(previousUiState & UISF_HIDEFOCUS ? UIS_SET : UIS_CLEAR, UISF_HIDEFOCUS), 0);
        ::SetFocus(previousFocus);
        ::SendMessageW(combo, CB_RESETCONTENT, 0, 0);

        CMenu menu;
        check(menu.CreatePopupMenu() != FALSE, "create native context menu");
        menu.AppendMenu(MF_STRING, 20001, L"&Copy\tCtrl+C");
        menu.AppendMenu(MF_STRING, 20002, L"&Clear");
        menu.AppendMenu(MF_STRING | MF_GRAYED, 20003, L"&Disabled");
        menu.AppendMenu(MF_STRING, 20004, L"Save && Exit");
        menu.AppendMenu(MF_STRING, 20005, L"&Select All");
        SendMessage(WM_INITMENUPOPUP, reinterpret_cast<WPARAM>(menu.GetSafeHmenu()), 0);
        MENUITEMINFOW item{sizeof(item)};
        item.fMask = MIIM_FTYPE | MIIM_DATA;
        check(GetMenuItemInfoW(menu.GetSafeHmenu(), 0, TRUE, &item) != FALSE && (item.fType & MFT_OWNERDRAW),
            "context menu adopts theme");
        MEASUREITEMSTRUCT measure{};
        measure.CtlType = ODT_MENU;
        measure.itemData = item.dwItemData;
        check(SendMessage(WM_MEASUREITEM, 0, reinterpret_cast<LPARAM>(&measure)) != 0 && measure.itemHeight > 0,
            "menu uses DPI-scaled native font measurement");
        auto mnemonic = [&](wchar_t character) {
            return SendMessage(WM_MENUCHAR, MAKEWPARAM(character, MF_POPUP), reinterpret_cast<LPARAM>(menu.GetSafeHmenu()));
        };
        check(HIWORD(mnemonic(L's')) == MNC_EXECUTE && LOWORD(mnemonic(L's')) == 4,
            "owner-drawn menu supports unique keyboard mnemonic");
        check(HIWORD(mnemonic(L'c')) == MNC_SELECT && LOWORD(mnemonic(L'c')) == 0,
            "duplicate menu mnemonics select first enabled match");
        MENUITEMINFOW highlighted{sizeof(highlighted)};
        highlighted.fMask = MIIM_STATE;
        highlighted.fState = MFS_HILITE;
        check(SetMenuItemInfoW(menu.GetSafeHmenu(), 0, TRUE, &highlighted) != FALSE,
            "set deterministic keyboard menu selection");
        check(HIWORD(mnemonic(L'c')) == MNC_SELECT && LOWORD(mnemonic(L'c')) == 1,
            "duplicate menu mnemonics cycle to next match");
        check(HIWORD(mnemonic(L'd')) == MNC_IGNORE && HIWORD(mnemonic(L'e')) == MNC_IGNORE,
            "menu mnemonics skip disabled items and escaped ampersands");
        SendMessage(WM_UNINITMENUPOPUP, reinterpret_cast<WPARAM>(menu.GetSafeHmenu()), 0);
        check(GetMenuItemInfoW(menu.GetSafeHmenu(), 0, TRUE, &item) != FALSE && !(item.fType & MFT_OWNERDRAW) &&
            item.dwItemData == 0, "menu lifetime restores original item ownership");
    }

    void ComboHeightTests() {
        const HWND combo = layout_.Find(IDC_HEALTH_PLOT)->GetSafeHwnd();
        const auto originalFont = ::SendMessageW(combo, WM_GETFONT, 0, 0);
        for (int dpi : {96, 120, 144, 192}) {
            CFont font;
            LOGFONT specification{};
            specification.lfHeight = -MulDiv(9, dpi, 72);
            wcscpy_s(specification.lfFaceName, L"Segoe UI");
            check(font.CreateFontIndirect(&specification) != FALSE, "create accessible combo font");
            ::SendMessageW(combo, WM_SETFONT, reinterpret_cast<WPARAM>(font.GetSafeHandle()), FALSE);
            CClientDC dc(CWnd::FromHandle(combo));
            CFont* previous = dc.SelectObject(&font);
            TEXTMETRIC metrics{};
            dc.GetTextMetrics(&metrics);
            dc.SelectObject(previous);
            const auto height = ::SendMessageW(combo, CB_GETITEMHEIGHT, 0, 0);
            check(height >= metrics.tmHeight && ::SendMessageW(combo, CB_GETITEMHEIGHT, static_cast<WPARAM>(-1), 0) == height,
                "high contrast updates both dropdown item and selection heights after font changes");
            ::SendMessageW(combo, WM_SETFONT, originalFont, FALSE);
        }
    }

    void ListAppearanceTests() {
        const HWND list = layout_.Find(IDC_PROFILES)->GetSafeHwnd();
        LVCOLUMNW column{};
        column.mask = LVCF_WIDTH;
        column.cx = 100;
        check(ListView_InsertColumn(list, 0, &column) == 0 && ListView_InsertColumn(list, 1, &column) == 1,
            "create PBX list columns for owner-draw clipping test");
        std::wstring name(120, L'W');
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.pszText = name.data();
        check(ListView_InsertItem(list, &item) == 0, "insert long PBX name");
        CClientDC screen(CWnd::FromHandle(list));
        CDC dc;
        CBitmap bitmap;
        check(dc.CreateCompatibleDC(&screen) && bitmap.CreateCompatibleBitmap(&screen, 240, 32),
            "create PBX list rendering buffer");
        CBitmap* previous = dc.SelectObject(&bitmap);
        for (bool selected : {false, true}) {
            ListView_SetItemState(list, 0, selected ? LVIS_SELECTED : 0, LVIS_SELECTED | LVIS_FOCUSED);
            NMLVCUSTOMDRAW draw{};
            draw.nmcd.hdr.hwndFrom = list;
            draw.nmcd.hdr.code = NM_CUSTOMDRAW;
            draw.nmcd.dwDrawStage = CDDS_ITEMPREPAINT;
            draw.nmcd.hdc = dc.GetSafeHdc();
            draw.nmcd.rc = {0, 0, 240, 32};
            const auto background = selected ? tlp::ui::Colours().selection : tlp::ui::Colours().surface;
            dc.FillSolidRect(0, 0, 240, 32, background);
            check(::SendMessageW(::GetParent(list), WM_NOTIFY, 0, reinterpret_cast<LPARAM>(&draw)) == CDRF_SKIPDEFAULT,
                "nested PBX list custom-draw notification is handled");
            bool clipped = true;
            for (int x = 101; x < 198; ++x)
                for (int y = 1; y < 31; ++y) clipped = clipped && dc.GetPixel(x, y) == background;
            check(clipped, "long PBX name never paints into the adjacent column");
        }
        dc.SelectObject(previous);
        ListView_DeleteAllItems(list);
        ListView_DeleteColumn(list, 1);
        ListView_DeleteColumn(list, 0);
    }

    static void CALLBACK AnswerMessage(HWND, UINT, UINT_PTR timer, DWORD) {
        const HWND window = ::GetActiveWindow();
        if (window && ::GetWindow(window, GW_OWNER) == messageOwner_ && ::GetDlgItem(window, IDC_MESSAGE_FIRST)) {
            ::KillTimer(nullptr, timer);
            ::SendMessageW(window, WM_COMMAND, MAKEWPARAM(messageButton_, BN_CLICKED),
                reinterpret_cast<LPARAM>(::GetDlgItem(window, messageButton_)));
        }
    }

    void MessageAppearanceTests() {
        const UINT modes[] = {MB_OK | MB_ICONERROR, MB_OKCANCEL | MB_ICONWARNING,
            MB_YESNO | MB_ICONQUESTION, MB_YESNOCANCEL | MB_ICONWARNING};
        const int buttons[] = {IDC_MESSAGE_FIRST, IDC_MESSAGE_SECOND, IDC_MESSAGE_SECOND, IDC_MESSAGE_THIRD};
        const int answers[] = {IDOK, IDCANCEL, IDNO, IDCANCEL};
        for (int i = 0; i < 4; ++i) {
            SetActiveWindow();
            messageOwner_ = ::GetActiveWindow();
            if (!messageOwner_) messageOwner_ = GetSafeHwnd();
            messageButton_ = buttons[i];
            const UINT_PTR timer = ::SetTimer(nullptr, 0, 10, AnswerMessage);
            check(timer != 0, "create deterministic message-dialog response");
            const int result = tlp::ui::ShowMessage(L"Appearance test: preserve confirmation and cancellation semantics.", modes[i]);
            ::KillTimer(nullptr, timer);
            check(result == answers[i], "themed errors and confirmations preserve original response codes");
        }
    }

    void GraphAppearanceTests() {
        const auto& palette = tlp::ui::Colours();
        tlp::HealthSnapshot snapshot;
        snapshot.snapshotTimestampMs = 30000;
        for (int i = 0; i < 15; ++i) {
            tlp::HealthSample sample;
            sample.timestampMs = i * 2000 + 1000;
            sample.tunnelKnown = true;
            sample.tunnelRunning = true;
            sample.probeKnown = true;
            sample.probeSucceeded = i != 8;
            if (sample.probeSucceeded) sample.latencyMs = 20 + i * 5;
            if (i % 3 == 0) {
                sample.wireGuardTelemetryAttempted = true;
                sample.receivedBytes = i * 1000;
                sample.transmittedBytes = i * 500;
            }
            snapshot.samples.push_back(sample);
        }
        CDC dc;
        check(dc.CreateCompatibleDC(nullptr) != FALSE, "create appearance graph DC");
        BITMAPINFO info{};
        info.bmiHeader.biSize = sizeof(info.bmiHeader);
        info.bmiHeader.biWidth = 480;
        info.bmiHeader.biHeight = -240;
        info.bmiHeader.biPlanes = 1;
        info.bmiHeader.biBitCount = 32;
        info.bmiHeader.biCompression = BI_RGB;
        void* bits = nullptr;
        HBITMAP bitmap = CreateDIBSection(dc.GetSafeHdc(), &info, DIB_RGB_COLORS, &bits, nullptr, 0);
        check(bitmap != nullptr, "create graph pixel buffer");
        const auto previousBitmap = SelectObject(dc.GetSafeHdc(), bitmap);
        for (int dpi : {96, 120, 144, 192}) {
            CFont font;
            LOGFONT specification{};
            specification.lfHeight = -MulDiv(9, dpi, 72);
            wcscpy_s(specification.lfFaceName, L"Segoe UI");
            check(font.CreateFontIndirect(&specification) != FALSE, "create scaled graph font");
            CFont* previousFont = dc.SelectObject(&font);
            for (int mode = 0; mode < 3; ++mode) {
                DrawConnectionHealthGraph(dc, CRect(0, 0, 480, 240), snapshot, 60, mode);
                GdiFlush();
                check(dc.GetPixel(0, 0) == palette.graph, "graph background follows theme at every DPI input");
                auto contains = [&](tlp::Colour colour) {
                    const unsigned dibColour = ((colour & 255) << 16) | (colour & 0xFF00) | ((colour >> 16) & 255);
                    const auto pixels = static_cast<const unsigned*>(bits);
                    for (int i = 0; i < 480 * 240; ++i) if ((pixels[i] & 0xFFFFFF) == dibColour) return true;
                    return false;
                };
                if (!tlp::ui::HighContrast()) {
                    check(contains(mode == 0 ? palette.latency : mode == 1 ? palette.download : palette.error),
                        "graph primary series renders selected palette pixels");
                    if (mode == 1) check(contains(palette.upload), "upload and download use distinct palette pixels");
                }
            }
            dc.SelectObject(previousFont);
        }
        SelectObject(dc.GetSafeHdc(), previousBitmap);
        DeleteObject(bitmap);
    }

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
                const int fixed[] = {IDC_CONNECT, IDC_DISCONNECT, IDC_OPEN_GUI, IDC_OPEN_SSH, IDC_SETTINGS, IDCANCEL,
                    IDC_PRODUCT_FOOTER};
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
    inline static HWND messageOwner_ = nullptr;
    inline static int messageButton_ = IDC_MESSAGE_FIRST;
};

BEGIN_MESSAGE_MAP(CWindowLifecycleTest, CAppearanceDialog)
    ON_WM_MOUSEWHEEL()
    ON_MESSAGE(WM_APP + 100, &CWindowLifecycleTest::WindowTests)
END_MESSAGE_MAP()

class CWindowTestApp : public CWinApp {
public:
    BOOL InitInstance() override {
        INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_WIN95_CLASSES};
        InitCommonControlsEx(&controls);
        CWinApp::InitInstance();
        tlp::ui::SimulateSystemAppearance(false, false);
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
