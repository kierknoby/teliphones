#include "../src/app/AppSettingsDlg.h"
#include "../src/app/ConnectPasswordDlg.h"
#include "../src/app/resource.h"
#include "../src/platform/Applications.h"
#include "../src/platform/WireGuardInstaller.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void checkSettings(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

CRect settingsControlRect(CAppSettingsDlg& dialog, int id) {
    const HWND control = dialog.GetDlgItem(id)->GetSafeHwnd();
    CRect actualControl;
    ::GetWindowRect(control, &actualControl);
    ::MapWindowPoints(nullptr, dialog.GetSafeHwnd(), reinterpret_cast<POINT*>(&actualControl), 2);
    if (id == IDC_APPS_BROWSER || id == IDC_APPS_TERMINAL || id == IDC_APPEARANCE) {
        COMBOBOXINFO info{sizeof(info)};
        if (!::GetComboBoxInfo(control, &info))
            throw std::runtime_error("query visible face of Settings combo box failed");
        // COMBOBOXINFO::rcItem is relative to the combo's client origin.
        // Map from the combo client space into the containing dialog client space.
        const HWND source = control;
        const HWND destination = dialog.GetSafeHwnd();
        RECT mapped = info.rcItem;
        ::MapWindowPoints(source, destination, reinterpret_cast<POINT*>(&mapped), 2);
        const CRect face(mapped);
        CRect contained;
        if (face.IsRectEmpty() || !contained.IntersectRect(face, actualControl) || contained != face) {
            const auto formatRect = [](const RECT& value) {
                return std::string("(") + std::to_string(value.left) + "," + std::to_string(value.top) + "," +
                    std::to_string(value.right) + "," + std::to_string(value.bottom) + ")";
            };
            throw std::runtime_error("Settings combo face conversion is outside its containing control: rawRcItem=" +
                formatRect(info.rcItem) + " sourceHwnd=" +
                std::to_string(reinterpret_cast<uintptr_t>(source)) + "(combo client) destinationHwnd=" +
                std::to_string(reinterpret_cast<uintptr_t>(destination)) + " mappedFace=" +
                formatRect(mapped) + " actualControl=" + formatRect(actualControl));
        }
        return face;
    }
    return actualControl;
}

bool intersects(const CRect& left, const CRect& right) {
    CRect overlap;
    return overlap.IntersectRect(left, right) != FALSE && !overlap.IsRectEmpty();
}

const char* settingsControlName(int id) {
    switch (id) {
        case IDC_APPS_HEADING: return "IDC_APPS_HEADING";
        case IDC_APPS_INTRO: return "IDC_APPS_INTRO";
        case IDC_APPS_BROWSER_LABEL: return "IDC_APPS_BROWSER_LABEL";
        case IDC_APPS_BROWSER: return "IDC_APPS_BROWSER";
        case IDC_APPS_LOCATE_BROWSER: return "IDC_APPS_LOCATE_BROWSER";
        case IDC_APPS_TERMINAL_LABEL: return "IDC_APPS_TERMINAL_LABEL";
        case IDC_APPS_TERMINAL: return "IDC_APPS_TERMINAL";
        case IDC_APPS_LOCATE_TERMINAL: return "IDC_APPS_LOCATE_TERMINAL";
        case IDC_APPS_STATUS: return "IDC_APPS_STATUS";
        case IDC_APPS_NOTE: return "IDC_APPS_NOTE";
        case IDC_APPEARANCE_LABEL: return "IDC_APPEARANCE_LABEL";
        case IDC_APPEARANCE: return "IDC_APPEARANCE";
        case IDC_CONNECT_STATUS: return "IDC_CONNECT_STATUS";
        case IDC_CONNECT_INSTALL: return "IDC_CONNECT_INSTALL";
        case IDC_CONNECT_CHECK: return "IDC_CONNECT_CHECK";
        case IDC_CONNECT_NOT_NOW: return "IDC_CONNECT_NOT_NOW";
        case IDC_CONNECT_PASSWORD: return "IDC_CONNECT_PASSWORD";
        case IDC_PASSWORD_LOCK_NOW: return "IDC_PASSWORD_LOCK_NOW";
        case IDC_SETUP_PBX: return "IDC_SETUP_PBX";
        case IDC_SETUP_SUPPORT: return "IDC_SETUP_SUPPORT";
        case IDC_APPS_SKIP: return "IDC_APPS_SKIP";
        case IDC_APPS_ABOUT: return "IDC_APPS_ABOUT";
        case IDOK: return "IDOK";
        case IDCANCEL: return "IDCANCEL";
        default: return "unknown Settings control";
    }
}

std::string formatSettingsRect(const RECT& rect) {
    return "(" + std::to_string(rect.left) + "," + std::to_string(rect.top) + "," +
        std::to_string(rect.right) + "," + std::to_string(rect.bottom) + ")";
}

void checkSettingsControlBounds(CAppSettingsDlg& dialog, const char* stage, int id,
                                const CRect& testedRect, const CRect& visibleRect, const CRect& client,
                                LONG footerTop, bool footer) {
    const bool withinBounds = testedRect.left >= 0 && testedRect.right <= client.right &&
        testedRect.top >= 0 && testedRect.bottom <= client.bottom;
    if (withinBounds) return;

    CWnd* control = dialog.GetDlgItem(id);
    CRect fullRect;
    control->GetWindowRect(&fullRect);
    dialog.ScreenToClient(&fullRect);
    CRect viewport(0, 0, client.right, footer ? client.bottom : std::max<LONG>(0, footerTop - 4));
    CRect effectivePortion;
    effectivePortion.IntersectRect(visibleRect, viewport);
    std::string footerGeometry;
    for (int footerId : {IDC_APPS_SKIP, IDC_APPS_ABOUT, IDOK, IDCANCEL}) {
        CWnd* footerControl = dialog.GetDlgItem(footerId);
        if (!footerControl || !footerControl->IsWindowVisible()) continue;
        CRect footerRect = settingsControlRect(dialog, footerId);
        footerGeometry += (footerGeometry.empty() ? "" : ";") + std::string(settingsControlName(footerId)) + "=" +
            formatSettingsRect(footerRect);
    }
    CRect regionBounds(0, 0, 0, 0);
    HRGN region = ::CreateRectRgn(0, 0, 0, 0);
    const int regionType = ::GetWindowRgn(control->GetSafeHwnd(), region);
    if (regionType != ERROR) ::GetRgnBox(region, &regionBounds);
    ::DeleteObject(region);

    throw std::runtime_error(std::string("visible Settings control portion remains within the content viewport or footer") +
        ": stage=" + stage + " control=" + settingsControlName(id) + " id=" + std::to_string(id) +
        " fullControl=" + formatSettingsRect(fullRect) + " testedGeometry=" + formatSettingsRect(testedRect) +
        " effectiveViewportPortion=" + formatSettingsRect(effectivePortion) +
        " parentHwnd=" + std::to_string(reinterpret_cast<uintptr_t>(::GetParent(control->GetSafeHwnd()))) +
        " viewport=" + formatSettingsRect(viewport) + " client=" + formatSettingsRect(client) +
        " footerTop=" + std::to_string(footerTop) + " footerRects={" + footerGeometry + "} footer=" + (footer ? "true" : "false") +
        " visible=" + (::IsWindowVisible(control->GetSafeHwnd()) ? "true" : "false") +
        " windowRegionType=" + std::to_string(regionType) +
        " windowRegionBounds(local)=" + formatSettingsRect(regionBounds));
}

void checkNoSettingsOverlap(CAppSettingsDlg& dialog, const char* stage) {
    const int controls[] = {
        IDC_APPS_HEADING, IDC_APPS_INTRO, IDC_APPS_BROWSER_LABEL, IDC_APPS_BROWSER,
        IDC_APPS_LOCATE_BROWSER, IDC_APPS_TERMINAL_LABEL, IDC_APPS_TERMINAL,
        IDC_APPS_LOCATE_TERMINAL, IDC_APPS_STATUS, IDC_APPS_NOTE,
        IDC_APPEARANCE_LABEL, IDC_APPEARANCE, IDC_CONNECT_STATUS,
        IDC_CONNECT_INSTALL, IDC_CONNECT_CHECK, IDC_CONNECT_NOT_NOW,
        IDC_CONNECT_PASSWORD, IDC_PASSWORD_LOCK_NOW,
        IDC_SETUP_PBX, IDC_SETUP_SUPPORT, IDC_APPS_SKIP, IDC_APPS_ABOUT, IDOK, IDCANCEL
    };
    const int groups[] = {IDC_APPS_GROUP, IDC_CONNECT_GROUP};
    const CRect client = [&]() { CRect rect; dialog.GetClientRect(&rect); return rect; }();
    LONG footerTop = client.bottom;
    for (int id : {IDC_APPS_SKIP, IDC_APPS_ABOUT, IDOK, IDCANCEL}) {
        CWnd* footer = dialog.GetDlgItem(id);
        if (footer && footer->IsWindowVisible()) footerTop = std::min(footerTop, settingsControlRect(dialog, id).top);
    }
    const auto isFooter = [](int id) {
        return id == IDC_APPS_SKIP || id == IDC_APPS_ABOUT || id == IDOK || id == IDCANCEL;
    };
    for (int id : groups) {
        CWnd* group = dialog.GetDlgItem(id);
        if (!group || !group->IsWindowVisible()) continue;
        const CRect rect = settingsControlRect(dialog, id);
        checkSettings(rect.left >= 0 && rect.top >= 0 && rect.right <= client.right && rect.bottom <= client.bottom,
                      "visible Settings section frame remains within the dialog client");
    }
    for (std::size_t i = 0; i < std::size(controls); ++i) {
        CWnd* first = dialog.GetDlgItem(controls[i]);
        if (!first || !first->IsWindowVisible()) continue;
        CRect firstRect = settingsControlRect(dialog, controls[i]);
        if (!isFooter(controls[i])) {
            firstRect.top = std::max<LONG>(firstRect.top, 0);
            firstRect.bottom = std::min<LONG>(firstRect.bottom, footerTop - 4);
            if (firstRect.bottom <= firstRect.top) continue;
        }
        checkSettingsControlBounds(dialog, stage, controls[i], firstRect, settingsControlRect(dialog, controls[i]),
                                   client, footerTop, isFooter(controls[i]));
        for (std::size_t j = i + 1; j < std::size(controls); ++j) {
            CWnd* second = dialog.GetDlgItem(controls[j]);
            if (!second || !second->IsWindowVisible()) continue;
            CRect secondRect = settingsControlRect(dialog, controls[j]);
            if (!isFooter(controls[j])) {
                secondRect.top = std::max<LONG>(secondRect.top, 0);
                secondRect.bottom = std::min<LONG>(secondRect.bottom, footerTop - 4);
                if (secondRect.bottom <= secondRect.top) continue;
            }
            checkSettings(!intersects(firstRect, secondRect),
                          "visible Settings controls do not overlap");
        }
    }
}

void checkSettingsFooterWithinClient(CAppSettingsDlg& dialog, const char* stage) {
    CRect client;
    dialog.GetClientRect(&client);
    const int minimumGap = MulDiv(8, GetDpiForWindow(dialog.GetSafeHwnd()), 96);
    for (int id : {IDC_APPS_SKIP, IDC_APPS_ABOUT, IDOK, IDCANCEL}) {
        CWnd* control = dialog.GetDlgItem(id);
        if (!control || !control->IsWindowVisible()) continue;
        const CRect rect = settingsControlRect(dialog, id);
        if (rect.left >= 0 && rect.top >= 0 && rect.right <= client.right &&
            client.bottom - rect.bottom >= minimumGap) continue;
        throw std::runtime_error(std::string("Settings footer remains inside client with spacing") +
            ": stage=" + stage + " control=" + settingsControlName(id) +
            " rect=" + formatSettingsRect(rect) + " client=" + formatSettingsRect(client) +
            " requiredBottomGap=" + std::to_string(minimumGap));
    }
}

}  // namespace

// Test-only replacements: exercise the production Settings dialog without
// detecting or installing software, changing preferences, or modifying a profile.
namespace tlp::win {
DetectedApps DetectApps(AppKind, const Preferences&) { return {}; }
std::string OpenSshClient() { return {}; }
void SavePreferences(const Preferences&) {}
WireGuardInstallation FindWireGuard() { return {}; }
SetupResult InstallWireGuard(const std::function<void(const std::string&)>&) { return {}; }
}  // namespace tlp::win

bool ManageConnectPassword(const tlp::Profile&, CWnd*) { return false; }

void RunSettingsDialogTests(CWnd* parent) {
    CAppSettingsDlg dialog(CAppSettingsDlg::Mode::Settings, std::nullopt, parent);
    checkSettings(dialog.Create(IDD_APP_SETTINGS, parent) != FALSE, "create production Settings dialog resource");
    dialog.ShowWindow(SW_SHOWNOACTIVATE);
    wchar_t title[128]{};
    GetWindowTextW(dialog.GetSafeHwnd(), title, static_cast<int>(std::size(title)));
    checkSettings(std::wstring(title) == L"TELIPHONES Settings", "Settings title remains consistent");

    CRect window, client;
    dialog.GetWindowRect(&window);
    dialog.GetClientRect(&client);
    MONITORINFO monitor{};
    monitor.cbSize = sizeof(monitor);
    checkSettings(GetMonitorInfo(MonitorFromWindow(dialog.GetSafeHwnd(), MONITOR_DEFAULTTONEAREST), &monitor) != FALSE,
                  "query Settings monitor work area");
    CRect work(monitor.rcWork);
    checkSettings(window.left >= work.left && window.top >= work.top && window.right <= work.right && window.bottom <= work.bottom,
                  "initial Settings window fits the monitor work area");
    checkSettingsFooterWithinClient(dialog, "initial");
    checkNoSettingsOverlap(dialog, "initial");

    CWnd* browser = dialog.GetDlgItem(IDC_APPS_BROWSER);
    CWnd* terminal = dialog.GetDlgItem(IDC_APPS_TERMINAL);
    checkSettings(terminal->IsWindowVisible() && !terminal->IsWindowEnabled(),
                  "terminal selection is visible but disabled when no terminal is detected");
    std::vector<int> tabSequence;
    CWnd* current = browser;
    for (std::size_t count = 0; current && count < 32; ++count) {
        if (current == browser && !tabSequence.empty()) break;
        tabSequence.push_back(current->GetDlgCtrlID());
        current = dialog.GetNextDlgTabItem(current);
    }
    const std::vector<int> expectedTabSequence = {
        IDC_APPS_BROWSER, IDC_APPS_LOCATE_BROWSER, IDC_APPS_LOCATE_TERMINAL,
        IDC_APPEARANCE, IDC_CONNECT_INSTALL, IDC_CONNECT_CHECK, IDC_CONNECT_NOT_NOW,
        IDC_APPS_ABOUT, IDOK, IDCANCEL
    };
    checkSettings(tabSequence == expectedTabSequence,
                  "Settings keyboard order skips the disabled terminal selection and includes intervening controls");

    const CRect originalWindow = window;
    dialog.SetWindowPos(nullptr, window.left, window.top, window.Width() - 80, window.Height() - 150,
                        SWP_NOZORDER | SWP_NOACTIVATE);
    dialog.GetClientRect(&client);
    checkSettingsFooterWithinClient(dialog, "compact-resize");
    SCROLLINFO scroll{sizeof(scroll), SIF_RANGE | SIF_PAGE | SIF_POS};
    checkSettings(dialog.GetScrollInfo(SB_VERT, &scroll) != FALSE && scroll.nMax > 0 &&
                  scroll.nMax - static_cast<int>(scroll.nPage) > 0,
                  "small Settings window exposes a vertical scroll range");
    const CRect saveBefore = settingsControlRect(dialog, IDOK);
    const CRect cancelBefore = settingsControlRect(dialog, IDCANCEL);
    checkSettings(saveBefore.bottom <= client.bottom && cancelBefore.bottom <= client.bottom &&
                  saveBefore.top >= 0 && cancelBefore.top >= 0,
                  "Save and Cancel remain visible in the reduced Settings window");
    const int saveBottomGap = client.bottom - saveBefore.bottom;
    const int cancelBottomGap = client.bottom - cancelBefore.bottom;
    dialog.SendMessage(WM_VSCROLL, SB_BOTTOM);
    dialog.GetClientRect(&client);
    const CRect saveAfter = settingsControlRect(dialog, IDOK);
    const CRect cancelAfter = settingsControlRect(dialog, IDCANCEL);
    checkSettings(client.bottom - saveAfter.bottom == saveBottomGap &&
                  client.bottom - cancelAfter.bottom == cancelBottomGap,
                  "Settings footer remains pinned while content scrolls");
    checkSettingsFooterWithinClient(dialog, "compact-maximum-scroll");
    checkNoSettingsOverlap(dialog, "compact-maximum-scroll");

    dialog.SendMessage(WM_VSCROLL, SB_TOP);
    CWnd* focusTarget = dialog.GetDlgItem(IDC_CONNECT_CHECK);
    focusTarget->SetFocus();
    // PreTranslateMessage posts this same reveal request after Tab navigation.
    dialog.SendMessage(WM_APP + 0x322);
    CRect focusRect = settingsControlRect(dialog, IDC_CONNECT_CHECK);
    LONG footerTop = client.bottom;
    for (int id : {IDC_APPS_SKIP, IDC_APPS_ABOUT, IDOK, IDCANCEL}) {
        CWnd* footer = dialog.GetDlgItem(id);
        if (footer && footer->IsWindowVisible()) footerTop = std::min<LONG>(footerTop, settingsControlRect(dialog, id).top);
    }
    checkSettings(focusRect.top >= 0 && focusRect.bottom <= footerTop - 8,
                  "Tab focus reveal scrolls Settings control fully above the fixed footer");
    checkNoSettingsOverlap(dialog, "compact-focus-reveal");

    dialog.SetWindowPos(nullptr, originalWindow.left, originalWindow.top, originalWindow.Width(), originalWindow.Height(),
                        SWP_NOZORDER | SWP_NOACTIVATE);
    RECT dpiBounds{originalWindow.left, originalWindow.top,
                   originalWindow.left + MulDiv(originalWindow.Width(), 144, 96),
                   originalWindow.top + MulDiv(originalWindow.Height(), 144, 96)};
    dialog.SendMessage(WM_DPICHANGED, MAKELONG(144, 144), reinterpret_cast<LPARAM>(&dpiBounds));
    dialog.GetClientRect(&client);
    checkSettingsFooterWithinClient(dialog, "dpi-144");
    checkNoSettingsOverlap(dialog, "dpi-144");
    checkSettings(settingsControlRect(dialog, IDOK).bottom <= client.bottom &&
                  settingsControlRect(dialog, IDCANCEL).bottom <= client.bottom,
                  "DPI-scaled Settings footer remains visible");
    RECT restoredBounds{originalWindow.left, originalWindow.top,
                        originalWindow.right, originalWindow.bottom};
    dialog.SendMessage(WM_DPICHANGED, MAKELONG(96, 96), reinterpret_cast<LPARAM>(&restoredBounds));
    dialog.SetWindowPos(nullptr, originalWindow.left, originalWindow.top, originalWindow.Width(), originalWindow.Height(),
                        SWP_NOZORDER | SWP_NOACTIVATE);
    checkSettingsFooterWithinClient(dialog, "dpi-96-restored");
    checkNoSettingsOverlap(dialog, "dpi-96-restored");
    dialog.DestroyWindow();
    std::puts("Native Settings dialogue tests: PASS (production MFC controls, compact geometry, keyboard order, resize and scroll)");
}
