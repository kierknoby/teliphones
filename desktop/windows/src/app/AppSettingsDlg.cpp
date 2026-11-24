#include "AppSettingsDlg.h"
#include "ConnectPasswordDlg.h"

#include <commdlg.h>

#include <algorithm>
#include <exception>
#include <iterator>
#include <memory>

#include "../platform/Applications.h"
#include "../platform/Win.h"
#include "../platform/WireGuardInstaller.h"
#include "resource.h"
#include "Version.h"

using tlp::AppKind;
using tlp::win::Widen;

namespace {

void ShowError(const std::string& text) { tlp::ui::ShowMessage(Widen(text).c_str(), MB_ICONERROR); }

bool Contains(const std::vector<std::string>& ids, const std::string& id) { return std::find(ids.begin(), ids.end(), id) != ids.end(); }

int ScaleDialogUnits(int value, int dpi, int referenceDpi) {
    return MulDiv(value, dpi, referenceDpi);
}

}  // namespace

BEGIN_MESSAGE_MAP(CSettingsViewport, CWnd)
    ON_WM_VSCROLL()
END_MESSAGE_MAP()

void CSettingsViewport::OnVScroll(UINT code, UINT position, CScrollBar* bar) {
    if (owner_) owner_->OnVScroll(code, position, bar);
}

BEGIN_MESSAGE_MAP(CAppSettingsDlg, CAppearanceDialog)
    ON_BN_CLICKED(IDC_APPS_ABOUT, &CAppSettingsDlg::OnAbout)
    ON_BN_CLICKED(IDC_CONNECT_PASSWORD, &CAppSettingsDlg::OnConnectPassword)
    ON_BN_CLICKED(IDC_PASSWORD_LOCK_NOW, &CAppSettingsDlg::OnLockNow)
    ON_BN_CLICKED(IDC_APPS_SKIP, &CAppSettingsDlg::OnSkip)
    ON_BN_CLICKED(IDC_APPS_LOCATE_BROWSER, &CAppSettingsDlg::OnLocateBrowser)
    ON_BN_CLICKED(IDC_APPS_LOCATE_TERMINAL, &CAppSettingsDlg::OnLocateTerminal)
    ON_CBN_SELCHANGE(IDC_APPS_BROWSER, &CAppSettingsDlg::OnSelectionChanged)
    ON_CBN_SELCHANGE(IDC_APPS_TERMINAL, &CAppSettingsDlg::OnSelectionChanged)
    ON_CBN_SELCHANGE(IDC_APPEARANCE, &CAppSettingsDlg::OnAppearanceChanged)
    ON_BN_CLICKED(IDC_CONNECT_INSTALL, &CAppSettingsDlg::OnInstallWireGuard)
    ON_BN_CLICKED(IDC_CONNECT_CHECK, &CAppSettingsDlg::OnCheckWireGuard)
    ON_BN_CLICKED(IDC_CONNECT_NOT_NOW, &CAppSettingsDlg::OnNotNow)
    ON_BN_CLICKED(IDC_SETUP_PBX, &CAppSettingsDlg::OnGetStartedPbx)
    ON_BN_CLICKED(IDC_SETUP_SUPPORT, &CAppSettingsDlg::OnGetStartedSupport)
    ON_MESSAGE(WM_APP_SETUP_PROGRESS, &CAppSettingsDlg::OnSetupProgress)
    ON_MESSAGE(WM_APP_SETUP_DONE, &CAppSettingsDlg::OnSetupDone)
    ON_WM_SIZE()
    ON_WM_VSCROLL()
    ON_WM_MOUSEWHEEL()
    ON_WM_GETMINMAXINFO()
    ON_MESSAGE(WM_DPICHANGED, &CAppSettingsDlg::OnDpiChanged)
    ON_MESSAGE(WM_DPICHANGED_AFTERPARENT, &CAppSettingsDlg::OnDpiLayout)
    ON_MESSAGE(WM_APP + 0x322, &CAppSettingsDlg::OnRevealFocusedControl)
END_MESSAGE_MAP()

CAppSettingsDlg::CAppSettingsDlg(Mode mode, const std::optional<tlp::Preferences>& stored, CWnd* parent)
    : CAppearanceDialog(IDD_APP_SETTINGS, parent), mode_(mode), stored_(stored), working_(stored.value_or(tlp::Preferences())) {}

CAppSettingsDlg::~CAppSettingsDlg() {
    if (installer_.joinable()) installer_.join();
    delete static_cast<CSettingsViewport*>(viewport_);
    viewport_ = nullptr;
}

void CAppSettingsDlg::DoDataExchange(CDataExchange* exchange) {
    CDialogEx::DoDataExchange(exchange);
    DDX_Control(exchange, IDC_APPS_BROWSER, browser_);
    DDX_Control(exchange, IDC_APPS_TERMINAL, terminal_);
    DDX_Control(exchange, IDC_APPS_MANAGED_SSH, managedSshTerminal_);
}

BOOL CAppSettingsDlg::OnInitDialog() {
    CAppearanceDialog::OnInitDialog();
    const HWND viewportWindow = ::GetDlgItem(m_hWnd, IDC_SETTINGS_VIEWPORT);
    auto viewport = std::make_unique<CSettingsViewport>();
    if (!viewportWindow || !viewport->SubclassWindow(viewportWindow))
        throw tlp::Error("The Settings content viewport is unavailable.");
    viewport->SetOwner(this);
    viewport_ = viewport.release();
    ::SetWindowLongPtrW(viewport_->GetSafeHwnd(), GWL_EXSTYLE,
        ::GetWindowLongPtrW(viewport_->GetSafeHwnd(), GWL_EXSTYLE) | WS_EX_CONTROLPARENT);
    GetDlgItem(IDC_CONNECT_PASSWORD)->EnableWindow(connectProfile.has_value()
        && connectProfile->kind == tlp::ProfileKind::Administrator && !connectionActive);
    GetDlgItem(IDC_PASSWORD_LOCK_NOW)->EnableWindow(connectionActive);
    CComboBox* appearance = static_cast<CComboBox*>(GetDlgItem(IDC_APPEARANCE));
    appearance->AddString(L"System (follow Windows)");
    appearance->AddString(L"Light");
    appearance->AddString(L"Dark");
    appearance->SetCurSel(working_.appearance == tlp::Appearance::Dark ? 2 : working_.appearance == tlp::Appearance::Light ? 1 : 0);
    if (mode_ == Mode::Welcome) {
        SetWindowText(L"Welcome to TELIPHONES");
        SetDlgItemText(IDC_APPS_HEADING, L"Step 1: Applications");
        SetDlgItemText(IDC_APPS_INTRO, L"Choose the browser and SSH terminals. Secure HTTPS management uses Edge, Chrome or Brave. My PBXs Open SSH defaults to Console (Default); Remote Support uses the selected external terminal.");
    } else {
        SetWindowText(L"TELIPHONES Settings");
        SetDlgItemText(IDC_APPS_HEADING, L"Applications");
        SetDlgItemText(IDC_APPS_INTRO, L"The selected browser opens FreePBX; secure HTTPS management requires Edge, Chrome or Brave. My PBXs Open SSH uses its selected terminal; Remote Support uses the external terminal. Preferences stay on this computer.");
        GetDlgItem(IDC_APPS_SKIP)->ShowWindow(SW_HIDE);
    }
    try {
        Detect();
    } catch (const std::exception& e) {
        ShowError(std::string("TELIPHONES could not check which applications are installed: ") + e.what());
    }
    tlp::Preferences effective = tlp::EffectivePreferences(stored_, browsers_, terminals_);
    Fill(AppKind::Browser, effective.browser);
    Fill(AppKind::Terminal, effective.terminal);
    managedSshTerminal_.AddString(L"Console (Default)");
    managedSshTerminal_.AddString(L"External OpenSSH terminal");
    managedSshTerminal_.SetCurSel(effective.managedSshTerminal == "external" ? 1 : 0);
    managedSshTerminal_.EnableWindow(mode_ != Mode::Welcome || step_ == 1);
    UpdateStatus();
    RefreshConnectivity();
    CRect client;
    GetClientRect(&client);
    initialClientWidth_ = std::max(1, client.Width());
    initialClientHeight_ = std::max(1, client.Height());
    CRect initialViewport;
    viewport_->GetWindowRect(&initialViewport);
    ScreenToClient(&initialViewport);
    initialViewportWidth_ = std::max(1, initialViewport.Width());
    initialViewportLeft_ = initialViewport.left;
    initialViewportTop_ = initialViewport.top;
    initialDpi_ = std::max(1, static_cast<int>(GetDpiForWindow(m_hWnd)));
    layoutDpi_ = initialDpi_;
    footerControls_.clear();
    for (HWND child = ::GetWindow(m_hWnd, GW_CHILD); child; child = ::GetWindow(child, GW_HWNDNEXT)) {
        const int id = ::GetDlgCtrlID(child);
        if (child == viewport_->GetSafeHwnd())
            continue;
        CRect rect;
        ::GetWindowRect(child, &rect);
        ScreenToClient(&rect);
        const bool footer = id == IDC_APPS_ABOUT || id == IDOK || id == IDCANCEL || id == IDC_APPS_SKIP;
        if (footer) footerControls_.push_back({child, rect, true, id == IDOK || id == IDCANCEL});
        else {
            layoutControls_.push_back({child, rect, false, false});
            if (id == IDC_APPS_GROUP || id == IDC_CONNECT_GROUP || id == IDC_PASSWORD_SECURITY_GROUP)
                sectionFrames_.push_back({id, child});
            contentExtent_ = std::max(contentExtent_, static_cast<int>(rect.bottom));
        }
    }
    MONITORINFO monitor{};
    monitor.cbSize = sizeof(monitor);
    if (GetMonitorInfo(MonitorFromWindow(m_hWnd, MONITOR_DEFAULTTONEAREST), &monitor)) {
        CRect work(monitor.rcWork), window;
        GetWindowRect(&window);
        const int width = std::min(window.Width(), work.Width());
        const int height = std::min(window.Height(), work.Height());
        const int x = std::clamp<int>(window.left, work.left, work.right - width);
        const int y = std::clamp<int>(window.top, work.top, work.bottom - height);
        SetWindowPos(nullptr, x, y, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
    }
    // Work-area clamping may resize the outer window; use its resulting client
    // dimensions as the baseline for footer and scroll layout.
    GetClientRect(&client);
    initialClientWidth_ = std::max(1, client.Width());
    initialClientHeight_ = std::max(1, client.Height());
    viewport_->GetWindowRect(&initialViewport);
    ScreenToClient(&initialViewport);
    initialViewportWidth_ = std::max(1, initialViewport.Width());
    initialViewportLeft_ = initialViewport.left;
    initialViewportTop_ = initialViewport.top;
    std::vector<LayoutControl> originalChildren;
    originalChildren.swap(layoutControls_);
    for (auto& item : originalChildren) {
        ::SetParent(item.window, viewport_->GetSafeHwnd());
        CRect itemRect = item.original;
        itemRect.OffsetRect(-initialViewportLeft_, -initialViewportTop_);
        item.original = itemRect;
        ::SetWindowPos(item.window, nullptr, itemRect.left, itemRect.top, itemRect.Width(), itemRect.Height(),
                       SWP_NOZORDER | SWP_NOACTIVATE);
        layoutControls_.push_back(item);
    }
    layoutReady_ = true;
    ShowStep();
    Arrange();
    return TRUE;
}

void CAppSettingsDlg::Arrange() {
    if (!layoutReady_ || arranging_ || !m_hWnd) return;
    arranging_ = true;
    CRect client;
    GetClientRect(&client);
    const auto scale = [&](int value) { return ScaleDialogUnits(value, layoutDpi_, initialDpi_); };
    const LONG footerTop = FooterTop(client);
    const LONG viewportLeft = scale(initialViewportLeft_);
    const LONG viewportTop = scale(initialViewportTop_);
    const LONG viewportWidth = std::max<LONG>(0, client.right - viewportLeft - MulDiv(8, layoutDpi_, 96));
    const LONG viewportBottom = std::max<LONG>(viewportTop, footerTop - MulDiv(8, layoutDpi_, 96));
    viewport_->SetWindowPos(nullptr, viewportLeft, viewportTop, viewportWidth,
                            viewportBottom - viewportTop,
                            SWP_NOZORDER | SWP_NOACTIVATE);
    const int baseViewportWidth = std::max(1, initialViewportWidth_);
    int visibleExtent = 0;
    for (const auto& item : layoutControls_) {
        if (!::IsWindowVisible(item.window) || std::any_of(sectionFrames_.begin(), sectionFrames_.end(),
                [&item](const SectionFrame& frame) { return frame.window == item.window; })) continue;
        visibleExtent = std::max(visibleExtent, scale(item.original.bottom));
    }
    // All layout and viewport values are current-DPI client pixels. Recompute
    // this from visible controls so hidden wizard sections and a DPI round-trip
    // cannot inflate the scroll range.
    contentExtent_ = std::max(0, visibleExtent);
    CRect viewportClient;
    viewport_->GetClientRect(&viewportClient);
    SCROLLINFO info{sizeof(info), SIF_RANGE | SIF_PAGE | SIF_POS};
    info.nMin = 0;
    info.nMax = std::max(0, contentExtent_ - 1);
    info.nPage = static_cast<UINT>(viewportClient.Height());
    info.nPos = scrollOffset_;
    viewport_->SetScrollInfo(SB_VERT, &info, TRUE);
    viewport_->ShowScrollBar(SB_VERT, contentExtent_ > static_cast<int>(info.nPage), TRUE);
    viewport_->GetClientRect(&viewportClient);
    info.nPage = static_cast<UINT>(viewportClient.Height());
    viewport_->SetScrollInfo(SB_VERT, &info, TRUE);
    SCROLLINFO settled{sizeof(settled), SIF_PAGE};
    viewport_->GetScrollInfo(SB_VERT, &settled);
    viewport_->GetClientRect(&viewportClient);
    if (settled.nPage != static_cast<UINT>(viewportClient.Height())) {
        info.nPage = static_cast<UINT>(viewportClient.Height());
        viewport_->SetScrollInfo(SB_VERT, &info, TRUE);
    }
    viewport_->GetClientRect(&viewportClient);
    const LONG viewportHeight = viewportClient.Height();
    info.nPage = static_cast<UINT>(viewportHeight);
    const int settledWidth = viewportClient.Width();
    const LONG maxScroll = std::max<LONG>(0, static_cast<LONG>(contentExtent_) - viewportHeight);
    scrollOffset_ = static_cast<int>(std::clamp<LONG>(scrollOffset_, 0, maxScroll));
    info.nPos = scrollOffset_;
    viewport_->SetScrollInfo(SB_VERT, &info, TRUE);
    viewport_->SetScrollPos(SB_VERT, scrollOffset_, TRUE);
    for (const auto& item : layoutControls_) {
        if (!::IsWindow(item.window)) continue;
        if (std::any_of(sectionFrames_.begin(), sectionFrames_.end(), [&item](const SectionFrame& frame) {
            return frame.window == item.window;
            })) continue;
        const int right = MulDiv(item.original.right, settledWidth, baseViewportWidth);
        const int left = MulDiv(item.original.left, settledWidth, baseViewportWidth);
        const int top = scale(item.original.top) - scrollOffset_;
        const int bottom = scale(item.original.bottom) - scrollOffset_;
        const int x = left;
        const int width = std::max(1, right - left);
        ::SetWindowPos(item.window, nullptr, x, top, std::max(1, width), std::max(1, bottom - top),
                       SWP_NOZORDER | SWP_NOACTIVATE);
    }
    for (const auto& frame : sectionFrames_) {
        if (!::IsWindowVisible(frame.window)) continue;
        CRect bounds;
        bool found = false;
        for (const auto& item : layoutControls_) {
            if (item.window == frame.window || !::IsWindowVisible(item.window) ||
                std::any_of(sectionFrames_.begin(), sectionFrames_.end(), [&item](const SectionFrame& other) {
                    return other.window == item.window;
                })) continue;
            const int id = ::GetDlgCtrlID(item.window);
            const bool inSection = frame.id == IDC_APPS_GROUP
                ? id == IDC_APPS_BROWSER_LABEL || id == IDC_APPS_BROWSER || id == IDC_APPS_LOCATE_BROWSER ||
                  id == IDC_APPS_TERMINAL_LABEL || id == IDC_APPS_TERMINAL || id == IDC_APPS_LOCATE_TERMINAL ||
                  id == IDC_APPS_MANAGED_SSH_LABEL || id == IDC_APPS_MANAGED_SSH || id == IDC_APPS_STATUS || id == IDC_APPS_NOTE
                : frame.id == IDC_CONNECT_GROUP
                    ? id == IDC_CONNECT_STATUS || id == IDC_CONNECT_INSTALL || id == IDC_CONNECT_CHECK || id == IDC_CONNECT_NOT_NOW
                    : id == IDC_CONNECT_PASSWORD || id == IDC_PASSWORD_LOCK_NOW;
            if (!inSection) continue;
            CRect child;
            ::GetWindowRect(item.window, &child);
            viewport_->ScreenToClient(&child);
            const int childLeft = child.left;
            const int childRight = child.right;
            const int childTop = child.top;
            const int childBottom = child.bottom;
            if (!found) {
                bounds = CRect(childLeft, childTop, childRight, childBottom);
                found = true;
            } else {
                bounds.left = std::min(bounds.left, childLeft);
                bounds.right = std::max(bounds.right, childRight);
                bounds.top = std::min(bounds.top, childTop);
                bounds.bottom = std::max(bounds.bottom, childBottom);
            }
        }
        if (found) {
            bounds.left -= MulDiv(10, layoutDpi_, initialDpi_);
            bounds.right += MulDiv(10, layoutDpi_, initialDpi_);
            bounds.top -= MulDiv(18, layoutDpi_, initialDpi_);
            bounds.bottom += MulDiv(4, layoutDpi_, initialDpi_);
                bounds.left = std::max<LONG>(0, bounds.left);
                bounds.right = std::min<LONG>(viewportClient.Width(), bounds.right);
            ::SetWindowPos(frame.window, nullptr, bounds.left, bounds.top,
                       bounds.Width(), bounds.Height(), SWP_NOZORDER | SWP_NOACTIVATE);
        }
    }
    for (const auto& frame : sectionFrames_) {
        if (!::IsWindowVisible(frame.window)) continue;
        CRect frameRect;
        ::GetWindowRect(frame.window, &frameRect);
        viewport_->ScreenToClient(&frameRect);
        if (frameRect.top >= 0 && frameRect.bottom <= viewportClient.Height()) {
            ::SetWindowRgn(frame.window, nullptr, TRUE);
            continue;
        }
        const int clipTop = std::clamp<LONG>(-frameRect.top, 0, frameRect.Height());
        const int clipBottom = std::clamp<LONG>(viewportClient.Height() - frameRect.top, clipTop, frameRect.Height());
        HRGN clip = ::CreateRectRgn(0, clipTop, std::max(0, frameRect.Width()), clipBottom);
        if (clip && !::SetWindowRgn(frame.window, clip, TRUE)) ::DeleteObject(clip);
    }
    for (const auto& item : footerControls_) {
        if (!::IsWindow(item.window)) continue;
        const int width = MulDiv(item.original.Width(), layoutDpi_, initialDpi_);
        const int height = MulDiv(item.original.Height(), layoutDpi_, initialDpi_);
        const int right = item.rightAnchored
            ? client.right - std::max(MulDiv(8, layoutDpi_, 96),
                                      MulDiv(initialClientWidth_ - item.original.right, layoutDpi_, initialDpi_))
            : MulDiv(item.original.right, client.Width(), std::max(1, initialClientWidth_));
        const int left = item.rightAnchored ? right - width
            : MulDiv(item.original.left, client.Width(), std::max(1, initialClientWidth_));
        const int bottom = client.bottom - FooterBottomGap(item);
        ::SetWindowPos(item.window, nullptr, left, bottom - height, width, height,
                       SWP_NOZORDER | SWP_NOACTIVATE);
    }
    if (!footerControls_.empty()) {
        std::vector<const LayoutControl*> visibleFooter;
        for (const auto& item : footerControls_) if (::IsWindowVisible(item.window)) visibleFooter.push_back(&item);
        std::sort(visibleFooter.begin(), visibleFooter.end(), [](const LayoutControl* left, const LayoutControl* right) {
            CRect leftRect, rightRect;
            ::GetWindowRect(left->window, &leftRect);
            ::GetWindowRect(right->window, &rightRect);
            return leftRect.left < rightRect.left;
        });
        for (std::size_t index = 1; index < visibleFooter.size(); ++index) {
            CRect previous, current;
            ::GetWindowRect(visibleFooter[index - 1]->window, &previous);
            ::GetWindowRect(visibleFooter[index]->window, &current);
            ScreenToClient(&previous);
            ScreenToClient(&current);
            const int minimumGap = MulDiv(8, layoutDpi_, 96);
            if (current.left < previous.right + minimumGap) {
                const int shift = previous.right + minimumGap - current.left;
                ::SetWindowPos(visibleFooter[index]->window, nullptr,
                               current.left + shift, current.top,
                               current.Width(), current.Height(), SWP_NOZORDER | SWP_NOACTIVATE);
            }
        }
    }
    arranging_ = false;
    UpdateScrollInfo();
    if (CWnd* focused = GetFocus(); focused && viewport_->IsChild(focused)) RevealFocusedControl();
}

int CAppSettingsDlg::FooterBottomGap(const LayoutControl& item) const {
    const int minimumGap = MulDiv(8, layoutDpi_, 96);
    const int originalGap = MulDiv(initialClientHeight_ - item.original.bottom, layoutDpi_, initialDpi_);
    return std::max(0, std::max(minimumGap, originalGap));
}

void CAppSettingsDlg::UpdateScrollInfo() {
    if (!viewport_ || !viewport_->GetSafeHwnd()) return;
    CRect client;
    viewport_->GetClientRect(&client);
    SCROLLINFO info{sizeof(info), SIF_RANGE | SIF_PAGE | SIF_POS};
    info.nMin = 0;
    info.nMax = std::max(0, contentExtent_ - 1);
    info.nPage = static_cast<UINT>(client.Height());
    info.nPos = scrollOffset_;
    viewport_->SetScrollInfo(SB_VERT, &info, TRUE);
    viewport_->SetScrollPos(SB_VERT, scrollOffset_, TRUE);
    SCROLLINFO settled{sizeof(settled), SIF_PAGE};
    viewport_->GetScrollInfo(SB_VERT, &settled);
    viewport_->GetClientRect(&client);
    if (settled.nPage != static_cast<UINT>(client.Height())) {
        info.nPage = static_cast<UINT>(client.Height());
        viewport_->SetScrollInfo(SB_VERT, &info, TRUE);
        viewport_->SetScrollPos(SB_VERT, scrollOffset_, TRUE);
    }
}

LONG CAppSettingsDlg::FooterTop(const CRect& client) const {
    LONG top = client.bottom;
    for (const auto& item : footerControls_) {
        if (!::IsWindowVisible(item.window)) continue;
        const int height = MulDiv(item.original.Height(), layoutDpi_, initialDpi_);
        top = std::min<LONG>(top, client.bottom - FooterBottomGap(item) - height);
    }
    return top;
}

void CAppSettingsDlg::ScrollTo(int offset) {
    CRect client;
    viewport_->GetClientRect(&client);
    const LONG maxScroll = std::max<LONG>(0, static_cast<LONG>(contentExtent_) - client.Height());
    scrollOffset_ = static_cast<int>(std::clamp<LONG>(offset, 0, maxScroll));
    Arrange();
}

void CAppSettingsDlg::OnSize(UINT type, int width, int height) {
    CAppearanceDialog::OnSize(type, width, height);
    Arrange();
}

void CAppSettingsDlg::OnVScroll(UINT code, UINT position, CScrollBar*) {
    SCROLLINFO info{sizeof(info), SIF_ALL};
    viewport_->GetScrollInfo(SB_VERT, &info);
    const int line = MulDiv(28, layoutDpi_, 96);
    switch (code) {
        case SB_TOP: ScrollTo(0); break;
        case SB_BOTTOM: ScrollTo(contentExtent_); break;
        case SB_LINEUP: ScrollTo(scrollOffset_ - line); break;
        case SB_LINEDOWN: ScrollTo(scrollOffset_ + line); break;
        case SB_PAGEUP: ScrollTo(scrollOffset_ - static_cast<int>(info.nPage)); break;
        case SB_PAGEDOWN: ScrollTo(scrollOffset_ + static_cast<int>(info.nPage)); break;
        case SB_THUMBTRACK: case SB_THUMBPOSITION: ScrollTo(static_cast<int>(info.nTrackPos)); break;
    }
}

BOOL CAppSettingsDlg::OnMouseWheel(UINT, short delta, CPoint) {
    wheelRemainder_ += delta;
    const int notches = wheelRemainder_ / WHEEL_DELTA;
    wheelRemainder_ %= WHEEL_DELTA;
    if (notches) ScrollTo(scrollOffset_ - notches * MulDiv(48, layoutDpi_, 96));
    return TRUE;
}

LRESULT CAppSettingsDlg::OnDpiChanged(WPARAM dpi, LPARAM rectangle) {
    layoutDpi_ = std::max(1, static_cast<int>(HIWORD(dpi)));
    const RECT& suggested = *reinterpret_cast<const RECT*>(rectangle);
    RECT bounds = suggested;
    MONITORINFO monitor{};
    monitor.cbSize = sizeof(monitor);
    if (::GetMonitorInfoW(::MonitorFromRect(&suggested, MONITOR_DEFAULTTONEAREST), &monitor)) {
        const int width = static_cast<int>(std::min<LONG>(bounds.right - bounds.left,
                                                          monitor.rcWork.right - monitor.rcWork.left));
        const int height = static_cast<int>(std::min<LONG>(bounds.bottom - bounds.top,
                                                           monitor.rcWork.bottom - monitor.rcWork.top));
        bounds.left = static_cast<LONG>(std::clamp<LONG>(bounds.left, monitor.rcWork.left,
                                                         monitor.rcWork.right - width));
        bounds.top = static_cast<LONG>(std::clamp<LONG>(bounds.top, monitor.rcWork.top,
                                                        monitor.rcWork.bottom - height));
        bounds.right = bounds.left + width;
        bounds.bottom = bounds.top + height;
    }
    SetWindowPos(nullptr, bounds.left, bounds.top, bounds.right - bounds.left,
                 bounds.bottom - bounds.top, SWP_NOZORDER | SWP_NOACTIVATE);
    Arrange();
    return 0;
}

LRESULT CAppSettingsDlg::OnDpiLayout(WPARAM, LPARAM) {
    layoutDpi_ = std::max(1, static_cast<int>(GetDpiForWindow(m_hWnd)));
    Arrange();
    return 0;
}

void CAppSettingsDlg::OnGetMinMaxInfo(MINMAXINFO* info) {
    CAppearanceDialog::OnGetMinMaxInfo(info);
    const int dpi = std::max(1, static_cast<int>(GetDpiForWindow(m_hWnd)));
    const int footerWidth = std::max(MulDiv(8, dpi, 96),
        MulDiv(54 + 56 + 8 + 8, dpi, 96));
    info->ptMinTrackSize.x = MulDiv(430, dpi, 96);
    info->ptMinTrackSize.x = std::max(info->ptMinTrackSize.x, footerWidth);
    info->ptMinTrackSize.y = MulDiv(300, dpi, 96);
}

BOOL CAppSettingsDlg::PreTranslateMessage(MSG* message) {
    const BOOL handled = CAppearanceDialog::PreTranslateMessage(message);
    if (message->message == WM_KEYDOWN && message->wParam == VK_TAB) PostMessage(kRevealFocusMessage);
    else if (message->message == WM_MOUSEWHEEL && viewport_ && message->hwnd &&
             (message->hwnd == viewport_->GetSafeHwnd() ||
              ::IsChild(viewport_->GetSafeHwnd(), message->hwnd))) {
        wheelRemainder_ += GET_WHEEL_DELTA_WPARAM(message->wParam);
        const int notches = wheelRemainder_ / WHEEL_DELTA;
        wheelRemainder_ %= WHEEL_DELTA;
        if (notches) ScrollTo(scrollOffset_ - notches * MulDiv(48, layoutDpi_, 96));
        return TRUE;
    }
    return handled;
}

LRESULT CAppSettingsDlg::OnRevealFocusedControl(WPARAM, LPARAM) {
    RevealFocusedControl();
    return 0;
}

void CAppSettingsDlg::RevealFocusedControl() {
    CWnd* focus = GetFocus();
    if (!focus || (!IsChild(focus) && !viewport_->IsChild(focus)) || !::IsWindowVisible(focus->GetSafeHwnd())) return;
    const auto found = std::find_if(layoutControls_.begin(), layoutControls_.end(),
        [focus](const LayoutControl& item) { return item.window == focus->GetSafeHwnd() && !item.footer; });
    if (found == layoutControls_.end()) return;
    CRect rect, client;
    focus->GetWindowRect(&rect);
    ::MapWindowPoints(nullptr, viewport_->GetSafeHwnd(), reinterpret_cast<POINT*>(&rect), 2);
    CRect viewportClient;
    viewport_->GetClientRect(&viewportClient);
    const LONG viewportHeight = viewportClient.Height();
    if (rect.top < 0) ScrollTo(scrollOffset_ + rect.top);
    else if (rect.bottom > viewportHeight) ScrollTo(scrollOffset_ + rect.bottom - viewportHeight);
}

void CAppSettingsDlg::Detect() {
    browsers_ = tlp::win::DetectApps(AppKind::Browser, working_);
    terminals_ = tlp::win::DetectApps(AppKind::Terminal, working_);
}

void CAppSettingsDlg::Fill(AppKind kind, const std::string& selected) {
    CComboBox& combo = kind == AppKind::Browser ? browser_ : terminal_;
    std::vector<std::string>& ids = kind == AppKind::Browser ? browserIds_ : terminalIds_;
    ids = tlp::AvailableApps(kind, kind == AppKind::Browser ? browsers_ : terminals_);
    bool missing = !selected.empty() && !Contains(ids, selected);
    combo.ResetContent();
    for (const std::string& id : ids) combo.AddString(Widen(tlp::AppName(kind, id)).c_str());
    if (missing) {
        // A stored choice that is no longer installed stays visible, clearly marked, until the user replaces it.
        ids.push_back(selected);
        combo.AddString(Widen(tlp::AppName(kind, selected) + " (not found)").c_str());
    }
    for (std::size_t i = 0; i < ids.size(); ++i) {
        if (ids[i] == selected) combo.SetCurSel(static_cast<int>(i));
    }
    if (combo.GetCurSel() < 0 && !ids.empty()) combo.SetCurSel(0);
    combo.EnableWindow(!ids.empty());
}

std::string CAppSettingsDlg::Selection(AppKind kind) const {
    const CComboBox& combo = kind == AppKind::Browser ? browser_ : terminal_;
    const std::vector<std::string>& ids = kind == AppKind::Browser ? browserIds_ : terminalIds_;
    int index = combo.GetCurSel();
    return index >= 0 && static_cast<std::size_t>(index) < ids.size() ? ids[static_cast<std::size_t>(index)] : std::string();
}

std::string CAppSettingsDlg::ManagedSshSelection() const {
    return managedSshTerminal_.GetCurSel() == 1 ? "external" : tlp::kConsoleDefault;
}

void CAppSettingsDlg::UpdateStatus() {
    std::string status = notice;
    auto add = [&status](const std::string& line) { status += (status.empty() ? "" : "\r\n") + line; };
    std::string browser = Selection(AppKind::Browser);
    std::string terminal = Selection(AppKind::Terminal);
    if (!Contains(tlp::AvailableApps(AppKind::Browser, browsers_), browser)) {
        add(tlp::AppName(AppKind::Browser, browser) + " was not found. Choose another browser, or use Locate... if it was moved.");
    }
    if (terminal.empty()) {
        add("No supported SSH terminal was found. Use Locate... to choose PuTTY, or install Windows PowerShell.");
    } else if (!Contains(tlp::AvailableApps(AppKind::Terminal, terminals_), terminal)) {
        add(tlp::AppName(AppKind::Terminal, terminal) + " was not found. Choose another SSH terminal, or use Locate... if it was moved.");
    } else if (const tlp::AppInfo* app = tlp::FindApp(AppKind::Terminal, terminal); app != nullptr && app->needsOpenSsh && tlp::win::OpenSshClient().empty()) {
        add(app->name + " uses the Windows OpenSSH Client, which is not installed. Add it in Windows Settings > System > Optional features, or choose PuTTY.");
    }
    SetDlgItemText(IDC_APPS_STATUS, Widen(status).c_str());
}

void CAppSettingsDlg::OnSelectionChanged() { UpdateStatus(); }

void CAppSettingsDlg::OnConnectPassword() {
    if (!installing_ && !connectionActive && connectProfile
        && connectProfile->kind == tlp::ProfileKind::Administrator)
        ManageConnectPassword(*connectProfile, this);
}

void CAppSettingsDlg::OnLockNow() {
    if (installing_ || !connectionActive) return;
    lockNow = true;
    EndDialog(IDOK);
}

void CAppSettingsDlg::OnAbout() {
    tlp::ui::ShowMessage(Widen(
        "TELIPHONES is a UK registered trademark.\r\n\r\n"
        "TELIPHONES " TELIPHONES_VERSION_STRING " for Windows is licensed under GPLv3.\r\n\r\n"
        "GPLv3 licensing applies to the software and does not grant trademark rights. "
        "See LICENSE for the full licence terms.").c_str(), MB_OK | MB_ICONINFORMATION);
}

void CAppSettingsDlg::OnAppearanceChanged() {
    const int row = static_cast<CComboBox*>(GetDlgItem(IDC_APPEARANCE))->GetCurSel();
    const tlp::Appearance selected = row == 2 ? tlp::Appearance::Dark : row == 1 ? tlp::Appearance::Light : tlp::Appearance::System;
    try {
        tlp::ui::SetAppearance(selected);
        working_.appearance = selected;
    } catch (const std::exception& e) {
        const auto current = tlp::ui::CurrentAppearance();
        static_cast<CComboBox*>(GetDlgItem(IDC_APPEARANCE))->SetCurSel(
            current == tlp::Appearance::Dark ? 2 : current == tlp::Appearance::Light ? 1 : 0);
        ShowError(e.what());
    }
}

void CAppSettingsDlg::OnLocateBrowser() { Locate(AppKind::Browser); }

void CAppSettingsDlg::OnLocateTerminal() { Locate(AppKind::Terminal); }

void CAppSettingsDlg::Locate(AppKind kind) {
    wchar_t path[MAX_PATH]{};
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = m_hWnd;
    dialog.lpstrFilter = L"Programs (*.exe)\0*.exe\0";
    dialog.lpstrFile = path;
    dialog.nMaxFile = static_cast<DWORD>(std::size(path));
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_HIDEREADONLY | OFN_DONTADDTORECENT;
    dialog.lpstrTitle = kind == AppKind::Browser ? L"Locate a supported web browser" : L"Locate a supported SSH terminal";
    if (!GetOpenFileNameW(&dialog)) return;
    std::string chosen = tlp::win::Narrow(path);
    std::string supported;
    for (const tlp::AppInfo& app : tlp::KnownApps(kind)) {
        if (app.executables.empty()) continue;
        if (kind == AppKind::Browser && !tlp::IsSupportedSecureBrowser(app.id)) continue;
        if (tlp::IsExpectedExecutable(app, chosen)) {
            working_.locations[app.id] = chosen;
            try {
                Detect();
            } catch (const std::exception& e) {
                ShowError(e.what());
            }
            Fill(kind, app.id);
            UpdateStatus();
            return;
        }
        supported += "\n  " + app.name + " (" + app.executables.front() + ")";
    }
    ShowError(kind == AppKind::Browser
        ? "Secure HTTPS management supports Microsoft Edge, Google Chrome or Brave. Choose one of these applications on a local drive:" + supported
        : "TELIPHONES cannot use this program. Choose one of the supported applications on a local drive:" + supported);
}

bool CAppSettingsDlg::Store(const tlp::Preferences& candidate) {
    try {
        tlp::win::SavePreferences(candidate);
    } catch (const std::exception& e) {
        ShowError(std::string("Your application preferences could not be saved: ") + e.what());
        return false;
    }
    preferences = candidate;
    stored_ = candidate;
    return true;
}

void CAppSettingsDlg::OnOK() {
    if (installing_) return;
    if (mode_ == Mode::Welcome && step_ != 1) {
        if (step_ == 2) {
            step_ = 3;
            ShowStep();
        } else {
            CDialogEx::OnOK();
        }
        return;
    }
    try {
        auto result = tlp::PreferencesAfterFirstRun(tlp::FirstRunOutcome::Saved, Selection(AppKind::Browser), Selection(AppKind::Terminal), browsers_,
                                                    terminals_, working_);
        if (result) result->managedSshTerminal = ManagedSshSelection();
        if (!result || !Store(*result)) return;
    } catch (const std::exception& e) {
        ShowError(e.what());
        return;
    }
    outcome = tlp::FirstRunOutcome::Saved;
    if (mode_ == Mode::Welcome) {
        step_ = 2;
        ShowStep();
        return;
    }
    CDialogEx::OnOK();
}

void CAppSettingsDlg::OnSkip() {
    if (installing_) return;
    auto result = tlp::PreferencesAfterFirstRun(tlp::FirstRunOutcome::Skipped, "", "", browsers_, terminals_, working_);
    if (result) result->managedSshTerminal = ManagedSshSelection();
    if (!result || !Store(*result)) return;
    outcome = tlp::FirstRunOutcome::Skipped;
    step_ = 2;
    ShowStep();
}

void CAppSettingsDlg::OnCancel() {
    if (installing_) return;
    try {
        tlp::ui::SetAppearance(stored_.value_or(tlp::Preferences()).appearance);
    } catch (const std::exception& e) {
        ShowError(e.what());
    }
    CDialogEx::OnCancel();
}

void CAppSettingsDlg::ShowStep() {
    bool welcome = mode_ == Mode::Welcome;
    for (int id : {IDC_APPS_GROUP, IDC_APPS_HEADING, IDC_APPS_INTRO, IDC_APPS_BROWSER_LABEL, IDC_APPS_TERMINAL_LABEL, IDC_APPS_BROWSER,
                   IDC_APPS_TERMINAL, IDC_APPS_LOCATE_BROWSER, IDC_APPS_LOCATE_TERMINAL, IDC_APPS_MANAGED_SSH_LABEL,
                   IDC_APPS_MANAGED_SSH, IDC_APPS_STATUS, IDC_APPS_NOTE,
                   IDC_APPEARANCE_LABEL, IDC_APPEARANCE}) {
        GetDlgItem(id)->ShowWindow(!welcome || step_ == 1 ? SW_SHOW : SW_HIDE);
    }
    managedSshTerminal_.EnableWindow(!welcome || step_ == 1);
    for (int id : {IDC_CONNECT_GROUP, IDC_CONNECT_STATUS, IDC_CONNECT_CHECK, IDC_CONNECT_INSTALL, IDC_CONNECT_NOT_NOW}) {
        GetDlgItem(id)->ShowWindow(!welcome || step_ == 2 ? SW_SHOW : SW_HIDE);
    }
    for (int id : {IDC_PASSWORD_SECURITY_GROUP, IDC_CONNECT_PASSWORD, IDC_PASSWORD_LOCK_NOW}) {
        GetDlgItem(id)->ShowWindow(!welcome ? SW_SHOW : SW_HIDE);
    }
    GetDlgItem(IDC_CONNECT_INSTALL)->ShowWindow((!welcome || step_ == 2) && !wireguard_.installed ? SW_SHOW : SW_HIDE);
    GetDlgItem(IDC_CONNECT_NOT_NOW)->ShowWindow((!welcome || step_ == 2) && !wireguard_.installed ? SW_SHOW : SW_HIDE);
    GetDlgItem(IDC_APPS_SKIP)->ShowWindow(welcome && step_ == 1 ? SW_SHOW : SW_HIDE);
    GetDlgItem(IDC_SETUP_PBX)->ShowWindow(welcome && step_ == 3 ? SW_SHOW : SW_HIDE);
    GetDlgItem(IDC_SETUP_SUPPORT)->ShowWindow(welcome && step_ == 3 ? SW_SHOW : SW_HIDE);
    GetDlgItem(IDC_SETUP_PBX)->EnableWindow(wireguard_.installed && wireguard_.trusted);
    GetDlgItem(IDC_SETUP_SUPPORT)->EnableWindow(wireguard_.installed && wireguard_.trusted);
    if (welcome) {
        for (int id : {IDC_CONNECT_INSTALL, IDC_CONNECT_NOT_NOW})
            GetDlgItem(id)->ShowWindow(step_ == 2 && !wireguard_.installed ? SW_SHOW : SW_HIDE);
        SetDlgItemText(IDC_APPS_HEADING, step_ == 1 ? L"Step 1: Applications" : step_ == 2 ? L"Step 2: Secure connectivity" : L"Step 3: Get started");
        if (step_ == 2) {
            SetDlgItemText(IDC_APPS_INTRO, wireguard_.installed
                ? (wireguard_.trusted ? L"WireGuard is already installed and verified. No installation is needed."
                                     : L"WireGuard is installed, but could not be verified. TELIPHONES will not overwrite it automatically. Check Again after administrator investigation.")
                : L"WireGuard is required\r\nTELIPHONES uses WireGuard to establish secure connections to your PBXs. WireGuard is not currently installed on this computer.");
        } else if (step_ == 3) {
            SetDlgItemText(IDC_APPS_INTRO, wireguard_.installed && wireguard_.trusted
                ? L"Add your first PBX or start the separately authorised Remote Support workflow. Profiles stay on this computer; a new computer has an empty list."
                : L"You can explore TELIPHONES now. Install WireGuard later from Settings > Connectivity before adding or connecting to a PBX.");
        }
        SetDlgItemText(IDOK, step_ == 1 ? L"Save & Next" : step_ == 2 ? L"Continue" : L"Finish");
    }
    Arrange();
}

void CAppSettingsDlg::RefreshConnectivity() {
    try {
        wireguard_ = tlp::win::FindWireGuard();
        std::string text;
        if (wireguard_.installed && wireguard_.trusted) {
            text = "Status: Installed (verified, signed by " + wireguard_.signer + ").";
        } else if (installation.state == tlp::SetupState::Failed) {
            text = "Status: Installation failed.";
        } else {
            text = wireguard_.installed ? "Status: Installed, but verification failed. Automatic replacement is disabled."
                                        : "Status: Not installed.";
        }
        if (!installation.message.empty()) text += "\r\n" + installation.message;
        else if (!wireguard_.installed) text += "\r\nWireGuard is required. TELIPHONES can download and verify the official installer, then request administrator approval.";
        SetDlgItemText(IDC_CONNECT_STATUS, Widen(text).c_str());
    } catch (const std::exception& e) {
        wireguard_ = {};
        SetDlgItemText(IDC_CONNECT_STATUS, Widen(std::string("WireGuard detection failed: ") + e.what()).c_str());
    }
    ShowStep();
}

void CAppSettingsDlg::OnCheckWireGuard() {
    if (!installing_) RefreshConnectivity();
}

void CAppSettingsDlg::OnNotNow() {
    if (!installing_) {
        if (mode_ == Mode::Settings) {
            OnCancel();
            return;
        }
        step_ = 3;
        ShowStep();
    }
}

void CAppSettingsDlg::OnInstallWireGuard() {
    if (installing_) return;
    RefreshConnectivity();
    if (wireguard_.installed) return;
    // This button is the explicit approval. No startup or detection path calls the installer.
    installing_ = true;
    for (int id : {IDOK, IDCANCEL, IDC_CONNECT_INSTALL, IDC_CONNECT_CHECK, IDC_CONNECT_NOT_NOW}) GetDlgItem(id)->EnableWindow(FALSE);
    SetDlgItemText(IDC_CONNECT_STATUS, L"Downloading the official WireGuard installer...");
    HWND window = m_hWnd;
    try {
        installer_ = std::thread([window] {
            auto result = std::make_unique<tlp::SetupResult>(tlp::win::InstallWireGuard([window](const std::string& text) {
                auto message = std::make_unique<std::string>(text);
                if (::PostMessageW(window, WM_APP_SETUP_PROGRESS, 0, reinterpret_cast<LPARAM>(message.get()))) message.release();
            }));
            if (::PostMessageW(window, WM_APP_SETUP_DONE, 0, reinterpret_cast<LPARAM>(result.get()))) result.release();
        });
    } catch (const std::exception& e) {
        installing_ = false;
        installation = {tlp::SetupState::Failed, e.what()};
        for (int id : {IDOK, IDCANCEL, IDC_CONNECT_INSTALL, IDC_CONNECT_CHECK, IDC_CONNECT_NOT_NOW}) GetDlgItem(id)->EnableWindow(TRUE);
        RefreshConnectivity();
    }
}

LRESULT CAppSettingsDlg::OnSetupProgress(WPARAM, LPARAM value) {
    std::unique_ptr<std::string> text(reinterpret_cast<std::string*>(value));
    SetDlgItemText(IDC_CONNECT_STATUS, Widen(*text).c_str());
    return 0;
}

LRESULT CAppSettingsDlg::OnSetupDone(WPARAM, LPARAM value) {
    std::unique_ptr<tlp::SetupResult> result(reinterpret_cast<tlp::SetupResult*>(value));
    if (installer_.joinable()) installer_.join();
    installing_ = false;
    installation = *result;
    for (int id : {IDOK, IDCANCEL, IDC_CONNECT_INSTALL, IDC_CONNECT_CHECK, IDC_CONNECT_NOT_NOW}) GetDlgItem(id)->EnableWindow(TRUE);
    RefreshConnectivity();
    return 0;
}

void CAppSettingsDlg::GetStarted(StartAction action) {
    if (installing_ || !wireguard_.installed || !wireguard_.trusted) return;
    startAction = action;
    EndDialog(IDOK);
}

void CAppSettingsDlg::OnGetStartedPbx() { GetStarted(StartAction::AddPbx); }
void CAppSettingsDlg::OnGetStartedSupport() { GetStarted(StartAction::Support); }
