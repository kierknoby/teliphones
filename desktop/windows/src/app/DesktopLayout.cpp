#include "DesktopLayout.h"
#include "Appearance.h"
#include <algorithm>
#include <functional>
#include <iterator>
#include <cwchar>
#include <stdexcept>
#include "../platform/Win.h"
#include "resource.h"
#include "Version.h"

namespace {
const int contentIds[] = {
    IDC_PBX_HEADING, IDC_PROFILES, IDC_ADD_PBX, IDC_REMOVE, IDC_ADD_SUPPORT, IDC_UPDATE_GRANT,
    IDC_SESSION_LABEL, IDC_SESSION, IDC_DETAILS, IDC_LOCK_WORKSTATION, IDC_ALLOWED_SOURCES_LABEL,
    IDC_ALLOWED_SOURCES, IDC_REQUEST_SOURCES, IDC_CONNECTION_HEADING, IDC_STATE, IDC_GUIDANCE,
    IDC_HEALTH_INLINE_TEXT, IDC_HEALTH_INLINE_HISTORY, IDC_HEALTH_PLOT, IDC_HEALTH_INLINE_GRAPH,
    IDC_CONNECTION_HEALTH, IDC_SESSION_LOG
};
const int actionIds[] = {IDC_CONNECT, IDC_DISCONNECT, IDC_OPEN_GUI, IDC_OPEN_SSH, IDC_SETTINGS, IDCANCEL};
static_assert(std::size(contentIds) == static_cast<int>(tlp::DesktopSlot::Count), "layout slots must match controls");
}

void CDesktopContent::ScrollTo(int position) {
    CRect client;
    GetClientRect(&client);
    const int next = std::clamp(position, 0, std::max<int>(0, extent - client.Height()));
    if (offset == next) return;
    offset = next;
    if (changed) changed();
}

void CDesktopContent::RevealFocus() {
    CWnd* focus = GetFocus();
    if (!focus || !IsChild(focus)) return;
    CRect rectangle, client;
    focus->GetWindowRect(&rectangle);
    ScreenToClient(&rectangle);
    GetClientRect(&client);
    if (rectangle.top < 0) ScrollTo(offset + rectangle.top);
    else if (rectangle.bottom > client.bottom) ScrollTo(offset + rectangle.bottom - client.bottom);
}

LRESULT CDesktopContent::WindowProc(UINT message, WPARAM wparam, LPARAM lparam) {
    if (controller && (message == WM_COMMAND || message == WM_NOTIFY || message == WM_DRAWITEM ||
        message == WM_CTLCOLORSTATIC || message == WM_CTLCOLOREDIT || message == WM_CTLCOLORLISTBOX)) {
        return controller->SendMessage(message, wparam, lparam);
    }
    if (message == WM_VSCROLL) {
        SCROLLINFO info{sizeof(info), SIF_ALL};
        GetScrollInfo(SB_VERT, &info);
        const int line = MulDiv(32, static_cast<int>(GetDpiForWindow(m_hWnd)), 96);
        switch (LOWORD(wparam)) {
            case SB_TOP: ScrollTo(0); break;
            case SB_BOTTOM: ScrollTo(extent); break;
            case SB_LINEUP: ScrollTo(offset - line); break;
            case SB_LINEDOWN: ScrollTo(offset + line); break;
            case SB_PAGEUP: ScrollTo(offset - static_cast<int>(info.nPage)); break;
            case SB_PAGEDOWN: ScrollTo(offset + static_cast<int>(info.nPage)); break;
            case SB_THUMBTRACK: case SB_THUMBPOSITION: ScrollTo(info.nTrackPos); break;
        }
        return 0;
    }
    if (message == WM_MOUSEWHEEL && controller) return controller->SendMessage(message, wparam, lparam);
    return CWnd::WindowProc(message, wparam, lparam);
}

void CDesktopLayout::Initialize(CWnd& window) {
    window_ = &window;
    window.SetDlgItemText(IDC_PRODUCT_FOOTER, tlp::win::Widen(
        "TELIPHONES is a UK registered trademark.  "
        "TELIPHONES " TELIPHONES_VERSION_STRING " for Windows is licensed under GPLv3.").c_str());
    content_.controller = &window;
    if (!content_.CreateEx(WS_EX_CONTROLPARENT, AfxRegisterWndClass(0, LoadCursor(nullptr, IDC_ARROW),
        GetSysColorBrush(COLOR_3DFACE)), L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_VSCROLL,
        CRect(0, 0, 1, 1), &window, IDC_CONTENT_VIEWPORT)) {
        tlp::win::ThrowLastError("Create TELIPHONES scrollable content");
    }
    tlp::ui::ThemeWindow(content_.GetSafeHwnd());
    const CWnd* previous = &CWnd::wndTop;
    for (int id : contentIds) {
        CWnd* control = window.GetDlgItem(id);
        if (!control) throw std::runtime_error("A required TELIPHONES layout control is missing.");
        control->SetParent(&content_);
        control->SetWindowPos(previous, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        previous = control;
    }
    content_.changed = [this] { Arrange(); };
    SetDpi(GetDpiForWindow(window.GetSafeHwnd()));
}

CWnd* CDesktopLayout::Find(int id) const {
    if (!window_) return nullptr;
    CWnd* direct = window_->GetDlgItem(id);
    return direct ? direct : content_.GetDlgItem(id);
}

void CDesktopLayout::SetDpi(UINT dpi) {
    dpi_ = dpi ? dpi : 96;
    if (!window_) return;
    LOGFONT font{};
    font.lfHeight = -MulDiv(9, static_cast<int>(dpi_), 72);
    wcscpy_s(font.lfFaceName, L"Segoe UI");
    font_.DeleteObject();
    if (!font_.CreateFontIndirect(&font)) tlp::win::ThrowLastError("Create TELIPHONES display font");
    for (int id : contentIds) Find(id)->SetFont(&font_);
    for (int id : actionIds) Find(id)->SetFont(&font_);
    Find(IDC_WG_STATUS)->SetFont(&font_);
    Find(IDC_PRODUCT_FOOTER)->SetFont(&font_);
    font.lfWeight = FW_SEMIBOLD;
    headingFont_.DeleteObject();
    if (!headingFont_.CreateFontIndirect(&font)) tlp::win::ThrowLastError("Create TELIPHONES heading font");
    Find(IDC_PBX_HEADING)->SetFont(&headingFont_);
    Find(IDC_CONNECTION_HEADING)->SetFont(&headingFont_);
    Arrange();
}

void CDesktopLayout::Arrange() {
    if (!window_ || arranging_ || !content_.GetSafeHwnd()) return;
    arranging_ = true;
    CRect client;
    window_->GetClientRect(&client);
    auto scale = [&](int value) { return MulDiv(value, static_cast<int>(dpi_), 96); };
    auto layout = tlp::ArrangeDesktop(MulDiv(client.Width(), 96, static_cast<int>(dpi_)),
                                     MulDiv(client.Height(), 96, static_cast<int>(dpi_)));
    auto move = [&](CWnd* control, tlp::LayoutRect bounds, int offset = 0, bool combo = false) {
        const int left = scale(bounds.x), top = scale(bounds.y) - offset;
        control->SetWindowPos(nullptr, left, top, scale(bounds.x + bounds.width) - left,
            scale(bounds.height + (combo ? 180 : 0)), SWP_NOZORDER | SWP_NOACTIVATE);
    };
    move(&content_, layout.viewport);
    CRect visible;
    content_.GetClientRect(&visible);
    const int inset = MulDiv(GetSystemMetricsForDpi(SM_CXVSCROLL, dpi_), 96, static_cast<int>(dpi_));
    layout = tlp::ArrangeDesktop(MulDiv(client.Width(), 96, static_cast<int>(dpi_)) - inset,
                                MulDiv(client.Height(), 96, static_cast<int>(dpi_)));
    content_.extent = scale(layout.contentHeight);
    content_.offset = std::clamp(content_.offset, 0, std::max(0, content_.extent - visible.Height()));
    SCROLLINFO info{sizeof(info), SIF_RANGE | SIF_PAGE | SIF_POS};
    info.nMin = 0;
    info.nMax = content_.extent - 1;
    info.nPage = static_cast<UINT>(visible.Height());
    info.nPos = content_.offset;
    content_.SetScrollInfo(SB_VERT, &info, TRUE);
    // Reserve scrollbar width even when it disappears, avoiding resize/scrollbar oscillation.
    for (std::size_t i = 0; i < std::size(contentIds); ++i) {
        const int id = contentIds[i];
        move(Find(id), layout.content[i], content_.offset,
             id == IDC_SESSION || id == IDC_HEALTH_INLINE_HISTORY || id == IDC_HEALTH_PLOT);
    }
    // Fixed actions use the full window width, independent of the scrolling content.
    const auto fixed = tlp::ArrangeDesktop(MulDiv(client.Width(), 96, static_cast<int>(dpi_)),
                                          MulDiv(client.Height(), 96, static_cast<int>(dpi_)));
    move(Find(IDC_WG_STATUS), fixed.wireguard);
    move(Find(IDC_PRODUCT_FOOTER), fixed.disclaimer);
    for (std::size_t i = 0; i < std::size(actionIds); ++i) move(Find(actionIds[i]), fixed.actions[i]);
    CListCtrl* list = static_cast<CListCtrl*>(Find(IDC_PROFILES));
    CRect listRect;
    list->GetClientRect(&listRect);
    const int column = std::max(1, listRect.Width() - scale(16));
    const int shares[] = {35, 18, 30, 17};
    if (list->GetHeaderCtrl()) {
        for (int i = 0; i < 4; ++i) list->SetColumnWidth(i, column * shares[i] / 100);
    }
    content_.Invalidate(TRUE);
    arranging_ = false;
}

BOOL CDesktopLayout::Wheel(short delta) {
    CRect visible;
    content_.GetClientRect(&visible);
    if (content_.extent <= visible.Height()) return FALSE;
    wheelRemainder_ += delta;
    const int notches = wheelRemainder_ / WHEEL_DELTA;
    wheelRemainder_ %= WHEEL_DELTA;
    content_.ScrollTo(content_.offset - MulDiv(notches * 96, static_cast<int>(dpi_), 96));
    return TRUE;
}

void CDesktopLayout::InitialPosition() {
    MONITORINFO info{};
    info.cbSize = sizeof(info);
    if (!GetMonitorInfo(MonitorFromWindow(window_->GetSafeHwnd(), MONITOR_DEFAULTTONEAREST), &info))
        tlp::win::ThrowLastError("Read TELIPHONES display work area");
    const int width = std::min(MulDiv(1050, static_cast<int>(dpi_), 96), static_cast<int>(info.rcWork.right - info.rcWork.left));
    const int height = std::min(MulDiv(620, static_cast<int>(dpi_), 96), static_cast<int>(info.rcWork.bottom - info.rcWork.top));
    window_->SetWindowPos(nullptr, info.rcWork.left + (info.rcWork.right - info.rcWork.left - width) / 2,
        info.rcWork.top + (info.rcWork.bottom - info.rcWork.top - height) / 2, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
}
