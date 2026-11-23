#include "PairDlg.h"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iterator>

#include "../core/Encoding.h"
#include "../core/Json.h"
#include "../core/Pairing.h"
#include "../core/Validation.h"
#include "../platform/Services.h"
#include "../platform/Ssh.h"
#include "../platform/Win.h"
#include "resource.h"

namespace {

class WipeString {
public:
    explicit WipeString(std::string& value) : value_(value) {}
    ~WipeString() { tlp::win::SecureWipe(value_); }

private:
    std::string& value_;
};

void SetEdit(CWnd* dialog, int id, const std::string& value) {
    dialog->SetDlgItemText(id, tlp::win::Widen(value).c_str());
}

std::string GetEdit(CWnd* dialog, int id) {
    CString value;
    dialog->GetDlgItemText(id, value);
    return tlp::win::Narrow(std::wstring(value.GetString()));
}

void CopyText(HWND owner, const std::string& text) {
    if (!OpenClipboard(owner)) throw tlp::Error("Windows could not open the clipboard.");
    EmptyClipboard();
    std::wstring wide = tlp::win::Widen(text);
    SIZE_T bytes = (wide.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (memory == nullptr) {
        CloseClipboard();
        throw tlp::Error("Windows could not allocate clipboard memory.");
    }
    void* target = GlobalLock(memory);
    if (target == nullptr) {
        GlobalFree(memory);
        CloseClipboard();
        throw tlp::Error("Windows could not access clipboard memory.");
    }
    memcpy(target, wide.c_str(), bytes);
    GlobalUnlock(memory);
    if (SetClipboardData(CF_UNICODETEXT, memory) == nullptr) {
        GlobalFree(memory);
        CloseClipboard();
        throw tlp::Error("Windows could not copy the text.");
    }
    CloseClipboard();
}

void ClipChildToViewport(CWnd* parent, HWND window, LONG viewportTop, LONG viewportBottom) {
    CRect child;
    ::GetWindowRect(window, &child);
    parent->ScreenToClient(&child);
    if (child.top >= viewportTop && child.bottom <= viewportBottom) {
        // A full-size custom region can interfere with native controls such as
        // combo boxes. Leave fully visible controls with their normal window shape.
        SetWindowRgn(window, nullptr, TRUE);
        return;
    }

    const int top = static_cast<int>(std::clamp<LONG>(viewportTop - child.top, 0, child.Height()));
    const int bottom = static_cast<int>(std::clamp<LONG>(viewportBottom - child.top, 0, child.Height()));
    HRGN region = CreateRectRgn(0, top, std::max(0, child.Width()), std::max(top, bottom));
    if (region && !SetWindowRgn(window, region, TRUE)) DeleteObject(region);
}

std::string ComputerName() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD length = static_cast<DWORD>(std::size(buffer));
    if (!GetComputerNameW(buffer, &length)) return "Windows workstation";
    std::string name = tlp::win::Narrow(std::wstring(buffer, length));
    for (char& c : name) {
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == ' ' || c == '.' || c == '_' || c == '(' || c == ')' || c == '-')) {
            c = '-';
        }
    }
    if (name.empty() || !((name.front() >= 'A' && name.front() <= 'Z') || (name.front() >= 'a' && name.front() <= 'z') ||
                          (name.front() >= '0' && name.front() <= '9'))) {
        name = "Windows-" + name;
    }
    if (name.size() > 64) name.resize(64);
    return name;
}

}  // namespace

BEGIN_MESSAGE_MAP(CPairDlg, CAppearanceDialog)
    ON_BN_CLICKED(IDC_PAIR_GENERATE, &CPairDlg::OnGenerate)
    ON_BN_CLICKED(IDC_PAIR_COPY, &CPairDlg::OnCopy)
    ON_EN_CHANGE(IDC_PAIR_WORKSTATION, &CPairDlg::OnRequestChanged)
    ON_CBN_SELCHANGE(IDC_PAIR_ACCESS, &CPairDlg::OnRequestChanged)
    ON_EN_CHANGE(IDC_PAIR_RESPONSE, &CPairDlg::OnResponseChanged)
    ON_WM_TIMER()
    ON_WM_SIZE()
    ON_MESSAGE(WM_DPICHANGED, &CPairDlg::OnDpiChanged)
    ON_MESSAGE(WM_DPICHANGED_AFTERPARENT, &CPairDlg::OnDpiLayout)
    ON_WM_VSCROLL()
    ON_WM_MOUSEWHEEL()
    ON_WM_SETFOCUS()
    ON_MESSAGE(WM_APP + 0x321, &CPairDlg::OnRevealFocusedControl)
END_MESSAGE_MAP()

CPairDlg::CPairDlg(const tlp::win::WireGuardInstallation& wireguard, CWnd* parent) : CAppearanceDialog(IDD_PAIR, parent), wireguard_(wireguard) {}

BOOL CPairDlg::OnInitDialog() {
    CAppearanceDialog::OnInitDialog();
    SetWindowText(L"Add my PBX");
    SetDlgItemText(IDC_PAIR_WORKSTATION, tlp::win::Widen(ComputerName()).c_str());
    SetDlgItemText(IDC_PAIR_SSHUSER, L"");
    auto* access = static_cast<CComboBox*>(GetDlgItem(IDC_PAIR_ACCESS));
    access->AddString(L"FreePBX Web Access");
    access->AddString(L"FreePBX Web + SSH Access");
    access->SetCurSel(0);
    static_cast<CEdit*>(GetDlgItem(IDC_PAIR_WORKSTATION))->SetLimitText(64);
    static_cast<CEdit*>(GetDlgItem(IDC_PAIR_RESPONSE))->SetLimitText(16000);
    static_cast<CEdit*>(GetDlgItem(IDC_PAIR_TLS_HOSTNAME))->SetLimitText(253);
    SetDlgItemText(IDC_PAIR_REQUEST, L"Generate a key and pairing request first.");
    SetDlgItemText(IDC_PAIR_FINGERPRINT, L"");
    SetDlgItemText(IDC_PAIR_STATUS, L"Choose Web Access, or request Web + SSH. FreePBX must separately approve SSH.");
    ModifyStyle(0, WS_THICKFRAME | WS_VSCROLL);
    CRect client;
    GetClientRect(&client);
    initialDpi_ = std::max(1, static_cast<int>(GetDpiForWindow(m_hWnd)));
    layoutDpi_ = initialDpi_;
    initialClientWidth_ = client.Width();
    footerControls_.clear();
    for (HWND child = ::GetWindow(m_hWnd, GW_CHILD); child; child = ::GetWindow(child, GW_HWNDNEXT)) {
        const int id = ::GetDlgCtrlID(child);
        CRect rect;
        ::GetWindowRect(child, &rect);
        ScreenToClient(&rect);
        if (id == IDOK || id == IDCANCEL) {
            const int minimumGap = MulDiv(8, initialDpi_, 96);
            footerControls_.push_back({child, rect,
                std::max(minimumGap, static_cast<int>(client.bottom - rect.bottom))});
        } else {
            contentControls_.push_back({child, rect, 0});
            contentExtent_ = std::max(contentExtent_, static_cast<int>(rect.bottom));
        }
    }
    // Cap the initial outer window size to the nearest monitor's work area.
    MONITORINFO monitor{};
    monitor.cbSize = sizeof(monitor);
    if (GetMonitorInfo(MonitorFromWindow(m_hWnd, MONITOR_DEFAULTTONEAREST), &monitor)) {
        const CRect work(monitor.rcWork);
        CRect window;
        GetWindowRect(&window);
        const int width = static_cast<int>(std::min(window.Width(), work.Width()));
        const int height = static_cast<int>(std::min(window.Height(), work.Height()));
        const int x = static_cast<int>(std::clamp(window.left, work.left, work.right - width));
        const int y = static_cast<int>(std::clamp(window.top, work.top, work.bottom - height));
        if (width != window.Width() || height != window.Height() || x != window.left || y != window.top)
            SetWindowPos(nullptr, x, y, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
    }
    initialized_ = true;
    ArrangePairDialog();
    SetDefID(IDC_PAIR_GENERATE);
    OnResponseChanged();
    return TRUE;
}

void CPairDlg::ArrangePairDialog() {
    if (!m_hWnd || arranging_) return;
    arranging_ = true;
    CRect client;
    GetClientRect(&client);
    const LONG baseWidth = std::max<LONG>(1, ScaleForDpi(initialClientWidth_));
    const auto scaleX = [&](int x) { return MulDiv(x, client.Width(), baseWidth); };
    const LONG currentFooterTop = FooterTop(client);
    const LONG viewportBottom = std::max<LONG>(0, currentFooterTop - 6);
    const LONG contentExtent = ScaledContentExtent();
    scrollOffset_ = std::clamp(scrollOffset_, LONG{0},
        std::max<LONG>(0, contentExtent - viewportBottom));

    for (const auto& item : contentControls_) {
        if (::IsWindow(item.window)) {
            const int left = scaleX(item.original.left);
            const int right = scaleX(item.original.right);
            const LONG top = ScaleForDpi(item.original.top) - scrollOffset_;
            const LONG bottom = ScaleForDpi(item.original.bottom) - scrollOffset_;
            ::SetWindowPos(item.window, nullptr, left, top, right - left, bottom - top,
                SWP_NOZORDER | SWP_NOACTIVATE);
            ClipChildToViewport(this, item.window, 0, viewportBottom);
        }
    }
    for (const auto& item : footerControls_) {
        if (::IsWindow(item.window)) {
            const int left = scaleX(item.original.left);
            const int right = scaleX(item.original.right);
            const LONG top = client.bottom - ScaleForDpi(item.bottomGap + item.original.Height());
            const LONG height = ScaleForDpi(item.original.Height());
            ::SetWindowPos(item.window, nullptr, left, top, right - left, height,
                SWP_NOZORDER | SWP_NOACTIVATE);
        }
    }

    SCROLLINFO info{sizeof(info), SIF_RANGE | SIF_PAGE | SIF_POS};
    info.nMin = 0;
    info.nMax = static_cast<int>(std::max<LONG>(0, contentExtent - 1));
    info.nPage = static_cast<UINT>(viewportBottom);
    info.nPos = static_cast<int>(scrollOffset_);
    SetScrollInfo(SB_VERT, &info, TRUE);
    arranging_ = false;
}

LONG CPairDlg::ScaleForDpi(LONG value) const {
    return static_cast<LONG>(MulDiv(value, std::max(1, layoutDpi_), initialDpi_));
}

LONG CPairDlg::FooterTop(const CRect& client) const {
    LONG top = client.bottom;
    for (const auto& item : footerControls_) {
        top = std::min(top, client.bottom - ScaleForDpi(item.bottomGap + item.original.Height()));
    }
    return top;
}

LONG CPairDlg::ScaledContentExtent() const {
    return ScaleForDpi(contentExtent_);
}

LRESULT CPairDlg::OnDpiChanged(WPARAM dpi, LPARAM rectangle) {
    layoutDpi_ = std::max(1, static_cast<int>(HIWORD(dpi)));
    const RECT& suggested = *reinterpret_cast<const RECT*>(rectangle);
    RECT bounds = suggested;
    MONITORINFO monitor{};
    monitor.cbSize = sizeof(monitor);
    if (GetMonitorInfoW(MonitorFromRect(&suggested, MONITOR_DEFAULTTONEAREST), &monitor)) {
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
    ArrangePairDialog();
    return 0;
}

LRESULT CPairDlg::OnDpiLayout(WPARAM, LPARAM) {
    layoutDpi_ = std::max(1, static_cast<int>(GetDpiForWindow(m_hWnd)));
    ArrangePairDialog();
    return 0;
}

void CPairDlg::ScrollPairContent(LONG offset) {
    CRect client;
    GetClientRect(&client);
    const LONG currentFooterTop = FooterTop(client);
    const LONG viewportBottom = std::max<LONG>(0, currentFooterTop - 6);
    const LONG next = std::clamp(offset, LONG{0}, std::max<LONG>(0, ScaledContentExtent() - viewportBottom));
    if (next == scrollOffset_) return;
    scrollOffset_ = next;
    ArrangePairDialog();
}

void CPairDlg::OnSize(UINT nType, int cx, int cy) {
    CAppearanceDialog::OnSize(nType, cx, cy);
    if (initialized_) ArrangePairDialog();
}

void CPairDlg::OnVScroll(UINT code, UINT position, CScrollBar* scrollbar) {
    (void)scrollbar;
    SCROLLINFO info{sizeof(info), SIF_ALL};
    GetScrollInfo(SB_VERT, &info);
    const LONG line = std::max<LONG>(16, GetSystemMetrics(SM_CXVSCROLL));
    switch (code) {
        case SB_TOP: ScrollPairContent(0); break;
        case SB_BOTTOM: ScrollPairContent(ScaledContentExtent()); break;
        case SB_LINEUP: ScrollPairContent(scrollOffset_ - line); break;
        case SB_LINEDOWN: ScrollPairContent(scrollOffset_ + line); break;
        case SB_PAGEUP: ScrollPairContent(scrollOffset_ - static_cast<LONG>(info.nPage)); break;
        case SB_PAGEDOWN: ScrollPairContent(scrollOffset_ + static_cast<LONG>(info.nPage)); break;
        case SB_THUMBTRACK:
        case SB_THUMBPOSITION:
            ScrollPairContent(static_cast<LONG>(position));
            break;
    }
}

void CPairDlg::OnSetFocus(CWnd* oldWindow) {
    CAppearanceDialog::OnSetFocus(oldWindow);
    CWnd* focus = GetFocus();
    if (!focus || focus == this) return;
    auto found = std::find_if(contentControls_.begin(), contentControls_.end(),
        [focus](const ContentControl& item) { return item.window == focus->GetSafeHwnd(); });
    if (found == contentControls_.end()) return;
    CRect client;
    GetClientRect(&client);
    const LONG footer = FooterTop(client);
    CRect rect;
    focus->GetWindowRect(&rect);
    ScreenToClient(&rect);
    const LONG viewportTop = ScaleForDpi(0);
    if (rect.top < viewportTop) ScrollPairContent(scrollOffset_ + rect.top - viewportTop);
    else if (rect.bottom > footer - 6) ScrollPairContent(scrollOffset_ + rect.bottom - footer + 6);
}

BOOL CPairDlg::PreTranslateMessage(MSG* message) {
    const BOOL handled = CAppearanceDialog::PreTranslateMessage(message);
    if (message->message == WM_KEYDOWN && message->wParam == VK_TAB)
        PostMessage(kRevealFocusMessage);
    return handled;
}

LRESULT CPairDlg::OnRevealFocusedControl(WPARAM, LPARAM) {
    CWnd* focus = GetFocus();
    if (!focus) return 0;
    const auto found = std::find_if(contentControls_.begin(), contentControls_.end(),
        [focus](const ContentControl& item) { return item.window == focus->GetSafeHwnd(); });
    if (found == contentControls_.end()) return 0;
    CRect client, rect;
    GetClientRect(&client);
    focus->GetWindowRect(&rect);
    ScreenToClient(&rect);
    const LONG top = ScaleForDpi(0);
    const LONG bottom = FooterTop(client) - 6;
    if (rect.top < top) ScrollPairContent(scrollOffset_ + rect.top - top);
    else if (rect.bottom > bottom) ScrollPairContent(scrollOffset_ + rect.bottom - bottom);
    return 0;
}

BOOL CPairDlg::OnMouseWheel(UINT flags, short delta, CPoint point) {
    (void)flags;
    (void)point;
    wheelRemainder_ += delta;
    const int notches = wheelRemainder_ / WHEEL_DELTA;
    wheelRemainder_ %= WHEEL_DELTA;
    if (notches != 0)
        ScrollPairContent(scrollOffset_ - notches * std::max(24, GetSystemMetrics(SM_CXVSCROLL)));
    return TRUE;
}

bool CPairDlg::RequestCurrent() const {
    CString name;
    GetDlgItemText(IDC_PAIR_WORKSTATION, name);
    auto* access = static_cast<CComboBox*>(GetDlgItem(IDC_PAIR_ACCESS));
    return keyStored_ && !request_.empty() && (access->GetCurSel() == 0 || access->GetCurSel() == 1) &&
        profile.workstationName == tlp::win::Narrow(std::wstring(name.GetString())) &&
        sshKeyRequested_ == (access->GetCurSel() == 1);
}

bool CPairDlg::InvalidateRequest() {
    request_.clear();
    publicKey_.clear();
    sshPublicKey_.clear();
    nonce_.clear();
    KillTimer(1);
    SetDlgItemText(IDC_PAIR_COPY, L"&Copy request");
    GetDlgItem(IDC_PAIR_COPY)->EnableWindow(FALSE);
    GetDlgItem(IDOK)->EnableWindow(FALSE);
    GetDlgItem(IDC_PAIR_RESPONSE)->EnableWindow(FALSE);
    SetDefID(IDC_PAIR_GENERATE);
    SetDlgItemText(IDC_PAIR_REQUEST, L"");
    SetDlgItemText(IDC_PAIR_FINGERPRINT, L"");
    SetDlgItemText(IDC_PAIR_RESPONSE, L"");
    SetDlgItemText(IDC_PAIR_SSHUSER, L"");
    GetDlgItem(IDC_PAIR_SSHUSER)->ShowWindow(SW_HIDE);
    GetDlgItem(IDC_PAIR_SSHLABEL)->ShowWindow(SW_HIDE);
    ArrangePairDialog();
    return DiscardKey();
}

void CPairDlg::OnRequestChanged() {
    if (!initialized_ || (request_.empty() && !keyStored_)) return;
    InvalidateRequest();
    SetDlgItemText(IDC_PAIR_STATUS, L"Name or access changed. Generate a new request; the previous response cannot be used.");
}

tlp::PairResponse CPairDlg::ValidatedResponse() {
    if (!RequestCurrent()) throw tlp::Error("Generate a request for the current workstation name and access choice.");
    auto pairing = tlp::ParsePairResponse(GetEdit(this, IDC_PAIR_RESPONSE), nonce_, publicKey_, sshPublicKey_);
    if (sshKeyRequested_ && !pairing.ssh)
        throw tlp::Error("FreePBX has not approved the requested SSH access. Obtain explicit SSH approval, or generate a new Web Access request.");
    if (pairing.ssh && sshPublicKey_.empty())
        throw tlp::Error("This request is web-only. Generate a new Web + SSH request before approving SSH.");
    if (pairing.ssh && pairing.sshPort == 0)
        throw tlp::Error("The PBX returned legacy SSH permission. Upgrade its TELIPHONES broker and approve again.");
    if (pairing.ssh && !tlp::IsLinuxUser(pairing.sshUser))
        throw tlp::Error("The PBX must supply the explicitly approved Linux SSH account.");
    const std::string hostname = GetEdit(this, IDC_PAIR_TLS_HOSTNAME);
    if (!hostname.empty() && (pairing.guiUrl.rfind("https://", 0) != 0 || !tlp::IsHostname(hostname)))
        throw tlp::Error("Enter only a DNS hostname (no scheme, port or path), and only when the paired primary management service is HTTPS.");
    return pairing;
}

void CPairDlg::OnResponseChanged() {
    if (!initialized_) return;
    GetDlgItem(IDOK)->EnableWindow(FALSE);
    SetDlgItemText(IDC_PAIR_SSHUSER, L"");
    GetDlgItem(IDC_PAIR_SSHUSER)->ShowWindow(SW_HIDE);
    GetDlgItem(IDC_PAIR_SSHLABEL)->ShowWindow(SW_HIDE);
    ArrangePairDialog();
    if (!RequestCurrent()) return;
    if (GetEdit(this, IDC_PAIR_RESPONSE).empty()) {
        SetDlgItemText(IDC_PAIR_STATUS, L"Copy the generated request to FreePBX, then paste its response here.");
        return;
    }
    try {
        const auto pairing = ValidatedResponse();
        if (pairing.managementHostnameSupplied) {
            if (!pairing.managementHostname.empty()) {
                SetEdit(this, IDC_PAIR_TLS_HOSTNAME, pairing.managementHostname);
                GetDlgItem(IDC_PAIR_TLS_HOSTNAME)->EnableWindow(TRUE);
            } else {
                SetEdit(this, IDC_PAIR_TLS_HOSTNAME, "");
                GetDlgItem(IDC_PAIR_TLS_HOSTNAME)->EnableWindow(TRUE);
                if (pairing.guiUrl.rfind("https://", 0) == 0)
                    SetDlgItemText(IDC_PAIR_STATUS, L"Pairing verified. The PBX has no configured management certificate hostname; confirm the exact certificate DNS name with its administrator.");
            }
        }
        if (pairing.ssh) {
            SetEdit(this, IDC_PAIR_SSHUSER, pairing.sshUser);
            GetDlgItem(IDC_PAIR_SSHUSER)->ShowWindow(SW_SHOW);
            GetDlgItem(IDC_PAIR_SSHLABEL)->ShowWindow(SW_SHOW);
            ArrangePairDialog();
        }
        if (!pairing.managementHostnameSupplied || !pairing.managementHostname.empty()) {
            SetDlgItemText(IDC_PAIR_STATUS, pairing.ssh
                ? L"Response verified. SSH approved by FreePBX for the account shown."
                : L"Response verified. FreePBX Web Access only; SSH is not approved.");
        }
        GetDlgItem(IDOK)->EnableWindow(TRUE);
        SetDefID(IDOK);
    } catch (const tlp::Error& error) {
        SetEdit(this, IDC_PAIR_STATUS, error.what());
    }
}

void CPairDlg::OnGenerate() {
    try {
        if (!InvalidateRequest()) return;
        std::string name = GetEdit(this, IDC_PAIR_WORKSTATION);
        if (!tlp::IsWorkstationName(name)) {
            throw tlp::Error("Use a workstation name beginning with a letter or number, up to 64 characters. Letters, numbers, spaces, dots, underscores, parentheses and hyphens are allowed.");
        }
        auto* access = static_cast<CComboBox*>(GetDlgItem(IDC_PAIR_ACCESS));
        if (access->GetCurSel() != 0 && access->GetCurSel() != 1)
            throw tlp::Error("Select FreePBX Web Access or FreePBX Web + SSH Access before generating a request.");
        std::string privateKey = tlp::win::GeneratePrivateKey(wireguard_);
        [[maybe_unused]] WipeString privateKeyWiper(privateKey);
        publicKey_ = tlp::win::DerivePublicKey(wireguard_, privateKey);
        if (!tlp::IsWireGuardKey(publicKey_)) throw tlp::Error("WireGuard returned an invalid public key.");
        profile = {};
        profile.id = tlp::win::NewProfileId();
        profile.kind = tlp::ProfileKind::Administrator;
        profile.name = name;
        profile.workstationName = name;
        profile.createdAt = tlp::win::UnixNow();
        nonce_ = tlp::MakeNonce(tlp::win::RandomBytes(16));
        tlp::win::SavePrivateKey(tlp::CredentialTargetFor(profile), privateKey);
        keyStored_ = true;
        sshKeyRequested_ = access->GetCurSel() == 1;
        const auto request = tlp::CreatePairRequest(name, publicKey_, nonce_,
            sshKeyRequested_,
            [this]() { return tlp::win::GenerateWorkstationSshIdentity(profile); });
        sshPublicKey_ = request.sshPublicKey;
        request_ = request.code;
        SetEdit(this, IDC_PAIR_REQUEST, request_);
        GetDlgItem(IDC_PAIR_COPY)->EnableWindow(TRUE);
        GetDlgItem(IDC_PAIR_RESPONSE)->EnableWindow(TRUE);
        SetDefID(IDOK);
        SetDlgItemText(IDC_PAIR_FINGERPRINT, tlp::win::Widen("Workstation public-key fingerprint: " + tlp::KeyFingerprint(publicKey_)).c_str());
        SetDlgItemText(IDC_PAIR_STATUS, sshKeyRequested_
            ? L"Request generated. FreePBX Web + SSH Access requires separate administrator approval."
            : L"Request generated for FreePBX Web Access. Copy it to the PBX to continue.");
    } catch (const std::exception& e) {
        InvalidateRequest();
        SetDlgItemText(IDC_PAIR_STATUS, L"Request generation failed. Correct the error and generate again.");
        tlp::ui::ShowMessage(tlp::win::Widen(e.what()).c_str(), MB_ICONERROR);
    }
}

void CPairDlg::OnCopy() {
    if (!RequestCurrent()) {
        tlp::ui::ShowMessage(L"Generate a pairing request first.", MB_ICONINFORMATION);
        return;
    }
    try {
        CopyText(m_hWnd, request_);
        SetDlgItemText(IDC_PAIR_COPY, L"Copied");
        SetTimer(1, 1800, nullptr);
    } catch (const std::exception& e) {
        tlp::ui::ShowMessage(tlp::win::Widen(e.what()).c_str(), MB_ICONERROR);
    }
}

void CPairDlg::OnTimer(UINT_PTR timerId) {
    if (timerId == 1) {
        KillTimer(timerId);
        SetDlgItemText(IDC_PAIR_COPY, L"&Copy request");
    }
    CAppearanceDialog::OnTimer(timerId);
}

void CPairDlg::OnOK() {
    try {
        tlp::PairResponse pairing = ValidatedResponse();
        std::string sshUser = pairing.sshUser;
        SetEdit(this, IDC_PAIR_SSHUSER, sshUser);
        SetDlgItemText(IDC_PAIR_STATUS, pairing.ssh
            ? L"SSH authorised by FreePBX for the selected existing account."
            : L"SSH not authorised by FreePBX. Web Access remains available.");
        profile.name = pairing.pbxName + " (" + profile.workstationName + ")";
        if (profile.name.size() > 128) profile.name.resize(128);
        profile.sshUser = pairing.ssh ? sshUser : std::string();
        profile.pairing = std::move(pairing);
        profile.managementTlsHostname = GetEdit(this, IDC_PAIR_TLS_HOSTNAME);
        CDialogEx::OnOK();
    } catch (const std::exception& e) {
        tlp::ui::ShowMessage(tlp::win::Widen(e.what()).c_str(), MB_ICONERROR);
    }
}

bool CPairDlg::DiscardKey() {
    if (!keyStored_) return true;
    try {
        tlp::win::DeletePrivateKey(tlp::CredentialTargetFor(profile));
        if (sshKeyRequested_) {
            tlp::win::DeleteSshPrivateKey(profile);
            tlp::win::RemoveSshRuntime(profile);
        }
    } catch (const std::exception& e) {
        tlp::ui::ShowMessage((std::wstring(L"The unused workstation key could not be removed from Windows Credential Manager: ") + tlp::win::Widen(e.what())).c_str(),
                      MB_ICONERROR);
        return false;
    }
    keyStored_ = false;
    sshKeyRequested_ = false;
    return true;
}

void CPairDlg::OnCancel() {
    DiscardKey();
    CDialogEx::OnCancel();
}
