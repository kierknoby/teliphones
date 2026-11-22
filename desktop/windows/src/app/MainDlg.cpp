#include "MainDlg.h"

#include <objbase.h>
#include <shellapi.h>

#include <ctime>
#include <algorithm>
#include <exception>
#include <functional>
#include <thread>

#include "../core/Admission.h"
#include "../core/CommandLine.h"
#include "../core/Encoding.h"
#include "../core/Json.h"
#include "../core/Pairing.h"
#include "../core/Rendezvous.h"
#include "../core/SessionDiagnostics.h"
#include "../core/SshRuntime.h"
#include "../core/TunnelConfig.h"
#include "../core/WorkstationHeartbeat.h"
#include "../core/Validation.h"
#include "../platform/Applications.h"
#include "../platform/Services.h"
#include "../platform/Ssh.h"
#include "../platform/Win.h"
#include "AppSettingsDlg.h"
#include "ConnectPasswordDlg.h"
#include "../core/ConnectProtection.h"
#include "PairDlg.h"
#include "SupportDlg.h"
#include "SessionLogDlg.h"
#include "resource.h"
#include "Version.h"

using tlp::Profile;
using tlp::ProfileKind;
using tlp::win::Narrow;
using tlp::win::Widen;

namespace {

constexpr UINT_PTR kMonitorTimer = 1;
constexpr UINT kMonitorIntervalMs = 2000;

enum class OperationKind { Connect, Disconnect, Cleanup, Recovery, Ssh, Policy };

struct OperationResult {
    OperationKind kind = OperationKind::Connect;
    bool declined = false;
    std::string error;
    std::string warning;
    std::string reason;
    bool policyLocked = false;
    bool unlockRequestPending = false;
    bool sourcesRequestPending = false;
    UINT_PTR generation = 0;
};

struct ProbeResult {
    bool statusKnown = false;
    bool serviceRunning = false;
    bool probeSucceeded = false;
    bool sessionAdmissionRequired = false;
    std::string sessionAdmissionError;
    bool admissionTransportFailure = false;
    std::string admissionFailureClass;
    int connectedWorkstations = 0;
    int maximumWorkstations = 0;
    bool policyLocked = false;
    bool unlockRequestPending = false;
    bool sourcesRequestPending = false;
    std::string policySummary;
    std::optional<tlp::PairResponse> migration;
    std::optional<tlp::PairResponse> pairingUpdate;
    bool sshRevoked = false;
    bool sshRequestRejected = false;
    tlp::HealthSample sample;
    std::string error;
};

class WipeString {
public:
    explicit WipeString(std::string& value) : value_(value) {}
    ~WipeString() { tlp::win::SecureWipe(value_); }
    WipeString(const WipeString&) = delete;
    WipeString& operator=(const WipeString&) = delete;

private:
    std::string& value_;
};

// Long operations (UAC approval, service installation, network probes) run off the UI thread and post
// their result back. If the window has gone, the result is discarded.
void RunInBackground(HWND window, OperationKind kind, std::string reason, std::function<bool(OperationResult&)> work) {
    std::thread([window, kind, reason, work]() {
        HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        auto* result = new OperationResult;
        result->kind = kind;
        result->reason = reason;
        try {
            result->declined = !work(*result);
        } catch (const std::exception& e) {
            result->error = e.what();
        }

        if (SUCCEEDED(com)) CoUninitialize();
        if (!::PostMessageW(window, WM_APP_OPERATION_DONE, 0, reinterpret_cast<LPARAM>(result))) delete result;
    }).detach();
}

std::string FormatTime(std::int64_t unixTime) {
    if (unixTime <= 0) return "never";
    CTime time(static_cast<time_t>(unixTime));
    return Narrow(std::wstring(time.Format(L"%Y-%m-%d %H:%M")));
}

// UI-thread notices raised while the main dialog is still hidden (OnInitDialog) wait until it is shown.
// A message box owned by the hidden dialog has no taskbar button and can be lost behind other windows,
// leaving a running TELIPHONES process with no reachable window.
std::vector<std::wstring> deferredNotices;

class CManagementHostnameDlg : public CDialogEx {
public:
    explicit CManagementHostnameDlg(const std::string& initial)
        : CDialogEx(IDD_MANAGEMENT_HOSTNAME), hostname_(initial) {}
    std::string hostname() const { return hostname_; }
protected:
    BOOL OnInitDialog() override {
        CDialogEx::OnInitDialog();
        SetDlgItemText(IDC_MANAGEMENT_HOSTNAME, Widen(hostname_).c_str());
        static_cast<CEdit*>(GetDlgItem(IDC_MANAGEMENT_HOSTNAME))->SetLimitText(253);
        return TRUE;
    }
    void OnOK() override {
        CString value;
        GetDlgItemText(IDC_MANAGEMENT_HOSTNAME, value);
        const std::string candidate = Narrow(std::wstring(value.GetString()));
        if (!candidate.empty() && !tlp::IsHostname(candidate)) {
            tlp::ui::ShowMessage(L"Enter a DNS hostname only (no scheme, port, path, or IP address).", MB_OK | MB_ICONWARNING);
            return;
        }
        hostname_ = candidate;
        CDialogEx::OnOK();
    }
private:
    std::string hostname_;
};

void ShowError(const std::string& text) {
    CWnd* main = AfxGetMainWnd();
    if (main != nullptr && main->GetSafeHwnd() != nullptr && !main->IsWindowVisible()) {
        if (deferredNotices.empty()) main->PostMessage(WM_APP_STARTUP_NOTICES);
        deferredNotices.push_back(Widen(text));
        return;
    }
    tlp::ui::ShowMessage(Widen(text).c_str(), MB_ICONERROR);
}

std::string AccessText(const Profile& profile, std::int64_t now) {
    if (profile.kind == ProfileKind::Administrator) {
        std::string access = profile.pairing.mode == "persistent" ? "Persistent" : "Temporary";
        if (profile.pairing.mode == "temporary") {
            access += profile.pairing.expiresAt > now ? " (" + tlp::FormatRemaining(profile.pairing.expiresAt - now) + " left)" : " (expired)";
        }
        return access + (profile.pairing.ssh ? ", web + SSH" : ", web only");
    }
    if (!profile.hasGrant) return "Awaiting grant";
    std::size_t live = 0;
    for (const auto& session : profile.grant.sessions) {
        if (session.expiresAt > now) ++live;
    }
    return std::to_string(live) + " authorised session(s)";
}

}  // namespace

BEGIN_MESSAGE_MAP(CMainDlg, CAppearanceDialog)
    ON_WM_SIZE()
    ON_WM_GETMINMAXINFO()
    ON_WM_MOUSEWHEEL()
    ON_WM_CTLCOLOR()
    ON_MESSAGE(WM_DPICHANGED, &CMainDlg::OnDpiChanged)
    ON_CBN_SELCHANGE(IDC_HEALTH_PLOT, &CMainDlg::OnPlotChanged)
    ON_BN_CLICKED(IDC_ADD_PBX, &CMainDlg::OnAddPbx)
    ON_BN_CLICKED(IDC_ADD_SUPPORT, &CMainDlg::OnAddSupport)
    ON_BN_CLICKED(IDC_UPDATE_GRANT, &CMainDlg::OnUpdateGrant)
    ON_BN_CLICKED(IDC_REMOVE, &CMainDlg::OnRemove)
    ON_BN_CLICKED(IDC_EDIT_MANAGEMENT_HOSTNAME, &CMainDlg::OnEditManagementHostname)
    ON_BN_CLICKED(IDC_CONNECT, &CMainDlg::OnConnect)
    ON_BN_CLICKED(IDC_DISCONNECT, &CMainDlg::OnDisconnect)
    ON_BN_CLICKED(IDC_OPEN_GUI, &CMainDlg::OnOpenGui)
    ON_BN_CLICKED(IDC_OPEN_SSH, &CMainDlg::OnOpenSsh)
    ON_BN_CLICKED(IDC_LOCK_WORKSTATION, &CMainDlg::OnLockWorkstation)
    ON_BN_CLICKED(IDC_REQUEST_SOURCES, &CMainDlg::OnRequestSources)
    ON_BN_CLICKED(IDC_SETTINGS, &CMainDlg::OnSettings)
    ON_BN_CLICKED(IDC_RECOVER, &CMainDlg::OnRecover)
    ON_BN_CLICKED(IDC_CONNECTION_HEALTH, &CMainDlg::OnConnectionHealth)
    ON_BN_CLICKED(IDC_SESSION_LOG, &CMainDlg::OnSessionLog)
    ON_CBN_SELCHANGE(IDC_HEALTH_INLINE_HISTORY, &CMainDlg::OnInlineHistoryChanged)
    ON_WM_DRAWITEM()
    ON_NOTIFY(LVN_ITEMCHANGED, IDC_PROFILES, &CMainDlg::OnSelectionChanged)
    ON_CBN_SELCHANGE(IDC_SESSION, &CMainDlg::UpdateButtons)
    ON_WM_TIMER()
    ON_MESSAGE(WM_APP_OPERATION_DONE, &CMainDlg::OnOperationDone)
    ON_MESSAGE(WM_APP_PROBE_DONE, &CMainDlg::OnProbeDone)
    ON_MESSAGE(WM_APP_FIRST_RUN, &CMainDlg::OnFirstRun)
    ON_MESSAGE(WM_APP_STARTUP_NOTICES, &CMainDlg::OnStartupNotices)
    ON_MESSAGE(WM_APP_NETWORK_CHANGED, &CMainDlg::OnNetworkChanged)
END_MESSAGE_MAP()

CMainDlg::CMainDlg(CWnd* parent) : CAppearanceDialog(IDD_MAIN, parent), healthDialog_(this) {}

void CMainDlg::DoDataExchange(CDataExchange* exchange) {
    CDialogEx::DoDataExchange(exchange);
    DDX_Control(exchange, IDC_PROFILES, list_);
    DDX_Control(exchange, IDC_SESSION, sessions_);
}

BOOL CMainDlg::OnInitDialog() {
    CAppearanceDialog::OnInitDialog();
    bool preferencesReadable = true;
    try {
        storedPreferences_ = tlp::win::LoadPreferences();
    } catch (const std::exception& e) {
        preferencesReadable = false;
        ShowError(std::string("Your browser and SSH terminal preferences could not be read and were left unchanged: ") + e.what() +
                  " Open Settings to choose them again.");
    }
    try {
        tlp::ui::SetAppearance(storedPreferences_.value_or(tlp::Preferences()).appearance);
    } catch (const std::exception& e) {
        ShowError(std::string("Your saved appearance could not be applied: ") + e.what());
    }
    try {
        layout_.Initialize(*this);
        layout_.InitialPosition();
    } catch (const std::exception& e) {
        ShowError(e.what());
        EndDialog(IDCANCEL);
        return FALSE;
    }
    LogEvent("startup", "info", "Application started; diagnostic timestamps are UTC. PBX clock may differ.");
    SetWindowText(Widen("TELIPHONES " TELIPHONES_VERSION_STRING).c_str());
    HICON icon = LoadIconW(nullptr, IDI_APPLICATION);
    SetIcon(icon, TRUE);
    SetIcon(icon, FALSE);

    list_.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    list_.InsertColumn(0, L"Name", LVCFMT_LEFT, 170);
    list_.InsertColumn(1, L"Type", LVCFMT_LEFT, 105);
    list_.InsertColumn(2, L"Access", LVCFMT_LEFT, 190);
    list_.InsertColumn(3, L"Status", LVCFMT_LEFT, 110);

    RefreshWireGuard();

    bool profilesLoaded = false;
    try {
        profiles_ = tlp::win::LoadProfiles();
        profilesLoaded = true;
    } catch (const std::exception& e) {
        ShowError(std::string("Saved connections could not be loaded and were left unchanged: ") + e.what());
    }
    RefreshList();
    // Files left by a crashed or interrupted SSH session are removed after, and independently of, loading.
    if (profilesLoaded) {
        const auto failures = tlp::CleanSshRuntimes(profiles_, [](const Profile& profile) { tlp::win::RemoveSshRuntime(profile); });
        if (!failures.empty()) {
            const auto text = "Saved connections were loaded. " + tlp::DescribeSshRuntimeCleanupFailures(failures);
            LogEvent("ssh_runtime_cleanup_incomplete", "warning", text);
            ShowError(text);
        }
    }
    SetState("Not connected", "Select a PBX and choose Connect. Add a PBX with \"Add my PBX...\" or a Remote Support gateway.");
    RemoveStaleTunnels();
    SetTimer(kMonitorTimer, kMonitorIntervalMs, nullptr);
    networkWatch_ = tlp::win::WatchNetworkChanges(m_hWnd, WM_APP_NETWORK_CHANGED);

    try {
        std::optional<tlp::HealthPreferences> storedHealth = tlp::win::LoadHealthPreferences();
        if (storedHealth) healthPreferences_ = *storedHealth;
    } catch (const std::exception& e) {
        ShowError(std::string("Connection Health preferences could not be read and were left unchanged: ") + e.what());
    }
    healthDialog_.SetPreferences(healthPreferences_);
    CComboBox* history = static_cast<CComboBox*>(GetDlgItem(IDC_HEALTH_INLINE_HISTORY));
    history->AddString(L"60 seconds");
    history->AddString(L"5 minutes");
    history->SetCurSel(healthPreferences_.historySeconds == 300 ? 1 : 0);
    CComboBox* plot = static_cast<CComboBox*>(GetDlgItem(IDC_HEALTH_PLOT));
    plot->AddString(L"Latency & jitter");
    plot->AddString(L"Upload / download");
    plot->AddString(L"Failures & interruptions");
    plot->SetCurSel(0);
    healthDialog_.preferencesChanged = [this](const tlp::HealthPreferences& preferences) {
        healthPreferences_ = preferences;
        static_cast<CComboBox*>(GetDlgItem(IDC_HEALTH_INLINE_HISTORY))->SetCurSel(preferences.historySeconds == 300 ? 1 : 0);
        if (active_ && active_->health) active_->health->SetThresholds(preferences.thresholds);
        try {
            tlp::win::SaveHealthPreferences(preferences);
        } catch (const std::exception& e) {
            ShowError(std::string("Connection Health preferences could not be saved: ") + e.what());
        }
        RefreshHealth();
    };
    if (preferencesReadable && tlp::NeedsFirstRun(storedPreferences_)) PostMessage(WM_APP_FIRST_RUN);
    return TRUE;
}

void CMainDlg::OnSize(UINT type, int cx, int cy) {
    CDialogEx::OnSize(type, cx, cy);
    if (type != SIZE_MINIMIZED) layout_.Arrange();
}

void CMainDlg::OnGetMinMaxInfo(MINMAXINFO* info) {
    CDialogEx::OnGetMinMaxInfo(info);
    MONITORINFO monitor{};
    monitor.cbSize = sizeof(monitor);
    if (GetSafeHwnd() && GetMonitorInfo(MonitorFromWindow(m_hWnd, MONITOR_DEFAULTTONEAREST), &monitor)) {
        const int dpi = static_cast<int>(GetDpiForWindow(m_hWnd));
        info->ptMinTrackSize.x = std::min<LONG>(MulDiv(420, dpi, 96), monitor.rcWork.right - monitor.rcWork.left);
        info->ptMinTrackSize.y = std::min<LONG>(MulDiv(300, dpi, 96), monitor.rcWork.bottom - monitor.rcWork.top);
    }
}

BOOL CMainDlg::OnMouseWheel(UINT, short delta, CPoint) { return layout_.Wheel(delta); }

LRESULT CMainDlg::OnDpiChanged(WPARAM dpi, LPARAM rectangle) {
    layout_.SetDpi(LOWORD(dpi));
    const RECT& suggested = *reinterpret_cast<RECT*>(rectangle);
    MONITORINFO monitor{};
    monitor.cbSize = sizeof(monitor);
    if (GetMonitorInfo(MonitorFromRect(&suggested, MONITOR_DEFAULTTONEAREST), &monitor)) {
        const auto bounds = tlp::FitHealthWindow(
            {static_cast<int>(suggested.left), static_cast<int>(suggested.top),
             static_cast<int>(suggested.right - suggested.left), static_cast<int>(suggested.bottom - suggested.top)},
            {static_cast<int>(monitor.rcWork.left), static_cast<int>(monitor.rcWork.top),
             static_cast<int>(monitor.rcWork.right - monitor.rcWork.left), static_cast<int>(monitor.rcWork.bottom - monitor.rcWork.top)}, 1, 1);
        SetWindowPos(nullptr, bounds.x, bounds.y, bounds.width, bounds.height, SWP_NOZORDER | SWP_NOACTIVATE);
    }
    return 0;
}

BOOL CMainDlg::PreTranslateMessage(MSG* message) {
    if (message->message == WM_MOUSEWHEEL && (message->hwnd == m_hWnd || ::IsChild(m_hWnd, message->hwnd)))
        return layout_.Wheel(GET_WHEEL_DELTA_WPARAM(message->wParam));
    const BOOL handled = CDialogEx::PreTranslateMessage(message);
    if (message->message == WM_KEYDOWN) layout_.RevealFocus();
    return handled;
}

void CMainDlg::OnPlotChanged() {
    graphMode_ = static_cast<CComboBox*>(GetDlgItem(IDC_HEALTH_PLOT))->GetCurSel();
    GetDlgItem(IDC_HEALTH_INLINE_GRAPH)->Invalidate(FALSE);
}

HBRUSH CMainDlg::OnCtlColor(CDC* dc, CWnd* window, UINT type) {
    HBRUSH brush = CDialogEx::OnCtlColor(dc, window, type);
    if (window->GetDlgCtrlID() == IDC_STATE) {
        COLORREF color = tlp::ui::Colours().text;
        const Profile* selected = Selected();
        if (active_ && selected && selected->id == active_->profileId) {
            if (active_->verified) color = tlp::ui::Colours().success;
            else if (healthSnapshot_.state == tlp::HealthState::Disconnected) color = tlp::ui::Colours().error;
        }
        dc->SetTextColor(color);
    }
    return brush;
}

void CMainDlg::LogEvent(const std::string& event, const std::string& severity, const std::string& detail,
                       const std::string& diagnosticId, const std::string& attemptId) {
    try {
        tlp::win::WriteSessionEvent(!diagnosticId.empty() ? diagnosticId : active_ ? active_->diagnosticId : "application",
                                   !diagnosticId.empty() ? attemptId : active_ ? active_->attemptId : "", event, severity, detail);
    } catch (const std::exception& e) {
        if (!logFailureShown_) {
            logFailureShown_ = true;
            ShowError(std::string("Session diagnostics cannot be saved: ") + e.what());
        }
    }
}

void CMainDlg::RefreshHealth() {
    const Profile* selected = Selected();
    healthSnapshot_ = {};
    if (active_ && active_->health) {
        healthSnapshot_ = active_->health->Snapshot(GetTickCount64(), 300);
        healthSnapshot_.authorizationKnown = true;
        healthSnapshot_.authorizationPersistent = active_->expiresAt == 0;
        healthSnapshot_.authorizationExpiresAt = active_->expiresAt;
        if (active_->expiresAt > 0) {
            const auto remaining = active_->expiresAt - tlp::win::UnixNow();
            healthSnapshot_.authorizationRemainingSeconds = remaining > 0 ? remaining : 0;
        }
        healthSnapshot_.sessionId = active_->diagnosticId;
        healthSnapshot_.attemptId = active_->attemptId;
        history_[active_->profileId] = healthSnapshot_;
    }
    const bool showingActive = selected && active_ && selected->id == active_->profileId;
    const auto saved = selected ? history_.find(selected->id) : history_.end();
    const bool showingHistory = saved != history_.end();
    tlp::HealthSnapshot display = showingActive ? healthSnapshot_ : showingHistory ? saved->second : tlp::HealthSnapshot{};
    if (!showingActive && selected && selected->kind == ProfileKind::Administrator) {
        display.authorizationKnown = true;
        display.authorizationPersistent = selected->pairing.mode == "persistent";
        display.authorizationExpiresAt = selected->pairing.expiresAt;
        if (!display.authorizationPersistent) {
            display.authorizationRemainingSeconds = std::max<std::int64_t>(0, display.authorizationExpiresAt - tlp::win::UnixNow());
        }
    }
    healthDialog_.UpdateSnapshot(display);
    RefreshConnectionText();
    SetDlgItemText(IDC_HEALTH_INLINE_TEXT, Widen(showingActive || showingHistory || (selected && display.authorizationKnown) ? ConnectionHealthSummary(display)
        : "Not connected. Select a PBX and choose Connect.\r\nMeasurements: Unknown.").c_str());
    GetDlgItem(IDC_HEALTH_INLINE_GRAPH)->Invalidate(FALSE);
}

void CMainDlg::OnDrawItem(int controlId, LPDRAWITEMSTRUCT item) {
    if (controlId == IDC_RECOVER && item != nullptr) {
        CDC dc;
        dc.Attach(item->hDC);
        const bool disabled = (item->itemState & ODS_DISABLED) != 0;
        const bool pressed = (item->itemState & ODS_SELECTED) != 0;
        DrawFrameControl(dc.GetSafeHdc(), &item->rcItem, DFC_BUTTON,
                         DFCS_BUTTONPUSH | (disabled ? DFCS_INACTIVE : 0) | (pressed ? DFCS_PUSHED : 0));
        const UINT dpi = GetDpiForWindow(m_hWnd);
        const int iconSize = MulDiv(16, static_cast<int>(dpi), 96);
        const HICON warning = static_cast<HICON>(LoadImageW(nullptr, IDI_WARNING, IMAGE_ICON, iconSize, iconSize, LR_SHARED));
        CFont* font = GetDlgItem(IDC_RECOVER)->GetFont();
        CFont* previousFont = font ? dc.SelectObject(font) : nullptr;
        const CString label = L"Recover";
        const CSize labelSize = dc.GetTextExtent(label.GetString(), label.GetLength());
        const int gap = MulDiv(4, static_cast<int>(dpi), 96);
        const int iconWidth = warning ? iconSize : 0;
        const int labelWidth = static_cast<int>(labelSize.cx);
        const int labelHeight = static_cast<int>(labelSize.cy);
        const int totalWidth = labelWidth + (iconWidth ? gap + iconWidth : 0);
        const int left = static_cast<int>(item->rcItem.left + (item->rcItem.right - item->rcItem.left - totalWidth) / 2);
        const int contentHeight = std::max(labelHeight, iconSize);
        const int top = static_cast<int>(item->rcItem.top + (item->rcItem.bottom - item->rcItem.top - contentHeight) / 2);
        dc.SetBkMode(TRANSPARENT);
        dc.SetTextColor(GetSysColor(disabled ? COLOR_GRAYTEXT : COLOR_BTNTEXT));
        CRect text(left, item->rcItem.top, left + labelWidth, item->rcItem.bottom);
        if (pressed) text.OffsetRect(1, 1);
        dc.DrawText(label, text, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_NOPREFIX);
        if (warning) DrawIconEx(dc.GetSafeHdc(), left + labelWidth + gap, top, warning, iconSize, iconSize, 0, nullptr, DI_NORMAL);
        if ((item->itemState & ODS_FOCUS) != 0) {
            CRect focus(item->rcItem);
            focus.DeflateRect(3, 3);
            dc.DrawFocusRect(&focus);
        }
        if (previousFont) dc.SelectObject(previousFont);
        dc.Detach();
        return;
    }
    if (controlId != IDC_HEALTH_INLINE_GRAPH || item == nullptr) {
        CDialogEx::OnDrawItem(controlId, item);
        return;
    }
    CDC dc;
    dc.Attach(item->hDC);
    dc.SelectObject(GetDlgItem(IDC_HEALTH_INLINE_GRAPH)->GetFont());
    const Profile* selected = Selected();
    const tlp::HealthSnapshot empty;
    const auto saved = selected ? history_.find(selected->id) : history_.end();
    DrawConnectionHealthGraph(dc, CRect(item->rcItem),
        selected && active_ && selected->id == active_->profileId ? healthSnapshot_ :
            saved != history_.end() ? saved->second : empty,
        healthPreferences_.historySeconds, graphMode_);
    dc.Detach();
}

void CMainDlg::OnInlineHistoryChanged() {
    healthPreferences_.historySeconds =
        static_cast<CComboBox*>(GetDlgItem(IDC_HEALTH_INLINE_HISTORY))->GetCurSel() == 1 ? 300 : 60;
    healthDialog_.SetPreferences(healthPreferences_);
    try {
        tlp::win::SaveHealthPreferences(healthPreferences_);
    } catch (const std::exception& e) {
        ShowError(std::string("Health preferences cannot be saved: ") + e.what());
    }
    RefreshHealth();
}

void CMainDlg::OnSessionLog() {
    try {
        const Profile* selected = Selected();
        const std::string id = selected ? (selected->kind == ProfileKind::Administrator
            ? "ws-" + selected->pairing.workstationId : "support-" + selected->id) : "application";
        const std::string contents = id == "application" ? tlp::win::ReadSessionEvents(id) :
            "APPLICATION LIFECYCLE\r\n" + tlp::win::ReadSessionEvents("application") +
            "\r\nSELECTED PAIRING: " + id + "\r\n" + tlp::win::ReadSessionEvents(id);
        CSessionLogDlg dialog(contents, this);
        dialog.DoModal();
    } catch (const std::exception& e) {
        ShowError(std::string("Session diagnostics cannot be read: ") + e.what());
    }
}

LRESULT CMainDlg::OnStartupNotices(WPARAM, LPARAM) {
    // Posted messages run before MFC's modal loop first shows the dialog, so show it explicitly.
    if (!IsWindowVisible()) {
        ShowWindow(SW_SHOWNORMAL);
        UpdateWindow();
    }
    SetForegroundWindow();
    std::vector<std::wstring> notices;
    notices.swap(deferredNotices);
    for (const auto& notice : notices) tlp::ui::ShowMessage(notice.c_str(), MB_ICONERROR);
    return 0;
}

LRESULT CMainDlg::OnFirstRun(WPARAM, LPARAM) {
    ShowAppSettings(tlp::NeedsFirstRun(storedPreferences_), "");
    return 0;
}

tlp::Preferences CMainDlg::CurrentPreferences() {
    tlp::Preferences locations = storedPreferences_.value_or(tlp::Preferences());
    return tlp::EffectivePreferences(storedPreferences_, tlp::win::DetectApps(tlp::AppKind::Browser, locations),
                                     tlp::win::DetectApps(tlp::AppKind::Terminal, locations));
}

// Shared by first run and Settings. Returns true when preferences were saved (or skipped with defaults).
bool CMainDlg::ShowAppSettings(bool welcome, const std::string& notice) {
    CAppSettingsDlg dialog(welcome ? CAppSettingsDlg::Mode::Welcome : CAppSettingsDlg::Mode::Settings, storedPreferences_, this);
    dialog.notice = notice;
    dialog.connectionActive = active_ != nullptr;
    if (!busy_ && active_) {
        const auto* profile = FindProfile(active_->profileId);
        if (profile && profile->kind == tlp::ProfileKind::Administrator) dialog.connectProfile = *profile;
    } else if (!busy_ && Selected()) {
        if (Selected()->kind == tlp::ProfileKind::Administrator) dialog.connectProfile = *Selected();
    }
    dialog.installation = installation_;
    if (dialog.DoModal() == -1) {
        ShowError("TELIPHONES could not open Settings. Your preferences and profiles were left unchanged.");
        return false;
    }
    installation_ = dialog.installation;
    bool saved = dialog.outcome != tlp::FirstRunOutcome::Cancelled;
    // Welcome saves Step 1 immediately, even when the user closes a later step.
    if (saved) storedPreferences_ = dialog.preferences;
    RefreshWireGuard();
    if (dialog.lockNow && active_) {
        StartDisconnect("Locked Now from Settings > Security.");
        return saved;
    }
    if (dialog.startAction == CAppSettingsDlg::StartAction::AddPbx) OnAddPbx();
    if (dialog.startAction == CAppSettingsDlg::StartAction::Support) OnAddSupport();
    return saved;
}

void CMainDlg::OnSettings() { ShowAppSettings(false, ""); }

void CMainDlg::OnConnectionHealth() {
    const Profile* selected = Selected();
    if (!selected) return;
    RefreshHealth();
    try {
        healthDialog_.ShowMonitor();
    } catch (const std::exception& e) {
        ShowError(e.what());
    } catch (CException* e) {
        wchar_t details[512]{};
        e->GetErrorMessage(details, 512);
        e->Delete();
        ShowError("The Connection Health window could not be opened: " + Narrow(details));
    }
}

int CMainDlg::SelectedIndex() const { return list_.GetNextItem(-1, LVNI_SELECTED); }

Profile* CMainDlg::Selected() {
    int index = SelectedIndex();
    return index >= 0 && static_cast<std::size_t>(index) < profiles_.size() ? &profiles_[static_cast<std::size_t>(index)] : nullptr;
}

Profile* CMainDlg::FindProfile(const std::string& id) {
    for (Profile& profile : profiles_) {
        if (profile.id == id) return &profile;
    }
    return nullptr;
}

std::string CMainDlg::SelectedSession() {
    int index = sessions_.GetCurSel();
    return index >= 0 && static_cast<std::size_t>(index) < sessionIds_.size() ? sessionIds_[static_cast<std::size_t>(index)] : std::string();
}

void CMainDlg::RefreshList() {
    int previous = SelectedIndex();
    std::int64_t now = tlp::win::UnixNow();
    list_.SetRedraw(FALSE);
    list_.DeleteAllItems();
    for (std::size_t i = 0; i < profiles_.size(); ++i) {
        const Profile& profile = profiles_[i];
        int row = list_.InsertItem(static_cast<int>(i), Widen(profile.name).c_str());
        list_.SetItemText(row, 1, profile.kind == ProfileKind::Administrator ? L"My PBX" : L"Remote Support");
        list_.SetItemText(row, 2, Widen(AccessText(profile, now)).c_str());
        std::string status;
        if (active_ && active_->profileId == profile.id) {
            status = active_->connected ? (active_->verified ? "Connected" : "Checking") : "Working...";
            if (active_->health) status = tlp::HealthStateName(active_->health->Snapshot(GetTickCount64(), healthPreferences_.historySeconds).state);
        }
        list_.SetItemText(row, 3, Widen(status).c_str());
    }
    if (previous >= 0 && previous < list_.GetItemCount()) list_.SetItemState(previous, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    list_.SetRedraw(TRUE);
    RefreshSessions();
}

void CMainDlg::RefreshSessions() {
    std::string current = SelectedSession();
    sessions_.ResetContent();
    sessionIds_.clear();
    const Profile* profile = Selected();
    std::string details;
    std::int64_t now = tlp::win::UnixNow();
    if (profile != nullptr && profile->kind == ProfileKind::Support) {
        details = "Engineer key fingerprint: " + tlp::KeyFingerprint(profile->engineerPublicKey);
        if (profile->hasGrant) {
            details += "\r\nGateway: " + profile->grant.endpoint + "\r\nEngineer address: " + profile->grant.engineerAddress;
            for (const auto& session : profile->grant.sessions) {
                if (session.expiresAt <= now) continue;
                std::string label = session.sessionId + "  (" + session.pbxAddress + ", " + tlp::FormatRemaining(session.expiresAt - now) + " left)";
                sessions_.AddString(Widen(label).c_str());
                sessionIds_.push_back(session.sessionId);
            }
            if (sessionIds_.empty()) details += "\r\nNo unexpired sessions. Ask the customer to authorise support, then import a new grant.";
        } else {
            details += "\r\nSend the engineer public key to your gateway operator, then choose \"Import grant...\".";
        }
        int select = 0;
        for (std::size_t i = 0; i < sessionIds_.size(); ++i) {
            if (sessionIds_[i] == current) select = static_cast<int>(i);
        }
        if (!sessionIds_.empty()) sessions_.SetCurSel(select);
    } else if (profile != nullptr) {
        const tlp::PairResponse& pairing = profile->pairing;
        details = "PBX: " + pairing.pbxName + "  (key " + tlp::KeyFingerprint(pairing.pbxPublicKey) + ")" + "\r\nEndpoint: " + pairing.endpoint +
                  "    Tunnel: " + pairing.address + " -> " + pairing.pbxAddress + "\r\nWorkstation: " + profile->workstationName + "  (id " +
                  pairing.workstationId + ")" + "\r\nExpires: " + (pairing.mode == "persistent" ? std::string("when revoked on the PBX") : FormatTime(pairing.expiresAt));
        details += pairing.ssh
            ? "    SSH authorised for: " + (profile->sshUser.empty() ? std::string("(account unavailable)") : profile->sshUser)
            : "    SSH not authorised";
    }
    sessions_.EnableWindow(!sessionIds_.empty());
    SetDlgItemText(IDC_DETAILS, Widen(details).c_str());
    UpdateButtons();
    RefreshHealth();
}

void CMainDlg::UpdateButtons() {
    const Profile* profile = Selected();
    bool selectedActive = profile != nullptr && active_ && active_->profileId == profile->id;
    bool usable = wireguard_.installed && wireguard_.trusted;
    bool canConnect = profile != nullptr && !busy_ && !active_ && usable &&
                      (profile->kind == ProfileKind::Administrator || !SelectedSession().empty());
    const Profile* activeProfile = active_ ? FindProfile(active_->profileId) : nullptr;
    bool connected = active_ && active_->connected && !busy_ && selectedActive;
    bool sshAllowed = activeProfile != nullptr &&
                      (activeProfile->kind == ProfileKind::Support || activeProfile->pairing.ssh ||
                       (activeProfile->kind == ProfileKind::Administrator && connected && active_->verified));
    bool verified = connected && active_->verified;

    GetDlgItem(IDC_ADD_PBX)->EnableWindow(!busy_);
    GetDlgItem(IDC_ADD_SUPPORT)->EnableWindow(!busy_);
    GetDlgItem(IDC_UPDATE_GRANT)->EnableWindow(profile != nullptr && profile->kind == ProfileKind::Support && !busy_ && !selectedActive);
    GetDlgItem(IDC_REMOVE)->EnableWindow(profile != nullptr && !busy_ && !selectedActive);
    GetDlgItem(IDC_EDIT_MANAGEMENT_HOSTNAME)->EnableWindow(profile != nullptr && profile->kind == ProfileKind::Administrator && !busy_ && !selectedActive);
    GetDlgItem(IDC_CONNECT)->EnableWindow(canConnect);
    GetDlgItem(IDC_DISCONNECT)->EnableWindow(active_ != nullptr && !closing_);
    GetDlgItem(IDC_OPEN_GUI)->EnableWindow(verified);
    GetDlgItem(IDC_OPEN_SSH)->EnableWindow(verified && sshAllowed);
    GetDlgItem(IDC_OPEN_SSH)->SetWindowTextW(activeProfile != nullptr && activeProfile->kind == ProfileKind::Administrator &&
        !activeProfile->pairing.ssh ? L"Request SSH" :
        L"Open SSH");
    const bool mayChangeWorkstationPolicy = connected && verified && activeProfile != nullptr &&
        activeProfile->kind == ProfileKind::Administrator &&
        (!activePolicyLocked_ || !unlockRequestPending_);
    layout_.Find(IDC_LOCK_WORKSTATION)->EnableWindow(mayChangeWorkstationPolicy);
    layout_.Find(IDC_LOCK_WORKSTATION)->SetWindowTextW(
        !connected ? L"Unavailable While Disconnected" :
        !verified ? L"Unavailable Until PBX Admission" :
        activeProfile == nullptr || activeProfile->kind != ProfileKind::Administrator
            ? L"Unavailable for this profile"
            : (activePolicyLocked_ ? (unlockRequestPending_ ? L"Unlock Pending Approval" : L"Request Unlock")
                                   : L"Lock to Current IP"));
    layout_.Find(IDC_ALLOWED_SOURCES)->EnableWindow(mayChangeWorkstationPolicy && !sourcesRequestPending_);
    layout_.Find(IDC_REQUEST_SOURCES)->EnableWindow(mayChangeWorkstationPolicy && !sourcesRequestPending_);
    layout_.Find(IDC_REQUEST_SOURCES)->SetWindowTextW(
        !connected ? L"Unavailable While Disconnected" :
        !verified ? L"Unavailable Until PBX Admission" :
        activeProfile == nullptr || activeProfile->kind != ProfileKind::Administrator
            ? L"Unavailable for this profile" :
        sourcesRequestPending_ ? L"Allowed List Pending Approval" : L"Request Allowed List Change");
    GetDlgItem(IDC_CONNECTION_HEALTH)->EnableWindow(profile != nullptr);
    GetDlgItem(IDC_CONNECTION_HEALTH)->SetWindowTextW(L"Pop Out");
    GetDlgItem(IDC_SETTINGS)->EnableWindow(!busy_);
    const bool recoverableActive = active_ && active_->lifecycle.stage == tlp::tunnel_lifecycle::ConnectionStage::CleanupIncomplete;
    GetDlgItem(IDC_RECOVER)->EnableWindow(!busy_ && (!active_ || recoverableActive));
}

void CMainDlg::SetState(const std::string& state, const std::string& guidance) {
    connectionState_ = state;
    connectionGuidance_ = guidance;
    RefreshConnectionText();
}

void CMainDlg::RefreshConnectionText() {
    const Profile* selected = Selected();
    const bool otherActive = active_ && selected && selected->id != active_->profileId;
    SetDlgItemText(IDC_CONNECTION_HEADING, Widen(selected ? selected->name : "Connection").c_str());
    SetDlgItemText(IDC_STATE, Widen(otherActive ? "Not connected (another PBX is active)" : connectionState_).c_str());
    SetDlgItemText(IDC_GUIDANCE, Widen(otherActive ?
        "Disconnect the active PBX before connecting this one. Disconnect always removes the active tunnel." : connectionGuidance_).c_str());
}

void CMainDlg::Persist() {
    try {
        tlp::win::SaveProfiles(profiles_);
    } catch (const std::exception& e) {
        ShowError(std::string("Your connections could not be saved: ") + e.what());
    }
}

bool CMainDlg::RequireWireGuard() {
    RefreshWireGuard();
    if (wireguard_.installed && wireguard_.trusted) return true;
    ShowAppSettings(false, "WireGuard is required. Use the Connectivity section below; installation is optional until you connect.");
    return wireguard_.installed && wireguard_.trusted;
}

void CMainDlg::RefreshWireGuard() {
    try {
        wireguard_ = tlp::win::FindWireGuard();
        std::string status = wireguard_.installed && wireguard_.trusted
            ? "WireGuard for Windows: installed (signed by " + wireguard_.signer + ")"
            : "WireGuard is required. Open Settings > Connectivity to install it or check again.";
        if (wireguard_.installed && !wireguard_.trusted) status = "WireGuard verification failed. Open Settings > Connectivity for details.";
        SetDlgItemText(IDC_WG_STATUS, Widen(status).c_str());
    } catch (const std::exception& e) {
        wireguard_ = {};
        SetDlgItemText(IDC_WG_STATUS, Widen(std::string("WireGuard detection failed: ") + e.what()).c_str());
    }
    UpdateButtons();
}

LRESULT CMainDlg::OnNetworkChanged(WPARAM, LPARAM) {
    const std::int64_t now = tlp::win::UnixNow();
    lastNetworkChangeUnix_ = now;
    if (now - lastNetworkChangeLogUnix_ >= 30) {
        lastNetworkChangeLogUnix_ = now;
        // Interface changes only; addresses are not recorded. WireGuard roams on its own next handshake, and the
        // existing monitor tick re-checks admission, so no separate reconnect is started here.
        LogEvent("network_changed", "info", active_ && active_->connected
            ? "A local network interface changed while connected. WireGuard follows the new path on its next handshake; "
              "admission is re-checked on the next monitor tick."
            : "A local network interface changed while no tunnel was connected.");
    }
    return 0;
}

void CMainDlg::RemoveStaleTunnels() {
    // A previous run may have ended without disconnecting (crash, power loss). Ask before a cleanup
    // that may require UAC; launching the GUI alone must not trigger a privileged operation.
    std::vector<std::string> saved;
    for (const Profile& profile : profiles_) {
        std::string name = tlp::TunnelNameFor(profile);
        tlp::win::TunnelState state = tlp::win::QueryTunnel(name);
        if (state != tlp::win::TunnelState::Absent && state != tlp::win::TunnelState::Unknown) saved.push_back(name);
    }
    // No TELIPHONES connection exists yet. Recovery candidates are restricted to saved profiles and valid protected
    // ownership records; a similar-looking WireGuard service or adapter is not evidence that TELIPHONES owns it.
    std::vector<std::string> stale = saved;
    try {
        stale = tlp::win::ResidualTeliphonesTunnels(saved);
    } catch (const std::exception& e) {
        LogEvent("residual_tunnels_found", "warning", std::string("Leftover tunnel enumeration was incomplete: ") + e.what());
    }
    if (stale.empty()) return;
    std::string names;
    for (const auto& name : stale) names += (names.empty() ? "" : ", ") + name;
    LogEvent("residual_tunnels_found", "warning", "TELIPHONES tunnels installed at startup: " + names + ".");
    if (tlp::ui::ShowMessage(Widen("TELIPHONES tunnels from a previous run are still installed (" + names +
                                   "). Remove them now? Other WireGuard tunnels are not changed.").c_str(),
                             MB_ICONQUESTION | MB_YESNO) != IDYES) {
        SetState("Recovery required", "Choose Recover when you are ready. Recovery works without a saved profile or active PBX pairing.");
        return;
    }
    busy_ = true;
    UpdateButtons();
    SetState("Removing a TELIPHONES tunnel left from a previous session...", "");
    RunInBackground(m_hWnd, OperationKind::Cleanup, "", [stale](OperationResult& result) {
        for (const std::string& name : stale) {
            try {
                tlp::win::RemoveTunnel(name);
            } catch (const std::exception& error) {
                result.error += (result.error.empty() ? "" : " ") + name + ": " + tlp::SanitizeDiagnosticDetail(error.what());
            }
        }
        return true;
    });
}

void CMainDlg::OnRecover() {
    if (busy_) return;
    const bool recoveringActive = active_ && active_->lifecycle.stage == tlp::tunnel_lifecycle::ConnectionStage::CleanupIncomplete;
    if (active_ && !recoveringActive) {
        SetState(connectionState_, "Disconnect the currently active TELIPHONES session before recovery.");
        return;
    }
    std::vector<std::string> savedTunnels;
    for (const auto& profile : profiles_) savedTunnels.push_back(tlp::TunnelNameFor(profile));
    std::vector<std::string> candidates;
    try {
        // Protected local ownership records remain authoritative after revocation or profile removal.
        // This scan is read-only and never discovers generic WireGuard VPNs.
        candidates = tlp::win::ResidualTeliphonesTunnels(savedTunnels);
    } catch (const std::exception& error) {
        LogEvent("recovery_reconcile", "error", std::string("Read-only TELIPHONES recovery scan failed: ") +
                 tlp::SanitizeDiagnosticDetail(error.what()));
        SetState("Recovery status unknown", "Windows could not safely inspect TELIPHONES tunnel ownership. No resources were changed; see Session Log.");
        return;
    }
    std::vector<std::string> toProcess = candidates;
    if (recoveringActive && std::find(toProcess.begin(), toProcess.end(), active_->tunnelName) == toProcess.end())
        toProcess.insert(toProcess.begin(), active_->tunnelName);
    std::string names;
    for (const auto& name : toProcess) names += (names.empty() ? "" : ", ") + name;
    if (tlp::ui::ShowMessage(Widen("Recover TELIPHONES runtime resources" + (names.empty() ? std::string() : " (tunnels: " + names + ")") +
            "? Windows may request administrative approval. Only positively identified TELIPHONES resources will be changed; other VPNs and saved connections are untouched.").c_str(),
            MB_ICONQUESTION | MB_YESNO) != IDYES) {
        LogEvent("recovery_reconcile", "info", "User deferred manual TELIPHONES recovery; ownership records were retained.");
        SetState("Recovery required", "Choose Recover to retry. The protected ownership record was retained.");
        return;
    }
    busy_ = true;
    ++generation_;
    probing_ = false;
    if (recoveringActive && active_->cancellation) active_->cancellation->Cancel();
    if (active_) {
        tlp::tunnel_lifecycle::CancelOperation(active_->lifecycle);
        active_->lifecycle.stage = tlp::tunnel_lifecycle::ConnectionStage::CleanupIncomplete;
    }
    UpdateButtons();
    LogEvent("recovery_reconcile", "info", "Manual full-runtime recovery requested for " + (names.empty() ? std::string("no discovered tunnels") : names) + ".");
    SetState("Recovering TELIPHONES...", "Stopping TELIPHONES work and closing owned sessions before verifying Windows tunnel state.");
    const std::optional<Profile> activeProfile = recoveringActive && FindProfile(active_->profileId)
        ? std::optional<Profile>(*FindProfile(active_->profileId)) : std::nullopt;
    const std::string activeAddress = recoveringActive ? active_->pbxAddress : std::string();
    RunInBackground(m_hWnd, OperationKind::Recovery, "Manual full-runtime recovery",
                    [toProcess, recoveringActive, activeProfile, activeAddress, savedTunnels](OperationResult& result) {
        try {
            if (!tlp::win::RecoverSecureBrowserSessions())
                result.error += "One or more TELIPHONES Edge sessions or marked browser profiles could not be closed and removed; ";
        } catch (const std::exception& error) {
            result.error += std::string("Secure browser cleanup: ") + tlp::SanitizeDiagnosticDetail(error.what()) + "; ";
        }
        try {
            tlp::win::CloseAllManagedSsh();
        } catch (const std::exception& error) {
            result.error += std::string("Managed SSH session teardown: ") + tlp::SanitizeDiagnosticDetail(error.what()) + "; ";
        }
        if (recoveringActive) {
            if (activeProfile && activeProfile->kind == ProfileKind::Administrator) {
                try {
                    tlp::win::MaintainWorkstationSession(activeAddress, true);
                } catch (const std::exception& error) {
                    result.warning += std::string("The PBX lease release was not confirmed: ") +
                                      tlp::SanitizeDiagnosticDetail(error.what()) + ". ";
                }
            }
        }
        for (const auto& name : toProcess) {
            try {
                tlp::win::RemoveTunnel(name);
            } catch (const std::exception& error) {
                result.error += (result.error.empty() || result.error.back() == ' ' ? "" : " ") + name + ": " +
                                tlp::SanitizeDiagnosticDetail(error.what()) + "; ";
            }
        }
        try {
            tlp::win::CleanAllSshRuntimes();
        } catch (const std::exception& error) {
            result.error += std::string("Temporary SSH runtime cleanup: ") + tlp::SanitizeDiagnosticDetail(error.what()) + "; ";
        }
        // RemoveTunnel waits for the elevated helper, which independently waits for service deletion and adapter release.
        // This second inventory is a fresh read-only Windows service/interface scan; it is not inferred from error 1168.
        try {
            const auto remaining = tlp::win::ResidualTeliphonesTunnels(savedTunnels);
            if (!remaining.empty()) {
                result.error += "Windows still reports TELIPHONES-owned or unverified tunnel state: ";
                for (const auto& name : remaining) result.error += name + " ";
                result.error += "Check Session Log for independent SCM, interface and recorded PnP diagnostics; unidentified devices were left untouched.";
            }
        } catch (const std::exception& error) {
            result.error += std::string("Final Windows service/interface/PnP reconciliation failed: ") +
                            tlp::SanitizeDiagnosticDetail(error.what());
        }
        if (!result.error.empty()) {
            result.error = "TELIPHONES recovery is incomplete. " + result.error;
        }
        return true;
    });
}

void CMainDlg::OnSelectionChanged(NMHDR* header, LRESULT* result) {
    auto* change = reinterpret_cast<NMLISTVIEW*>(header);
    if ((change->uChanged & LVIF_STATE) != 0 && ((change->uNewState ^ change->uOldState) & LVIS_SELECTED) != 0) RefreshSessions();
    *result = 0;
}

void CMainDlg::OnAddPbx() {
    if (!RequireWireGuard()) return;
    CPairDlg dialog(wireguard_, this);
    if (dialog.DoModal() != IDOK) return;
    profiles_.push_back(dialog.profile);
    try {
        tlp::win::WriteSessionEvent("ws-" + dialog.profile.pairing.workstationId, "", "pairing_saved", "info",
            dialog.profile.pairing.mode == "persistent" ? "Administrator-approved authorization: Until revoked." :
            "Administrator-approved temporary authorization expires at Unix UTC " + std::to_string(dialog.profile.pairing.expiresAt));
    } catch (const std::exception& e) {
        ShowError(std::string("Pairing diagnostics cannot be saved: ") + e.what());
    }
    Persist();
    RefreshList();
}

void CMainDlg::OnAddSupport() {
    if (!RequireWireGuard()) return;
    CSupportDlg dialog(wireguard_, nullptr, this);
    if (dialog.DoModal() != IDOK) return;
    profiles_.push_back(dialog.profile);
    Persist();
    RefreshList();
}

void CMainDlg::OnUpdateGrant() {
    Profile* profile = Selected();
    if (profile == nullptr || profile->kind != ProfileKind::Support) return;
    CSupportDlg dialog(wireguard_, profile, this);
    if (dialog.DoModal() != IDOK) return;
    *profile = dialog.profile;
    Persist();
    RefreshList();
}

void CMainDlg::OnEditManagementHostname() {
    Profile* profile = Selected();
    if (profile == nullptr || profile->kind != ProfileKind::Administrator || (active_ && active_->profileId == profile->id)) return;
    CManagementHostnameDlg dialog(profile->managementTlsHostname);
    if (dialog.DoModal() != IDOK) return;
    const std::string previous = profile->managementTlsHostname;
    profile->managementTlsHostname = dialog.hostname();
    try {
        tlp::win::SaveProfiles(profiles_);
    } catch (const std::exception& error) {
        profile->managementTlsHostname = previous;
        ShowError(std::string("The HTTPS hostname was not saved: ") + error.what());
        return;
    }
    RefreshList();
}

void CMainDlg::OnRemove() {
    Profile* profile = Selected();
    if (profile == nullptr || (active_ && active_->profileId == profile->id)) return;
    std::wstring question = L"Remove \"" + Widen(profile->name) + L"\" and delete its WireGuard key from this computer?";
    if (profile->kind == ProfileKind::Administrator && !profile->pairing.sshPublicKey.empty()) {
        question += L"\n\nThis does not revoke the workstation on the PBX. Revoke it in FreePBX > Connectivity > TELIPHONES > Windows workstations.";
    }
    if (tlp::ui::ShowMessage(question.c_str(), MB_ICONQUESTION | MB_YESNO) != IDYES) return;
    try {
        tlp::win::DeletePrivateKey(tlp::CredentialTargetFor(*profile));
        if (profile->kind == ProfileKind::Administrator) {
            tlp::win::DeleteSshPrivateKey(*profile);
            try {
                tlp::win::RemoveSshRuntime(*profile);
            } catch (const tlp::SshRuntimeResidual& residual) {
                ShowError(std::string("The profile's keys were deleted, but temporary SSH files remain for manual inspection: ") +
                          residual.what());
            }
        }
    } catch (const std::exception& e) {
        ShowError(std::string("The saved key could not be deleted: ") + e.what());
        return;
    }
    try {
        tlp::win::WriteSessionEvent(profile->kind == ProfileKind::Administrator ? "ws-" + profile->pairing.workstationId : "support-" + profile->id,
            "", "profile_removed", "info", "Local profile removed. This does not revoke authorization on the PBX.");
    } catch (const std::exception& e) {
        ShowError(std::string("Profile diagnostics cannot be saved: ") + e.what());
    }
    history_.erase(profile->id);
    profiles_.erase(profiles_.begin() + SelectedIndex());
    Persist();
    RefreshList();
}

void CMainDlg::OnConnect() {
    Profile* profile = Selected();
    if (profile == nullptr || active_ || busy_ || !RequireWireGuard()) return;
    std::string sessionId = profile->kind == ProfileKind::Support ? SelectedSession() : std::string();
    std::int64_t now = tlp::win::UnixNow();
    std::string configText;
    [[maybe_unused]] WipeString configTextWiper(configText);
    auto active = std::make_unique<Active>();
    active->diagnosticId = profile->kind == ProfileKind::Administrator ? "ws-" + profile->pairing.workstationId : "support-" + profile->id;
    try {
        active->attemptId = tlp::win::NewProfileId();
        active->operationId = tlp::HexEncode(tlp::win::RandomBytes(16));
        LogEvent("connection_attempt", "info", "Manual connection attempt. Correlation ID identifies this pairing; attempt ID is workstation-local.",
                 active->diagnosticId, active->attemptId);
        if (profile->kind == ProfileKind::Administrator && profile->pairing.mode == "temporary" && profile->pairing.expiresAt <= now) {
            throw tlp::Error("This temporary pairing has expired. Remove it and pair this workstation again from the PBX.");
        }
        const auto credentialTarget = tlp::CredentialTargetFor(*profile);
        if (profile->kind == ProfileKind::Administrator && !tlp::win::PrivateKeyNeedsPassword(credentialTarget)
            && !profile->connectPasswordSkippedPermanently) {
            CConnectPasswordChoiceDlg firstUse(tlp::ConnectProtectionAvailable(), this);
            if (firstUse.DoModal() != IDOK) {
                if (firstUse.choice == IDC_PASSWORD_SET) {
                    if (!ManageConnectPassword(*profile, this)) return;
                } else if (firstUse.choice == IDC_PASSWORD_SKIP_ALWAYS) {
                    profile->connectPasswordSkippedPermanently = true;
                    Persist();
                } else if (firstUse.choice != IDC_PASSWORD_SKIP_ONCE) {
                    return;
                }
            } else {
                return;
            }
        }
        CConnectPasswordDlg unlock(false, this);
        if (tlp::win::PrivateKeyNeedsPassword(credentialTarget) && unlock.DoModal() != IDOK) return;
        std::string privateKey = tlp::win::LoadPrivateKey(credentialTarget, unlock.password);
        tlp::win::SecureWipe(unlock.password);
        [[maybe_unused]] WipeString privateKeyWiper(privateKey);
        if (privateKey.empty()) throw tlp::Error("The WireGuard key for this connection is missing from Windows Credential Manager. Remove the connection and pair again.");
        std::string expectedPublicKey =
            profile->kind == ProfileKind::Administrator ? profile->pairing.workstationPublicKey : profile->engineerPublicKey;
        std::string actualPublicKey = tlp::win::DerivePublicKey(wireguard_, privateKey);
        if (actualPublicKey != expectedPublicKey) {
            throw tlp::Error("The saved private key does not match this profile's enrolled public key. Remove the connection and pair or enroll a new engineer key.");
        }
        tlp::TunnelConfig config = profile->kind == ProfileKind::Administrator ? tlp::AdministratorTunnel(*profile, privateKey)
                                                                                : tlp::SupportTunnel(*profile, privateKey, sessionId, now);
        [[maybe_unused]] WipeString configKeyWiper(config.privateKey);
        configText = tlp::RenderTunnel(config);
        active->profileId = profile->id;
        active->sessionId = sessionId;
        active->tunnelName = tlp::TunnelNameFor(*profile);
        active->pbxAddress = tlp::ConnectionAddress(*profile, sessionId);
        active->expiresAt = tlp::ConnectionExpiry(*profile, sessionId);
        active->peerPublicKey = profile->kind == ProfileKind::Administrator ? profile->pairing.pbxPublicKey : profile->grant.gatewayPublicKey;
    } catch (const std::exception& e) {
        tlp::win::SecureWipe(configText);
        LogEvent("connection_failed", "error", e.what(), active->diagnosticId, active->attemptId);
        ShowError(e.what());
        return;
    }
    std::string tunnelName = active->tunnelName;
    lastTelemetryTickMs_ = 0;
    active_ = std::move(active);
    ++generation_;
    active_->lifecycle = tlp::tunnel_lifecycle::BeginConnection(generation_, GetTickCount64(), 90000);
    active_->cancellation = std::make_shared<tlp::win::TunnelCancellation>();
    const auto operationId = active_->operationId;
    const auto profileId = active_->profileId;
    const auto workstationId = active_->diagnosticId;
    const auto operationGeneration = generation_;
    const auto cancellation = active_->cancellation;
    busy_ = true;
    RefreshList();
    SetState("Connecting - establishing WireGuard...", "Windows will ask for administrative approval to start the WireGuard tunnel.");
    auto stagedConfig = std::shared_ptr<std::string>(new std::string(std::move(configText)), [](std::string* value) {
        tlp::win::SecureWipe(*value);
        delete value;
    });
    try {
        RunInBackground(m_hWnd, OperationKind::Connect, "", [tunnelName, stagedConfig, profileId, workstationId,
                                                               operationId, operationGeneration, cancellation](OperationResult& result) {
            result.generation = operationGeneration;
            bool installed = false;
            try {
                installed = tlp::win::InstallTunnel(tunnelName, *stagedConfig, profileId, workstationId,
                                                    operationId, operationGeneration, cancellation);
            } catch (...) {
                tlp::win::SecureWipe(*stagedConfig);
                throw;
            }
            tlp::win::SecureWipe(*stagedConfig);
            return installed;
        });
    } catch (const std::exception& e) {
        LogEvent("connection_failed", "error", e.what());
        active_.reset();
        busy_ = false;
        SetState("Not connected", "The connection worker could not start.");
        ShowError(e.what());
        RefreshList();
    }
}

void CMainDlg::StartDisconnect(const std::string& reason) {
    if (!active_) return;
    if (busy_) {
        if (active_->cancellation) active_->cancellation->Cancel();
        tlp::tunnel_lifecycle::CancelOperation(active_->lifecycle);
        ++generation_;
        SetState("Cancelling connection...", reason.empty() ?
            "TELIPHONES is stopping the current operation and will remove only its owned tunnel." : reason);
        UpdateButtons();
        return;
    }
    busy_ = true;
    LogEvent("disconnect_requested", "info", reason.empty() ? "User requested tunnel removal." : reason);
    tlp::win::CloseSecureBrowserSessions(active_->profileId);
    ++generation_;
    tlp::tunnel_lifecycle::CancelOperation(active_->lifecycle);
    UpdateButtons();
    SetState("Disconnecting...", reason);
    std::string tunnelName = active_->tunnelName;
    const std::string sessionAddress = active_->pbxAddress;
    try {
        const auto profile = *FindProfile(active_->profileId);
        RunInBackground(m_hWnd, OperationKind::Disconnect, reason, [tunnelName, profile, sessionAddress](OperationResult& result) {
            if (profile.kind == ProfileKind::Administrator) tlp::win::CloseManagedSsh(profile.id);
            if (profile.kind == ProfileKind::Administrator) {
                try {
                    tlp::win::MaintainWorkstationSession(sessionAddress, true);
                } catch (const std::exception& error) {
                    result.warning = std::string("The PBX could not confirm lease release; capacity will be recovered after lease expiry: ") +
                                     tlp::SanitizeDiagnosticDetail(error.what());
                }
            }
            tlp::win::RemoveTunnel(tunnelName);
            // The tunnel is gone and owned SSH sessions were verified closed; leftover public files do not
            // keep the connection open, so they are reported rather than failing the disconnect.
            if (tlp::MayHaveSshRuntime(profile)) {
                try {
                    tlp::win::RemoveSshRuntime(profile);
                } catch (const tlp::SshRuntimeResidual& residual) {
                    result.warning += std::string(result.warning.empty() ? "" : " ") +
                                      "Temporary SSH files could not be removed and will be retried at the next start: " +
                                      residual.what();
                }
            }
            return true;
        });
    } catch (const std::exception& e) {
        busy_ = false;
        LogEvent("disconnect_failed", "error", e.what());
        SetState("Disconnect worker unavailable", "The tunnel has not been removed. Choose Disconnect again: " + std::string(e.what()));
        UpdateButtons();
    }
}

void CMainDlg::OnDisconnect() { StartDisconnect(""); }

void CMainDlg::OnOpenGui() {
    const Profile* profile = active_ && active_->connected && active_->verified && !busy_ ? FindProfile(active_->profileId) : nullptr;
    if (profile == nullptr) return;
    try {
        tlp::win::OpenFreePbx(*profile, active_->sessionId, CurrentPreferences());
    } catch (const tlp::AppUnavailable& e) {
        if (profile->kind == ProfileKind::Administrator && profile->pairing.guiUrl.rfind("https://", 0) == 0) {
            ShowError(std::string(e.what()) +
                " Secure HTTPS management does not fall back to the Windows default browser. Choose an installed Edge, Chrome, or Brave browser in Settings, or use Locate... to find the selected browser.");
            return;
        }
        std::string text = std::string(e.what()) +
                           "\n\nYes: use the Windows default browser from now on.\nNo: choose another browser in Settings.\nCancel: do nothing.";
        int answer = tlp::ui::ShowMessage(Widen(text).c_str(), MB_YESNOCANCEL | MB_ICONWARNING);
        bool retry = false;
        if (answer == IDYES) {
            tlp::Preferences updated = storedPreferences_.value_or(CurrentPreferences());
            updated.browser = tlp::kWindowsDefaultBrowser;
            if (updated.setup.empty()) updated.setup = "completed";
            try {
                tlp::win::SavePreferences(updated);
                storedPreferences_ = updated;
                retry = true;
            } catch (const std::exception& saveError) {
                ShowError(std::string("Your application preferences could not be saved: ") + saveError.what());
            }
        } else if (answer == IDNO) {
            retry = ShowAppSettings(false, e.what());
        }
        if (!retry) return;
        profile = active_ && active_->connected && active_->verified && !busy_ ? FindProfile(active_->profileId) : nullptr;
        if (profile == nullptr) return;
        try {
            tlp::win::OpenFreePbx(*profile, active_->sessionId, CurrentPreferences());
        } catch (const std::exception& again) {
            ShowError(again.what());
        }
    } catch (const std::exception& e) {
        ShowError(e.what());
    }
}

// SSH opens only for an active, monitor-verified connection whose PBX or grant explicitly authorised SSH.
bool CMainDlg::SshReady() {
    const Profile* profile = active_ ? FindProfile(active_->profileId) : nullptr;
    if (profile == nullptr || busy_ || !active_->connected) return false;
    if (!active_->verified) {
        ShowError("The PBX has not yet answered through the secure connection. Wait until TELIPHONES shows Connected, then choose Open SSH again.");
        return false;
    }
    if (profile->kind == ProfileKind::Administrator && !profile->pairing.ssh) return false;
    if (profile->kind == ProfileKind::Administrator && profile->sshUser.empty()) {
        ShowError("No SSH user is set for this PBX. Remove and pair it again, entering the Linux account to use for SSH.");
        return false;
    }
    return true;
}

void CMainDlg::OnOpenSsh() {
    const Profile* selected = active_ ? FindProfile(active_->profileId) : nullptr;
    if (selected != nullptr && selected->kind == ProfileKind::Administrator && !selected->pairing.ssh) {
        if (busy_ || !active_->connected || !active_->verified) {
            ShowError("Connect and wait for PBX admission before requesting SSH access.");
            return;
        }
        try {
            Profile* profile = FindProfile(selected->id);
            if (profile->pairing.sshRequestPublicKey.empty()) {
                const std::string publicKey = tlp::win::GenerateWorkstationSshIdentity(*profile);
                profile->pairing.sshRequestPublicKey = publicKey;
                try {
                    tlp::win::SaveProfiles(profiles_);
                } catch (...) {
                    profile->pairing.sshRequestPublicKey.clear();
                    throw;
                }
            }
            const Profile requestProfile = *profile;
            const std::string publicKey = profile->pairing.sshRequestPublicKey;
            busy_ = true;
            UpdateButtons();
            RunInBackground(m_hWnd, OperationKind::Ssh, "", [requestProfile, publicKey](OperationResult& result) {
                auto status = tlp::win::MaintainWorkstationSession(requestProfile.pairing.pbxAddress, false,
                    &requestProfile.pairing, "ssh-request", publicKey);
                result.warning = status.sshRequestStatus == "applied"
                    ? "SSH access was already approved by FreePBX."
                    : "SSH request is Pending Approval by a FreePBX administrator. Web access remains unchanged.";
                return true;
            });
        } catch (const std::exception& error) {
            busy_ = false;
            UpdateButtons();
            ShowError(std::string("SSH access request could not be sent: ") + error.what());
        }
        return;
    }
    if (!SshReady()) return;
    try {
        const auto profile = *FindProfile(active_->profileId);
        if (profile.kind == ProfileKind::Administrator) tlp::win::RequireManagedSsh(profile);
        const auto session = active_->sessionId;
        auto preferences = CurrentPreferences();
        try {
            tlp::ResolveApp(tlp::AppKind::Terminal, preferences.terminal, tlp::win::DetectApps(tlp::AppKind::Terminal, preferences));
        } catch (const tlp::AppUnavailable& error) {
            if (tlp::ui::ShowMessage(Widen(std::string(error.what()) + "\n\nChoose OK to select another SSH terminal in Settings.").c_str(),
                                    MB_OKCANCEL | MB_ICONWARNING) != IDOK) return;
            if (!ShowAppSettings(false, error.what()) || !SshReady()) return;
            preferences = CurrentPreferences();
        }
        busy_ = true;
        UpdateButtons();
        LogEvent("ssh_requested", "info", "Requesting SSH; terminal launch is not proof of terminal authentication.");
        RunInBackground(m_hWnd, OperationKind::Ssh, "", [profile, session, preferences](OperationResult&) {
            tlp::win::OpenSsh(profile, session, preferences);
            return true;
        });
    } catch (const std::exception& e) {
        busy_ = false;
        UpdateButtons();
        ShowError(e.what());
    }
}

void CMainDlg::OnLockWorkstation() {
    if (!active_ || busy_ || !active_->connected || !active_->verified) return;
    const Profile* current = FindProfile(active_->profileId);
    if (current == nullptr || current->kind != ProfileKind::Administrator ||
        (activePolicyLocked_ && unlockRequestPending_)) return;
    const Profile profile = *current;
    busy_ = true;
    active_->verified = false;
    UpdateButtons();
    const bool requestUnlock = activePolicyLocked_;
    SetState(requestUnlock ? "Requesting workstation unlock" : "Applying workstation restriction",
             requestUnlock
                 ? "The PBX will keep this workstation's current restrictions until a FreePBX administrator approves the request."
                 : "The PBX will lock this workstation to its verified WireGuard public source. Session admission remains enforced during the listener migration.");
    try {
        RunInBackground(m_hWnd, OperationKind::Policy, "", [profile, requestUnlock](OperationResult& result) {
            const auto status = tlp::win::MaintainWorkstationSession(profile.pairing.pbxAddress, false,
                &profile.pairing, requestUnlock ? "unlock-request" : "lock-current");
            result.warning = status.policySummary;
            result.policyLocked = status.policyLocked || requestUnlock;
            result.unlockRequestPending = status.unlockRequestPending;
            return true;
        });
    } catch (const std::exception& error) {
        busy_ = false;
        if (active_) active_->verified = true;
        UpdateButtons();
        ShowError(std::string("The workstation restriction request could not be started: ") + error.what());
    }
}

void CMainDlg::OnRequestSources() {
    if (!active_ || busy_ || !active_->connected || !active_->verified || sourcesRequestPending_) return;
    const Profile* current = FindProfile(active_->profileId);
    if (current == nullptr || current->kind != ProfileKind::Administrator) return;
    CStringW sourceText;
    layout_.Find(IDC_ALLOWED_SOURCES)->GetWindowText(sourceText);
    std::string sources;
    try {
        const std::wstring wideSources(sourceText.GetString(), static_cast<std::size_t>(sourceText.GetLength()));
        sources = Narrow(wideSources);
    } catch (const std::exception& error) {
        ShowError(std::string("Allowed List text could not be encoded: ") + error.what());
        return;
    }
    if (sources.empty() || sources.size() > 2048) {
        ShowError("Enter one or more IPv4, IPv6, CIDR or DNS entries (maximum 2048 bytes).");
        return;
    }
    const Profile profile = *current;
    busy_ = true;
    active_->verified = false;
    UpdateButtons();
    SetState("Requesting Allowed List change",
             "The current PBX restrictions remain in force until a FreePBX administrator approves the requested list.");
    try {
        RunInBackground(m_hWnd, OperationKind::Policy, "", [profile, sources](OperationResult& result) {
            const auto status = tlp::win::MaintainWorkstationSession(profile.pairing.pbxAddress, false,
                &profile.pairing, "sources-request", "", sources);
            result.warning = status.policySummary;
            result.policyLocked = status.policyLocked;
            result.sourcesRequestPending = status.sourcesRequestPending;
            return true;
        });
    } catch (const std::exception& error) {
        busy_ = false;
        if (active_) active_->verified = true;
        UpdateButtons();
        ShowError(std::string("The Allowed List request could not be started: ") + error.what());
    }
}

void CMainDlg::OnTimer(UINT_PTR id) {
    if (id != kMonitorTimer) {
        CDialogEx::OnTimer(id);
        return;
    }
    for (int row = 0; row < list_.GetItemCount() && static_cast<std::size_t>(row) < profiles_.size(); ++row) {
        list_.SetItemText(row, 2, Widen(AccessText(profiles_[static_cast<std::size_t>(row)], tlp::win::UnixNow())).c_str());
    }
    if (closing_ && GetTickCount64() >= closeDeadlineTickMs_) {
        LogEvent("shutdown_cleanup_deferred", "warning",
                 "The bounded close window ended; persisted ownership will drive cleanup at the next launch.");
        FinishClose();
        return;
    }
    if (active_ && tlp::tunnel_lifecycle::CheckDeadline(active_->lifecycle, GetTickCount64()) ==
                       tlp::tunnel_lifecycle::LifecycleAction::BeginCleanup) {
        LogEvent("connection_deadline", "error", "The connection stage exceeded its deadline; automatic retries stopped.");
        if (active_->cancellation) active_->cancellation->Cancel();
        ++generation_;
        SetState("Connection timed out - cancelling...",
                 "Automatic retries stopped. The current helper is being cancelled before owned-resource cleanup.");
        UpdateButtons();
        if (!busy_) StartDisconnect("The connection stage reached its deadline.");
        return;
    }
    if (!active_ || !active_->connected || busy_) {
        RefreshHealth();
        return;
    }
    if (active_->expiresAt > 0 && tlp::win::UnixNow() >= active_->expiresAt) {
        active_->verified = false;
        RefreshHealth();
        LogEvent("authorization_expired", "warning", "Local approved expiry reached; disconnecting tunnel.");
        StartDisconnect("Temporary access expired.");
        return;
    }
    if (probing_) return;
    probing_ = true;
    HWND window = m_hWnd;
    UINT_PTR generation = generation_;
    std::string tunnelName = active_->tunnelName;
    std::string address = active_->pbxAddress;
    std::string peerPublicKey = active_->peerPublicKey;
    const auto* connectedProfile = FindProfile(active_->profileId);
    const std::string managementUrl = connectedProfile && connectedProfile->kind == ProfileKind::Administrator ?
                                     connectedProfile->pairing.guiUrl : "http://" + address + "/admin/";
    std::string managedSshProfile = connectedProfile && connectedProfile->kind == ProfileKind::Administrator ?
                                   connectedProfile->id : std::string();
    const bool workstationSessionRequired = connectedProfile && connectedProfile->kind == ProfileKind::Administrator;
    const tlp::PairResponse pairing = connectedProfile ? connectedProfile->pairing : tlp::PairResponse{};
    std::wstring wgExecutable = wireguard_.wgExe;
    std::int64_t expiresAt = active_->expiresAt;
    const std::string diagnosticId = active_->diagnosticId;
    const std::string attemptId = active_->attemptId;
    const std::int64_t networkChangedAt = lastNetworkChangeUnix_;
    std::uint64_t tickNow = GetTickCount64();
    bool collectTelemetry = lastTelemetryTickMs_ == 0 ||
                            tickNow - lastTelemetryTickMs_ >= tlp::ConnectionHealthMonitor::kTelemetryIntervalSeconds * 1000ULL;
    if (collectTelemetry) lastTelemetryTickMs_ = tickNow;
    try {
    std::thread([window, generation, tunnelName, address, managementUrl, peerPublicKey, managedSshProfile, pairing,
                 workstationSessionRequired, wgExecutable, expiresAt, collectTelemetry, diagnosticId, attemptId,
                 networkChangedAt]() {
        auto* result = new ProbeResult;
        std::unique_ptr<tlp::AdmissionTransportError> transportFailure;
        result->sample.authorizationExpiresAt = expiresAt;
        result->sample.authorizationKnown = true;
        result->sample.authorizationPersistent = expiresAt == 0;
        try {
            tlp::win::TunnelState service = tlp::win::QueryTunnel(tunnelName);
            if (!managedSshProfile.empty() &&
                (service == tlp::win::TunnelState::Stopped || service == tlp::win::TunnelState::Absent)) {
                tlp::win::CloseManagedSsh(managedSshProfile);
            }
            result->statusKnown = service == tlp::win::TunnelState::Running || service == tlp::win::TunnelState::Stopped ||
                                  service == tlp::win::TunnelState::Absent;
            result->serviceRunning = service == tlp::win::TunnelState::Running;
            result->sample.tunnelKnown = result->statusKnown;
            result->sample.tunnelRunning = result->serviceRunning;
            if (result->serviceRunning && (expiresAt == 0 || tlp::win::UnixNow() < expiresAt)) {
                if (workstationSessionRequired) {
                    result->sessionAdmissionRequired = true;
                    try {
                        const auto lease = tlp::win::MaintainWorkstationSession(address, false, &pairing, "", "", "", attemptId);
                        result->connectedWorkstations = lease.connectedWorkstations;
                        result->maximumWorkstations = lease.maximumWorkstations;
                        result->policyLocked = lease.policyLocked;
                        result->unlockRequestPending = lease.unlockRequestPending;
                        result->sourcesRequestPending = lease.sourcesRequestPending;
                        result->policySummary = lease.policySummary;
                        result->migration = lease.migration;
                        result->pairingUpdate = lease.pairingUpdate;
                        result->sshRevoked = lease.sshRevoked;
                        result->sshRequestRejected = lease.sshRequestRejected;
                    } catch (const tlp::AdmissionTransportError& e) {
                        result->sessionAdmissionError = e.what();
                        transportFailure = std::make_unique<tlp::AdmissionTransportError>(e);
                    } catch (const std::exception& e) {
                        result->sessionAdmissionError = e.what();
                    }
                }
                if (result->sessionAdmissionError.empty()) {
                    tlp::win::TcpProbeMeasurement probe = tlp::win::MeasureTcpProbe(address, tlp::ManagementProbePort(managementUrl), 1200);
                    result->sample.probeKnown = probe.known;
                    result->error = probe.error;
                    result->sample.probeSucceeded = probe.known && probe.succeeded;
                    if (result->sample.probeSucceeded) result->sample.latencyMs = probe.latencyMs;
                }
                // A transport failure is only meaningful alongside this probe's handshake age.
                if (collectTelemetry || transportFailure) {
                    result->sample.wireGuardTelemetryAttempted = true;
                    try {
                        tlp::WireGuardCounters counters = tlp::win::ReadWireGuardCounters(wgExecutable, tunnelName, peerPublicKey);
                        result->sample.receivedBytes = counters.receivedBytes;
                        result->sample.transmittedBytes = counters.transmittedBytes;
                        result->sample.handshakeUnixSeconds = counters.handshakeUnixSeconds;
                        result->sample.trafficSource = "WireGuard peer counters";
                    } catch (const std::exception& e) {
                        result->sample.telemetryReason = e.what();
                        try {
                            tlp::WireGuardCounters counters = tlp::win::ReadTunnelInterfaceCounters(tunnelName);
                            result->sample.receivedBytes = counters.receivedBytes;
                            result->sample.transmittedBytes = counters.transmittedBytes;
                            result->sample.trafficSource = "Windows tunnel interface IP bytes";
                        } catch (const std::exception& interfaceError) {
                            result->sample.telemetryReason += std::string(" Interface counters: ") + interfaceError.what();
                        }
                    }
                    result->sample.telemetryTimestampMs = static_cast<std::int64_t>(GetTickCount64());
                }
                if (transportFailure) {
                    const std::int64_t observed = tlp::win::UnixNow();
                    tlp::AdmissionContext context;
                    try {
                        const auto route = tlp::win::RouteToAddress(tunnelName, address);
                        context.route = route.route;
                        context.routeInterface = route.interfaceAlias;
                        context.routeInterfaceTeliphones = tlp::tunnel_lifecycle::IsTeliphonesTunnelName(route.interfaceAlias);
                    } catch (const std::exception&) {
                        context.route = tlp::RouteEvidence::Unknown;
                    }
                    if (networkChangedAt > 0) context.networkChangedUnixSeconds = networkChangedAt;
                    context.correlationId = diagnosticId;
                    result->sessionAdmissionError = tlp::DescribeAdmissionFailure(
                        *transportFailure, result->sample.handshakeUnixSeconds, observed, pairing.endpoint,
                        address + ":8766", context);
                    result->admissionTransportFailure = true;
                    // The stage is part of the key so a change from connect to response failures is recorded too.
                    result->admissionFailureClass = std::string(tlp::AdmissionFailureName(tlp::ClassifyAdmissionFailure(
                        transportFailure->stage, result->sample.handshakeUnixSeconds, observed, context.route))) + "/" +
                        tlp::AdmissionStageName(transportFailure->stage);
                }
            }
            result->probeSucceeded = result->sample.probeKnown && result->sample.probeSucceeded;
        } catch (const std::exception& e) {
            result->error = e.what();
            result->statusKnown = false;
            result->sample.tunnelKnown = false;
            result->sample.probeKnown = false;
        }
        result->sample.timestampMs = static_cast<std::int64_t>(GetTickCount64());
        result->sample.utcUnixSeconds = tlp::win::UnixNow();
        if (!::PostMessageW(window, WM_APP_PROBE_DONE, generation, reinterpret_cast<LPARAM>(result))) delete result;
    }).detach();
    } catch (const std::exception& e) {
        probing_ = false;
        LogEvent("measurement_error", "error", e.what());
        SetState("Monitoring worker unavailable", e.what());
    }
}

LRESULT CMainDlg::OnProbeDone(WPARAM generation, LPARAM lparam) {
    std::unique_ptr<ProbeResult> result(reinterpret_cast<ProbeResult*>(lparam));
    probing_ = false;
    if (generation != generation_ || !active_ || !active_->monitor || busy_) return 0;
    if (active_->lifecycle.stage == tlp::tunnel_lifecycle::ConnectionStage::Authenticating &&
        result->sample.handshakeUnixSeconds && *result->sample.handshakeUnixSeconds > 0) {
        tlp::tunnel_lifecycle::AuthenticationObserved(active_->lifecycle, GetTickCount64(), 30000);
        SetState("Waiting for controller admission...", "WireGuard authentication was observed; management remains blocked until the PBX admits this session.");
    }
    if (result->migration) {
        active_->verified = false;
        UpdateButtons();
        Profile* profile = FindProfile(active_->profileId);
        if (profile == nullptr || profile->kind != ProfileKind::Administrator ||
            result->migration->workstationId != profile->pairing.workstationId ||
            result->migration->workstationPublicKey != profile->pairing.workstationPublicKey ||
            result->migration->pbxPublicKey != profile->pairing.pbxPublicKey) {
            SetState("Configuration migration rejected", "The migration did not match this saved workstation identity. The old tunnel remains in place and management access remains blocked.");
            return 0;
        }
        const tlp::PairResponse previous = profile->pairing;
        profile->pairing = *result->migration;
        try {
            tlp::win::SaveProfiles(profiles_);
        } catch (const std::exception& error) {
            profile->pairing = previous;
            SetState("Configuration migration not saved", std::string("The saved profile was preserved; retry the secure migration. ") + error.what());
            return 0;
        }
        migrationReconnectPending_ = true;
        SetState("Applying PBX configuration", "The updated tunnel details were authenticated over the existing WireGuard identity. The old tunnel will be removed before reconnecting.");
        StartDisconnect("Applying authenticated PBX configuration migration.");
        return 0;
    }
    const auto recordHealth = [&]() {
        if (active_->health) {
            try {
                active_->health->AddSample(result->sample);
                RefreshHealth();
                const auto& health = healthSnapshot_;
                const bool changed = active_->lastHealthState != health.state;
                if (changed) {
                    LogEvent("health_changed", health.state == tlp::HealthState::Stable ? "info" : "warning",
                        std::string("Health: ") + tlp::HealthStateName(health.state) +
                        "; app failures=" + std::to_string(health.consecutiveFailures) +
                        "; handshake age=" + (health.handshakeAgeSeconds ? std::to_string(*health.handshakeAgeSeconds) : "Unknown") +
                        "; tunnel known=" + std::to_string(result->sample.tunnelKnown) +
                        "; tunnel running=" + std::to_string(result->sample.tunnelRunning) +
                        ". Probe failure is not proof of revocation or packet loss.");
                    if (health.state != tlp::HealthState::Stable) {
                        std::string recent;
                        const std::size_t start = health.samples.size() > 15 ? health.samples.size() - 15 : 0;
                        for (std::size_t i = start; i < health.samples.size(); ++i) {
                            const auto& sample = health.samples[i];
                            const std::string row = "utc=" + std::to_string(sample.utcUnixSeconds) +
                                " tick_ms=" + std::to_string(sample.timestampMs) +
                                " probe=" + (sample.probeKnown ? (sample.probeSucceeded ? std::string("ok") : std::string("failed")) : std::string("Unknown")) +
                                " latency_ms=" + (sample.latencyMs ? std::to_string(*sample.latencyMs) : "Unknown") +
                                " rx=" + (sample.receivedBytes ? std::to_string(*sample.receivedBytes) : "Unknown") +
                                " tx=" + (sample.transmittedBytes ? std::to_string(*sample.transmittedBytes) : "Unknown") +
                                " hs_utc=" + (sample.handshakeUnixSeconds ? std::to_string(*sample.handshakeUnixSeconds) : "Unknown") + "; ";
                            if (recent.size() + row.size() > 1800) {
                                LogEvent("recent_measurements", "info", recent);
                                recent.clear();
                            }
                            recent += row;
                        }
                        LogEvent("recent_measurements", "info", recent);
                    }
                    active_->lastHealthState = health.state;
                }
                if (result->sample.probeKnown &&
                    (!active_->lastProbeSucceeded || *active_->lastProbeSucceeded != result->sample.probeSucceeded)) {
                    LogEvent("probe_changed", result->sample.probeSucceeded ? "info" : "warning",
                        result->sample.probeSucceeded ? "Authorized PBX answers TCP probes." : "PBX application probe failed: " + result->error);
                    active_->lastProbeSucceeded = result->sample.probeSucceeded;
                }
                if (!result->error.empty() && active_->lastMeasurementError != result->error) {
                    LogEvent("measurement_error", "warning", result->error);
                }
                active_->lastMeasurementError = result->error;
                if (health.handshakeAgeSeconds) {
                    bool stale = *health.handshakeAgeSeconds > tlp::ConnectionHealthMonitor::kStaleHandshakeSeconds;
                    if (!active_->lastHandshakeStale || *active_->lastHandshakeStale != stale) {
                        LogEvent("telemetry_changed", stale ? "warning" : "info",
                            stale ? "WireGuard handshake older than configured freshness threshold; idle is not proof of disconnection."
                                  : "WireGuard handshake is recent.");
                        active_->lastHandshakeStale = stale;
                    }
                }
                if (result->sample.wireGuardTelemetryAttempted && active_->lastTelemetryReason != result->sample.telemetryReason) {
                    LogEvent("telemetry_changed", result->sample.telemetryReason.empty() ? "info" : "warning",
                        result->sample.telemetryReason.empty() ? "WireGuard peer counters and handshake available." : result->sample.telemetryReason);
                    active_->lastTelemetryReason = result->sample.telemetryReason;
                }
                if (GetTickCount64() - active_->lastSummaryTickMs >= 60000) {
                    LogEvent("session_summary", "info", ConnectionHealthSummary(health));
                    active_->lastSummaryTickMs = GetTickCount64();
                }
            } catch (const std::exception& e) {
                LogEvent("measurement_error", "error", e.what());
                SetState("Connection health unavailable", std::string("TELIPHONES discarded an invalid measurement: ") + e.what());
            }
        }
    };
    if (result->sessionAdmissionRequired && !result->sessionAdmissionError.empty()) {
        active_->verified = false;
        UpdateButtons();
        recordHealth();
        const std::string failureClass = result->admissionTransportFailure ? result->admissionFailureClass : "refused";
        if (active_->lastAdmissionFailure != failureClass) {
            LogEvent("admission_failed", "warning", result->sessionAdmissionError);
            active_->lastAdmissionFailure = failureClass;
        }
        const bool atLimit = result->sessionAdmissionError.find("Session limit reached:") == 0;
        SetState(atLimit ? "Session limit reached" : "Admission unavailable",
                 result->sessionAdmissionError + (atLimit
                     ? " Disconnect an active workstation or ask the PBX administrator to increase the limit."
                     : result->admissionTransportFailure ? std::string()
                     : " The tunnel is authenticated, but management access remains blocked until the PBX grants a session."));
        return 0;
    }
    if (result->sessionAdmissionRequired && result->sessionAdmissionError.empty()) {
        tlp::tunnel_lifecycle::AdmissionObserved(active_->lifecycle);
        if (!active_->lastAdmissionFailure.empty()) {
            LogEvent("admission_recovered", "info", "The PBX session controller answered and admitted this workstation.");
            active_->lastAdmissionFailure.clear();
        }
        Profile* profile = FindProfile(active_->profileId);
        if (result->sshRevoked && profile != nullptr && profile->kind == ProfileKind::Administrator) {
            const tlp::PairResponse previous = profile->pairing;
            const std::string previousUser = profile->sshUser;
            tlp::ApplyWorkstationSshRevocation(*profile);
            try {
                tlp::win::SaveProfiles(profiles_);
            } catch (const std::exception& error) {
                profile->pairing = previous;
                profile->sshUser = previousUser;
                SetState("SSH revocation not saved", std::string("FreePBX revoked SSH, but the Windows profile could not be updated: ") + error.what());
                return 0;
            }
            try {
                tlp::win::CloseManagedSsh(profile->id);
            } catch (const std::exception& error) {
                LogEvent("ssh_local_cleanup_failed", "warning", error.what());
            }
            RefreshList();
            UpdateButtons();
        }
        if (result->sshRequestRejected && profile != nullptr && profile->kind == ProfileKind::Administrator) {
            const std::string previous = profile->pairing.sshRequestPublicKey;
            tlp::ApplyWorkstationSshRequestRejection(*profile);
            try {
                tlp::win::SaveProfiles(profiles_);
            } catch (const std::exception& error) {
                profile->pairing.sshRequestPublicKey = previous;
                SetState("SSH rejection not saved", std::string("FreePBX rejected or removed SSH elevation; the local pending request could not be updated: ") + error.what());
                return 0;
            }
            result->policySummary += " SSH elevation request was rejected or withdrawn; web access remains enabled.";
        }
        if (result->pairingUpdate) {
            if (profile == nullptr) {
                SetState("SSH approval not applied", "The PBX approval did not match this saved workstation's pending SSH key. Web access remains available.");
                return 0;
            }
            const tlp::PairResponse previous = profile->pairing;
            const std::string previousUser = profile->sshUser;
            if (!tlp::ApplyWorkstationSshApproval(*profile, *result->pairingUpdate)) {
                SetState("SSH approval not applied", "The PBX approval did not match this saved workstation's pending SSH key. Web access remains available.");
                return 0;
            }
            try {
                tlp::win::SaveProfiles(profiles_);
            } catch (const std::exception& error) {
                profile->pairing = previous;
                profile->sshUser = previousUser;
                SetState("SSH approval not saved", std::string("The saved profile remains web-only; retry after resolving the local storage error. ") + error.what());
                return 0;
            }
            RefreshList();
            UpdateButtons();
        }
    }
    if (!result->sessionAdmissionRequired && result->probeSucceeded)
        tlp::tunnel_lifecycle::AdmissionObserved(active_->lifecycle);
    const Profile* observedProfile = FindProfile(active_->profileId);
    activePolicyLocked_ = observedProfile != nullptr && observedProfile->kind == ProfileKind::Administrator &&
                          result->policyLocked;
    unlockRequestPending_ = observedProfile != nullptr && observedProfile->kind == ProfileKind::Administrator &&
                            result->unlockRequestPending;
    sourcesRequestPending_ = observedProfile != nullptr && observedProfile->kind == ProfileKind::Administrator &&
                             result->sourcesRequestPending;
    recordHealth();
    std::int64_t now = tlp::win::UnixNow();
    if (active_->expiresAt > 0 && now >= active_->expiresAt) {
        active_->verified = false;
        UpdateButtons();
        SetState("Authorization expired", "The pairing duration has ended. TELIPHONES is disconnecting the tunnel.");
        StartDisconnect("Temporary access expired.");
        return 0;
    }
    if (!result->statusKnown) {
        tlp::win::CloseSecureBrowserSessions(active_->profileId);
        active_->verified = false;
        UpdateButtons();
        SetState("Connection status temporarily unavailable",
                 "TELIPHONES will retry automatically; this is not being treated as a tunnel failure.");
        return 0;
    }
    if (result->serviceRunning && !result->sample.probeKnown) {
        tlp::win::CloseSecureBrowserSessions(active_->profileId);
        active_->verified = false;
        UpdateButtons();
        SetState("PBX probe unavailable", "The local TCP probe could not be measured; this is not counted as a failed probe.");
        return 0;
    }
    tlp::MonitorDecision decision = active_->monitor->Observe(now, result->serviceRunning, result->probeSucceeded);
    std::string guidance = decision.guidance;
    if (result->sessionAdmissionRequired && result->maximumWorkstations > 0) {
        guidance += " PBX-admitted workstations: " + std::to_string(result->connectedWorkstations) +
                    " of " + std::to_string(result->maximumWorkstations) + ".";
    }
    if (!result->policySummary.empty()) guidance += " " + result->policySummary;
    SetState(decision.summary, guidance);
    bool verified = decision.state == tlp::LinkState::Connected;
    if (!verified) tlp::win::CloseSecureBrowserSessions(active_->profileId);
    if (verified != active_->verified) {
        active_->verified = verified;
        UpdateButtons();
    }
    if (decision.disconnect && decision.state == tlp::LinkState::Expired) StartDisconnect(decision.summary + " " + decision.guidance);
    else if (decision.state == tlp::LinkState::Lost || decision.state == tlp::LinkState::NoResponse ||
             decision.state == tlp::LinkState::Stopped) {
        tlp::win::CloseSecureBrowserSessions(active_->profileId);
        SetState(decision.summary,
                 decision.guidance + (decision.state == tlp::LinkState::Stopped ?
                     " The Connection Health monitor will keep checking; managed My PBXs SSH sessions have been closed." :
                     " The Connection Health monitor will keep checking; existing terminal windows are not closed."));
    }
    UpdateButtons();
    return 0;
}

LRESULT CMainDlg::OnOperationDone(WPARAM, LPARAM lparam) {
    std::unique_ptr<OperationResult> result(reinterpret_cast<OperationResult*>(lparam));
    busy_ = false;
    if (result->kind == OperationKind::Connect && result->generation != generation_) {
        // Disconnect/Close superseded this result.  A late successful install is never promoted.
        if (active_) {
            LogEvent("obsolete_connection_result", "warning", "A superseded connection worker completed; cleanup is being enforced.");
            StartDisconnect("The connection attempt was cancelled.");
        } else if (closing_) {
            FinishClose();
        }
        return 0;
    }
    const bool reconnectAfterMigration = result->kind == OperationKind::Disconnect &&
                                         migrationReconnectPending_ && result->error.empty();
    const std::string reconnectProfileId = active_ ? active_->profileId : std::string();
    switch (result->kind) {
        case OperationKind::Ssh:
            if (!result->error.empty()) {
                LogEvent("ssh_failed", "error", result->error);
                ShowError(result->error);
            } else {
                LogEvent("ssh_launched", "info", "Selected external SSH terminal process launched; authentication is not yet observed.");
                if (!result->warning.empty()) SetState("SSH request submitted", result->warning);
            }
            break;
        case OperationKind::Policy:
            if (!result->error.empty()) {
                if (active_) active_->verified = false;
                SetState("Workstation restriction unavailable", result->error);
                ShowError(result->error);
            } else {
                activePolicyLocked_ = result->policyLocked;
                unlockRequestPending_ = result->unlockRequestPending;
                sourcesRequestPending_ = result->sourcesRequestPending;
                SetState(sourcesRequestPending_ ? "Allowed List request submitted" :
                    unlockRequestPending_ ? "Unlock request submitted" :
                    activePolicyLocked_ ? "Restriction applied" : "Workstation policy updated", result->warning);
            }
            break;
        case OperationKind::Recovery:
            if (!result->error.empty()) {
                LogEvent("recovery_reconcile", "error", result->error);
                if (active_) active_->lifecycle.stage = tlp::tunnel_lifecycle::ConnectionStage::CleanupIncomplete;
                SetState("Recovery required", result->error + " The recovery context and ownership records were retained; choose Recover to retry.");
                if (!result->warning.empty()) {
                    LogEvent("session_release_warning", "warning", result->warning);
                    SetState("Recovery required", result->error + " " + result->warning +
                             " The recovery context and ownership records were retained; choose Recover to retry.");
                }
            } else {
                LogEvent("recovery_reconcile", "info", "Full TELIPHONES runtime cleanup completed and Windows tunnel state was reconciled.");
                if (active_) {
                    active_.reset();
                    lastTelemetryTickMs_ = 0;
                    tlp::HealthSnapshot disconnected;
                    disconnected.state = tlp::HealthState::Disconnected;
                    healthDialog_.UpdateSnapshot(disconnected);
                }
                SetState("Not connected", result->warning.empty()
                    ? "TELIPHONES runtime cleanup completed and no residual owned tunnel state was found."
                    : "TELIPHONES runtime cleanup completed. " + result->warning);
            }
            break;
        case OperationKind::Cleanup:
            if (!result->error.empty()) {
                std::string reconciliation = "Post-failure read-only reconciliation unavailable.";
                try {
                    const auto remaining = tlp::win::ResidualTeliphonesTunnels({});
                    reconciliation = remaining.empty() ? "Read-only reconciliation found no currently observable TELIPHONES residual; the protected journal was not assumed absent." :
                        "Read-only reconciliation still finds TELIPHONES candidate(s): " + remaining.front() +
                        (remaining.size() > 1 ? " (and additional candidates)." : ".");
                } catch (const std::exception& error) {
                    reconciliation += " " + tlp::SanitizeDiagnosticDetail(error.what());
                }
                LogEvent("recovery_reconcile", "warning", reconciliation);
                SetState("Recovery required", "TELIPHONES cleanup did not complete: " + result->error + " " + reconciliation +
                    " Use Recover to retry; no unrelated VPN or unverified device will be changed.");
            } else {
                SetState("Not connected", "A tunnel left from a previous session was removed.");
            }
            break;
        case OperationKind::Connect:
            if (!result->error.empty() || result->declined) {
                LogEvent("connection_failed", "error", result->declined ? "UAC declined." : result->error);
                active_.reset();
                lastTelemetryTickMs_ = 0;
                tlp::HealthSnapshot disconnected;
                disconnected.state = tlp::HealthState::Disconnected;
                healthDialog_.UpdateSnapshot(disconnected);
                SetState("Not connected", result->declined ? "Connection cancelled: administrative approval was not given." : result->error);
                if (!result->error.empty()) ShowError(result->error);
                if (closing_) FinishClose();
                break;
            }
            if (const Profile* profile = FindProfile(active_->profileId)) {
                bool viaGateway = profile->kind == ProfileKind::Support;
                std::string endpoint = viaGateway ? profile->grant.endpoint : tlp::DirectProvider().Plan(profile->pairing.endpoint).endpoint;
                active_->monitor = std::make_unique<tlp::ConnectionMonitor>(tlp::win::UnixNow(), active_->expiresAt, endpoint, viaGateway);
                active_->health = std::make_unique<tlp::ConnectionHealthMonitor>(healthPreferences_.thresholds);
            }
            active_->connected = true;
            tlp::tunnel_lifecycle::TunnelEstablished(active_->lifecycle, GetTickCount64(), 30000);
            LogEvent("tunnel_started", "info", "WireGuard tunnel service started. PBX application reachability not yet verified.");
            SetState("Waiting for WireGuard authentication...",
                     "The local tunnel service is running. TELIPHONES is waiting for handshake evidence before controller admission.");
            break;
        case OperationKind::Disconnect:
            if (!result->error.empty()) {
                LogEvent("disconnect_failed", "error", result->error);
                std::string reconciliation = "Post-failure read-only reconciliation could not verify candidate state.";
                try {
                    const auto remaining = tlp::win::ResidualTeliphonesTunnels({});
                    if (remaining.empty()) reconciliation = "No valid owned residual is currently observable; any uncertain ownership record was preserved.";
                    else reconciliation = "Recovery candidate remains: " + remaining.front() +
                        (remaining.size() > 1 ? " (and additional candidates)." : ".");
                } catch (const std::exception& error) {
                    reconciliation += " " + tlp::SanitizeDiagnosticDetail(error.what());
                }
                LogEvent("recovery_reconcile", "warning", reconciliation);
                SetState("Recovery required", result->error + " " + reconciliation +
                    " Use Recover to retry. The active UI record is retained until removal is verified.");
                ShowError(result->error);
                if (active_) active_->lifecycle.stage = tlp::tunnel_lifecycle::ConnectionStage::CleanupIncomplete;
                if (closing_) FinishClose();
                break;
            }
            LogEvent("tunnel_removed", "info", "Tunnel removed: " + result->reason);
            {
                auto& saved = history_[active_->profileId];
                saved = healthSnapshot_;
                saved.state = tlp::HealthState::Disconnected;
                saved.connectedSeconds.reset();
                saved.continuouslyHealthySeconds.reset();
            }
            active_.reset();
            lastTelemetryTickMs_ = 0;
            {
                tlp::HealthSnapshot disconnected;
                disconnected.state = tlp::HealthState::Disconnected;
                healthDialog_.UpdateSnapshot(disconnected);
            }
            SetState("Disconnected", result->reason);
            if (!result->warning.empty()) {
                LogEvent("session_release_warning", "warning", result->warning);
                SetState("Disconnected", result->reason + " " + result->warning);
            }
            if (closing_) {
                FinishClose();
                return 0;
            }
            break;
    }
    if (reconnectAfterMigration) migrationReconnectPending_ = false;
    RefreshList();
    if (active_ && active_->lifecycle.stage == tlp::tunnel_lifecycle::ConnectionStage::Disconnecting &&
        result->kind != OperationKind::Disconnect) {
        StartDisconnect(closing_ ? "Application shutdown requested." : "The active operation was cancelled by Disconnect.");
        return 0;
    }
    if (closing_ && active_ && result->kind != OperationKind::Disconnect) {
        StartDisconnect("Application shutdown requested.");
        return 0;
    }
    if (reconnectAfterMigration) {
        for (std::size_t index = 0; index < profiles_.size(); ++index) {
            if (profiles_[index].id == reconnectProfileId) {
                list_.SetItemState(static_cast<int>(index), LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                OnConnect();
                break;
            }
        }
    }
    return 0;
}

void CMainDlg::OnCancel() {
    if (closing_) {
        FinishClose();
        return;
    }
    if (active_ && tlp::ui::ShowMessage(
            L"Disconnect from the PBX and exit TELIPHONES? Cleanup is bounded; unresolved owned resources will be recovered at the next launch.",
            MB_ICONQUESTION | MB_YESNO) != IDYES) return;
    closing_ = true;
    closeDeadlineTickMs_ = GetTickCount64() + 5000;
    ++generation_;
    if (active_ && active_->cancellation) active_->cancellation->Cancel();
    probing_ = false;  // late probe messages carry an obsolete generation and are discarded
    UpdateButtons();
    SetState("Closing...", "Cancelling active work and starting bounded owned-resource cleanup.");
    if (active_ && !busy_) {
        StartDisconnect("Application shutdown requested.");
    } else if (!active_) {
        FinishClose();
    }
}

void CMainDlg::FinishClose() {
    if (GetSafeHwnd() == nullptr) return;
    tlp::win::CloseAllSecureBrowserSessions();
    try {
        tlp::win::CloseAllManagedSsh();
    } catch (const std::exception& error) {
        LogEvent("shutdown_with_recovery_state", "warning", "Managed SSH session teardown could not be verified: " +
                 tlp::SanitizeDiagnosticDetail(error.what()));
    }
    if (active_) {
        LogEvent("shutdown_with_recovery_state", "warning",
                 "Application closed before owned-resource cleanup was verified; next-launch recovery is required.");
    }
    active_.reset();
    healthDialog_.PersistWindowState();
    KillTimer(kMonitorTimer);
    tlp::win::StopWatchingNetworkChanges(networkWatch_);
    networkWatch_ = nullptr;
    LogEvent("shutdown", "info", "Application shutdown completed.");
    CDialogEx::OnCancel();
}
