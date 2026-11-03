#include "MainDlg.h"

#include <objbase.h>

#include <ctime>
#include <exception>
#include <functional>
#include <thread>

#include "../core/CommandLine.h"
#include "../core/Json.h"
#include "../core/Pairing.h"
#include "../core/Rendezvous.h"
#include "../core/TunnelConfig.h"
#include "../platform/Applications.h"
#include "../platform/Services.h"
#include "../platform/Win.h"
#include "AppSettingsDlg.h"
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

enum class OperationKind { Connect, Disconnect, Cleanup };

struct OperationResult {
    OperationKind kind = OperationKind::Connect;
    bool declined = false;
    std::string error;
    std::string reason;
};

struct ProbeResult {
    bool statusKnown = false;
    bool serviceRunning = false;
    bool probeSucceeded = false;
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
void RunInBackground(HWND window, OperationKind kind, std::string reason, std::function<bool()> work) {
    std::thread([window, kind, reason, work]() {
        HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        auto* result = new OperationResult;
        result->kind = kind;
        result->reason = reason;
        try {
            result->declined = !work();
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

void ShowError(const std::string& text) { AfxMessageBox(Widen(text).c_str(), MB_ICONERROR); }

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

BEGIN_MESSAGE_MAP(CMainDlg, CDialogEx)
    ON_BN_CLICKED(IDC_ADD_PBX, &CMainDlg::OnAddPbx)
    ON_BN_CLICKED(IDC_ADD_SUPPORT, &CMainDlg::OnAddSupport)
    ON_BN_CLICKED(IDC_UPDATE_GRANT, &CMainDlg::OnUpdateGrant)
    ON_BN_CLICKED(IDC_REMOVE, &CMainDlg::OnRemove)
    ON_BN_CLICKED(IDC_CONNECT, &CMainDlg::OnConnect)
    ON_BN_CLICKED(IDC_DISCONNECT, &CMainDlg::OnDisconnect)
    ON_BN_CLICKED(IDC_OPEN_GUI, &CMainDlg::OnOpenGui)
    ON_BN_CLICKED(IDC_OPEN_SSH, &CMainDlg::OnOpenSsh)
    ON_BN_CLICKED(IDC_SETTINGS, &CMainDlg::OnSettings)
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
END_MESSAGE_MAP()

CMainDlg::CMainDlg(CWnd* parent) : CDialogEx(IDD_MAIN, parent), healthDialog_(this) {}

void CMainDlg::DoDataExchange(CDataExchange* exchange) {
    CDialogEx::DoDataExchange(exchange);
    DDX_Control(exchange, IDC_PROFILES, list_);
    DDX_Control(exchange, IDC_SESSION, sessions_);
}

BOOL CMainDlg::OnInitDialog() {
    CDialogEx::OnInitDialog();
    LogEvent("startup", "info", "Application started; diagnostic timestamps are UTC. PBX clock may differ.");
    SetWindowText(Widen("TELIPHONES " TELIPHONES_VERSION_STRING).c_str());
    HICON icon = LoadIconW(nullptr, IDI_APPLICATION);
    SetIcon(icon, TRUE);
    SetIcon(icon, FALSE);

    list_.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    list_.InsertColumn(0, L"Name", LVCFMT_LEFT, 170);
    list_.InsertColumn(1, L"Type", LVCFMT_LEFT, 105);
    list_.InsertColumn(2, L"Access", LVCFMT_LEFT, 190);
    list_.InsertColumn(3, L"Status", LVCFMT_LEFT, 110);

    RefreshWireGuard();

    try {
        profiles_ = tlp::win::LoadProfiles();
    } catch (const std::exception& e) {
        ShowError(std::string("Saved connections could not be loaded and were left unchanged: ") + e.what());
    }
    RefreshList();
    SetState("Not connected", "Select a PBX and choose Connect. Add a PBX with \"Add my PBX...\" or a Remote Support gateway.");
    RemoveStaleTunnels();
    SetTimer(kMonitorTimer, kMonitorIntervalMs, nullptr);

    bool preferencesReadable = true;
    try {
        storedPreferences_ = tlp::win::LoadPreferences();
    } catch (const std::exception& e) {
        preferencesReadable = false;
        ShowError(std::string("Your browser and SSH terminal preferences could not be read and were left unchanged: ") + e.what() +
                  " Open Settings to choose them again.");
    }
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
    healthSnapshot_ = {};
    if (active_ && active_->health) {
        healthSnapshot_ = active_->health->Snapshot(GetTickCount64(), healthPreferences_.historySeconds);
        healthSnapshot_.authorizationKnown = true;
        healthSnapshot_.authorizationPersistent = active_->expiresAt == 0;
        healthSnapshot_.authorizationExpiresAt = active_->expiresAt;
        if (active_->expiresAt > 0) {
            const auto remaining = active_->expiresAt - tlp::win::UnixNow();
            healthSnapshot_.authorizationRemainingSeconds = remaining > 0 ? remaining : 0;
        }
        healthSnapshot_.sessionId = active_->diagnosticId;
        healthSnapshot_.attemptId = active_->attemptId;
    }
    healthDialog_.UpdateSnapshot(healthSnapshot_);
    const Profile* selected = Selected();
    const bool showingActive = selected && active_ && selected->id == active_->profileId;
    SetDlgItemText(IDC_HEALTH_INLINE_TEXT, Widen(showingActive ? ConnectionHealthSummary(healthSnapshot_)
        : "Selected PBX is not connected. Measurements: Unknown.").c_str());
    GetDlgItem(IDC_HEALTH_INLINE_GRAPH)->Invalidate(FALSE);
}

void CMainDlg::OnDrawItem(int controlId, LPDRAWITEMSTRUCT item) {
    if (controlId != IDC_HEALTH_INLINE_GRAPH || item == nullptr) {
        CDialogEx::OnDrawItem(controlId, item);
        return;
    }
    CDC dc;
    dc.Attach(item->hDC);
    const Profile* selected = Selected();
    const tlp::HealthSnapshot empty;
    DrawConnectionHealthGraph(dc, CRect(item->rcItem),
        selected && active_ && selected->id == active_->profileId ? healthSnapshot_ : empty,
        healthPreferences_.historySeconds);
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
    if (dialog.startAction == CAppSettingsDlg::StartAction::AddPbx) OnAddPbx();
    if (dialog.startAction == CAppSettingsDlg::StartAction::Support) OnAddSupport();
    return saved;
}

void CMainDlg::OnSettings() { ShowAppSettings(false, ""); }

void CMainDlg::OnConnectionHealth() {
    const Profile* selected = Selected();
    if (!active_ || !active_->connected || !active_->health || !selected || selected->id != active_->profileId) return;
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
        if (pairing.ssh) details += "    SSH user: " + (profile->sshUser.empty() ? std::string("(not set)") : profile->sshUser);
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
    bool connected = active_ && active_->connected && !busy_;
    bool sshAllowed = activeProfile != nullptr && (activeProfile->kind == ProfileKind::Support || activeProfile->pairing.ssh);
    bool verified = connected && active_->verified;

    GetDlgItem(IDC_ADD_PBX)->EnableWindow(!busy_);
    GetDlgItem(IDC_ADD_SUPPORT)->EnableWindow(!busy_);
    GetDlgItem(IDC_UPDATE_GRANT)->EnableWindow(profile != nullptr && profile->kind == ProfileKind::Support && !busy_ && !selectedActive);
    GetDlgItem(IDC_REMOVE)->EnableWindow(profile != nullptr && !busy_ && !selectedActive);
    GetDlgItem(IDC_CONNECT)->EnableWindow(canConnect);
    GetDlgItem(IDC_DISCONNECT)->EnableWindow(active_ && !busy_);
    GetDlgItem(IDC_OPEN_GUI)->EnableWindow(connected);
    GetDlgItem(IDC_OPEN_SSH)->EnableWindow(verified && sshAllowed);
    GetDlgItem(IDC_CONNECTION_HEALTH)->EnableWindow(connected && selectedActive);
    GetDlgItem(IDC_CONNECTION_HEALTH)->SetWindowTextW(L"Pop Out");
    GetDlgItem(IDC_SETTINGS)->EnableWindow(!busy_);
}

void CMainDlg::SetState(const std::string& state, const std::string& guidance) {
    SetDlgItemText(IDC_STATE, Widen(state).c_str());
    SetDlgItemText(IDC_GUIDANCE, Widen(guidance).c_str());
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

void CMainDlg::RemoveStaleTunnels() {
    // A previous run may have ended without disconnecting (crash, power loss). Ask before a cleanup
    // that may require UAC; launching the GUI alone must not trigger a privileged operation.
    std::vector<std::string> stale;
    for (const Profile& profile : profiles_) {
        std::string name = tlp::TunnelNameFor(profile);
        tlp::win::TunnelState state = tlp::win::QueryTunnel(name);
        if (state != tlp::win::TunnelState::Absent && state != tlp::win::TunnelState::Unknown) stale.push_back(name);
    }
    if (stale.empty()) return;
    if (AfxMessageBox(L"A TELIPHONES tunnel from a previous run is still installed. Remove it now?", MB_ICONQUESTION | MB_YESNO) != IDYES) {
        SetState("Previous tunnel still installed", "Remove it from WireGuard for Windows, or restart TELIPHONES and approve cleanup.");
        return;
    }
    busy_ = true;
    UpdateButtons();
    SetState("Removing a TELIPHONES tunnel left from a previous session...", "");
    RunInBackground(m_hWnd, OperationKind::Cleanup, "", [stale]() {
        for (const std::string& name : stale) tlp::win::RemoveTunnel(name);
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

void CMainDlg::OnRemove() {
    Profile* profile = Selected();
    if (profile == nullptr || (active_ && active_->profileId == profile->id)) return;
    std::wstring question = L"Remove \"" + Widen(profile->name) + L"\" and delete its WireGuard key from this computer?";
    if (profile->kind == ProfileKind::Administrator) {
        question += L"\n\nThis does not revoke the workstation on the PBX. Revoke it in FreePBX > Connectivity > TELIPHONES > Windows workstations.";
    }
    if (AfxMessageBox(question.c_str(), MB_ICONQUESTION | MB_YESNO) != IDYES) return;
    try {
        tlp::win::DeletePrivateKey(tlp::CredentialTargetFor(*profile));
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
        LogEvent("connection_attempt", "info", "Manual connection attempt. Correlation ID identifies this pairing; attempt ID is workstation-local.",
                 active->diagnosticId, active->attemptId);
        if (profile->kind == ProfileKind::Administrator && profile->pairing.mode == "temporary" && profile->pairing.expiresAt <= now) {
            throw tlp::Error("This temporary pairing has expired. Remove it and pair this workstation again from the PBX.");
        }
        std::string privateKey = tlp::win::LoadPrivateKey(tlp::CredentialTargetFor(*profile));
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
    busy_ = true;
    RefreshList();
    SetState("Connecting...", "Windows will ask for administrative approval to start the WireGuard tunnel.");
    auto stagedConfig = std::shared_ptr<std::string>(new std::string(std::move(configText)), [](std::string* value) {
        tlp::win::SecureWipe(*value);
        delete value;
    });
    try {
        RunInBackground(m_hWnd, OperationKind::Connect, "", [tunnelName, stagedConfig]() {
            bool installed = false;
            try {
                installed = tlp::win::InstallTunnel(tunnelName, *stagedConfig);
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
    if (!active_ || busy_) return;
    busy_ = true;
    LogEvent("disconnect_requested", "info", reason.empty() ? "User requested tunnel removal." : reason);
    ++generation_;
    UpdateButtons();
    SetState("Disconnecting...", reason);
    std::string tunnelName = active_->tunnelName;
    try {
        RunInBackground(m_hWnd, OperationKind::Disconnect, reason, [tunnelName]() {
            tlp::win::RemoveTunnel(tunnelName);
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
    const Profile* profile = active_ && active_->connected && !busy_ ? FindProfile(active_->profileId) : nullptr;
    if (profile == nullptr) return;
    try {
        tlp::win::OpenFreePbx(*profile, active_->sessionId, CurrentPreferences());
    } catch (const tlp::AppUnavailable& e) {
        std::string text = std::string(e.what()) +
                           "\n\nYes: use the Windows default browser from now on.\nNo: choose another browser in Settings.\nCancel: do nothing.";
        int answer = AfxMessageBox(Widen(text).c_str(), MB_YESNOCANCEL | MB_ICONWARNING);
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
        profile = active_ && active_->connected && !busy_ ? FindProfile(active_->profileId) : nullptr;
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
    if (profile->kind == ProfileKind::Administrator && !profile->pairing.ssh) {
        ShowError("SSH was not authorised for this workstation when it was paired.");
        return false;
    }
    if (profile->kind == ProfileKind::Administrator && profile->sshUser.empty()) {
        ShowError("No SSH user is set for this PBX. Remove and pair it again, entering the Linux account to use for SSH.");
        return false;
    }
    return true;
}

void CMainDlg::OnOpenSsh() {
    if (!SshReady()) return;
    try {
        tlp::win::OpenSsh(*FindProfile(active_->profileId), active_->sessionId, CurrentPreferences());
    } catch (const tlp::AppUnavailable& e) {
        std::string text = std::string(e.what()) + "\n\nChoose OK to select another SSH terminal in Settings.";
        if (AfxMessageBox(Widen(text).c_str(), MB_OKCANCEL | MB_ICONWARNING) != IDOK) return;
        if (!ShowAppSettings(false, e.what()) || !SshReady()) return;
        try {
            tlp::win::OpenSsh(*FindProfile(active_->profileId), active_->sessionId, CurrentPreferences());
        } catch (const std::exception& again) {
            ShowError(again.what());
        }
    } catch (const std::exception& e) {
        ShowError(e.what());
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
    if (!active_ || !active_->connected || busy_) return;
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
    std::wstring wgExecutable = wireguard_.wgExe;
    std::int64_t expiresAt = active_->expiresAt;
    std::uint64_t tickNow = GetTickCount64();
    bool collectTelemetry = lastTelemetryTickMs_ == 0 ||
                            tickNow - lastTelemetryTickMs_ >= tlp::ConnectionHealthMonitor::kTelemetryIntervalSeconds * 1000ULL;
    if (collectTelemetry) lastTelemetryTickMs_ = tickNow;
    try {
    std::thread([window, generation, tunnelName, address, peerPublicKey, wgExecutable, expiresAt, collectTelemetry]() {
        auto* result = new ProbeResult;
        result->sample.authorizationExpiresAt = expiresAt;
        result->sample.authorizationKnown = true;
        result->sample.authorizationPersistent = expiresAt == 0;
        try {
            tlp::win::TunnelState service = tlp::win::QueryTunnel(tunnelName);
            result->statusKnown = service == tlp::win::TunnelState::Running || service == tlp::win::TunnelState::Stopped ||
                                  service == tlp::win::TunnelState::Absent;
            result->serviceRunning = service == tlp::win::TunnelState::Running;
            result->sample.tunnelKnown = result->statusKnown;
            result->sample.tunnelRunning = result->serviceRunning;
            if (result->serviceRunning && (expiresAt == 0 || tlp::win::UnixNow() < expiresAt)) {
                tlp::win::TcpProbeMeasurement probe = tlp::win::MeasureTcpProbe(address, 443, 1200);
                if (!probe.known || !probe.succeeded) {
                    const std::string httpsError = probe.error;
                    tlp::win::TcpProbeMeasurement fallback = tlp::win::MeasureTcpProbe(address, 80, 1200);
                    if (fallback.known) probe = fallback;
                    if (!probe.succeeded) probe.error = "HTTPS 443: " + httpsError + "; HTTP 80: " + fallback.error;
                }
                result->sample.probeKnown = probe.known;
                result->error = probe.error;
                result->sample.probeSucceeded = probe.known && probe.succeeded;
                if (result->sample.probeSucceeded) result->sample.latencyMs = probe.latencyMs;
                if (collectTelemetry) {
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
    std::int64_t now = tlp::win::UnixNow();
    if (active_->expiresAt > 0 && now >= active_->expiresAt) {
        active_->verified = false;
        UpdateButtons();
        SetState("Authorization expired", "The pairing duration has ended. TELIPHONES is disconnecting the tunnel.");
        StartDisconnect("Temporary access expired.");
        return 0;
    }
    if (!result->statusKnown) {
        active_->verified = false;
        UpdateButtons();
        SetState("Connection status temporarily unavailable",
                 "TELIPHONES will retry automatically; this is not being treated as a tunnel failure.");
        return 0;
    }
    if (result->serviceRunning && !result->sample.probeKnown) {
        active_->verified = false;
        UpdateButtons();
        SetState("PBX probe unavailable", "The local TCP probe could not be measured; this is not counted as a failed probe.");
        return 0;
    }
    tlp::MonitorDecision decision = active_->monitor->Observe(now, result->serviceRunning, result->probeSucceeded);
    SetState(decision.summary, decision.guidance);
    bool verified = decision.state == tlp::LinkState::Connected;
    if (verified != active_->verified) {
        active_->verified = verified;
        UpdateButtons();
    }
    if (decision.disconnect && decision.state == tlp::LinkState::Expired) StartDisconnect(decision.summary + " " + decision.guidance);
    else if (decision.state == tlp::LinkState::Lost || decision.state == tlp::LinkState::NoResponse ||
             decision.state == tlp::LinkState::Stopped) {
        SetState(decision.summary,
                 decision.guidance + " The Connection Health monitor will keep checking; existing terminal windows are not closed.");
    }
    UpdateButtons();
    return 0;
}

LRESULT CMainDlg::OnOperationDone(WPARAM, LPARAM lparam) {
    std::unique_ptr<OperationResult> result(reinterpret_cast<OperationResult*>(lparam));
    busy_ = false;
    switch (result->kind) {
        case OperationKind::Cleanup:
            if (!result->error.empty()) {
                SetState("Not connected", "A TELIPHONES tunnel from a previous session could not be removed: " + result->error +
                                              " You can remove it in the WireGuard for Windows application.");
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
                break;
            }
            if (const Profile* profile = FindProfile(active_->profileId)) {
                bool viaGateway = profile->kind == ProfileKind::Support;
                std::string endpoint = viaGateway ? profile->grant.endpoint : tlp::DirectProvider().Plan(profile->pairing.endpoint).endpoint;
                active_->monitor = std::make_unique<tlp::ConnectionMonitor>(tlp::win::UnixNow(), active_->expiresAt, endpoint, viaGateway);
                active_->health = std::make_unique<tlp::ConnectionHealthMonitor>(healthPreferences_.thresholds);
            }
            active_->connected = true;
            LogEvent("tunnel_started", "info", "WireGuard tunnel service started. PBX application reachability not yet verified.");
            SetState("Tunnel started - waiting for the PBX to answer...", "");
            break;
        case OperationKind::Disconnect:
            if (!result->error.empty()) {
                LogEvent("disconnect_failed", "error", result->error);
                SetState("Disconnect failed", result->error + " The tunnel may still be installed; choose Disconnect again or remove it in WireGuard for Windows.");
                ShowError(result->error);
                break;
            }
            LogEvent("tunnel_removed", "info", "Tunnel removed: " + result->reason);
            active_.reset();
            lastTelemetryTickMs_ = 0;
            {
                tlp::HealthSnapshot disconnected;
                disconnected.state = tlp::HealthState::Disconnected;
                healthDialog_.UpdateSnapshot(disconnected);
            }
            SetState("Disconnected", result->reason);
            break;
    }
    RefreshList();
    return 0;
}

void CMainDlg::OnCancel() {
    if (busy_) {
        AfxMessageBox(L"Please wait for the current operation to finish.", MB_ICONINFORMATION);
        return;
    }
    if (probing_) {
        AfxMessageBox(L"Please wait for the connection status check to finish before closing.", MB_ICONINFORMATION);
        return;
    }
    if (active_) {
        if (AfxMessageBox(L"Disconnect from the PBX and exit TELIPHONES?", MB_ICONQUESTION | MB_YESNO) != IDYES) return;
        CWaitCursor wait;
        LogEvent("disconnect_requested", "info", "Application shutdown: removing active tunnel.");
        try {
            tlp::win::RemoveTunnel(active_->tunnelName);
        } catch (const std::exception& e) {
            LogEvent("disconnect_failed", "error", e.what());
            ShowError(std::string("The tunnel could not be removed: ") + e.what() + " Remove it in WireGuard for Windows.");
            return;
        }
        LogEvent("tunnel_removed", "info", "Tunnel removed during application shutdown.");
        active_.reset();
    }
    healthDialog_.PersistWindowState();
    KillTimer(kMonitorTimer);
    LogEvent("shutdown", "info", "Application shutdown completed.");
    CDialogEx::OnCancel();
}
