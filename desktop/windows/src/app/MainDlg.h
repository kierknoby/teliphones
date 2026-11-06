#pragma once
#include "Appearance.h"

#include <atomic>
#include <memory>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "../core/Launchers.h"
#include "../core/ConnectionHealth.h"
#include "../core/Monitor.h"
#include "../core/WireGuardSetup.h"
#include "../core/Profiles.h"
#include "../platform/WireGuard.h"
#include "ConnectionHealthDlg.h"
#include "DesktopLayout.h"

class CMainDlg : public CAppearanceDialog {
public:
    explicit CMainDlg(CWnd* parent = nullptr);

protected:
    BOOL PreTranslateMessage(MSG* message) override;
    afx_msg void OnSize(UINT type, int cx, int cy);
    afx_msg void OnGetMinMaxInfo(MINMAXINFO* info);
    afx_msg BOOL OnMouseWheel(UINT flags, short delta, CPoint point);
    afx_msg LRESULT OnDpiChanged(WPARAM dpi, LPARAM rectangle);
    afx_msg void OnPlotChanged();
    afx_msg HBRUSH OnCtlColor(CDC* dc, CWnd* window, UINT type);
    void DoDataExchange(CDataExchange* exchange) override;
    BOOL OnInitDialog() override;
    void OnCancel() override;
    void OnOK() override {}
    afx_msg void OnAddPbx();
    afx_msg void OnAddSupport();
    afx_msg void OnUpdateGrant();
    afx_msg void OnRemove();
    afx_msg void OnConnect();
    afx_msg void OnDisconnect();
    afx_msg void OnOpenGui();
    afx_msg void OnOpenSsh();
    afx_msg void OnLockWorkstation();
    afx_msg void OnRequestSources();
    afx_msg void OnSettings();
    afx_msg void OnConnectionHealth();
    afx_msg void OnSessionLog();
    afx_msg void OnInlineHistoryChanged();
    afx_msg void OnDrawItem(int controlId, LPDRAWITEMSTRUCT drawItem);
    afx_msg void OnSelectionChanged(NMHDR* header, LRESULT* result);
    afx_msg void OnTimer(UINT_PTR id);
    afx_msg LRESULT OnOperationDone(WPARAM, LPARAM result);
    afx_msg LRESULT OnProbeDone(WPARAM generation, LPARAM result);
    afx_msg LRESULT OnFirstRun(WPARAM, LPARAM);
    afx_msg LRESULT OnStartupNotices(WPARAM, LPARAM);
    DECLARE_MESSAGE_MAP()

private:
    CWnd* GetDlgItem(int id) const { return layout_.Find(id); }
    void SetDlgItemText(int id, LPCWSTR text) { if (CWnd* control = GetDlgItem(id)) control->SetWindowText(text); }
    struct Active {
        std::string profileId;
        std::string sessionId;
        std::string tunnelName;
        std::string pbxAddress;
        std::string peerPublicKey;
        std::string diagnosticId;
        std::string attemptId;
        std::string lastTelemetryReason;
        std::string lastMeasurementError;
        std::string lastAdmissionFailure;  // classification logged most recently; empty when admitted
        std::optional<bool> lastHandshakeStale;
        tlp::HealthState lastHealthState = tlp::HealthState::Unknown;
        std::optional<bool> lastProbeSucceeded;
        std::uint64_t lastSummaryTickMs = 0;
        std::int64_t expiresAt = 0;
        std::unique_ptr<tlp::ConnectionMonitor> monitor;
        std::unique_ptr<tlp::ConnectionHealthMonitor> health;
        bool connected = false;
        // Set only after the monitor has confirmed the PBX answers through the tunnel.
        bool verified = false;
    };

    int SelectedIndex() const;
    tlp::Profile* Selected();
    tlp::Profile* FindProfile(const std::string& id);
    std::string SelectedSession();
    void RefreshList();
    void RefreshSessions();
    void UpdateButtons();
    void SetState(const std::string& state, const std::string& guidance);
    void RefreshConnectionText();
    void Persist();
    void StartDisconnect(const std::string& reason);
    void RemoveStaleTunnels();
    bool RequireWireGuard();
    void RefreshWireGuard();
    tlp::Preferences CurrentPreferences();
    bool ShowAppSettings(bool welcome, const std::string& notice);
    bool SshReady();
    void RefreshHealth();
    void LogEvent(const std::string& event, const std::string& severity, const std::string& detail,
                  const std::string& diagnosticId = "", const std::string& attemptId = "");

    CListCtrl list_;
    CDesktopLayout layout_;
    int graphMode_ = 0;
    std::map<std::string, tlp::HealthSnapshot> history_;
    std::string connectionState_ = "Not connected";
    std::string connectionGuidance_;
    CComboBox sessions_;
    std::vector<std::string> sessionIds_;
    std::vector<tlp::Profile> profiles_;
    tlp::win::WireGuardInstallation wireguard_;
    CConnectionHealthDlg healthDialog_;
    tlp::HealthPreferences healthPreferences_;
    tlp::HealthSnapshot healthSnapshot_;
    bool logFailureShown_ = false;
    std::unique_ptr<Active> active_;
    std::optional<tlp::Preferences> storedPreferences_;
    tlp::SetupResult installation_;
    bool busy_ = false;
    bool probing_ = false;
    bool migrationReconnectPending_ = false;
    bool activePolicyLocked_ = false;
    bool unlockRequestPending_ = false;
    bool sourcesRequestPending_ = false;
    UINT_PTR generation_ = 0;
    std::uint64_t lastTelemetryTickMs_ = 0;
};
