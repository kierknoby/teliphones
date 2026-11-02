#pragma once
#include "framework.h"

#include <atomic>
#include <memory>
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

class CMainDlg : public CDialogEx {
public:
    explicit CMainDlg(CWnd* parent = nullptr);

protected:
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
    afx_msg void OnSettings();
    afx_msg void OnConnectionHealth();
    afx_msg void OnSelectionChanged(NMHDR* header, LRESULT* result);
    afx_msg void OnTimer(UINT_PTR id);
    afx_msg LRESULT OnOperationDone(WPARAM, LPARAM result);
    afx_msg LRESULT OnProbeDone(WPARAM generation, LPARAM result);
    afx_msg LRESULT OnFirstRun(WPARAM, LPARAM);
    DECLARE_MESSAGE_MAP()

private:
    struct Active {
        std::string profileId;
        std::string sessionId;
        std::string tunnelName;
        std::string pbxAddress;
        std::string peerPublicKey;
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
    void Persist();
    void StartDisconnect(const std::string& reason);
    void RemoveStaleTunnels();
    bool RequireWireGuard();
    void RefreshWireGuard();
    tlp::Preferences CurrentPreferences();
    bool ShowAppSettings(bool welcome, const std::string& notice);
    bool SshReady();

    CListCtrl list_;
    CComboBox sessions_;
    std::vector<std::string> sessionIds_;
    std::vector<tlp::Profile> profiles_;
    tlp::win::WireGuardInstallation wireguard_;
    CConnectionHealthDlg healthDialog_;
    tlp::HealthPreferences healthPreferences_;
    std::unique_ptr<Active> active_;
    std::optional<tlp::Preferences> storedPreferences_;
    tlp::SetupResult installation_;
    bool busy_ = false;
    bool probing_ = false;
    UINT_PTR generation_ = 0;
    std::uint64_t lastTelemetryTickMs_ = 0;
};
