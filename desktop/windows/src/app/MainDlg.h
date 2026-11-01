#pragma once
#include "framework.h"

#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include "../core/Monitor.h"
#include "../core/Profiles.h"
#include "../platform/WireGuard.h"

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
    afx_msg void OnSelectionChanged(NMHDR* header, LRESULT* result);
    afx_msg void OnTimer(UINT_PTR id);
    afx_msg LRESULT OnOperationDone(WPARAM, LPARAM result);
    afx_msg LRESULT OnProbeDone(WPARAM generation, LPARAM result);
    DECLARE_MESSAGE_MAP()

private:
    struct Active {
        std::string profileId;
        std::string sessionId;
        std::string tunnelName;
        std::string pbxAddress;
        std::int64_t expiresAt = 0;
        std::unique_ptr<tlp::ConnectionMonitor> monitor;
        bool connected = false;
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

    CListCtrl list_;
    CComboBox sessions_;
    std::vector<std::string> sessionIds_;
    std::vector<tlp::Profile> profiles_;
    tlp::win::WireGuardInstallation wireguard_;
    std::unique_ptr<Active> active_;
    bool busy_ = false;
    bool probing_ = false;
    UINT_PTR generation_ = 0;
};
