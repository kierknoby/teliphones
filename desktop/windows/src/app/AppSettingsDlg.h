#pragma once
#include "framework.h"

#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "../core/Launchers.h"
#include "../core/WireGuardSetup.h"
#include "../platform/WireGuard.h"

// One dialog, one storage mechanism: shown as "Welcome to TELIPHONES" on first run and as Settings afterwards.
// Preferences are saved to the current Windows user's local application data before the dialog closes.
class CAppSettingsDlg : public CDialogEx {
public:
    enum class Mode { Welcome, Settings };
    CAppSettingsDlg(Mode mode, const std::optional<tlp::Preferences>& stored, CWnd* parent = nullptr);
    ~CAppSettingsDlg() override;
    enum class StartAction { None, AddPbx, Support };
    StartAction startAction = StartAction::None;
    tlp::SetupResult installation;

    // Valid when outcome is Saved or Skipped. Cancelled stores nothing.
    tlp::Preferences preferences;
    tlp::FirstRunOutcome outcome = tlp::FirstRunOutcome::Cancelled;
    // Optional explanation shown when Settings is opened because a selected application is missing.
    std::string notice;

protected:
    void DoDataExchange(CDataExchange* exchange) override;
    BOOL OnInitDialog() override;
    void OnOK() override;
    void OnCancel() override;
    afx_msg void OnSkip();
    afx_msg void OnLocateBrowser();
    afx_msg void OnLocateTerminal();
    afx_msg void OnSelectionChanged();
    afx_msg void OnInstallWireGuard();
    afx_msg void OnCheckWireGuard();
    afx_msg void OnNotNow();
    afx_msg void OnGetStartedPbx();
    afx_msg void OnGetStartedSupport();
    afx_msg LRESULT OnSetupProgress(WPARAM, LPARAM);
    afx_msg LRESULT OnSetupDone(WPARAM, LPARAM);
    DECLARE_MESSAGE_MAP()

private:
    void Detect();
    void Fill(tlp::AppKind kind, const std::string& selected);
    std::string Selection(tlp::AppKind kind) const;
    void Locate(tlp::AppKind kind);
    void UpdateStatus();
    bool Store(const tlp::Preferences& candidate);
    void RefreshConnectivity();
    void ShowStep();
    void GetStarted(StartAction action);

    Mode mode_;
    std::optional<tlp::Preferences> stored_;
    tlp::Preferences working_;
    tlp::DetectedApps browsers_;
    tlp::DetectedApps terminals_;
    std::vector<std::string> browserIds_;
    std::vector<std::string> terminalIds_;
    CComboBox browser_;
    CComboBox terminal_;
    int step_ = 1;
    bool installing_ = false;
    tlp::win::WireGuardInstallation wireguard_;
    std::thread installer_;
};
