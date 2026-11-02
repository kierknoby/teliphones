#pragma once
#include "framework.h"

#include <optional>
#include <string>
#include <vector>

#include "../core/Launchers.h"

// One dialog, one storage mechanism: shown as "Welcome to TELIPHONES" on first run and as Settings afterwards.
// Preferences are saved to the current Windows user's local application data before the dialog closes.
class CAppSettingsDlg : public CDialogEx {
public:
    enum class Mode { Welcome, Settings };
    CAppSettingsDlg(Mode mode, const std::optional<tlp::Preferences>& stored, CWnd* parent = nullptr);

    // Valid when outcome is Saved or Skipped. Cancelled stores nothing.
    tlp::Preferences preferences;
    tlp::FirstRunOutcome outcome = tlp::FirstRunOutcome::Cancelled;
    // Optional explanation shown when Settings is opened because a selected application is missing.
    std::string notice;

protected:
    void DoDataExchange(CDataExchange* exchange) override;
    BOOL OnInitDialog() override;
    void OnOK() override;
    afx_msg void OnSkip();
    afx_msg void OnLocateBrowser();
    afx_msg void OnLocateTerminal();
    afx_msg void OnSelectionChanged();
    DECLARE_MESSAGE_MAP()

private:
    void Detect();
    void Fill(tlp::AppKind kind, const std::string& selected);
    std::string Selection(tlp::AppKind kind) const;
    void Locate(tlp::AppKind kind);
    void UpdateStatus();
    bool Store(const tlp::Preferences& candidate);

    Mode mode_;
    std::optional<tlp::Preferences> stored_;
    tlp::Preferences working_;
    tlp::DetectedApps browsers_;
    tlp::DetectedApps terminals_;
    std::vector<std::string> browserIds_;
    std::vector<std::string> terminalIds_;
    CComboBox browser_;
    CComboBox terminal_;
};
