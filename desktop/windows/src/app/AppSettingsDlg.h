#pragma once
#include "Appearance.h"

#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "../core/Launchers.h"
#include "../core/Profiles.h"
#include "../core/WireGuardSetup.h"
#include "../platform/WireGuard.h"

// One dialog, one storage mechanism: shown as "Welcome to TELIPHONES" on first run and as Settings afterwards.
// Preferences are saved to the current Windows user's local application data before the dialog closes.
class CAppSettingsDlg : public CAppearanceDialog {
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
    std::optional<tlp::Profile> connectProfile;
    bool connectionActive = false;
    bool lockNow = false;

protected:
    void DoDataExchange(CDataExchange* exchange) override;
    BOOL OnInitDialog() override;
    void OnOK() override;
    void OnCancel() override;
    afx_msg void OnSkip();
    afx_msg void OnAbout();
    afx_msg void OnConnectPassword();
    afx_msg void OnLockNow();
    afx_msg void OnLocateBrowser();
    afx_msg void OnLocateTerminal();
    afx_msg void OnSelectionChanged();
    afx_msg void OnAppearanceChanged();
    afx_msg void OnInstallWireGuard();
    afx_msg void OnCheckWireGuard();
    afx_msg void OnNotNow();
    afx_msg void OnGetStartedPbx();
    afx_msg void OnGetStartedSupport();
    afx_msg LRESULT OnSetupProgress(WPARAM, LPARAM);
    afx_msg LRESULT OnSetupDone(WPARAM, LPARAM);
    afx_msg void OnSize(UINT type, int width, int height);
    afx_msg void OnVScroll(UINT code, UINT position, CScrollBar* bar);
    afx_msg BOOL OnMouseWheel(UINT flags, short delta, CPoint point);
    afx_msg LRESULT OnDpiChanged(WPARAM dpi, LPARAM rectangle);
    afx_msg LRESULT OnDpiLayout(WPARAM, LPARAM);
    afx_msg void OnGetMinMaxInfo(MINMAXINFO* info);
    BOOL PreTranslateMessage(MSG* message) override;
    afx_msg LRESULT OnRevealFocusedControl(WPARAM, LPARAM);
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
    void Arrange();
    void ScrollTo(int offset);

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
    struct LayoutControl { HWND window = nullptr; CRect original; bool footer = false; bool rightAnchored = false; };
    std::vector<LayoutControl> layoutControls_;
    int initialClientWidth_ = 0;
    int initialClientHeight_ = 0;
    int initialDpi_ = 96;
    int layoutDpi_ = 96;
    int contentExtent_ = 0;
    int scrollOffset_ = 0;
    int wheelRemainder_ = 0;
    bool layoutReady_ = false;
    bool arranging_ = false;
    static constexpr UINT kRevealFocusMessage = WM_APP + 0x322;
};
