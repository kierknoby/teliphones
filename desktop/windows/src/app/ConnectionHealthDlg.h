#pragma once
#include "framework.h"

#include <functional>

#include "../core/ConnectionHealth.h"

class CConnectionHealthDlg : public CDialogEx {
public:
    explicit CConnectionHealthDlg(CWnd* parent = nullptr);
    bool CreateMonitor();
    void ShowMonitor();
    void PersistWindowState();
    void UpdateSnapshot(const tlp::HealthSnapshot& snapshot);
    void SetPreferences(const tlp::HealthPreferences& preferences);
    std::function<void(const tlp::HealthPreferences&)> preferencesChanged;

protected:
    void DoDataExchange(CDataExchange* exchange) override;
    BOOL OnInitDialog() override;
    void OnOK() override;
    void OnCancel() override;
    afx_msg void OnClose();
    afx_msg void OnSize(UINT type, int cx, int cy);
    afx_msg void OnHistoryChanged();
    afx_msg void OnTopmostChanged();
    afx_msg void OnThresholds();
    afx_msg void OnDrawItem(int controlId, LPDRAWITEMSTRUCT drawItem);
    afx_msg HBRUSH OnCtlColor(CDC* dc, CWnd* window, UINT controlColor);
    DECLARE_MESSAGE_MAP()

private:
    void SaveWindowPosition();
    void SavePreferences();
    void ApplyTopmost();
    void RefreshText();
    void LayoutGraph(int width, int height);

    tlp::HealthPreferences preferences_;
    tlp::HealthSnapshot snapshot_;
    CComboBox history_;
    CButton topmost_;
};
