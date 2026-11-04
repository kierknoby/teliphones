#pragma once

#include "Appearance.h"
#include "../core/Profiles.h"

class CConnectPasswordDlg : public CAppearanceDialog {
public:
    CConnectPasswordDlg(bool setting, CWnd* parent);
    ~CConnectPasswordDlg() override;
    std::string password;
protected:
    BOOL OnInitDialog() override;
    void OnOK() override;
    void OnCancel() override;
private:
    void ClearFields();
    bool setting_;
};

// Changes take effect immediately, independently of application preferences.
class CConnectPasswordChoiceDlg : public CAppearanceDialog {
public:
    explicit CConnectPasswordChoiceDlg(bool protectionAvailable, CWnd* parent = nullptr);
    int choice = IDCANCEL;
protected:
    BOOL OnInitDialog() override;
    afx_msg void OnSetPassword();
    afx_msg void OnSkipThisTime();
    afx_msg void OnSkipPermanently();
    DECLARE_MESSAGE_MAP()
private:
    bool protectionAvailable_;
};

bool ManageConnectPassword(const tlp::Profile& profile, CWnd* parent);
