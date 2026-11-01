#pragma once
#include "framework.h"

#include <string>

#include "../core/Profiles.h"
#include "../platform/WireGuard.h"

// Creates a Remote Support profile (engineer key) or imports an updated gateway grant for an existing one.
class CSupportDlg : public CDialogEx {
public:
    // existing == nullptr creates a profile; otherwise the dialog imports a new grant for it.
    CSupportDlg(const tlp::win::WireGuardInstallation& wireguard, const tlp::Profile* existing, CWnd* parent = nullptr);
    tlp::Profile profile;  // valid after IDOK

protected:
    BOOL OnInitDialog() override;
    void OnOK() override;
    void OnCancel() override;
    afx_msg void OnGenerate();
    afx_msg void OnCopy();
    afx_msg void OnBrowse();
    DECLARE_MESSAGE_MAP()

private:
    tlp::win::WireGuardInstallation wireguard_;
    bool updating_;
    bool keyStored_ = false;
};
