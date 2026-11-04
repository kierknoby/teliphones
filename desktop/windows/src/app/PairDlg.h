#pragma once
#include "Appearance.h"

#include <string>

#include "../core/Profiles.h"
#include "../platform/WireGuard.h"

// Pairs this workstation with a PBX. The PBX administrator must approve the request in
// FreePBX > Connectivity > TELIPHONES; the response is pasted back here.
class CPairDlg : public CAppearanceDialog {
public:
    explicit CPairDlg(const tlp::win::WireGuardInstallation& wireguard, CWnd* parent = nullptr);
    tlp::Profile profile;  // valid after IDOK

protected:
    BOOL OnInitDialog() override;
    void OnOK() override;
    void OnCancel() override;
    afx_msg void OnGenerate();
    afx_msg void OnCopy();
    afx_msg void OnTimer(UINT_PTR timerId);
    DECLARE_MESSAGE_MAP()

private:
    bool DiscardKey();
    tlp::win::WireGuardInstallation wireguard_;
    std::string publicKey_;
    std::string sshPublicKey_;
    std::string nonce_;
    std::string request_;
    bool keyStored_ = false;
    bool sshKeyRequested_ = false;
};
