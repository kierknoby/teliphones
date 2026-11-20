#pragma once
#include "Appearance.h"

#include <string>

#include "../core/Profiles.h"
#include "../platform/WireGuard.h"

#include <vector>

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
    afx_msg void OnRequestChanged();
    afx_msg void OnResponseChanged();
    afx_msg void OnTimer(UINT_PTR timerId);
    afx_msg void OnSize(UINT nType, int cx, int cy);
    afx_msg void OnVScroll(UINT code, UINT position, CScrollBar* scrollbar);
    afx_msg void OnSetFocus(CWnd* oldWindow);
    BOOL OnMouseWheel(UINT flags, short delta, CPoint point) override;
    DECLARE_MESSAGE_MAP()

private:
    bool DiscardKey();
    bool RequestCurrent() const;
    bool InvalidateRequest();
    tlp::PairResponse ValidatedResponse();
    tlp::win::WireGuardInstallation wireguard_;
    std::string publicKey_;
    std::string sshPublicKey_;
    std::string nonce_;
    std::string request_;
    bool keyStored_ = false;
    bool sshKeyRequested_ = false;
    bool initialized_ = false;
    struct ContentControl {
        HWND window = nullptr;
        CRect original;
    };
    std::vector<ContentControl> contentControls_;
    std::vector<ContentControl> footerControls_;
    int initialClientWidth_ = 0;
    int initialClientHeight_ = 0;
    int scrollOffset_ = 0;
    int contentExtent_ = 0;
    int footerTop_ = 0;
    int wheelRemainder_ = 0;
    bool arranging_ = false;
    void ArrangePairDialog();
    void ScrollPairContent(int offset);
};
