#pragma once

#include "Appearance.h"

#include <memory>

#include "../platform/Ssh.h"

namespace tlp { class TerminalEmulator; }
class CTerminalView;

class CSshTerminalDlg final : public CAppearanceDialog {
public:
    CSshTerminalDlg(const tlp::Profile& profile, std::shared_ptr<tlp::win::ManagedSshConsole> console,
                    CWnd* parent = nullptr);
    ~CSshTerminalDlg() override;

protected:
    BOOL OnInitDialog() override;
    BOOL PreTranslateMessage(MSG* message) override;
    void OnCancel() override;
    afx_msg void OnSize(UINT type, int cx, int cy);
    afx_msg void OnTimer(UINT_PTR timerId);
    afx_msg void OnCopyAll();
    afx_msg void OnClearAll();
    afx_msg void OnPaste();
    afx_msg void OnReconnect();
    afx_msg void OnDisconnect();
    DECLARE_MESSAGE_MAP()

private:
    BOOL InitializeConsole();
    void StopConsole();
    void ResizeTerminal();

    tlp::Profile profile_;
    std::shared_ptr<tlp::win::ManagedSshConsole> console_;
    std::unique_ptr<tlp::TerminalEmulator> terminal_;
    std::unique_ptr<CTerminalView> terminalView_;
    bool authenticated_ = false;
};
