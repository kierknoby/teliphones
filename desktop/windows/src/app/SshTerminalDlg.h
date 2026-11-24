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
    afx_msg LRESULT OnTerminalInput(WPARAM, LPARAM);
    afx_msg LRESULT OnTerminalScroll(WPARAM, LPARAM);
    afx_msg LRESULT OnPasteError(WPARAM, LPARAM);
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
    void UpdatePasteButton();
    bool ShellPromptVisible(int& promptRow, int& cursorColumn) const;
    void ScheduleAutomaticReconnect(const std::string& reason);
    void ShowButtonFeedback(int controlId, const wchar_t* temporary, const wchar_t* normal);

    tlp::Profile profile_;
    std::shared_ptr<tlp::win::ManagedSshConsole> console_;
    std::unique_ptr<tlp::TerminalEmulator> terminal_;
    std::unique_ptr<CTerminalView> terminalView_;
    bool authenticated_ = false;
    bool inactivityTimedOut_ = false;
    bool cursorBlinkVisible_ = true;
    UINT_PTR feedbackTimer_ = 0;
    UINT_PTR reconnectTimer_ = 0;
    int automaticReconnectAttempts_ = 0;
    ULONGLONG lastInputTick_ = 0;
    CPoint pastePosition_{};
    bool pastePositionValid_ = false;
};
