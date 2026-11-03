#pragma once
#include "Appearance.h"

#include <string>

class CSessionLogDlg : public CAppearanceDialog {
public:
    // The caller supplies one human-readable, already-redacted UTF-8 snapshot.
    explicit CSessionLogDlg(std::string contents, CWnd* parent = nullptr);

protected:
    BOOL OnInitDialog() override;
    afx_msg void OnExport();
    afx_msg void OnSize(UINT type, int cx, int cy);
    afx_msg void OnGetMinMaxInfo(MINMAXINFO* info);
    DECLARE_MESSAGE_MAP()

private:
    void Layout(int width, int height);
    const std::string contents_;
};
