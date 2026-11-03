#include "SessionLogDlg.h"

#include <afxdlgs.h>
#include <algorithm>
#include <iterator>
#include <utility>

#include "../platform/Win.h"
#include "resource.h"

BEGIN_MESSAGE_MAP(CSessionLogDlg, CAppearanceDialog)
    ON_BN_CLICKED(IDC_SESSION_LOG_EXPORT, &CSessionLogDlg::OnExport)
    ON_WM_SIZE()
    ON_WM_GETMINMAXINFO()
END_MESSAGE_MAP()

CSessionLogDlg::CSessionLogDlg(std::string contents, CWnd* parent)
    : CAppearanceDialog(IDD_SESSION_LOG, parent), contents_(std::move(contents)) {}

BOOL CSessionLogDlg::OnInitDialog() {
    CAppearanceDialog::OnInitDialog();
    CEdit* text = static_cast<CEdit*>(GetDlgItem(IDC_SESSION_LOG_TEXT));
    text->SetLimitText(0x7FFFFFFE);
    std::wstring display = tlp::win::Widen(contents_);
    std::wstring windowsLines;
    windowsLines.reserve(display.size());
    for (std::size_t i = 0; i < display.size(); ++i) {
        if (display[i] == L'\n' && (i == 0 || display[i - 1] != L'\r')) windowsLines += L'\r';
        windowsLines += display[i];
    }
    text->SetWindowText(windowsLines.c_str());
    CRect client;
    GetClientRect(&client);
    Layout(client.Width(), client.Height());
    return TRUE;
}

void CSessionLogDlg::OnExport() {
    CFileDialog save(FALSE, L"txt", L"TELIPHONES-session-log.txt",
        OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
        L"Text files (*.txt)|*.txt|All files (*.*)|*.*||", this);
    if (save.DoModal() != IDOK) return;
    try {
        CFile output(save.GetPathName(), CFile::modeCreate | CFile::modeWrite | CFile::shareExclusive);
        std::size_t offset = 0;
        while (offset < contents_.size()) {
            const UINT count = static_cast<UINT>(std::min<std::size_t>(contents_.size() - offset, 1024 * 1024));
            output.Write(contents_.data() + offset, count);
            offset += count;
        }
        output.Flush();
        output.Close();
        tlp::ui::ShowMessage(L"The displayed session log snapshot was exported as UTF-8.", MB_ICONINFORMATION);
    } catch (CFileException* error) {
        wchar_t details[512]{};
        error->GetErrorMessage(details, static_cast<UINT>(std::size(details)));
        error->Delete();
        CString message(L"The session log could not be exported. A partial file may remain.\r\n");
        message += details;
        tlp::ui::ShowMessage(message, MB_ICONERROR);
    }
}

void CSessionLogDlg::OnSize(UINT type, int cx, int cy) {
    CDialogEx::OnSize(type, cx, cy);
    if (type != SIZE_MINIMIZED && GetDlgItem(IDC_SESSION_LOG_TEXT)) Layout(cx, cy);
}

void CSessionLogDlg::OnGetMinMaxInfo(MINMAXINFO* info) {
    CDialogEx::OnGetMinMaxInfo(info);
    if (!GetSafeHwnd()) return;
    CRect minimum(0, 0, 360, 220);
    MapDialogRect(&minimum);
    AdjustWindowRectEx(&minimum, static_cast<DWORD>(GetStyle()), FALSE, static_cast<DWORD>(GetExStyle()));
    info->ptMinTrackSize.x = minimum.Width();
    info->ptMinTrackSize.y = minimum.Height();
}

void CSessionLogDlg::Layout(int width, int height) {
    CRect spacing(8, 26, 83, 46);
    MapDialogRect(&spacing);
    const int margin = static_cast<int>(spacing.left);
    const int buttonHeight = spacing.Height();
    const int buttonWidth = spacing.Width();
    const int buttonsTop = height - margin - buttonHeight;
    GetDlgItem(IDC_SESSION_LOG_TEXT)->SetWindowPos(nullptr, margin, spacing.top,
        std::max<int>(100, width - margin * 2), std::max<int>(60, buttonsTop - margin - static_cast<int>(spacing.top)), SWP_NOZORDER);
    GetDlgItem(IDOK)->SetWindowPos(nullptr, width - margin - buttonWidth, buttonsTop,
        buttonWidth, buttonHeight, SWP_NOZORDER);
    GetDlgItem(IDC_SESSION_LOG_EXPORT)->SetWindowPos(nullptr, width - margin * 2 - buttonWidth * 2, buttonsTop,
        buttonWidth, buttonHeight, SWP_NOZORDER);
}
