#include "AppSettingsDlg.h"

#include <algorithm>
#include <exception>
#include <iterator>

#include "../platform/Applications.h"
#include "../platform/Win.h"
#include "resource.h"

using tlp::AppKind;
using tlp::win::Widen;

namespace {

void ShowError(const std::string& text) { AfxMessageBox(Widen(text).c_str(), MB_ICONERROR); }

bool Contains(const std::vector<std::string>& ids, const std::string& id) { return std::find(ids.begin(), ids.end(), id) != ids.end(); }

}  // namespace

BEGIN_MESSAGE_MAP(CAppSettingsDlg, CDialogEx)
    ON_BN_CLICKED(IDC_APPS_SKIP, &CAppSettingsDlg::OnSkip)
    ON_BN_CLICKED(IDC_APPS_LOCATE_BROWSER, &CAppSettingsDlg::OnLocateBrowser)
    ON_BN_CLICKED(IDC_APPS_LOCATE_TERMINAL, &CAppSettingsDlg::OnLocateTerminal)
    ON_CBN_SELCHANGE(IDC_APPS_BROWSER, &CAppSettingsDlg::OnSelectionChanged)
    ON_CBN_SELCHANGE(IDC_APPS_TERMINAL, &CAppSettingsDlg::OnSelectionChanged)
END_MESSAGE_MAP()

CAppSettingsDlg::CAppSettingsDlg(Mode mode, const std::optional<tlp::Preferences>& stored, CWnd* parent)
    : CDialogEx(IDD_APP_SETTINGS, parent), mode_(mode), stored_(stored), working_(stored.value_or(tlp::Preferences())) {}

void CAppSettingsDlg::DoDataExchange(CDataExchange* exchange) {
    CDialogEx::DoDataExchange(exchange);
    DDX_Control(exchange, IDC_APPS_BROWSER, browser_);
    DDX_Control(exchange, IDC_APPS_TERMINAL, terminal_);
}

BOOL CAppSettingsDlg::OnInitDialog() {
    CDialogEx::OnInitDialog();
    if (mode_ == Mode::Welcome) {
        SetWindowText(L"Welcome to TELIPHONES");
        SetDlgItemText(IDC_APPS_HEADING, L"Welcome to TELIPHONES");
        SetDlgItemText(IDC_APPS_INTRO, L"Choose the applications TELIPHONES uses to open FreePBX and SSH sessions through your secure connection. "
                                       L"Only applications found on this computer are listed. You can change these at any time in Settings.");
    } else {
        SetWindowText(L"TELIPHONES Settings");
        SetDlgItemText(IDC_APPS_HEADING, L"Applications");
        SetDlgItemText(IDC_APPS_INTRO, L"These preferences apply to every saved PBX connection. They are stored only on this computer, for your "
                                       L"Windows account, and are never sent to a PBX.");
        GetDlgItem(IDC_APPS_SKIP)->ShowWindow(SW_HIDE);
    }
    try {
        Detect();
    } catch (const std::exception& e) {
        ShowError(std::string("TELIPHONES could not check which applications are installed: ") + e.what());
    }
    tlp::Preferences effective = tlp::EffectivePreferences(stored_, browsers_, terminals_);
    Fill(AppKind::Browser, effective.browser);
    Fill(AppKind::Terminal, effective.terminal);
    UpdateStatus();
    return TRUE;
}

void CAppSettingsDlg::Detect() {
    browsers_ = tlp::win::DetectApps(AppKind::Browser, working_);
    terminals_ = tlp::win::DetectApps(AppKind::Terminal, working_);
}

void CAppSettingsDlg::Fill(AppKind kind, const std::string& selected) {
    CComboBox& combo = kind == AppKind::Browser ? browser_ : terminal_;
    std::vector<std::string>& ids = kind == AppKind::Browser ? browserIds_ : terminalIds_;
    ids = tlp::AvailableApps(kind, kind == AppKind::Browser ? browsers_ : terminals_);
    bool missing = !selected.empty() && !Contains(ids, selected);
    combo.ResetContent();
    for (const std::string& id : ids) combo.AddString(Widen(tlp::AppName(kind, id)).c_str());
    if (missing) {
        // A stored choice that is no longer installed stays visible, clearly marked, until the user replaces it.
        ids.push_back(selected);
        combo.AddString(Widen(tlp::AppName(kind, selected) + " (not found)").c_str());
    }
    for (std::size_t i = 0; i < ids.size(); ++i) {
        if (ids[i] == selected) combo.SetCurSel(static_cast<int>(i));
    }
    if (combo.GetCurSel() < 0 && !ids.empty()) combo.SetCurSel(0);
    combo.EnableWindow(!ids.empty());
}

std::string CAppSettingsDlg::Selection(AppKind kind) const {
    const CComboBox& combo = kind == AppKind::Browser ? browser_ : terminal_;
    const std::vector<std::string>& ids = kind == AppKind::Browser ? browserIds_ : terminalIds_;
    int index = combo.GetCurSel();
    return index >= 0 && static_cast<std::size_t>(index) < ids.size() ? ids[static_cast<std::size_t>(index)] : std::string();
}

void CAppSettingsDlg::UpdateStatus() {
    std::string status = notice;
    auto add = [&status](const std::string& line) { status += (status.empty() ? "" : "\r\n") + line; };
    std::string browser = Selection(AppKind::Browser);
    std::string terminal = Selection(AppKind::Terminal);
    if (!Contains(tlp::AvailableApps(AppKind::Browser, browsers_), browser)) {
        add(tlp::AppName(AppKind::Browser, browser) + " was not found. Choose another browser, or use Locate... if it was moved.");
    }
    if (terminal.empty()) {
        add("No supported SSH terminal was found. Use Locate... to choose PuTTY, or install Windows PowerShell.");
    } else if (!Contains(tlp::AvailableApps(AppKind::Terminal, terminals_), terminal)) {
        add(tlp::AppName(AppKind::Terminal, terminal) + " was not found. Choose another SSH terminal, or use Locate... if it was moved.");
    } else if (const tlp::AppInfo* app = tlp::FindApp(AppKind::Terminal, terminal); app != nullptr && app->needsOpenSsh && tlp::win::OpenSshClient().empty()) {
        add(app->name + " uses the Windows OpenSSH Client, which is not installed. Add it in Windows Settings > System > Optional features, or choose PuTTY.");
    }
    SetDlgItemText(IDC_APPS_STATUS, Widen(status).c_str());
}

void CAppSettingsDlg::OnSelectionChanged() { UpdateStatus(); }

void CAppSettingsDlg::OnLocateBrowser() { Locate(AppKind::Browser); }

void CAppSettingsDlg::OnLocateTerminal() { Locate(AppKind::Terminal); }

void CAppSettingsDlg::Locate(AppKind kind) {
    wchar_t path[MAX_PATH]{};
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = m_hWnd;
    dialog.lpstrFilter = L"Programs (*.exe)\0*.exe\0";
    dialog.lpstrFile = path;
    dialog.nMaxFile = static_cast<DWORD>(std::size(path));
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_HIDEREADONLY | OFN_DONTADDTORECENT;
    dialog.lpstrTitle = kind == AppKind::Browser ? L"Locate a supported web browser" : L"Locate a supported SSH terminal";
    if (!GetOpenFileNameW(&dialog)) return;
    std::string chosen = tlp::win::Narrow(path);
    std::string supported;
    for (const tlp::AppInfo& app : tlp::KnownApps(kind)) {
        if (app.executables.empty()) continue;
        if (tlp::IsExpectedExecutable(app, chosen)) {
            working_.locations[app.id] = chosen;
            try {
                Detect();
            } catch (const std::exception& e) {
                ShowError(e.what());
            }
            Fill(kind, app.id);
            UpdateStatus();
            return;
        }
        supported += "\n  " + app.name + " (" + app.executables.front() + ")";
    }
    ShowError("TELIPHONES cannot use this program. Choose one of the supported applications on a local drive:" + supported);
}

bool CAppSettingsDlg::Store(const tlp::Preferences& candidate) {
    try {
        tlp::win::SavePreferences(candidate);
    } catch (const std::exception& e) {
        ShowError(std::string("Your application preferences could not be saved: ") + e.what());
        return false;
    }
    preferences = candidate;
    return true;
}

void CAppSettingsDlg::OnOK() {
    try {
        auto result = tlp::PreferencesAfterFirstRun(tlp::FirstRunOutcome::Saved, Selection(AppKind::Browser), Selection(AppKind::Terminal), browsers_,
                                                    terminals_, working_);
        if (!result || !Store(*result)) return;
    } catch (const std::exception& e) {
        ShowError(e.what());
        return;
    }
    outcome = tlp::FirstRunOutcome::Saved;
    CDialogEx::OnOK();
}

void CAppSettingsDlg::OnSkip() {
    auto result = tlp::PreferencesAfterFirstRun(tlp::FirstRunOutcome::Skipped, "", "", browsers_, terminals_, working_);
    if (!result || !Store(*result)) return;
    outcome = tlp::FirstRunOutcome::Skipped;
    EndDialog(IDOK);
}
