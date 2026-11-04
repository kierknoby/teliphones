#include "AppSettingsDlg.h"
#include "ConnectPasswordDlg.h"

#include <commdlg.h>

#include <algorithm>
#include <exception>
#include <iterator>
#include <memory>

#include "../platform/Applications.h"
#include "../platform/Win.h"
#include "../platform/WireGuardInstaller.h"
#include "resource.h"
#include "Version.h"

using tlp::AppKind;
using tlp::win::Widen;

namespace {

void ShowError(const std::string& text) { tlp::ui::ShowMessage(Widen(text).c_str(), MB_ICONERROR); }

bool Contains(const std::vector<std::string>& ids, const std::string& id) { return std::find(ids.begin(), ids.end(), id) != ids.end(); }

}  // namespace

BEGIN_MESSAGE_MAP(CAppSettingsDlg, CAppearanceDialog)
    ON_BN_CLICKED(IDC_APPS_ABOUT, &CAppSettingsDlg::OnAbout)
    ON_BN_CLICKED(IDC_CONNECT_PASSWORD, &CAppSettingsDlg::OnConnectPassword)
    ON_BN_CLICKED(IDC_PASSWORD_LOCK_NOW, &CAppSettingsDlg::OnLockNow)
    ON_BN_CLICKED(IDC_APPS_SKIP, &CAppSettingsDlg::OnSkip)
    ON_BN_CLICKED(IDC_APPS_LOCATE_BROWSER, &CAppSettingsDlg::OnLocateBrowser)
    ON_BN_CLICKED(IDC_APPS_LOCATE_TERMINAL, &CAppSettingsDlg::OnLocateTerminal)
    ON_CBN_SELCHANGE(IDC_APPS_BROWSER, &CAppSettingsDlg::OnSelectionChanged)
    ON_CBN_SELCHANGE(IDC_APPS_TERMINAL, &CAppSettingsDlg::OnSelectionChanged)
    ON_CBN_SELCHANGE(IDC_APPEARANCE, &CAppSettingsDlg::OnAppearanceChanged)
    ON_BN_CLICKED(IDC_CONNECT_INSTALL, &CAppSettingsDlg::OnInstallWireGuard)
    ON_BN_CLICKED(IDC_CONNECT_CHECK, &CAppSettingsDlg::OnCheckWireGuard)
    ON_BN_CLICKED(IDC_CONNECT_NOT_NOW, &CAppSettingsDlg::OnNotNow)
    ON_BN_CLICKED(IDC_SETUP_PBX, &CAppSettingsDlg::OnGetStartedPbx)
    ON_BN_CLICKED(IDC_SETUP_SUPPORT, &CAppSettingsDlg::OnGetStartedSupport)
    ON_MESSAGE(WM_APP_SETUP_PROGRESS, &CAppSettingsDlg::OnSetupProgress)
    ON_MESSAGE(WM_APP_SETUP_DONE, &CAppSettingsDlg::OnSetupDone)
END_MESSAGE_MAP()

CAppSettingsDlg::CAppSettingsDlg(Mode mode, const std::optional<tlp::Preferences>& stored, CWnd* parent)
    : CAppearanceDialog(IDD_APP_SETTINGS, parent), mode_(mode), stored_(stored), working_(stored.value_or(tlp::Preferences())) {}

CAppSettingsDlg::~CAppSettingsDlg() {
    if (installer_.joinable()) installer_.join();
}

void CAppSettingsDlg::DoDataExchange(CDataExchange* exchange) {
    CDialogEx::DoDataExchange(exchange);
    DDX_Control(exchange, IDC_APPS_BROWSER, browser_);
    DDX_Control(exchange, IDC_APPS_TERMINAL, terminal_);
}

BOOL CAppSettingsDlg::OnInitDialog() {
    CAppearanceDialog::OnInitDialog();
    GetDlgItem(IDC_CONNECT_PASSWORD)->EnableWindow(connectProfile.has_value()
        && connectProfile->kind == tlp::ProfileKind::Administrator && !connectionActive);
    GetDlgItem(IDC_PASSWORD_LOCK_NOW)->EnableWindow(connectionActive);
    CComboBox* appearance = static_cast<CComboBox*>(GetDlgItem(IDC_APPEARANCE));
    appearance->AddString(L"System (follow Windows)");
    appearance->AddString(L"Light");
    appearance->AddString(L"Dark");
    appearance->SetCurSel(working_.appearance == tlp::Appearance::Dark ? 2 : working_.appearance == tlp::Appearance::Light ? 1 : 0);
    if (mode_ == Mode::Welcome) {
        SetWindowText(L"Welcome to TELIPHONES");
        SetDlgItemText(IDC_APPS_HEADING, L"Step 1: Applications");
        SetDlgItemText(IDC_APPS_INTRO, L"Choose the browser used to open FreePBX and the terminal used for Remote Support. Managed My PBXs SSH opens in the built-in TELIPHONES console. "
                                       L"Only applications found on this computer are listed. You can change these at any time in Settings.");
    } else {
        SetWindowText(L"TELIPHONES Settings");
        SetDlgItemText(IDC_APPS_HEADING, L"Applications");
        SetDlgItemText(IDC_APPS_INTRO, L"The browser opens FreePBX; the selected terminal applies to Remote Support. Managed My PBXs SSH uses the built-in TELIPHONES console. "
                                       L"Preferences are stored locally for your Windows account and are never sent to a PBX.");
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
    RefreshConnectivity();
    ShowStep();
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

void CAppSettingsDlg::OnConnectPassword() {
    if (!installing_ && !connectionActive && connectProfile
        && connectProfile->kind == tlp::ProfileKind::Administrator)
        ManageConnectPassword(*connectProfile, this);
}

void CAppSettingsDlg::OnLockNow() {
    if (installing_ || !connectionActive) return;
    lockNow = true;
    EndDialog(IDOK);
}

void CAppSettingsDlg::OnAbout() {
    tlp::ui::ShowMessage(Widen(
        "TELIPHONES is a UK registered trademark.\r\n\r\n"
        "TELIPHONES " TELIPHONES_VERSION_STRING " for Windows is licensed under GPLv3.\r\n\r\n"
        "GPLv3 licensing applies to the software and does not grant trademark rights. "
        "See LICENSE for the full licence terms.").c_str(), MB_OK | MB_ICONINFORMATION);
}

void CAppSettingsDlg::OnAppearanceChanged() {
    const int row = static_cast<CComboBox*>(GetDlgItem(IDC_APPEARANCE))->GetCurSel();
    const tlp::Appearance selected = row == 2 ? tlp::Appearance::Dark : row == 1 ? tlp::Appearance::Light : tlp::Appearance::System;
    try {
        tlp::ui::SetAppearance(selected);
        working_.appearance = selected;
    } catch (const std::exception& e) {
        const auto current = tlp::ui::CurrentAppearance();
        static_cast<CComboBox*>(GetDlgItem(IDC_APPEARANCE))->SetCurSel(
            current == tlp::Appearance::Dark ? 2 : current == tlp::Appearance::Light ? 1 : 0);
        ShowError(e.what());
    }
}

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
    stored_ = candidate;
    return true;
}

void CAppSettingsDlg::OnOK() {
    if (installing_) return;
    if (mode_ == Mode::Welcome && step_ != 1) {
        if (step_ == 2) {
            step_ = 3;
            ShowStep();
        } else {
            CDialogEx::OnOK();
        }
        return;
    }
    try {
        auto result = tlp::PreferencesAfterFirstRun(tlp::FirstRunOutcome::Saved, Selection(AppKind::Browser), Selection(AppKind::Terminal), browsers_,
                                                    terminals_, working_);
        if (!result || !Store(*result)) return;
    } catch (const std::exception& e) {
        ShowError(e.what());
        return;
    }
    outcome = tlp::FirstRunOutcome::Saved;
    if (mode_ == Mode::Welcome) {
        step_ = 2;
        ShowStep();
        return;
    }
    CDialogEx::OnOK();
}

void CAppSettingsDlg::OnSkip() {
    if (installing_) return;
    auto result = tlp::PreferencesAfterFirstRun(tlp::FirstRunOutcome::Skipped, "", "", browsers_, terminals_, working_);
    if (!result || !Store(*result)) return;
    outcome = tlp::FirstRunOutcome::Skipped;
    step_ = 2;
    ShowStep();
}

void CAppSettingsDlg::OnCancel() {
    if (installing_) return;
    try {
        tlp::ui::SetAppearance(stored_.value_or(tlp::Preferences()).appearance);
    } catch (const std::exception& e) {
        ShowError(e.what());
    }
    CDialogEx::OnCancel();
}

void CAppSettingsDlg::ShowStep() {
    bool welcome = mode_ == Mode::Welcome;
    for (int id : {IDC_APPS_GROUP, IDC_APPS_BROWSER_LABEL, IDC_APPS_TERMINAL_LABEL, IDC_APPS_BROWSER,
                   IDC_APPS_TERMINAL, IDC_APPS_LOCATE_BROWSER, IDC_APPS_LOCATE_TERMINAL, IDC_APPS_STATUS, IDC_APPS_NOTE,
                   IDC_APPEARANCE_LABEL, IDC_APPEARANCE}) {
        GetDlgItem(id)->ShowWindow(!welcome || step_ == 1 ? SW_SHOW : SW_HIDE);
    }
    for (int id : {IDC_CONNECT_GROUP, IDC_CONNECT_STATUS, IDC_CONNECT_CHECK}) {
        GetDlgItem(id)->ShowWindow(!welcome || step_ == 2 ? SW_SHOW : SW_HIDE);
    }
    for (int id : {IDC_PASSWORD_SECURITY_GROUP, IDC_CONNECT_PASSWORD, IDC_PASSWORD_LOCK_NOW}) {
        GetDlgItem(id)->ShowWindow(!welcome ? SW_SHOW : SW_HIDE);
    }
    GetDlgItem(IDC_CONNECT_INSTALL)->ShowWindow((!welcome || step_ == 2) && !wireguard_.installed ? SW_SHOW : SW_HIDE);
    GetDlgItem(IDC_CONNECT_NOT_NOW)->ShowWindow((!welcome || step_ == 2) && !wireguard_.installed ? SW_SHOW : SW_HIDE);
    GetDlgItem(IDC_APPS_SKIP)->ShowWindow(welcome && step_ == 1 ? SW_SHOW : SW_HIDE);
    GetDlgItem(IDC_SETUP_PBX)->ShowWindow(welcome && step_ == 3 ? SW_SHOW : SW_HIDE);
    GetDlgItem(IDC_SETUP_SUPPORT)->ShowWindow(welcome && step_ == 3 ? SW_SHOW : SW_HIDE);
    GetDlgItem(IDC_SETUP_PBX)->EnableWindow(wireguard_.installed && wireguard_.trusted);
    GetDlgItem(IDC_SETUP_SUPPORT)->EnableWindow(wireguard_.installed && wireguard_.trusted);
    if (welcome) {
        SetDlgItemText(IDC_APPS_HEADING, step_ == 1 ? L"Step 1: Applications" : step_ == 2 ? L"Step 2: Secure connectivity" : L"Step 3: Get started");
        if (step_ == 2) {
            SetDlgItemText(IDC_APPS_INTRO, wireguard_.installed
                ? (wireguard_.trusted ? L"WireGuard is already installed and verified. No installation is needed."
                                     : L"WireGuard is installed, but could not be verified. TELIPHONES will not overwrite it automatically. Check Again after administrator investigation.")
                : L"WireGuard is required\r\nTELIPHONES uses WireGuard to establish secure connections to your PBXs. WireGuard is not currently installed on this computer.");
        } else if (step_ == 3) {
            SetDlgItemText(IDC_APPS_INTRO, wireguard_.installed && wireguard_.trusted
                ? L"Add your first PBX or start the separately authorised Remote Support workflow. Profiles stay on this computer; a new computer has an empty list."
                : L"You can explore TELIPHONES now. Install WireGuard later from Settings > Connectivity before adding or connecting to a PBX.");
        }
        SetDlgItemText(IDOK, step_ == 1 ? L"Save & Next" : step_ == 2 ? L"Continue" : L"Finish");
    }
}

void CAppSettingsDlg::RefreshConnectivity() {
    try {
        wireguard_ = tlp::win::FindWireGuard();
        std::string text;
        if (wireguard_.installed && wireguard_.trusted) {
            text = "Status: Installed (verified, signed by " + wireguard_.signer + ").";
        } else if (installation.state == tlp::SetupState::Failed) {
            text = "Status: Installation failed.";
        } else {
            text = wireguard_.installed ? "Status: Installed, but verification failed. Automatic replacement is disabled."
                                        : "Status: Not installed.";
        }
        if (!installation.message.empty()) text += "\r\n" + installation.message;
        else if (!wireguard_.installed) text += "\r\nWireGuard is required. TELIPHONES can download and verify the official installer, then request administrator approval.";
        SetDlgItemText(IDC_CONNECT_STATUS, Widen(text).c_str());
    } catch (const std::exception& e) {
        wireguard_ = {};
        SetDlgItemText(IDC_CONNECT_STATUS, Widen(std::string("WireGuard detection failed: ") + e.what()).c_str());
    }
    ShowStep();
}

void CAppSettingsDlg::OnCheckWireGuard() {
    if (!installing_) RefreshConnectivity();
}

void CAppSettingsDlg::OnNotNow() {
    if (!installing_) {
        if (mode_ == Mode::Settings) {
            OnCancel();
            return;
        }
        step_ = 3;
        ShowStep();
    }
}

void CAppSettingsDlg::OnInstallWireGuard() {
    if (installing_) return;
    RefreshConnectivity();
    if (wireguard_.installed) return;
    // This button is the explicit approval. No startup or detection path calls the installer.
    installing_ = true;
    for (int id : {IDOK, IDCANCEL, IDC_CONNECT_INSTALL, IDC_CONNECT_CHECK, IDC_CONNECT_NOT_NOW}) GetDlgItem(id)->EnableWindow(FALSE);
    SetDlgItemText(IDC_CONNECT_STATUS, L"Downloading the official WireGuard installer...");
    HWND window = m_hWnd;
    try {
        installer_ = std::thread([window] {
            auto result = std::make_unique<tlp::SetupResult>(tlp::win::InstallWireGuard([window](const std::string& text) {
                auto message = std::make_unique<std::string>(text);
                if (::PostMessageW(window, WM_APP_SETUP_PROGRESS, 0, reinterpret_cast<LPARAM>(message.get()))) message.release();
            }));
            if (::PostMessageW(window, WM_APP_SETUP_DONE, 0, reinterpret_cast<LPARAM>(result.get()))) result.release();
        });
    } catch (const std::exception& e) {
        installing_ = false;
        installation = {tlp::SetupState::Failed, e.what()};
        for (int id : {IDOK, IDCANCEL, IDC_CONNECT_INSTALL, IDC_CONNECT_CHECK, IDC_CONNECT_NOT_NOW}) GetDlgItem(id)->EnableWindow(TRUE);
        RefreshConnectivity();
    }
}

LRESULT CAppSettingsDlg::OnSetupProgress(WPARAM, LPARAM value) {
    std::unique_ptr<std::string> text(reinterpret_cast<std::string*>(value));
    SetDlgItemText(IDC_CONNECT_STATUS, Widen(*text).c_str());
    return 0;
}

LRESULT CAppSettingsDlg::OnSetupDone(WPARAM, LPARAM value) {
    std::unique_ptr<tlp::SetupResult> result(reinterpret_cast<tlp::SetupResult*>(value));
    if (installer_.joinable()) installer_.join();
    installing_ = false;
    installation = *result;
    for (int id : {IDOK, IDCANCEL, IDC_CONNECT_INSTALL, IDC_CONNECT_CHECK, IDC_CONNECT_NOT_NOW}) GetDlgItem(id)->EnableWindow(TRUE);
    RefreshConnectivity();
    return 0;
}

void CAppSettingsDlg::GetStarted(StartAction action) {
    if (installing_ || !wireguard_.installed || !wireguard_.trusted) return;
    startAction = action;
    EndDialog(IDOK);
}

void CAppSettingsDlg::OnGetStartedPbx() { GetStarted(StartAction::AddPbx); }
void CAppSettingsDlg::OnGetStartedSupport() { GetStarted(StartAction::Support); }
