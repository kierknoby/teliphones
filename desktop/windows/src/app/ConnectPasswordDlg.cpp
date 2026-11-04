#include "ConnectPasswordDlg.h"

#include "../core/ConnectProtection.h"
#include "../core/Json.h"
#include "../platform/Services.h"
#include "../platform/Win.h"
#include "../platform/WireGuard.h"
#include "resource.h"

namespace {
std::string readPassword(CWnd* window, int id) {
    CString text;
    window->GetDlgItem(id)->GetWindowText(text);
    struct WipeText {
        CString& value;
        ~WipeText() {
            const auto length = value.GetLength();
            SecureZeroMemory(value.GetBuffer(), static_cast<std::size_t>(length) * sizeof(wchar_t));
            value.ReleaseBuffer(0);
        }
    } wipe{text};
    std::string result;
    if (!text.IsEmpty()) {
        const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.GetString(), text.GetLength(), nullptr, 0, nullptr, nullptr);
        if (length <= 0) throw tlp::Error("The password contains invalid Unicode.");
        result.resize(static_cast<std::size_t>(length));
        if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.GetString(), text.GetLength(), result.data(), length, nullptr, nullptr)) {
            tlp::win::SecureWipe(result);
            throw tlp::Error("The password contains invalid Unicode.");
        }
    }
    return result;
}
struct Wipe {
    std::string& value;
    ~Wipe() { tlp::win::SecureWipe(value); }
};
}

CConnectPasswordDlg::CConnectPasswordDlg(bool setting, CWnd* parent)
    : CAppearanceDialog(IDD_CONNECT_PASSWORD, parent), setting_(setting) {}

CConnectPasswordDlg::~CConnectPasswordDlg() { tlp::win::SecureWipe(password); }

BOOL CConnectPasswordDlg::OnInitDialog() {
    CAppearanceDialog::OnInitDialog();
    SetWindowText(setting_ ? L"Set Password Protection" : L"Unlock this connection");
    SetDlgItemText(IDC_PASSWORD_NOTICE, setting_
        ? L"Use a long, unique passphrase (at least 12 UTF-8 bytes). This is a local password, not a PBX/SSH password, required on every Connect. If forgotten, remove this connection and its protected key, revoke it on the PBX, then pair again."
        : L"Enter this connection's Password Protection passphrase. It is not sent to the PBX and is not remembered after this attempt.");
    GetDlgItem(IDC_PASSWORD_CONFIRM)->ShowWindow(setting_ ? SW_SHOW : SW_HIDE);
    GetDlgItem(IDC_PASSWORD_CONFIRM_LABEL)->ShowWindow(setting_ ? SW_SHOW : SW_HIDE);
    static_cast<CEdit*>(GetDlgItem(IDC_PASSWORD_VALUE))->SetLimitText(256);
    static_cast<CEdit*>(GetDlgItem(IDC_PASSWORD_CONFIRM))->SetLimitText(256);
    GetDlgItem(IDC_PASSWORD_VALUE)->SetFocus();
    return FALSE;
}

void CConnectPasswordDlg::ClearFields() {
    SetDlgItemText(IDC_PASSWORD_VALUE, L"");
    SetDlgItemText(IDC_PASSWORD_CONFIRM, L"");
}

void CConnectPasswordDlg::OnOK() {
    try {
        tlp::win::SecureWipe(password);
        password = readPassword(this, IDC_PASSWORD_VALUE);
        std::string confirmation = readPassword(this, IDC_PASSWORD_CONFIRM);
        Wipe wipe{confirmation};
        if (password.empty() || password.size() > 1024 ||
            (setting_ && (password.size() < 12 || password != confirmation)))
            throw tlp::Error(setting_ ? "Enter matching passwords of at least 12 UTF-8 bytes." : "Enter your Connect password.");
        ClearFields();
        CDialogEx::OnOK();
    } catch (const std::exception& error) {
        tlp::win::SecureWipe(password);
        ClearFields();
        tlp::ui::ShowMessage(tlp::win::Widen(error.what()).c_str(), MB_ICONERROR);
    }
}

void CConnectPasswordDlg::OnCancel() {
    tlp::win::SecureWipe(password);
    ClearFields();
    CDialogEx::OnCancel();
}

BEGIN_MESSAGE_MAP(CConnectPasswordChoiceDlg, CAppearanceDialog)
    ON_BN_CLICKED(IDC_PASSWORD_SET, &CConnectPasswordChoiceDlg::OnSetPassword)
    ON_BN_CLICKED(IDC_PASSWORD_SKIP_ONCE, &CConnectPasswordChoiceDlg::OnSkipThisTime)
    ON_BN_CLICKED(IDC_PASSWORD_SKIP_ALWAYS, &CConnectPasswordChoiceDlg::OnSkipPermanently)
END_MESSAGE_MAP()

CConnectPasswordChoiceDlg::CConnectPasswordChoiceDlg(bool protectionAvailable, CWnd* parent)
    : CAppearanceDialog(IDD_CONNECT_PASSWORD_CHOICE, parent), protectionAvailable_(protectionAvailable) {}

BOOL CConnectPasswordChoiceDlg::OnInitDialog() {
    CAppearanceDialog::OnInitDialog();
    GetDlgItem(IDC_PASSWORD_SET)->EnableWindow(protectionAvailable_);
    if (!protectionAvailable_) {
        SetDlgItemText(IDC_PASSWORD_CHOICE_NOTICE,
            L"Password Protection is unavailable because this OpenSSL build has no Argon2id provider. No substitute is used.");
    }
    return TRUE;
}

void CConnectPasswordChoiceDlg::OnSetPassword() {
    choice = IDC_PASSWORD_SET;
    EndDialog(choice);
}

void CConnectPasswordChoiceDlg::OnSkipThisTime() {
    choice = IDC_PASSWORD_SKIP_ONCE;
    EndDialog(choice);
}

void CConnectPasswordChoiceDlg::OnSkipPermanently() {
    choice = IDC_PASSWORD_SKIP_ALWAYS;
    EndDialog(choice);
}

bool ManageConnectPassword(const tlp::Profile& profile, CWnd* parent) {
    try {
        const auto target = tlp::CredentialTargetFor(profile);
        const bool protectedKey = tlp::win::PrivateKeyNeedsPassword(target);
        bool disable = false;
        CConnectPasswordDlg current(false, parent);
        if (protectedKey) {
            const int action = tlp::ui::ShowMessage(
                L"This connection has Password Protection.\r\n\r\nYes: change password.\r\nNo: remove protection (current password required).\r\nCancel: leave unchanged.",
                MB_YESNOCANCEL | MB_ICONQUESTION);
            if (action == IDCANCEL) return false;
            disable = action == IDNO;
            if (current.DoModal() != IDOK) return false;
            std::string key = tlp::win::LoadPrivateKey(target, current.password);
            Wipe wipe{key};
        }
        CConnectPasswordDlg replacement(true, parent);
        if (!disable) {
            if (!tlp::ConnectProtectionAvailable())
                throw tlp::Error("Password Protection needs OpenSSL's Argon2id provider. No substitute is permitted.");
            if (replacement.DoModal() != IDOK) return false;
        }
        // Remove any legacy plaintext service/config before claiming protection is enabled.
        tlp::win::RemoveTunnel(tlp::TunnelNameFor(profile));
        tlp::win::SetConnectPassword(target, current.password, disable ? "" : replacement.password);
        return true;
    } catch (const std::exception& error) {
        tlp::ui::ShowMessage(tlp::win::Widen(error.what()).c_str(), MB_ICONERROR);
        return false;
    }
}
