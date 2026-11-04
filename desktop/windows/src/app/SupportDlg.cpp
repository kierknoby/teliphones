#include "SupportDlg.h"

#include <commdlg.h>

#include <cstring>
#include <fstream>
#include <iterator>

#include "../core/Encoding.h"
#include "../core/Json.h"
#include "../core/Validation.h"
#include "../platform/Services.h"
#include "../platform/Win.h"
#include "resource.h"

namespace {

class WipeString {
public:
    explicit WipeString(std::string& value) : value_(value) {}
    ~WipeString() { tlp::win::SecureWipe(value_); }

private:
    std::string& value_;
};

void SetEdit(CWnd* dialog, int id, const std::string& value) {
    dialog->SetDlgItemText(id, tlp::win::Widen(value).c_str());
}

std::string GetEdit(CWnd* dialog, int id) {
    CString value;
    dialog->GetDlgItemText(id, value);
    return tlp::win::Narrow(std::wstring(value.GetString()));
}

void CopyText(HWND owner, const std::string& text) {
    if (!OpenClipboard(owner)) throw tlp::Error("Windows could not open the clipboard.");
    EmptyClipboard();
    std::wstring wide = tlp::win::Widen(text);
    SIZE_T bytes = (wide.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (memory == nullptr) {
        CloseClipboard();
        throw tlp::Error("Windows could not allocate clipboard memory.");
    }
    void* target = GlobalLock(memory);
    if (target == nullptr) {
        GlobalFree(memory);
        CloseClipboard();
        throw tlp::Error("Windows could not access clipboard memory.");
    }
    memcpy(target, wide.c_str(), bytes);
    GlobalUnlock(memory);
    if (SetClipboardData(CF_UNICODETEXT, memory) == nullptr) {
        GlobalFree(memory);
        CloseClipboard();
        throw tlp::Error("Windows could not copy the text.");
    }
    CloseClipboard();
}

std::string ReadGrantFile(const std::wstring& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw tlp::Error("The selected grant file could not be opened.");
    std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    if (text.empty() || text.size() > 256 * 1024) throw tlp::Error("The selected grant file is empty or too large.");
    return text;
}

}  // namespace

BEGIN_MESSAGE_MAP(CSupportDlg, CAppearanceDialog)
    ON_BN_CLICKED(IDC_SUP_GENERATE, &CSupportDlg::OnGenerate)
    ON_BN_CLICKED(IDC_SUP_COPY, &CSupportDlg::OnCopy)
    ON_BN_CLICKED(IDC_SUP_BROWSE, &CSupportDlg::OnBrowse)
    ON_WM_TIMER()
END_MESSAGE_MAP()

CSupportDlg::CSupportDlg(const tlp::win::WireGuardInstallation& wireguard, const tlp::Profile* existing, CWnd* parent)
    : CAppearanceDialog(IDD_SUPPORT, parent), wireguard_(wireguard), updating_(existing != nullptr) {
    if (existing != nullptr) profile = *existing;
}

BOOL CSupportDlg::OnInitDialog() {
    CAppearanceDialog::OnInitDialog();
    SetEdit(this, IDC_SUP_NAME, profile.name);
    if (updating_) {
        SetEdit(this, IDC_SUP_PUBKEY, profile.engineerPublicKey);
        GetDlgItem(IDC_SUP_GENERATE)->EnableWindow(FALSE);
        SetDlgItemText(IDC_SUP_HINT, L"Send this public key to the gateway operator when requesting a refreshed grant. Import a new grant below to update authorised sessions.");
        if (profile.hasGrant) {
            std::string summary = std::to_string(profile.grant.sessions.size()) + " session(s) in current grant for " + profile.grant.engineerId;
            SetEdit(this, IDC_SUP_GRANT, summary);
        }
    } else {
        SetDlgItemText(IDC_SUP_PUBKEY, L"Generate an engineer key first.");
        SetDlgItemText(IDC_SUP_HINT, L"TELIPHONES creates a local engineer key. Send only its public key to the gateway operator. Never share the private key.");
        GetDlgItem(IDC_SUP_BROWSE)->EnableWindow(FALSE);
    }
    return TRUE;
}

void CSupportDlg::OnGenerate() {
    if (updating_ || keyStored_) return;
    try {
        std::string name = GetEdit(this, IDC_SUP_NAME);
        if (!tlp::IsPbxName(name)) throw tlp::Error("Use a profile name with letters, numbers, dots, underscores or hyphens (up to 64 characters).");
        std::string privateKey = tlp::win::GeneratePrivateKey(wireguard_);
        [[maybe_unused]] WipeString privateKeyWiper(privateKey);
        profile = {};
        profile.id = tlp::win::NewProfileId();
        profile.kind = tlp::ProfileKind::Support;
        profile.name = name;
        profile.createdAt = tlp::win::UnixNow();
        profile.engineerPublicKey = tlp::win::DerivePublicKey(wireguard_, privateKey);
        if (!tlp::IsWireGuardKey(profile.engineerPublicKey)) throw tlp::Error("WireGuard returned an invalid public key.");
        tlp::win::SavePrivateKey(tlp::CredentialTargetFor(profile), privateKey);
        keyStored_ = true;
        SetEdit(this, IDC_SUP_PUBKEY, profile.engineerPublicKey);
        SetDlgItemText(IDC_SUP_HINT, L"Send this public key to your gateway operator. When they issue a grant for this exact key, import it here.");
        GetDlgItem(IDC_SUP_BROWSE)->EnableWindow(TRUE);
    } catch (const std::exception& e) {
        tlp::ui::ShowMessage(tlp::win::Widen(e.what()).c_str(), MB_ICONERROR);
    }
}

void CSupportDlg::OnCopy() {
    if (profile.engineerPublicKey.empty()) {
        tlp::ui::ShowMessage(L"Generate or select an engineer public key first.", MB_ICONINFORMATION);
        return;
    }
    try {
        CopyText(m_hWnd, profile.engineerPublicKey);
        SetDlgItemText(IDC_SUP_COPY, L"Copied");
        SetTimer(1, 1800, nullptr);
    } catch (const std::exception& e) {
        tlp::ui::ShowMessage(tlp::win::Widen(e.what()).c_str(), MB_ICONERROR);
    }
}

void CSupportDlg::OnTimer(UINT_PTR timerId) {
    if (timerId == 1) {
        KillTimer(timerId);
        SetDlgItemText(IDC_SUP_COPY, L"Copy public key");
    }
    CAppearanceDialog::OnTimer(timerId);
}

void CSupportDlg::OnBrowse() {
    wchar_t path[MAX_PATH]{};
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = m_hWnd;
    dialog.lpstrFilter = L"TELIPHONES grant JSON (*.json)\0*.json\0All files (*.*)\0*.*\0";
    dialog.lpstrFile = path;
    dialog.nMaxFile = static_cast<DWORD>(std::size(path));
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_HIDEREADONLY;
    dialog.lpstrTitle = L"Import a grant from your gateway operator";
    if (!GetOpenFileNameW(&dialog)) return;
    try {
        std::string text = ReadGrantFile(path);
        tlp::SupportGrant grant = tlp::ParseEngineerGrantFor(text, profile.engineerPublicKey);
        profile.grant = std::move(grant);
        profile.hasGrant = true;
        SetEdit(this, IDC_SUP_GRANT, std::to_string(profile.grant.sessions.size()) + " session(s) for " + profile.grant.engineerId);
        tlp::win::SecureWipe(text);
    } catch (const std::exception& e) {
        tlp::ui::ShowMessage(tlp::win::Widen(e.what()).c_str(), MB_ICONERROR);
    }
}

void CSupportDlg::OnOK() {
    try {
        std::string name = GetEdit(this, IDC_SUP_NAME);
        if (!tlp::IsPbxName(name)) throw tlp::Error("Use a profile name with letters, numbers, dots, underscores or hyphens (up to 64 characters).");
        if (updating_) {
            if (!profile.hasGrant) throw tlp::Error("Import a grant for this engineer key before saving the update.");
        } else {
            if (!keyStored_) throw tlp::Error("Generate an engineer key before saving this Remote Support profile.");
            // A profile may be saved before a grant is issued so its public key can be provided to the gateway operator.
        }
        profile.name = name;
        CDialogEx::OnOK();
    } catch (const std::exception& e) {
        tlp::ui::ShowMessage(tlp::win::Widen(e.what()).c_str(), MB_ICONERROR);
    }
}

void CSupportDlg::OnCancel() {
    if (keyStored_) {
        try {
            tlp::win::DeletePrivateKey(tlp::CredentialTargetFor(profile));
        } catch (const std::exception& e) {
            tlp::ui::ShowMessage((std::wstring(L"The unused engineer key could not be removed from Windows Credential Manager: ") + tlp::win::Widen(e.what())).c_str(),
                          MB_ICONERROR);
        }
    }
    CDialogEx::OnCancel();
}
