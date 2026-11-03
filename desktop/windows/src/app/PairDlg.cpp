#include "PairDlg.h"

#include <cstring>
#include <ctime>
#include <iterator>

#include "../core/Encoding.h"
#include "../core/Json.h"
#include "../core/Pairing.h"
#include "../core/Validation.h"
#include "../platform/Services.h"
#include "../platform/Ssh.h"
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

std::string ComputerName() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD length = static_cast<DWORD>(std::size(buffer));
    if (!GetComputerNameW(buffer, &length)) return "Windows workstation";
    std::string name = tlp::win::Narrow(std::wstring(buffer, length));
    for (char& c : name) {
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == ' ' || c == '.' || c == '_' || c == '(' || c == ')' || c == '-')) {
            c = '-';
        }
    }
    if (name.empty() || !((name.front() >= 'A' && name.front() <= 'Z') || (name.front() >= 'a' && name.front() <= 'z') ||
                          (name.front() >= '0' && name.front() <= '9'))) {
        name = "Windows-" + name;
    }
    if (name.size() > 64) name.resize(64);
    return name;
}

}  // namespace

BEGIN_MESSAGE_MAP(CPairDlg, CAppearanceDialog)
    ON_BN_CLICKED(IDC_PAIR_GENERATE, &CPairDlg::OnGenerate)
    ON_BN_CLICKED(IDC_PAIR_COPY, &CPairDlg::OnCopy)
END_MESSAGE_MAP()

CPairDlg::CPairDlg(const tlp::win::WireGuardInstallation& wireguard, CWnd* parent) : CAppearanceDialog(IDD_PAIR, parent), wireguard_(wireguard) {}

BOOL CPairDlg::OnInitDialog() {
    CAppearanceDialog::OnInitDialog();
    SetDlgItemText(IDC_PAIR_WORKSTATION, tlp::win::Widen(ComputerName()).c_str());
    SetDlgItemText(IDC_PAIR_SSHUSER, L"");
    CheckDlgButton(IDC_PAIR_SSH_CAPABILITY, BST_UNCHECKED);
    SetDlgItemText(IDC_PAIR_REQUEST, L"Generate a key and pairing request first.");
    SetDlgItemText(IDC_PAIR_FINGERPRINT, L"");
    return TRUE;
}

void CPairDlg::OnGenerate() {
    try {
        if (!DiscardKey()) return;
        publicKey_.clear();
        sshPublicKey_.clear();
        nonce_.clear();
        request_.clear();
        SetDlgItemText(IDC_PAIR_REQUEST, L"");
        SetDlgItemText(IDC_PAIR_FINGERPRINT, L"");
        SetDlgItemText(IDC_PAIR_RESPONSE, L"");
        std::string name = GetEdit(this, IDC_PAIR_WORKSTATION);
        if (!tlp::IsWorkstationName(name)) {
            throw tlp::Error("Use a workstation name beginning with a letter or number, up to 64 characters. Letters, numbers, spaces, dots, underscores, parentheses and hyphens are allowed.");
        }
        std::string privateKey = tlp::win::GeneratePrivateKey(wireguard_);
        [[maybe_unused]] WipeString privateKeyWiper(privateKey);
        publicKey_ = tlp::win::DerivePublicKey(wireguard_, privateKey);
        if (!tlp::IsWireGuardKey(publicKey_)) throw tlp::Error("WireGuard returned an invalid public key.");
        profile = {};
        profile.id = tlp::win::NewProfileId();
        profile.kind = tlp::ProfileKind::Administrator;
        profile.name = name;
        profile.workstationName = name;
        profile.createdAt = tlp::win::UnixNow();
        nonce_ = tlp::MakeNonce(tlp::win::RandomBytes(16));
        tlp::win::SavePrivateKey(tlp::CredentialTargetFor(profile), privateKey);
        keyStored_ = true;
        sshKeyRequested_ = IsDlgButtonChecked(IDC_PAIR_SSH_CAPABILITY) == BST_CHECKED;
        const auto request = tlp::CreatePairRequest(name, publicKey_, nonce_,
            sshKeyRequested_,
            [this]() { return tlp::win::GenerateWorkstationSshIdentity(profile); });
        sshPublicKey_ = request.sshPublicKey;
        request_ = request.code;
        SetEdit(this, IDC_PAIR_REQUEST, request_);
        SetDlgItemText(IDC_PAIR_FINGERPRINT, tlp::win::Widen("Workstation public-key fingerprint: " + tlp::KeyFingerprint(publicKey_)).c_str());
        tlp::ui::ShowMessage(L"Copy this pairing request and paste it into the Windows workstations section of the TELIPHONES page on your PBX. Then copy the pairing response back into this dialog.", MB_ICONINFORMATION);
    } catch (const std::exception& e) {
        tlp::ui::ShowMessage(tlp::win::Widen(e.what()).c_str(), MB_ICONERROR);
    }
}

void CPairDlg::OnCopy() {
    if (request_.empty()) {
        tlp::ui::ShowMessage(L"Generate a pairing request first.", MB_ICONINFORMATION);
        return;
    }
    try {
        CopyText(m_hWnd, request_);
        tlp::ui::ShowMessage(L"Pairing request copied.", MB_ICONINFORMATION);
    } catch (const std::exception& e) {
        tlp::ui::ShowMessage(tlp::win::Widen(e.what()).c_str(), MB_ICONERROR);
    }
}

void CPairDlg::OnOK() {
    try {
        if (!keyStored_ || request_.empty()) throw tlp::Error("Generate a WireGuard key and pairing request first.");
        std::string responseText = GetEdit(this, IDC_PAIR_RESPONSE);
        if (responseText.empty()) throw tlp::Error("Paste the pairing response from the TELIPHONES page on your PBX.");
        tlp::PairResponse pairing = tlp::ParsePairResponse(responseText, nonce_, publicKey_, sshPublicKey_);
        if (pairing.ssh && sshPublicKey_.empty())
            throw tlp::Error("This request is web-only. Leave SSH disabled on the PBX, or request SSH in a new pairing request.");
        std::string sshUser = pairing.sshUser;
        SetEdit(this, IDC_PAIR_SSHUSER, sshUser);
        if (pairing.ssh && pairing.sshPort == 0)
            throw tlp::Error("The PBX returned legacy SSH permission. Upgrade the PBX TELIPHONES broker and approve this request again.");
        if (pairing.ssh && !tlp::IsLinuxUser(sshUser)) {
            throw tlp::Error("The PBX must supply the explicitly approved Linux SSH account.");
        }
        if (!pairing.ssh && !sshUser.empty() && !tlp::IsLinuxUser(sshUser)) {
            throw tlp::Error("The SSH account name is invalid.");
        }
        profile.name = pairing.pbxName + " (" + profile.workstationName + ")";
        if (profile.name.size() > 128) profile.name.resize(128);
        profile.sshUser = pairing.ssh ? sshUser : std::string();
        profile.pairing = std::move(pairing);
        CDialogEx::OnOK();
    } catch (const std::exception& e) {
        tlp::ui::ShowMessage(tlp::win::Widen(e.what()).c_str(), MB_ICONERROR);
    }
}

bool CPairDlg::DiscardKey() {
    if (!keyStored_) return true;
    try {
        tlp::win::DeletePrivateKey(tlp::CredentialTargetFor(profile));
        if (sshKeyRequested_) {
            tlp::win::DeleteSshPrivateKey(profile);
            tlp::win::RemoveSshRuntime(profile);
        }
    } catch (const std::exception& e) {
        tlp::ui::ShowMessage((std::wstring(L"The unused workstation key could not be removed from Windows Credential Manager: ") + tlp::win::Widen(e.what())).c_str(),
                      MB_ICONERROR);
        return false;
    }
    keyStored_ = false;
    sshKeyRequested_ = false;
    return true;
}

void CPairDlg::OnCancel() {
    DiscardKey();
    CDialogEx::OnCancel();
}
