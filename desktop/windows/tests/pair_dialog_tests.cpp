#include "../src/app/PairDlg.h"
#include "../src/app/resource.h"
#include "../src/core/Encoding.h"
#include "../src/core/Json.h"
#include "../src/core/Pairing.h"
#include "../src/platform/Services.h"
#include "../src/platform/Ssh.h"
#include "../src/platform/Win.h"

#include <cstdio>
#include <map>
#include <stdexcept>

namespace {
const std::string publicKey = std::string(42, 'A') + "E=";
const std::string pbxKey = std::string(42, 'B') + "E=";
std::map<std::string, std::string> credentials;
int sshGenerated = 0, sshDeleted = 0, runtimeRemoved = 0, nextId = 0;

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::string sshKey() {
    tlp::Bytes blob{0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0, 32};
    blob.insert(blob.end(), 32, 7);
    return "ssh-ed25519 " + tlp::Base64Encode(blob);
}

std::string text(CWnd& dialog, int id) {
    CString value;
    dialog.GetDlgItemText(id, value);
    return tlp::win::Narrow(std::wstring(value.GetString()));
}

tlp::json::Value request(CWnd& dialog) {
    const auto code = text(dialog, IDC_PAIR_REQUEST);
    const auto body = tlp::Base64UrlDecode(code.substr(code.find(':') + 1));
    return tlp::json::Parse(std::string(body.begin(), body.end()));
}

void replaceResponse(CWnd& dialog, const std::string& value) {
    // WM_SETTEXT does not emit EN_CHANGE for a multiline edit. Replace text
    // through its editing path so the production notification handler runs.
    const auto wide = tlp::win::Widen(value);
    auto* edit = static_cast<CEdit*>(dialog.GetDlgItem(IDC_PAIR_RESPONSE));
    edit->SetSel(0, -1);
    edit->ReplaceSel(wide.c_str());
}

std::string changeResponse(const std::string& code, const std::string& field, const tlp::json::Value& value,
                           bool remove = false) {
    const auto separator = code.find(':') + 1;
    const auto raw = tlp::Base64UrlDecode(code.substr(separator));
    auto fields = tlp::json::Parse(std::string(raw.begin(), raw.end())).asObject();
    if (remove) fields.erase(field);
    else fields[field] = value;
    const auto body = tlp::json::Serialize(tlp::json::Value(fields));
    return code.substr(0, separator) + tlp::Base64UrlEncode(tlp::Bytes(body.begin(), body.end()));
}

std::string response(const tlp::json::Value& request, bool managed, bool approved = true) {
    tlp::json::Value::Object value{{"schema", managed ? "teliphones-pair-response/2" : "teliphones-pair-response/1"},
        {"nonce", request.at("nonce")}, {"workstation_id", "0123456789abcdef"},
        {"workstation_public_key", request.at("public_key")}, {"address", "100.70.1.2/32"},
        {"pbx_address", "100.70.1.1"}, {"pbx_name", "Test-PBX"}, {"pbx_public_key", pbxKey},
        {"endpoint", "pbx.example.net:51821"}, {"mode", "persistent"}, {"expires_at", nullptr},
        {"ssh", managed && approved}, {"gui_url", "https://100.70.1.1/admin/"}};
    if (managed) {
        value.emplace("ssh_user", approved ? "administrator" : "");
        value.emplace("ssh_host_key", approved ? sshKey() : "");
        value.emplace("ssh_ca_key", approved ? sshKey() : "");
        value.emplace("ssh_port", approved ? 22002 : 0);
        value.emplace("ssh_api_port", approved ? 8765 : 0);
    }
    const auto body = tlp::json::Serialize(tlp::json::Value(value));
    return std::string(managed ? "TELIPHONES-PAIR-RESPONSE-2:" : tlp::kPairResponsePrefix) +
        tlp::Base64UrlEncode(tlp::Bytes(body.begin(), body.end()));
}

class PairTestDialog : public CPairDlg {
public:
    explicit PairTestDialog(CWnd* parent, bool saveTest = false, bool requestSsh = true)
        : CPairDlg({}, parent), saveTest_(saveTest), requestSsh_(requestSsh) {}
    using CPairDlg::OnGenerate;

protected:
    BOOL OnInitDialog() override {
        const BOOL result = CPairDlg::OnInitDialog();
        if (saveTest_) {
            SetDlgItemText(IDC_PAIR_WORKSTATION, L"SAVE-PC");
            auto* access = static_cast<CComboBox*>(GetDlgItem(IDC_PAIR_ACCESS));
            access->SetCurSel(requestSsh_ ? 1 : 0);
            OnGenerate();
            replaceResponse(*this, response(request(*this), requestSsh_));
            check(GetDlgItem(IDOK)->IsWindowEnabled() != FALSE, "modal valid response enables save through edit notification");
            SetDlgItemText(IDC_PAIR_SSHUSER, L"root");
            PostMessage(WM_COMMAND, IDOK);
        }
        return result;
    }

private:
    bool saveTest_;
    bool requestSsh_;
};
} // namespace

// Test-target-only replacements: exercise the production MFC dialogue without
// invoking WireGuard, writing credentials or creating SSH keys on the runner.
namespace tlp::win {
std::string GeneratePrivateKey(const WireGuardInstallation&) { return "synthetic-private-key"; }
std::string DerivePublicKey(const WireGuardInstallation&, const std::string&) { return publicKey; }
void SavePrivateKey(const std::string& target, const std::string& key) { credentials[target] = key; }
void DeletePrivateKey(const std::string& target) { check(credentials.erase(target) == 1, "delete owned fixture credential"); }
std::string NewProfileId() { return std::string(15, '0') + std::to_string(++nextId); }
std::string GenerateWorkstationSshIdentity(const Profile&) { ++sshGenerated; return sshKey(); }
void DeleteSshPrivateKey(const Profile&) { ++sshDeleted; }
void RemoveSshRuntime(const Profile&) { ++runtimeRemoved; }
} // namespace tlp::win

void RunPairDialogTests(CWnd* parent) {
    PairTestDialog dialog(parent);
    check(dialog.Create(IDD_PAIR, parent) != FALSE, "create real pairing dialogue");
    dialog.ShowWindow(SW_SHOWNOACTIVATE);
    const auto enabled = [&](int id) { return dialog.GetDlgItem(id)->IsWindowEnabled() != FALSE; };
    check(!enabled(IDC_PAIR_COPY) && !enabled(IDOK) && !enabled(IDC_PAIR_RESPONSE), "initial copy/save/response disabled");
    check(!dialog.GetDlgItem(IDC_PAIR_SSHUSER)->IsWindowVisible(), "no initial SSH account");
    check((dialog.GetDlgItem(IDC_PAIR_SSHUSER)->GetStyle() & ES_READONLY) != 0, "approved account is read-only");
    auto* access = static_cast<CComboBox*>(dialog.GetDlgItem(IDC_PAIR_ACCESS));
    check(access->GetCurSel() == 0, "initial access web-only");
    const int ordered[] = {IDC_PAIR_WORKSTATION, IDC_PAIR_ACCESS, IDC_PAIR_GENERATE, IDC_PAIR_REQUEST,
                           IDC_PAIR_COPY, IDC_PAIR_RESPONSE, IDC_PAIR_SSHUSER, IDOK};
    int previousTop = -1;
    CRect client;
    dialog.GetClientRect(client);
    for (int id : ordered) {
        CRect rect;
        dialog.GetDlgItem(id)->GetWindowRect(rect);
        dialog.ScreenToClient(rect);
        check(rect.top > previousTop && rect.right <= client.right && rect.bottom <= client.bottom,
              "pairing control order and client bounds");
        previousTop = rect.top;
    }
    check(dialog.GetNextDlgTabItem(dialog.GetDlgItem(IDC_PAIR_WORKSTATION))->GetDlgCtrlID() == IDC_PAIR_ACCESS,
          "Tab moves from workstation to access before generation");
    check(dialog.GetNextDlgTabItem(dialog.GetDlgItem(IDC_PAIR_ACCESS))->GetDlgCtrlID() == IDC_PAIR_GENERATE,
          "Tab moves from access to Generate");
    dialog.SetDlgItemText(IDC_PAIR_WORKSTATION, L"ADMIN-PC");
    dialog.OnGenerate();
    check(enabled(IDC_PAIR_COPY) && enabled(IDC_PAIR_RESPONSE) && !enabled(IDOK), "generated request enables copy not save");
    const auto first = request(dialog);
    check(first.at("schema").asString() == "teliphones-pair-request/1" && sshGenerated == 0, "web request needs no SSH key");
    const auto approvedWeb = response(first, false);
    const auto parsedWeb = tlp::ParsePairResponse(approvedWeb, first.at("nonce").asString(),
                                                first.at("public_key").asString());
    check(!parsedWeb.ssh && parsedWeb.sshUser.empty(), "web fixture validates without an SSH account");
    dialog.SetDlgItemText(IDC_PAIR_RESPONSE, tlp::win::Widen(approvedWeb).c_str());
    check(!enabled(IDOK), "multiline WM_SETTEXT does not notify response validation");
    dialog.SetDlgItemText(IDC_PAIR_RESPONSE, L"");
    replaceResponse(dialog, approvedWeb);
    check(enabled(IDOK) && !dialog.GetDlgItem(IDC_PAIR_SSHUSER)->IsWindowVisible(), "valid web approval enables save without SSH account");
    auto wrongNonce = first.at("nonce").asString();
    wrongNonce[0] = wrongNonce[0] == 'A' ? 'B' : 'A';
    replaceResponse(dialog, changeResponse(approvedWeb, "nonce", wrongNonce));
    check(!enabled(IDOK), "unbound web approval disables save");
    replaceResponse(dialog, approvedWeb.substr(0, 60));
    check(!enabled(IDOK), "incomplete web approval disables save");
    replaceResponse(dialog, response(first, true));
    check(!enabled(IDOK) && !dialog.GetDlgItem(IDC_PAIR_SSHUSER)->IsWindowVisible(),
          "web-only request cannot acquire an unenrolled SSH approval");
    replaceResponse(dialog, "invalid response");
    check(!enabled(IDOK), "invalid response disables save");
    replaceResponse(dialog, "");
    check(!enabled(IDOK), "empty response disables save");
    replaceResponse(dialog, approvedWeb);
    check(enabled(IDOK), "corrected web response re-enables save");
    access->SetCurSel(1);
    dialog.SendMessage(WM_COMMAND, MAKEWPARAM(IDC_PAIR_ACCESS, CBN_SELCHANGE),
                       reinterpret_cast<LPARAM>(access->GetSafeHwnd()));
    check(!enabled(IDC_PAIR_COPY) && !enabled(IDOK) && text(dialog, IDC_PAIR_REQUEST).empty() &&
          text(dialog, IDC_PAIR_RESPONSE).empty() && credentials.empty(), "access change invalidates request and removes credential");
    dialog.OnGenerate();
    const auto sshRequest = request(dialog);
    check(sshRequest.at("schema").asString() == "teliphones-pair-request/2" &&
          sshRequest.at("ssh_public_key").asString() == sshKey() && sshGenerated == 1, "SSH choice encoded before generation");
    check(text(dialog, IDC_PAIR_WORKSTATION) == "ADMIN-PC", "regeneration preserves name");
    replaceResponse(dialog, approvedWeb);
    check(!enabled(IDOK), "previous generation response cannot be saved");
    replaceResponse(dialog, response(sshRequest, false));
    check(!enabled(IDOK), "web approval cannot satisfy requested Web + SSH access");
    replaceResponse(dialog, response(sshRequest, true, false));
    check(!enabled(IDOK) && !dialog.GetDlgItem(IDC_PAIR_SSHUSER)->IsWindowVisible(),
          "explicitly denied managed SSH approval blocks save and hides account");
    dialog.SetDlgItemText(IDC_PAIR_SSHUSER, L"root");
    check(!enabled(IDOK), "manual account cannot enable save without SSH approval");
    replaceResponse(dialog, response(sshRequest, true));
    check(enabled(IDOK) && text(dialog, IDC_PAIR_SSHUSER) == "administrator" &&
          dialog.GetDlgItem(IDC_PAIR_SSHUSER)->IsWindowVisible(), "validated PBX response populates approved account");
    replaceResponse(dialog, changeResponse(response(sshRequest, true), "ssh_user", ""));
    check(!enabled(IDOK) && !dialog.GetDlgItem(IDC_PAIR_SSHUSER)->IsWindowVisible(), "invalid approved account hides field and blocks save");
    replaceResponse(dialog, changeResponse(response(sshRequest, true), "ssh_user", nullptr, true));
    check(!enabled(IDOK), "missing approved account blocks save");
    replaceResponse(dialog, changeResponse(response(sshRequest, true), "ssh_user", "invalid account"));
    check(!enabled(IDOK), "malformed approved account blocks save");
    replaceResponse(dialog, response(sshRequest, true));
    check(enabled(IDOK), "corrected SSH response re-enables save");
    dialog.SetDlgItemText(IDC_PAIR_WORKSTATION, L"RENAMED-PC");
    check(!enabled(IDC_PAIR_COPY) && !enabled(IDOK) && text(dialog, IDC_PAIR_RESPONSE).empty() &&
          credentials.empty() && sshDeleted == 1 && runtimeRemoved == 1, "name change invalidates and cleans both identities");
    dialog.OnGenerate();
    check(request(dialog).at("workstation").asString() == "RENAMED-PC", "new request uses changed name");
    dialog.SetDlgItemText(IDC_PAIR_WORKSTATION, L"FINISHED-PC");
    check(credentials.empty(), "final unused request cleaned");
    dialog.DestroyWindow();
    PairTestDialog saveDialog(parent, true);
    check(saveDialog.DoModal() == IDOK, "save current valid response through modal dialogue");
    check(saveDialog.profile.sshUser == "administrator" && saveDialog.profile.pairing.sshUser == "administrator",
          "save revalidates response rather than trusting account display");
    credentials.clear();
    PairTestDialog webSaveDialog(parent, true, false);
    check(webSaveDialog.DoModal() == IDOK, "save current web-only response through modal dialogue");
    check(!webSaveDialog.profile.pairing.ssh && webSaveDialog.profile.sshUser.empty() &&
          webSaveDialog.profile.pairing.sshUser.empty(), "web save ignores manually altered SSH account display");
    credentials.clear();
    std::puts("Native pairing dialogue tests: PASS (fixture key storage; actual MFC controls, events, response validation and layout)");
}
