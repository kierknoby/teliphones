#include "../src/app/PairDlg.h"
#include "../src/app/resource.h"
#include "../src/core/Encoding.h"
#include "../src/core/Json.h"
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

std::string response(const tlp::json::Value& request, bool managed) {
    tlp::json::Value::Object value{{"schema", managed ? "teliphones-pair-response/2" : "teliphones-pair-response/1"},
        {"nonce", request.at("nonce")}, {"workstation_id", "0123456789abcdef"},
        {"workstation_public_key", request.at("public_key")}, {"address", "100.70.1.2/32"},
        {"pbx_address", "100.70.1.1"}, {"pbx_name", "Test-PBX"}, {"pbx_public_key", pbxKey},
        {"endpoint", "pbx.example.net:51821"}, {"mode", "persistent"}, {"expires_at", nullptr},
        {"ssh", managed}, {"gui_url", "https://100.70.1.1/admin/"}};
    if (managed) {
        value.emplace("ssh_user", "administrator");
        value.emplace("ssh_host_key", sshKey());
        value.emplace("ssh_ca_key", sshKey());
        value.emplace("ssh_port", 22002);
        value.emplace("ssh_api_port", 8765);
    }
    const auto body = tlp::json::Serialize(tlp::json::Value(value));
    return std::string(managed ? "TELIPHONES-PAIR-RESPONSE-2:" : tlp::kPairResponsePrefix) +
        tlp::Base64UrlEncode(tlp::Bytes(body.begin(), body.end()));
}

class PairTestDialog : public CPairDlg {
public:
    explicit PairTestDialog(CWnd* parent, bool saveTest = false) : CPairDlg({}, parent), saveTest_(saveTest) {}
    using CPairDlg::OnGenerate;

protected:
    BOOL OnInitDialog() override {
        const BOOL result = CPairDlg::OnInitDialog();
        if (saveTest_) {
            SetDlgItemText(IDC_PAIR_WORKSTATION, L"SAVE-PC");
            auto* access = static_cast<CComboBox*>(GetDlgItem(IDC_PAIR_ACCESS));
            access->SetCurSel(1);
            OnGenerate();
            SetDlgItemText(IDC_PAIR_RESPONSE, tlp::win::Widen(response(request(*this), true)).c_str());
            SetDlgItemText(IDC_PAIR_SSHUSER, L"root");
            PostMessage(WM_COMMAND, IDOK);
        }
        return result;
    }

private:
    bool saveTest_;
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
    dialog.SetDlgItemText(IDC_PAIR_RESPONSE, tlp::win::Widen(approvedWeb).c_str());
    check(enabled(IDOK) && !dialog.GetDlgItem(IDC_PAIR_SSHUSER)->IsWindowVisible(), "valid web approval enables save without SSH account");
    dialog.SetDlgItemText(IDC_PAIR_RESPONSE, L"invalid response");
    check(!enabled(IDOK), "invalid response disables save");
    dialog.SetDlgItemText(IDC_PAIR_RESPONSE, L"");
    check(!enabled(IDOK), "empty response disables save");
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
    dialog.SetDlgItemText(IDC_PAIR_RESPONSE, tlp::win::Widen(approvedWeb).c_str());
    check(!enabled(IDOK), "previous generation response cannot be saved");
    dialog.SetDlgItemText(IDC_PAIR_RESPONSE, tlp::win::Widen(response(sshRequest, true)).c_str());
    check(enabled(IDOK) && text(dialog, IDC_PAIR_SSHUSER) == "administrator" &&
          dialog.GetDlgItem(IDC_PAIR_SSHUSER)->IsWindowVisible(), "validated PBX response populates approved account");
    auto invalidAccount = response(sshRequest, true);
    const auto body = tlp::Base64UrlDecode(invalidAccount.substr(invalidAccount.find(':') + 1));
    auto invalidFields = tlp::json::Parse(std::string(body.begin(), body.end())).asObject();
    invalidFields["ssh_user"] = "";
    const auto invalidBody = tlp::json::Serialize(tlp::json::Value(invalidFields));
    invalidAccount = "TELIPHONES-PAIR-RESPONSE-2:" +
        tlp::Base64UrlEncode(tlp::Bytes(invalidBody.begin(), invalidBody.end()));
    dialog.SetDlgItemText(IDC_PAIR_RESPONSE, tlp::win::Widen(invalidAccount).c_str());
    check(!enabled(IDOK) && !dialog.GetDlgItem(IDC_PAIR_SSHUSER)->IsWindowVisible(), "invalid approved account hides field and blocks save");
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
    std::puts("Native pairing dialogue tests: PASS (fixture key storage; actual MFC controls, events, response validation and layout)");
}
