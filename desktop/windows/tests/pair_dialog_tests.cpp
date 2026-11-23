#include "../src/app/PairDlg.h"
#include "../src/app/resource.h"
#include "../src/core/Encoding.h"
#include "../src/core/Json.h"
#include "../src/core/Pairing.h"
#include "../src/platform/Services.h"
#include "../src/platform/Ssh.h"
#include "../src/platform/Win.h"

#include <algorithm>
#include <cstdio>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>

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
    const bool version3 = request.at("schema").asString() == "teliphones-pair-request/3";
    tlp::json::Value::Object value{{"schema", version3 ? "teliphones-pair-response/3" : managed ? "teliphones-pair-response/2" : "teliphones-pair-response/1"},
        {"nonce", request.at("nonce")}, {"workstation_id", "0123456789abcdef"},
        {"workstation_public_key", request.at("public_key")}, {"address", "100.70.1.2/32"},
        {"pbx_address", "100.70.1.1"}, {"pbx_name", "Test-PBX"}, {"pbx_public_key", pbxKey},
        {"endpoint", "pbx.example.net:51821"}, {"mode", "persistent"}, {"expires_at", nullptr},
        {"ssh", managed && approved}, {"gui_url", "https://100.70.1.1/admin/"}};
    if (version3) value.emplace("management_hostname", "pbx.example.net");
    if (managed || version3) {
        const bool sshApproved = managed && approved;
        value.emplace("ssh_user", sshApproved ? "administrator" : "");
        value.emplace("ssh_host_key", sshApproved ? sshKey() : "");
        value.emplace("ssh_ca_key", sshApproved ? sshKey() : "");
        value.emplace("ssh_port", sshApproved ? 22002 : 0);
        value.emplace("ssh_api_port", sshApproved ? 8765 : 0);
    }
    const auto body = tlp::json::Serialize(tlp::json::Value(value));
    return std::string(version3 ? "TELIPHONES-PAIR-RESPONSE-3:" : managed ? "TELIPHONES-PAIR-RESPONSE-2:" : tlp::kPairResponsePrefix) +
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
        wchar_t title[128]{};
        GetWindowTextW(dialog.GetSafeHwnd(), title, static_cast<int>(std::size(title)));
        check(std::wstring(title) == L"Add my PBX", "pairing window title identifies Add my PBX");
    const auto enabled = [&](int id) { return dialog.GetDlgItem(id)->IsWindowEnabled() != FALSE; };
    check(!enabled(IDC_PAIR_COPY) && !enabled(IDOK) && !enabled(IDC_PAIR_RESPONSE), "initial copy/save/response disabled");
    check(!dialog.GetDlgItem(IDC_PAIR_SSHUSER)->IsWindowVisible(), "no initial SSH account");
    check((dialog.GetDlgItem(IDC_PAIR_SSHUSER)->GetStyle() & ES_READONLY) != 0, "approved account is read-only");
    auto* access = static_cast<CComboBox*>(dialog.GetDlgItem(IDC_PAIR_ACCESS));
    check(access->GetCurSel() == 0, "initial access web-only");
    const int ordered[] = {IDC_PAIR_WORKSTATION, IDC_PAIR_ACCESS, IDC_PAIR_GENERATE, IDC_PAIR_REQUEST,
                           IDC_PAIR_COPY, IDC_PAIR_RESPONSE, IDC_PAIR_SSHUSER};
    int previousTop = -1;
    CRect client;
    dialog.GetClientRect(client);
    const int initialDpi = std::max(1, static_cast<int>(GetDpiForWindow(dialog.GetSafeHwnd())));
    const auto clientRect = [&](int id) {
        CRect rect;
        dialog.GetDlgItem(id)->GetWindowRect(&rect);
        dialog.ScreenToClient(&rect);
        return rect;
    };
    const auto controlFaceRect = [&](int id) {
        CRect rect = clientRect(id);
        if (id == IDC_PAIR_ACCESS) {
            COMBOBOXINFO info{sizeof(info)};
            check(::GetComboBoxInfo(dialog.GetDlgItem(id)->GetSafeHwnd(), &info) != FALSE,
                  "query pairing access combo face rectangle");
            rect = info.rcItem;
            dialog.ScreenToClient(&rect);
        }
        return rect;
    };
    const auto regionControlRect = [&](int id) {
        const CRect rect = controlFaceRect(id);
        HRGN region = ::CreateRectRgn(0, 0, 0, 0);
        check(region != nullptr, "allocate pairing control visibility region");
        const int regionType = ::GetWindowRgn(dialog.GetDlgItem(id)->GetSafeHwnd(), region);
        if (regionType == ERROR) {
            // No custom region means the complete native window shape is visible.
            ::DeleteObject(region);
            return rect;
        }
        RECT bounds{};
        const int boundsType = ::GetRgnBox(region, &bounds);
        ::DeleteObject(region);
        check(boundsType != ERROR,
              "query native clipping region for pairing content control");
        if (boundsType == NULLREGION) return CRect(rect.left, rect.top, rect.left, rect.top);
        CRect clipped(clientRect(id).left + bounds.left, clientRect(id).top + bounds.top,
                      clientRect(id).left + bounds.right, clientRect(id).top + bounds.bottom);
        return rect & clipped;
    };
    const auto visibleControlRect = [&](int id) {
        const HWND hwnd = dialog.GetDlgItem(id)->GetSafeHwnd();
        if (!::IsWindowVisible(dialog.GetSafeHwnd()) || !::IsWindowVisible(hwnd)) {
            const CRect face = controlFaceRect(id);
            return CRect(face.left, face.top, face.left, face.top);
        }
        return regionControlRect(id);
    };
    const auto windowDiagnostics = [&](int id) {
        CRect windowRect, clientRectValue;
        dialog.GetDlgItem(id)->GetWindowRect(&windowRect);
        dialog.GetDlgItem(id)->GetClientRect(&clientRectValue);
        const HWND hwnd = dialog.GetDlgItem(id)->GetSafeHwnd();
        const HWND parentHwnd = ::GetParent(hwnd);
        const HWND ownerHwnd = ::GetWindow(hwnd, GW_OWNER);
        HRGN region = ::CreateRectRgn(0, 0, 0, 0);
        const int regionType = region ? ::GetWindowRgn(hwnd, region) : ERROR;
        RECT regionBounds{};
        const int boundsType = regionType == ERROR ? ERROR : ::GetRgnBox(region, &regionBounds);
        if (region) ::DeleteObject(region);
        const auto formatRect = [](const RECT& rect) {
            return std::string("(") + std::to_string(rect.left) + "," + std::to_string(rect.top) + "," +
                std::to_string(rect.right) + "," + std::to_string(rect.bottom) + ")";
        };
        CString controlText;
        dialog.GetDlgItemText(id, controlText);
        std::ostringstream out;
        out << "id=" << id << " text='" << tlp::win::Narrow(std::wstring(controlText.GetString())) << "'"
            << " windowScreen=" << formatRect(windowRect) << " windowClient=" << formatRect(clientRectValue)
            << " faceDialog=" << formatRect(controlFaceRect(id))
            << " visibleFaceDialog=" << formatRect(visibleControlRect(id))
            << " styleVisible=" << ((::GetWindowLongPtr(hwnd, GWL_STYLE) & WS_VISIBLE) != 0)
            << " IsWindowVisible=" << (::IsWindowVisible(hwnd) != FALSE)
            << " enabled=" << (::IsWindowEnabled(hwnd) != FALSE)
            << " parent=" << parentHwnd << " parentVisible=" << (::IsWindowVisible(parentHwnd) != FALSE)
            << " owner=" << ownerHwnd << " ownerVisible=" << (ownerHwnd && ::IsWindowVisible(ownerHwnd))
            << " dialog=" << dialog.GetSafeHwnd() << " dialogVisible=" << (::IsWindowVisible(dialog.GetSafeHwnd()) != FALSE)
            << " regionType=" << regionType << " regionBoundsType=" << boundsType
            << " regionLocal=" << formatRect(regionBounds);
        for (HWND ancestor = parentHwnd; ancestor; ancestor = ::GetParent(ancestor))
            out << " ancestor=" << ancestor << ":visible=" << (::IsWindowVisible(ancestor) != FALSE)
                << ":enabled=" << (::IsWindowEnabled(ancestor) != FALSE);
        return out.str();
    };
    const auto fail = [](const std::string& message) -> void { throw std::runtime_error(message); };
    const auto isDescendant = [](HWND child, HWND ancestor) {
        for (HWND current = child; current; current = ::GetParent(current))
            if (current == ancestor) return true;
        return false;
    };
    const auto isUnobscured = [&](int id) {
        HWND hwnd = dialog.GetDlgItem(id)->GetSafeHwnd();
        if (!::IsWindowVisible(hwnd) || !::IsWindowVisible(dialog.GetSafeHwnd())) return false;
        CRect bounds;
        dialog.GetDlgItem(id)->GetWindowRect(&bounds);
        const CPoint points[] = {
            CPoint(bounds.left + bounds.Width() / 2, bounds.top + bounds.Height() / 2),
            CPoint(bounds.left + 2, bounds.top + 2), CPoint(bounds.right - 3, bounds.top + 2),
            CPoint(bounds.left + 2, bounds.bottom - 3), CPoint(bounds.right - 3, bounds.bottom - 3)};
        for (const CPoint& point : points) {
            HWND target = ::WindowFromPoint(point);
            if (!target || !isDescendant(target, hwnd)) return false;
        }
        return true;
    };
    const auto isVisibleFaceHitTestable = [&](int id) {
        const CRect face = visibleControlRect(id);
        if (face.IsRectEmpty()) return false;
        CRect screenFace = face;
        ::MapWindowPoints(dialog.GetSafeHwnd(), nullptr, reinterpret_cast<POINT*>(&screenFace), 2);
        const HWND hwnd = dialog.GetDlgItem(id)->GetSafeHwnd();
        const CPoint points[] = {
            CPoint(screenFace.left + screenFace.Width() / 2, screenFace.top + screenFace.Height() / 2),
            CPoint(screenFace.left + 1, screenFace.top + 1),
            CPoint(screenFace.right - 2, screenFace.top + 1),
            CPoint(screenFace.left + 1, screenFace.bottom - 2),
            CPoint(screenFace.right - 2, screenFace.bottom - 2)};
        for (const CPoint& point : points) {
            const HWND target = ::WindowFromPoint(point);
            if (!target || !isDescendant(target, hwnd)) return false;
        }
        return true;
    };
    const auto controlFullyVisible = [&](int id, const CRect& viewport) {
        const HWND hwnd = dialog.GetDlgItem(id)->GetSafeHwnd();
        if (!::IsWindowVisible(dialog.GetSafeHwnd()) || !::IsWindowVisible(hwnd)) return false;
        const CRect bounds = clientRect(id);
        return (bounds & viewport) == bounds && visibleControlRect(id) == controlFaceRect(id);
    };
    const auto checkControlVisible = [&](int id, const char* stage, const CRect& viewport) {
        if (controlFullyVisible(id, viewport) && isUnobscured(id)) return;
        fail(std::string(stage) + ": expected fully visible, hit-testable control; " + windowDiagnostics(id));
    };
    const CRect initialOk = clientRect(IDOK);
    const CRect initialCancel = clientRect(IDCANCEL);
    const CRect initialViewport(0, 0, client.right, initialOk.top - 6);
    checkControlVisible(IDC_PAIR_ACCESS, "initial pairing state", initialViewport);
    const auto assertFooterVisible = [&](const char* stage, int expectedOkGap, int expectedCancelGap) {
        CRect currentClient;
        dialog.GetClientRect(&currentClient);
        const CRect ok = clientRect(IDOK);
        const CRect cancel = clientRect(IDCANCEL);
        const bool inside = ok.left >= 0 && ok.top >= 0 && ok.right <= currentClient.right &&
            ok.bottom <= currentClient.bottom && cancel.left >= 0 && cancel.top >= 0 &&
            cancel.right <= currentClient.right && cancel.bottom <= currentClient.bottom;
        const bool footerGaps = currentClient.bottom - ok.bottom == expectedOkGap &&
            currentClient.bottom - cancel.bottom == expectedCancelGap;
        const bool windowsVisible = ::IsWindowVisible(dialog.GetDlgItem(IDOK)->GetSafeHwnd()) &&
            ::IsWindowVisible(dialog.GetDlgItem(IDCANCEL)->GetSafeHwnd());
        const bool unobscured = isUnobscured(IDOK) && isUnobscured(IDCANCEL);
        if (!inside || !footerGaps || !windowsVisible || !unobscured) {
            fail(std::string(stage) + ": footer bounds=" + (inside ? "ok" : "FAIL") +
                " gaps=" + (footerGaps ? "ok" : "FAIL") + " visibility=" + (windowsVisible ? "ok" : "FAIL") +
                " unobscured=" + (unobscured ? "ok" : "FAIL") +
                " dpi=" + std::to_string(GetDpiForWindow(dialog.GetSafeHwnd())) +
                " client=" + std::to_string(currentClient.Width()) + "x" + std::to_string(currentClient.Height()) +
                " save=" + windowDiagnostics(IDOK) + " cancel=" + windowDiagnostics(IDCANCEL));
        }
        for (int id : {IDOK, IDCANCEL}) {
            if (!dialog.GetDlgItem(id)->IsWindowEnabled()) continue;
            if (!isVisibleFaceHitTestable(id))
                fail(std::string(stage) + ": enabled footer control is not hit-testable: " + windowDiagnostics(id));
        }
    };
    const int initialOkGap = client.bottom - initialOk.bottom;
    const int initialCancelGap = client.bottom - initialCancel.bottom;
    assertFooterVisible("initial Save and Cancel remain visible in client coordinates", initialOkGap, initialCancelGap);
    for (int id : ordered) {
        const CRect rect = clientRect(id);
        if (!(rect.left >= client.left && rect.top >= client.top && rect.top > previousTop &&
              rect.right <= client.right && rect.bottom <= client.bottom)) {
            fail("initial content order/bounds failure: previousTop=" + std::to_string(previousTop) +
                 " " + windowDiagnostics(id) + " dialogClient=(0,0," +
                 std::to_string(client.right) + "," + std::to_string(client.bottom) + ")");
        }
        previousTop = rect.top;
    }
    check(clientRect(IDC_PAIR_TLS_HOSTNAME).top > previousTop &&
          clientRect(IDC_PAIR_TLS_HOSTNAME).bottom <= client.bottom,
          "HTTPS hostname follows the content tab order and remains within initial client bounds");
    CRect originalWindow;
    dialog.GetWindowRect(&originalWindow);
    const CRect originalOk = clientRect(IDOK);
    const CRect originalCancel = clientRect(IDCANCEL);
    const int okBottomGap = client.bottom - originalOk.bottom;
    const int cancelBottomGap = client.bottom - originalCancel.bottom;
    dialog.SetWindowPos(nullptr, originalWindow.left, originalWindow.top,
                        originalWindow.Width() - 120, originalWindow.Height() - 100,
                        SWP_NOZORDER | SWP_NOACTIVATE);
    CRect resizedClient;
    dialog.GetClientRect(&resizedClient);
    check(resizedClient.Width() < client.Width() && resizedClient.Height() < client.Height(),
          "pairing dialogue resizes to a smaller client area");
    assertFooterVisible("resized Save and Cancel remain visible in client coordinates",
                        okBottomGap, cancelBottomGap);
    SCROLLINFO scrollInfo{sizeof(scrollInfo), SIF_RANGE | SIF_PAGE | SIF_POS};
    check(dialog.GetScrollInfo(SB_VERT, &scrollInfo) != FALSE && scrollInfo.nMax > 0 &&
          scrollInfo.nMax - static_cast<int>(scrollInfo.nPage) > 0,
          "small pairing dialogue exposes a scrollable content range");
    const CRect resizedOk = clientRect(IDOK);
    const CRect resizedCancel = clientRect(IDCANCEL);
    const CRect resizedViewport(0, 0, resizedClient.right, resizedOk.top - 6);
    dialog.SendMessage(WM_VSCROLL, SB_BOTTOM);
    dialog.GetScrollInfo(SB_VERT, &scrollInfo);
    check(scrollInfo.nPos > 0, "pairing content scrolls to reveal its bottom controls");
        check(visibleControlRect(IDC_PAIR_ACCESS).IsRectEmpty(),
                    "access selector is clipped when scrolling to the bottom");
    check(resizedClient.bottom - resizedOk.bottom == okBottomGap &&
          resizedClient.bottom - resizedCancel.bottom == cancelBottomGap,
          "Save and Cancel remain pinned to the resized client bottom");
    check(resizedCancel.left >= 0 && resizedCancel.top >= 0 && resizedCancel.right <= resizedClient.right &&
          resizedCancel.bottom <= resizedClient.bottom,
          "Cancel remains within the resized client bounds");
    const int viewportBottom = resizedOk.top - 6;
    const auto setScrollPosition = [&](int position) {
        // WM_VSCROLL carries the thumb position in HIWORD(wParam), not lParam.
        dialog.SendMessage(WM_VSCROLL, MAKEWPARAM(SB_THUMBPOSITION, position));
        dialog.GetScrollInfo(SB_VERT, &scrollInfo);
        check(scrollInfo.nPos == position, "pairing dialog reaches requested scroll position");
    };
    const auto assertScrollGeometry = [&](const char* stage, int expectedPosition) {
        setScrollPosition(expectedPosition);
        dialog.GetClientRect(&resizedClient);
        const CRect viewport(0, 0, resizedClient.right, viewportBottom);
        if (!isUnobscured(IDOK) || !isUnobscured(IDCANCEL))
            fail(std::string(stage) + ": fixed Save/Cancel are not hit-test accessible; save=" +
                 windowDiagnostics(IDOK) + " cancel=" + windowDiagnostics(IDCANCEL));
        const CRect saveRect = clientRect(IDOK);
        const CRect cancelRect = clientRect(IDCANCEL);
        for (HWND child = ::GetWindow(dialog.GetSafeHwnd(), GW_CHILD); child;
             child = ::GetWindow(child, GW_HWNDNEXT)) {
            const int id = ::GetDlgCtrlID(child);
            if (id == IDOK || id == IDCANCEL || !::IsWindowVisible(child)) continue;
            wchar_t className[32]{};
            ::GetClassNameW(child, className, static_cast<int>(std::size(className)));
            if (std::wstring(className) == L"Button" &&
                (::GetWindowLongPtr(child, GWL_STYLE) & BS_TYPEMASK) == BS_GROUPBOX) continue;
            CRect childRect;
            ::GetWindowRect(child, &childRect);
            dialog.ScreenToClient(&childRect);
            HRGN childRegion = ::CreateRectRgn(0, 0, 0, 0);
            check(childRegion != nullptr, "allocate child overlap region");
            const int regionType = ::GetWindowRgn(child, childRegion);
            CRect effective = childRect;
            if (regionType != ERROR) {
                RECT bounds{};
                const int boundsType = ::GetRgnBox(childRegion, &bounds);
                check(boundsType != ERROR, "query content control region before footer overlap check");
                if (boundsType == NULLREGION) effective.SetRectEmpty();
                else effective = CRect(childRect.left + bounds.left, childRect.top + bounds.top,
                                       childRect.left + bounds.right, childRect.top + bounds.bottom);
            }
            ::DeleteObject(childRegion);
            const auto overlapsFooter = [&](const CRect& footer) {
                CRect overlap;
                return !effective.IsRectEmpty() && overlap.IntersectRect(effective, footer) &&
                    !overlap.IsRectEmpty();
            };
            if (overlapsFooter(saveRect) || overlapsFooter(cancelRect)) {
                fail(std::string(stage) + ": scrollable control overlaps fixed footer: " +
                     windowDiagnostics(id) + " save=" + std::to_string(saveRect.left) + "," +
                     std::to_string(saveRect.top) + "," + std::to_string(saveRect.right) + "," +
                     std::to_string(saveRect.bottom) + " cancel=" + std::to_string(cancelRect.left) + "," +
                     std::to_string(cancelRect.top) + "," + std::to_string(cancelRect.right) + "," +
                     std::to_string(cancelRect.bottom));
            }
        }
        LONG priorTop = std::numeric_limits<LONG>::min();
        LONG priorVisibleBottom = std::numeric_limits<LONG>::min();
        int aboveCount = 0, belowCount = 0, partialCount = 0, containedCount = 0;
        for (int id : ordered) {
            const CRect rect = clientRect(id);
            const CRect face = controlFaceRect(id);
            const CRect clippedFace = regionControlRect(id);
            const CRect visibleRect = visibleControlRect(id);
            const bool above = rect.bottom <= viewport.top;
            const bool below = rect.top >= viewport.bottom;
            const bool intersects = !above && !below;
            const bool partial = intersects && (rect.top < viewport.top || rect.bottom > viewport.bottom);
            const bool visible = dialog.GetDlgItem(id)->IsWindowVisible() != FALSE;
            const CRect expectedClip = face & viewport;
            const CRect expectedVisible = visible ? expectedClip :
                CRect(face.left, face.top, face.left, face.top);
            const bool regionMatches = clippedFace == expectedClip && visibleRect == expectedVisible;
            const auto failGeometry = [&]() {
                throw std::runtime_error(std::string(stage) + " pairing control geometry: id=" +
                    std::to_string(id) + " rect=(" + std::to_string(rect.left) + "," +
                    std::to_string(rect.top) + "," + std::to_string(rect.right) + "," +
                    std::to_string(rect.bottom) + ") viewport=(0,0," +
                    std::to_string(resizedClient.right) + "," + std::to_string(viewportBottom) +
                    ") scroll=" + std::to_string(scrollInfo.nPos) + "/" +
                    std::to_string(std::max(0, scrollInfo.nMax - static_cast<int>(scrollInfo.nPage) + 1)) +
                    " dpi=" + std::to_string(GetDpiForWindow(dialog.GetSafeHwnd())) +
                    " aboveViewport=" + (above ? "true" : "false") +
                    " intersectsViewport=" + (intersects ? "true" : "false") +
                    " belowViewport=" + (below ? "true" : "false") +
                    " expectedClip=(" + std::to_string(expectedClip.left) + "," +
                    std::to_string(expectedClip.top) + "," + std::to_string(expectedClip.right) + "," +
                    std::to_string(expectedClip.bottom) + ") clippedFace=(" +
                    std::to_string(clippedFace.left) + "," + std::to_string(clippedFace.top) + "," +
                    std::to_string(clippedFace.right) + "," + std::to_string(clippedFace.bottom) +
                    ") expectedVisible=(" + std::to_string(expectedVisible.left) + "," +
                    std::to_string(expectedVisible.top) + "," + std::to_string(expectedVisible.right) + "," +
                    std::to_string(expectedVisible.bottom) + ") visibleRect=(" +
                    std::to_string(visibleRect.left) + "," + std::to_string(visibleRect.top) + "," +
                    std::to_string(visibleRect.right) + "," + std::to_string(visibleRect.bottom) +
                    ") visible=" + (visible ? "true" : "false") +
                    " enabled=" + (dialog.GetDlgItem(id)->IsWindowEnabled() ? "true" : "false") +
                    " " + windowDiagnostics(id));
            };
            if (!(rect.left >= 0 && rect.right <= resizedClient.right && rect.top > priorTop &&
                rect.bottom > rect.top && regionMatches)) failGeometry();
            if (above) {
                ++aboveCount;
                if (!visibleRect.IsRectEmpty()) failGeometry();
            } else if (below) {
                ++belowCount;
                if (!visibleRect.IsRectEmpty()) failGeometry();
            } else if (partial) {
                ++partialCount;
                if (visible && (visibleRect.IsRectEmpty() || visibleRect.top < viewport.top ||
                    visibleRect.bottom > viewport.bottom)) failGeometry();
            } else {
                ++containedCount;
                if (visible && visibleRect.IsRectEmpty()) failGeometry();
            }
            if (visible && !visibleRect.IsRectEmpty()) {
                if (visibleRect.top < priorVisibleBottom) failGeometry();
                priorVisibleBottom = visibleRect.bottom;
            }
            priorTop = rect.top;
        }
        if (expectedPosition == 0) {
            check(belowCount > 0 && containedCount > 0,
                "top scroll position includes below-viewport and visible controls");
        } else if (expectedPosition >= scrollInfo.nMax - static_cast<int>(scrollInfo.nPage) + 1) {
            check(aboveCount > 0 && containedCount > 0,
                "maximum scroll position includes above-viewport and visible controls");
        } else {
            check(partialCount > 0, "intermediate scroll position exercises clipped partial visibility");
        }
        assertFooterVisible(stage, okBottomGap, cancelBottomGap);
    };

    SCROLLINFO currentScroll{sizeof(currentScroll), SIF_RANGE | SIF_PAGE | SIF_POS};
    dialog.GetScrollInfo(SB_VERT, &currentScroll);
    const int maxScroll = std::max(0, currentScroll.nMax - static_cast<int>(currentScroll.nPage) + 1);
    setScrollPosition(0);
    checkControlVisible(IDC_PAIR_ACCESS, "resized dialog at top scroll position", resizedViewport);
    assertFooterVisible("resized dialog at top scroll position", okBottomGap, cancelBottomGap);
    checkControlVisible(IDC_PAIR_ACCESS, "top scroll position", CRect(0, 0, resizedClient.right, viewportBottom));
    const CRect topHostname = clientRect(IDC_PAIR_TLS_HOSTNAME);
    const int partialScroll = static_cast<int>(std::clamp<LONG>(
        topHostname.top + topHostname.Height() / 2 - viewportBottom,
        1L, std::max<LONG>(1L, static_cast<LONG>(maxScroll) - 1L)));
    assertScrollGeometry("top", 0);
        check(visibleControlRect(IDC_PAIR_TLS_HOSTNAME).IsRectEmpty(),
                    "hostname below the top viewport has no visible region");
    assertScrollGeometry("intermediate", partialScroll);
    assertScrollGeometry("maximum", maxScroll);
    checkControlVisible(IDC_PAIR_TLS_HOSTNAME, "maximum scroll position",
                        CRect(0, 0, resizedClient.right, viewportBottom));
    check(!dialog.GetDlgItem(IDC_PAIR_SSHUSER)->IsWindowVisible(),
          "unapproved SSH account remains hidden independently of scrolling");

    setScrollPosition(0);
    CWnd* hostname = dialog.GetDlgItem(IDC_PAIR_TLS_HOSTNAME);
    ::SetFocus(hostname->GetSafeHwnd());
    dialog.SendMessage(WM_APP + 0x321);
    const CRect focusedHostname = clientRect(IDC_PAIR_TLS_HOSTNAME);
    const CRect focusedHostnameVisible = visibleControlRect(IDC_PAIR_TLS_HOSTNAME);
    dialog.GetScrollInfo(SB_VERT, &scrollInfo);
    check(scrollInfo.nPos > 0 && focusedHostname.top >= 0 && focusedHostname.bottom <= viewportBottom &&
            !focusedHostnameVisible.IsRectEmpty() && hostname->IsWindowVisible() &&
            focusedHostnameVisible == controlFaceRect(IDC_PAIR_TLS_HOSTNAME) &&
          ::GetFocus() == hostname->GetSafeHwnd(),
          "keyboard focus scrolls the off-screen hostname into the clipped viewport");
        assertFooterVisible("keyboard focus scrolling preserves Save and Cancel", okBottomGap, cancelBottomGap);
    check(resizedOk.left >= 0 && resizedOk.right <= resizedClient.right &&
          resizedCancel.left >= 0 && resizedCancel.right <= resizedClient.right,
          "pinned pairing buttons remain within the resized client bounds");
    assertFooterVisible("scrolled Save and Cancel remain visible in client coordinates",
                        okBottomGap, cancelBottomGap);
    dialog.SendMessage(WM_VSCROLL, SB_TOP);
    dialog.SetWindowPos(nullptr, originalWindow.left, originalWindow.top,
                        originalWindow.Width(), originalWindow.Height(),
                        SWP_NOZORDER | SWP_NOACTIVATE);
    RECT dpiBounds{originalWindow.left, originalWindow.top,
                   originalWindow.left + MulDiv(originalWindow.Width(), 144, initialDpi),
                   originalWindow.top + MulDiv(originalWindow.Height(), 144, initialDpi)};
    dialog.SendMessage(WM_DPICHANGED, MAKELONG(144, 144), reinterpret_cast<LPARAM>(&dpiBounds));
    const int dpiOkGap = MulDiv(okBottomGap, 144, initialDpi);
    const int dpiCancelGap = MulDiv(cancelBottomGap, 144, initialDpi);
    assertFooterVisible("DPI-scaled Save and Cancel remain visible in client coordinates",
                        dpiOkGap, dpiCancelGap);
    CRect dpiClient;
    dialog.GetClientRect(&dpiClient);
    checkControlVisible(IDC_PAIR_ACCESS, "144-DPI layout", CRect(0, 0, dpiClient.right, clientRect(IDOK).top - 6));
        check(clientRect(IDOK).Height() == MulDiv(initialOk.Height(), 144, initialDpi) &&
            clientRect(IDCANCEL).Height() == MulDiv(initialCancel.Height(), 144, initialDpi),
          "Save and Cancel heights scale with the simulated DPI");
    RECT restoredBounds{originalWindow.left, originalWindow.top,
                        originalWindow.right, originalWindow.bottom};
    dialog.SendMessage(WM_DPICHANGED, MAKELONG(initialDpi, initialDpi),
                       reinterpret_cast<LPARAM>(&restoredBounds));
    dialog.SetWindowPos(nullptr, originalWindow.left, originalWindow.top,
                        originalWindow.Width(), originalWindow.Height(),
                        SWP_NOZORDER | SWP_NOACTIVATE);
    assertFooterVisible("restored-DPI Save and Cancel remain visible in client coordinates",
                        initialOkGap, initialCancelGap);
    CRect restoredClient;
    dialog.GetClientRect(&restoredClient);
    checkControlVisible(IDC_PAIR_ACCESS, "restored DPI", CRect(0, 0, restoredClient.right, clientRect(IDOK).top - 6));
    check(dialog.GetNextDlgTabItem(dialog.GetDlgItem(IDC_PAIR_WORKSTATION))->GetDlgCtrlID() == IDC_PAIR_ACCESS,
          "Tab moves from workstation to access before generation");
    check(dialog.GetNextDlgTabItem(dialog.GetDlgItem(IDC_PAIR_ACCESS))->GetDlgCtrlID() == IDC_PAIR_GENERATE,
          "Tab moves from access to Generate");
    dialog.SetDlgItemText(IDC_PAIR_WORKSTATION, L"ADMIN-PC");
    dialog.OnGenerate();
    check(enabled(IDC_PAIR_COPY) && enabled(IDC_PAIR_RESPONSE) && !enabled(IDOK), "generated request enables copy not save");
    const auto first = request(dialog);
    check(first.at("schema").asString() == "teliphones-pair-request/3" && sshGenerated == 0, "web request uses v3 and needs no SSH key");
    const auto approvedWeb = response(first, false);
    const auto parsedWeb = tlp::ParsePairResponse(approvedWeb, first.at("nonce").asString(),
                                                first.at("public_key").asString());
    check(!parsedWeb.ssh && parsedWeb.sshUser.empty(), "web fixture validates without an SSH account");
    dialog.SetDlgItemText(IDC_PAIR_RESPONSE, tlp::win::Widen(approvedWeb).c_str());
    check(!enabled(IDOK), "multiline WM_SETTEXT does not notify response validation");
    dialog.SetDlgItemText(IDC_PAIR_RESPONSE, L"");
    replaceResponse(dialog, approvedWeb);
        check(enabled(IDOK) && !dialog.GetDlgItem(IDC_PAIR_SSHUSER)->IsWindowVisible()
            && text(dialog, IDC_PAIR_TLS_HOSTNAME) == "pbx.example.net",
            "valid v3 web approval populates hostname and enables save without SSH account");
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
        checkControlVisible(IDC_PAIR_ACCESS, "access option changed", initialViewport);
    dialog.OnGenerate();
    const auto sshRequest = request(dialog);
    check(sshRequest.at("schema").asString() == "teliphones-pair-request/3" &&
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
