#include "ConnectionHealthDlg.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <iterator>
#include <string>

#include "../core/Profiles.h"
#include "../platform/Win.h"
#include "resource.h"

using tlp::win::Widen;

namespace {

class CHealthThresholdsDlg : public CDialogEx {
public:
    explicit CHealthThresholdsDlg(tlp::HealthThresholds& thresholds, CWnd* parent)
        : CDialogEx(IDD_HEALTH_LIMITS, parent), thresholds_(thresholds), original_(thresholds) {}

protected:
    BOOL OnInitDialog() override {
        CDialogEx::OnInitDialog();
        const int latency[] = {200, 300, 500};
        const int jitter[] = {50, 100, 200};
        const int failures[] = {2, 3, 4};
        AddChoices(IDC_HEALTH_LIMIT_LATENCY, latency, std::size(latency), thresholds_.warningLatencyMs);
        AddChoices(IDC_HEALTH_LIMIT_JITTER, jitter, std::size(jitter), thresholds_.warningJitterMs);
        AddChoices(IDC_HEALTH_LIMIT_FAILURES, failures, std::size(failures), thresholds_.consecutiveFailures);
        return TRUE;
    }

    void OnOK() override {
        if (!Read(IDC_HEALTH_LIMIT_LATENCY, thresholds_.warningLatencyMs) ||
            !Read(IDC_HEALTH_LIMIT_JITTER, thresholds_.warningJitterMs) ||
            !Read(IDC_HEALTH_LIMIT_FAILURES, thresholds_.consecutiveFailures)) {
            thresholds_ = original_;
            AfxMessageBox(L"Choose a value for each health threshold.", MB_ICONWARNING);
            return;
        }
        CDialogEx::OnOK();
    }

    void OnCancel() override {
        thresholds_ = original_;
        CDialogEx::OnCancel();
    }

private:
    template <std::size_t N>
    void AddChoices(int id, const int (&values)[N], std::size_t count, int selected) {
        CComboBox* combo = static_cast<CComboBox*>(GetDlgItem(id));
        for (std::size_t i = 0; i < count; ++i) {
            CString text;
            if (id == IDC_HEALTH_LIMIT_FAILURES) text.Format(L"%d consecutive checks", values[i]);
            else text.Format(L"%d ms", values[i]);
            int row = combo->AddString(text);
            combo->SetItemData(row, static_cast<DWORD_PTR>(values[i]));
            if (values[i] == selected) combo->SetCurSel(row);
        }
    }

    bool Read(int id, int& value) {
        CComboBox* combo = static_cast<CComboBox*>(GetDlgItem(id));
        int row = combo->GetCurSel();
        if (row < 0) return false;
        value = static_cast<int>(combo->GetItemData(row));
        return true;
    }

    tlp::HealthThresholds& thresholds_;
    tlp::HealthThresholds original_;
};

std::string measurement(const std::optional<double>& value, const char* suffix) {
    if (!value) return "Unknown";
    char text[64]{};
    std::snprintf(text, sizeof(text), "%.0f %s", *value, suffix);
    return text;
}

std::string rate(const std::optional<double>& bytesPerSecond) {
    if (!bytesPerSecond) return "Unknown";
    double value = *bytesPerSecond;
    const char* unit = "B/s";
    if (value >= 1024.0 * 1024.0) {
        value /= 1024.0 * 1024.0;
        unit = "MiB/s";
    } else if (value >= 1024.0) {
        value /= 1024.0;
        unit = "KiB/s";
    }
    char text[64]{};
    std::snprintf(text, sizeof(text), "%.1f %s", value, unit);
    return text;
}

}  // namespace

BEGIN_MESSAGE_MAP(CConnectionHealthDlg, CDialogEx)
    ON_WM_CLOSE()
    ON_WM_SIZE()
    ON_CBN_SELCHANGE(IDC_HEALTH_HISTORY, &CConnectionHealthDlg::OnHistoryChanged)
    ON_BN_CLICKED(IDC_HEALTH_TOPMOST, &CConnectionHealthDlg::OnTopmostChanged)
    ON_BN_CLICKED(IDC_HEALTH_THRESHOLDS, &CConnectionHealthDlg::OnThresholds)
    ON_WM_DRAWITEM()
    ON_WM_CTLCOLOR()
END_MESSAGE_MAP()

CConnectionHealthDlg::CConnectionHealthDlg(CWnd* parent) : CDialogEx(IDD_CONNECTION_HEALTH, parent) {}

void CConnectionHealthDlg::DoDataExchange(CDataExchange* exchange) {
    CDialogEx::DoDataExchange(exchange);
    DDX_Control(exchange, IDC_HEALTH_HISTORY, history_);
    DDX_Control(exchange, IDC_HEALTH_TOPMOST, topmost_);
}

BOOL CConnectionHealthDlg::OnInitDialog() {
    CDialogEx::OnInitDialog();
    history_.AddString(L"60 seconds");
    history_.AddString(L"5 minutes");
    history_.SetCurSel(preferences_.historySeconds == 300 ? 1 : 0);
    topmost_.SetCheck(preferences_.alwaysOnTop ? BST_CHECKED : BST_UNCHECKED);
    ApplyTopmost();
    RefreshText();
    CRect client;
    GetClientRect(&client);
    LayoutGraph(client.Width(), client.Height());
    if (preferences_.windowWidth > 0 && preferences_.windowHeight > 0) {
        CRect current;
        GetWindowRect(&current);
        int width = preferences_.windowWidth > 0 ? preferences_.windowWidth : current.Width();
        int height = preferences_.windowHeight > 0 ? preferences_.windowHeight : current.Height();
        CRect saved(preferences_.windowX, preferences_.windowY, preferences_.windowX + width, preferences_.windowY + height);
        HMONITOR monitor = MonitorFromRect(&saved, MONITOR_DEFAULTTONULL);
        if (monitor != nullptr) {
            SetWindowPos(nullptr, saved.left, saved.top, saved.Width(), saved.Height(), SWP_NOZORDER);
        }
    }
    return TRUE;
}

bool CConnectionHealthDlg::CreateMonitor() {
    if (GetSafeHwnd()) return true;
    if (!Create(IDD_CONNECTION_HEALTH, GetParent())) return false;
    return true;
}

void CConnectionHealthDlg::ShowMonitor() {
    if (!CreateMonitor()) throw tlp::Error("The Connection Health monitor could not be opened.");
    ShowWindow(SW_SHOW);
    SetForegroundWindow();
}

void CConnectionHealthDlg::UpdateSnapshot(const tlp::HealthSnapshot& snapshot) {
    snapshot_ = snapshot;
    RefreshText();
    if (GetSafeHwnd() && IsWindowVisible()) GetDlgItem(IDC_HEALTH_GRAPH)->Invalidate(FALSE);
}

void CConnectionHealthDlg::SetPreferences(const tlp::HealthPreferences& preferences) {
    preferences_ = preferences;
    if (GetSafeHwnd()) {
        history_.SetCurSel(preferences_.historySeconds == 300 ? 1 : 0);
        topmost_.SetCheck(preferences_.alwaysOnTop ? BST_CHECKED : BST_UNCHECKED);
        ApplyTopmost();
    }
}

void CConnectionHealthDlg::OnOK() { PersistWindowState(); ShowWindow(SW_HIDE); }
void CConnectionHealthDlg::OnCancel() { PersistWindowState(); ShowWindow(SW_HIDE); }

void CConnectionHealthDlg::OnClose() {
    SaveWindowPosition();
    SavePreferences();
    ShowWindow(SW_HIDE);
}

void CConnectionHealthDlg::OnSize(UINT type, int cx, int cy) {
    CDialogEx::OnSize(type, cx, cy);
    if (type != SIZE_MINIMIZED && GetDlgItem(IDC_HEALTH_GRAPH)) LayoutGraph(cx, cy);
}

void CConnectionHealthDlg::LayoutGraph(int width, int height) {
    CWnd* graph = GetDlgItem(IDC_HEALTH_GRAPH);
    if (graph == nullptr) return;
    CRect graphDlu(7, 68, 153, 84);
    CRect bottomMarginDlu(0, 0, 0, 2);
    CRect rightMarginDlu(0, 0, 6, 0);
    CRect historyDlu(7, 98, 55, 110);
    CRect topmostDlu(58, 98, 104, 110);
    CRect limitsDlu(107, 96, 153, 110);
    CRect warningDlu(7, 85, 153, 96);
    CRect warningGapDlu(0, 0, 0, 1);
    MapDialogRect(&graphDlu);
    MapDialogRect(&bottomMarginDlu);
    MapDialogRect(&rightMarginDlu);
    MapDialogRect(&historyDlu);
    MapDialogRect(&topmostDlu);
    MapDialogRect(&limitsDlu);
    MapDialogRect(&warningDlu);
    MapDialogRect(&warningGapDlu);
    int bottomMargin = bottomMarginDlu.bottom;
    int historyTop = height - bottomMargin - historyDlu.Height();
    int topmostTop = height - bottomMargin - topmostDlu.Height();
    int limitsTop = height - bottomMargin - limitsDlu.Height();
    int warningBottom = std::min({historyTop, topmostTop, limitsTop}) - warningGapDlu.bottom;
    int warningTop = warningBottom - warningDlu.Height();
    int graphBottom = warningTop - warningGapDlu.bottom;
    graph->SetWindowPos(nullptr, graphDlu.left, graphDlu.top, std::max<int>(80, static_cast<int>(width - graphDlu.left * 2)),
                        std::max<int>(30, static_cast<int>(graphBottom - graphDlu.top)), SWP_NOZORDER);
    GetDlgItem(IDC_HEALTH_WARNING)->SetWindowPos(nullptr, warningDlu.left, warningTop, std::max<int>(80, static_cast<int>(width - warningDlu.left * 2)),
                                                  warningDlu.Height(), SWP_NOZORDER);
    GetDlgItem(IDC_HEALTH_HISTORY)->SetWindowPos(nullptr, historyDlu.left, historyTop, historyDlu.Width(), historyDlu.Height(), SWP_NOZORDER);
    GetDlgItem(IDC_HEALTH_TOPMOST)->SetWindowPos(nullptr, topmostDlu.left, topmostTop, topmostDlu.Width(), topmostDlu.Height(), SWP_NOZORDER);
    GetDlgItem(IDC_HEALTH_THRESHOLDS)->SetWindowPos(nullptr, width - limitsDlu.Width() - rightMarginDlu.right, limitsTop,
                                                    limitsDlu.Width(), limitsDlu.Height(), SWP_NOZORDER);
}

void CConnectionHealthDlg::OnHistoryChanged() {
    preferences_.historySeconds = history_.GetCurSel() == 1 ? 300 : 60;
    SavePreferences();
}

void CConnectionHealthDlg::OnTopmostChanged() {
    preferences_.alwaysOnTop = topmost_.GetCheck() == BST_CHECKED;
    ApplyTopmost();
    SavePreferences();
}

void CConnectionHealthDlg::OnThresholds() {
    CHealthThresholdsDlg dialog(preferences_.thresholds, this);
    if (dialog.DoModal() == IDOK) SavePreferences();
}

void CConnectionHealthDlg::OnDrawItem(int controlId, LPDRAWITEMSTRUCT drawItem) {
    if (controlId != IDC_HEALTH_GRAPH || drawItem == nullptr) {
        CDialogEx::OnDrawItem(controlId, drawItem);
        return;
    }
    CDC dc;
    dc.Attach(drawItem->hDC);
    CRect rect(drawItem->rcItem);
    dc.FillSolidRect(rect, RGB(250, 250, 250));
    CPen grid(PS_SOLID, 1, RGB(220, 225, 230));
    CPen* oldPen = dc.SelectObject(&grid);
    for (int line = 1; line < 4; ++line) {
        int y = rect.top + rect.Height() * line / 4;
        dc.MoveTo(rect.left, y);
        dc.LineTo(rect.right, y);
    }
    dc.SelectObject(oldPen);

    const std::int64_t now = static_cast<std::int64_t>(GetTickCount64());
    const std::int64_t range = static_cast<std::int64_t>(preferences_.historySeconds) * 1000;
    double maximumLatency = std::max(500.0, preferences_.thresholds.warningLatencyMs * 2.0);
    for (const auto& sample : snapshot_.samples) if (sample.latencyMs) maximumLatency = std::max(maximumLatency, *sample.latencyMs * 1.15);
    CPen latency(PS_SOLID, 2, RGB(30, 110, 190));
    CPen failure(PS_SOLID, 2, RGB(190, 45, 45));
    bool previous = false;
    for (const auto& sample : snapshot_.samples) {
        std::int64_t age = now - sample.timestampMs;
        if (age < 0 || age > range) continue;
        int x = rect.left + rect.Width() - static_cast<int>((static_cast<double>(age) / range) * rect.Width());
        if (sample.probeKnown && !sample.probeSucceeded) {
            dc.SelectObject(&failure);
            dc.MoveTo(x - 3, rect.bottom - 8);
            dc.LineTo(x + 3, rect.bottom - 2);
            dc.MoveTo(x - 3, rect.bottom - 2);
            dc.LineTo(x + 3, rect.bottom - 8);
            previous = false;
        } else if (sample.probeSucceeded && sample.latencyMs) {
            int y = rect.bottom - 8 - static_cast<int>(std::min(1.0, *sample.latencyMs / maximumLatency) * (rect.Height() - 16));
            CPoint point(x, y);
            dc.SelectObject(&latency);
            if (previous) dc.LineTo(point);
            else dc.MoveTo(point);
            previous = true;
        } else {
            previous = false;
        }
    }
    dc.SelectObject(oldPen);
    dc.Detach();
}

HBRUSH CConnectionHealthDlg::OnCtlColor(CDC* dc, CWnd* window, UINT controlColor) {
    HBRUSH brush = CDialogEx::OnCtlColor(dc, window, controlColor);
    if (controlColor == CTLCOLOR_STATIC && window->GetDlgCtrlID() == IDC_HEALTH_STATE) {
        COLORREF color = RGB(100, 100, 100);
        switch (snapshot_.state) {
            case tlp::HealthState::Stable: color = RGB(20, 120, 55); break;
            case tlp::HealthState::Degraded: color = RGB(170, 105, 0); break;
            case tlp::HealthState::Unstable:
            case tlp::HealthState::Disconnected: color = RGB(180, 35, 35); break;
            case tlp::HealthState::Unknown: break;
        }
        dc->SetTextColor(color);
        dc->SetBkMode(TRANSPARENT);
    }
    return brush;
}

void CConnectionHealthDlg::SaveWindowPosition() {
    if (!GetSafeHwnd() || IsIconic()) return;
    CRect rect;
    GetWindowRect(&rect);
    preferences_.windowX = rect.left;
    preferences_.windowY = rect.top;
    preferences_.windowWidth = rect.Width();
    preferences_.windowHeight = rect.Height();
}

void CConnectionHealthDlg::PersistWindowState() {
    SaveWindowPosition();
    SavePreferences();
}

void CConnectionHealthDlg::SavePreferences() {
    if (preferencesChanged) preferencesChanged(preferences_);
}

void CConnectionHealthDlg::ApplyTopmost() {
    if (!GetSafeHwnd()) return;
    SetWindowPos(preferences_.alwaysOnTop ? &wndTopMost : &wndNoTopMost, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
}

void CConnectionHealthDlg::RefreshText() {
    if (!GetSafeHwnd()) return;
    std::string state = tlp::HealthStateName(snapshot_.state);
    if (snapshot_.continuouslyHealthySeconds) state += " | healthy " + tlp::FormatRemaining(*snapshot_.continuouslyHealthySeconds);
    state += " | fails " + std::to_string(snapshot_.consecutiveFailures);
    SetDlgItemText(IDC_HEALTH_STATE, Widen(state).c_str());
    std::string auth = "Authorization: ";
    if (snapshot_.authorizationRemainingSeconds) {
        auth += *snapshot_.authorizationRemainingSeconds <= 0 ? "expired" : tlp::FormatRemaining(*snapshot_.authorizationRemainingSeconds) + " remaining";
    } else {
        auth += "persistent / revoked by administrator";
    }
    SetDlgItemText(IDC_HEALTH_AUTH, Widen(auth).c_str());

    std::string latency = measurement(snapshot_.latencyMs, "ms");
    std::string jitter = measurement(snapshot_.jitterMs, "ms");
    SetDlgItemText(IDC_HEALTH_LATENCY, Widen("TCP RTT: " + latency + "   Jitter: " + jitter).c_str());
    std::string success = snapshot_.probeSuccessPercent ? measurement(snapshot_.probeSuccessPercent, "%") : "Unknown";
    std::string failure = snapshot_.probeFailurePercent ? measurement(snapshot_.probeFailurePercent, "%") : "Unknown";
    SetDlgItemText(IDC_HEALTH_PROBES, Widen("App probes: " + success + " ok / " + failure + " failed").c_str());
    std::string rates = "Rx " + rate(snapshot_.receiveBytesPerSecond) + " Tx " + rate(snapshot_.transmitBytesPerSecond) + " HS ";
    rates += snapshot_.handshakeAgeSeconds ? std::to_string(*snapshot_.handshakeAgeSeconds) + "s" : "Unknown";
    SetDlgItemText(IDC_HEALTH_TRAFFIC, Widen(rates).c_str());
    std::string warning = "Probes != packet loss; bandwidth not measured.";
    if (snapshot_.consecutiveFailures > 0) {
        warning = std::to_string(snapshot_.consecutiveFailures) + " app failures; not packet loss; SSH stays open.";
    } else if (snapshot_.deterioration) {
        warning = "Latency/probe trend worsening; congestion not measured.";
    }
    SetDlgItemText(IDC_HEALTH_WARNING, Widen(warning).c_str());
    if (GetSafeHwnd() && GetDlgItem(IDC_HEALTH_GRAPH)) GetDlgItem(IDC_HEALTH_GRAPH)->Invalidate(FALSE);
}
