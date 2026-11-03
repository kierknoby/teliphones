#include "ConnectionHealthDlg.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <iterator>
#include <string>
#include <vector>

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

std::string authorization(const tlp::HealthSnapshot& snapshot) {
    std::string text = tlp::AuthorizationRemainingText(snapshot);
    if (!snapshot.authorizationKnown || snapshot.authorizationPersistent) return text;
    if (snapshot.authorizationExpiresAt > 0) {
        const __time64_t expiry = snapshot.authorizationExpiresAt;
        tm utc{};
        if (_gmtime64_s(&utc, &expiry) == 0) {
            char date[48]{};
            std::strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S UTC", &utc);
            text += " (expires " + std::string(date) + ")";
        }
    }
    return text;
}

bool valid(const std::optional<double>& value) {
    return value && std::isfinite(*value) && *value >= 0;
}

double niceMaximum(double value, double minimum) {
    value = std::max(value * 1.1, minimum);
    const double magnitude = std::pow(10.0, std::floor(std::log10(value)));
    const double fraction = value / magnitude;
    return (fraction <= 1 ? 1 : fraction <= 2 ? 2 : fraction <= 5 ? 5 : 10) * magnitude;
}

void graphText(CDC& dc, CRect rect, const std::string& text, UINT alignment = DT_LEFT) {
    CString wide(Widen(text).c_str());
    dc.DrawText(wide, &rect, alignment | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
}

}  // namespace

std::string ConnectionHealthSummary(const tlp::HealthSnapshot& snapshot) {
    std::string text = tlp::ConnectedDurationText(snapshot) + " | Authorisation remaining: " + authorization(snapshot);
    text += "\r\n" + tlp::HealthyDurationText(snapshot);
    text += "\r\nTCP RTT: " + measurement(snapshot.latencyMs, "ms") +
        " | Jitter: " + measurement(snapshot.jitterMs, "ms") +
        " | Failed probes: " + measurement(snapshot.probeFailurePercent, "%") +
        " (" + std::to_string(snapshot.consecutiveFailures) + " consecutive)";
    text += "\r\nRx (download): " + rate(snapshot.receiveBytesPerSecond) +
        " | Tx (upload): " + rate(snapshot.transmitBytesPerSecond) + " | Handshake: ";
    text += snapshot.handshakeAgeSeconds ? std::to_string(*snapshot.handshakeAgeSeconds) + " s ago" : "Unknown";
    text += " | Traffic source: " + (snapshot.trafficSource.empty() ? std::string("Unknown") : snapshot.trafficSource);
    if (!snapshot.telemetryReason.empty()) text += "\r\nTelemetry: " + snapshot.telemetryReason;
    return text;
}

void DrawConnectionHealthGraph(CDC& dc, const CRect& rect, const tlp::HealthSnapshot& snapshot, int historySeconds) {
    const int saved = dc.SaveDC();
    dc.IntersectClipRect(rect);
    dc.FillSolidRect(rect, RGB(250, 252, 254));
    dc.SetBkMode(TRANSPARENT);
    dc.SetTextColor(RGB(40, 50, 65));
    dc.SelectStockObject(DEFAULT_GUI_FONT);
    TEXTMETRIC metrics{};
    dc.GetTextMetrics(&metrics);
    const int line = static_cast<int>(metrics.tmHeight) + 2;
    if (rect.Width() < 200 || rect.Height() < line * 7) {
        graphText(dc, rect, "Enlarge the monitor to view connection history.");
        dc.RestoreDC(saved);
        return;
    }
    historySeconds = historySeconds == 300 ? 300 : 60;
    const std::int64_t now = snapshot.snapshotTimestampMs > 0 ? snapshot.snapshotTimestampMs :
        (snapshot.samples.empty() ? static_cast<std::int64_t>(GetTickCount64()) : snapshot.samples.back().timestampMs);
    const std::int64_t range = static_cast<std::int64_t>(historySeconds) * 1000;
    const int left = static_cast<int>(rect.left) + std::max<int>(58, static_cast<int>(dc.GetTextExtent(L"999.9 MiB/s").cx) + 6);
    const int right = static_cast<int>(rect.right) - 12;
    const int plotHeight = (rect.Height() - line * 5 - 8) / 2;
    const int top = static_cast<int>(rect.top) + line + 2;
    const CRect latencyPlot(left, top, right, top + plotHeight);
    const CRect trafficPlot(left, latencyPlot.bottom + line + 6, right,
        latencyPlot.bottom + line + 6 + plotHeight);
    auto xAt = [&](std::int64_t time) {
        const double fraction = std::clamp(static_cast<double>(time - now + range) / range, 0.0, 1.0);
        return left + static_cast<int>(fraction * (right - left));
    };
    auto visible = [&](std::int64_t time) { return time >= now - range && time <= now; };

    struct TrafficPoint {
        std::int64_t time;
        double rx;
        double tx;
        bool join;
    };
    std::vector<TrafficPoint> traffic;
    const tlp::HealthSample* previous = nullptr;
    bool joinTraffic = false;
    double maxLatency = 0, maxTraffic = 0;
    for (const auto& sample : snapshot.samples) {
        if (visible(sample.timestampMs) && sample.probeKnown && sample.probeSucceeded && valid(sample.latencyMs))
            maxLatency = std::max(maxLatency, *sample.latencyMs);
        if (sample.tunnelKnown && !sample.tunnelRunning) {
            previous = nullptr;
            joinTraffic = false;
            continue;
        }
        if (!sample.receivedBytes || !sample.transmittedBytes) {
            previous = nullptr;
            joinTraffic = false;
            continue;
        }
        const auto time = sample.telemetryTimestampMs > 0 ? sample.telemetryTimestampMs : sample.timestampMs;
        if (previous != nullptr) {
            const auto priorTime = previous->telemetryTimestampMs > 0 ? previous->telemetryTimestampMs : previous->timestampMs;
            if (time == priorTime) continue;  // Cached counters are not new measurements.
            if (sample.trafficSource == previous->trafficSource &&
                time > priorTime && time - priorTime <= tlp::ConnectionHealthMonitor::kTelemetryIntervalSeconds * 3000LL &&
                *sample.receivedBytes >= *previous->receivedBytes && *sample.transmittedBytes >= *previous->transmittedBytes) {
                const double seconds = static_cast<double>(time - priorTime) / 1000;
                const double rx = static_cast<double>(*sample.receivedBytes - *previous->receivedBytes) / seconds;
                const double tx = static_cast<double>(*sample.transmittedBytes - *previous->transmittedBytes) / seconds;
                if (visible(time)) {
                    traffic.push_back({time, rx, tx, joinTraffic});
                    maxTraffic = std::max({maxTraffic, rx, tx});
                    joinTraffic = true;
                }
            } else {
                joinTraffic = false;
            }
        }
        previous = &sample;
    }
    maxLatency = niceMaximum(maxLatency, 10);
    maxTraffic = niceMaximum(maxTraffic, 1024);
    double divisor = 1;
    std::string trafficUnit = "B/s";
    if (maxTraffic >= 1024 * 1024) { divisor = 1024 * 1024; trafficUnit = "MiB/s"; }
    else if (maxTraffic >= 1024) { divisor = 1024; trafficUnit = "KiB/s"; }
    CPen grid(PS_SOLID, 1, RGB(219, 225, 233));
    auto axes = [&](const CRect& plot, double maximum, const std::string& unit) {
        dc.SelectObject(&grid);
        for (int tick = 0; tick <= 2; ++tick) {
            const int y = static_cast<int>(plot.bottom) - tick * plot.Height() / 2;
            dc.MoveTo(plot.left, y);
            dc.LineTo(plot.right, y);
            char label[48]{};
            std::snprintf(label, sizeof(label), "%.3g %s", maximum * tick / 2, unit.c_str());
            graphText(dc, CRect(rect.left, y - line / 2, plot.left - 5, y + line / 2 + 1), label, DT_RIGHT);
        }
        for (int tick = 0; tick <= 4; ++tick) {
            const int x = static_cast<int>(plot.left) + plot.Width() * tick / 4;
            dc.MoveTo(x, plot.top);
            dc.LineTo(x, plot.bottom);
        }
    };
    axes(latencyPlot, maxLatency, "ms");
    axes(trafficPlot, maxTraffic / divisor, trafficUnit);
    graphText(dc, CRect(left, rect.top, right, top), "TCP latency  |  X failed probe  |  D tunnel down / R up  |  grey ticks: missing");
    graphText(dc, CRect(left, latencyPlot.bottom + 3, right, trafficPlot.top), "Traffic: Rx download = blue solid   |   Tx upload = orange dashed");

    CPen latencyPen(PS_SOLID, 2, RGB(112, 62, 165));
    CPen failurePen(PS_SOLID, 2, RGB(190, 40, 45));
    CPen missingPen(PS_SOLID, 1, RGB(135, 140, 150));
    CPen downPen(PS_DOT, 1, RGB(185, 45, 50));
    CPen upPen(PS_DOT, 1, RGB(30, 125, 70));
    bool connectedPoint = false, haveLatency = false;
    std::optional<bool> lastTunnel;
    std::int64_t previousTime = 0;
    for (const auto& sample : snapshot.samples) {
        if (sample.timestampMs > now) continue;
        if (!visible(sample.timestampMs)) {
            lastTunnel = sample.tunnelKnown ? std::optional<bool>(sample.tunnelRunning) : std::nullopt;
            continue;
        }
        const int x = xAt(sample.timestampMs);
        if (sample.tunnelKnown && (!lastTunnel || *lastTunnel != sample.tunnelRunning)) {
            dc.SelectObject(sample.tunnelRunning ? &upPen : &downPen);
            dc.MoveTo(x, latencyPlot.top);
            dc.LineTo(x, trafficPlot.bottom);
            dc.SetTextColor(sample.tunnelRunning ? RGB(30, 125, 70) : RGB(185, 45, 50));
            graphText(dc, CRect(x - 6, latencyPlot.top, x + 12, latencyPlot.top + line), sample.tunnelRunning ? "R" : "D");
            dc.SetTextColor(RGB(40, 50, 65));
            connectedPoint = false;
        }
        lastTunnel = sample.tunnelKnown ? std::optional<bool>(sample.tunnelRunning) : std::nullopt;
        if (sample.probeKnown && !sample.probeSucceeded) {
            dc.SelectObject(&failurePen);
            const int y = static_cast<int>(latencyPlot.bottom) - 4;
            dc.MoveTo(x - 3, y - 3); dc.LineTo(x + 4, y + 4);
            dc.MoveTo(x - 3, y + 3); dc.LineTo(x + 4, y - 4);
            connectedPoint = false;
        } else if (sample.probeKnown && sample.probeSucceeded && valid(sample.latencyMs) &&
                   !(sample.tunnelKnown && !sample.tunnelRunning)) {
            const int y = static_cast<int>(latencyPlot.bottom) - static_cast<int>(*sample.latencyMs / maxLatency * latencyPlot.Height());
            dc.SelectObject(&latencyPen);
            if (connectedPoint && sample.timestampMs > previousTime &&
                sample.timestampMs - previousTime <= tlp::ConnectionHealthMonitor::kSampleIntervalSeconds * 3000LL) {
                dc.LineTo(x, y);
            } else {
                dc.MoveTo(x, y);
            }
            dc.FillSolidRect(x - 1, y - 1, 3, 3, RGB(112, 62, 165));
            connectedPoint = true;
            haveLatency = true;
        } else {
            dc.SelectObject(&missingPen);
            dc.MoveTo(x, latencyPlot.bottom - 3); dc.LineTo(x, latencyPlot.bottom);
            connectedPoint = false;
        }
        previousTime = sample.timestampMs;
    }
    dc.SelectObject(&missingPen);
    for (const auto& sample : snapshot.samples) {
        if (visible(sample.timestampMs) && sample.wireGuardTelemetryAttempted &&
            (!sample.receivedBytes || !sample.transmittedBytes)) {
            const int x = xAt(sample.timestampMs);
            dc.MoveTo(x, trafficPlot.bottom - 3);
            dc.LineTo(x, trafficPlot.bottom);
        }
    }
    CPen rxPen(PS_SOLID, 2, RGB(20, 105, 185));
    CPen txPen(PS_DASH, 1, RGB(195, 95, 10));
    for (int direction = 0; direction < 2; ++direction) {
        dc.SelectObject(direction == 0 ? &rxPen : &txPen);
        bool havePrevious = false;
        for (const auto& point : traffic) {
            const int x = xAt(point.time);
            const double value = direction == 0 ? point.rx : point.tx;
            const int y = static_cast<int>(trafficPlot.bottom) - static_cast<int>(value / maxTraffic * trafficPlot.Height());
            if (havePrevious && point.join) dc.LineTo(x, y);
            else dc.MoveTo(x, y);
            if (direction == 0) dc.FillSolidRect(x - 1, y - 1, 3, 3, RGB(20, 105, 185));
            else {
                dc.MoveTo(x - 2, y - 2); dc.LineTo(x + 3, y + 3);
                dc.MoveTo(x, y);
            }
            havePrevious = true;
        }
    }
    if (!haveLatency) graphText(dc, latencyPlot, "No successful latency measurements in this window", DT_CENTER);
    if (traffic.empty()) graphText(dc, trafficPlot, "Traffic unavailable: awaiting two current counter readings", DT_CENTER);
    const int timeTop = static_cast<int>(trafficPlot.bottom) + 2;
    graphText(dc, CRect(left, timeTop, left + 90, timeTop + line),
        historySeconds == 300 ? "-5 min" : "-60 s");
    graphText(dc, CRect((left + right) / 2 - 45, timeTop, (left + right) / 2 + 45, timeTop + line),
        historySeconds == 300 ? "-2.5 min" : "-30 s", DT_CENTER);
    graphText(dc, CRect(right - 90, timeTop, right, timeTop + line), "Now", DT_RIGHT);
    graphText(dc, CRect(left, timeTop + line, right, rect.bottom),
        "Time before latest snapshot | gaps are unknown, not zero | probes are not packet loss", DT_CENTER);
    dc.RestoreDC(saved);
}

BEGIN_MESSAGE_MAP(CConnectionHealthDlg, CDialogEx)
    ON_WM_CLOSE()
    ON_WM_SIZE()
    ON_WM_GETMINMAXINFO()
    ON_CBN_SELCHANGE(IDC_HEALTH_HISTORY, &CConnectionHealthDlg::OnHistoryChanged)
    ON_BN_CLICKED(IDC_HEALTH_TOPMOST, &CConnectionHealthDlg::OnTopmostChanged)
    ON_BN_CLICKED(IDC_HEALTH_THRESHOLDS, &CConnectionHealthDlg::OnThresholds)
    ON_WM_DRAWITEM()
    ON_WM_CTLCOLOR()
END_MESSAGE_MAP()

CConnectionHealthDlg::CConnectionHealthDlg(CWnd* parent) : CDialogEx(IDD_CONNECTION_HEALTH, parent), owner_(parent) {}

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
    return TRUE;
}

bool CConnectionHealthDlg::CreateMonitor() {
    if (GetSafeHwnd()) return true;
    if (owner_ == nullptr || !::IsWindow(owner_->GetSafeHwnd())) {
        throw tlp::Error("The Connection Health monitor requires an active TELIPHONES owner window.");
    }
    // GetParent() cannot resolve an owner before this modeless dialog has an HWND.
    if (!Create(IDD_CONNECTION_HEALTH, owner_)) return false;
    return true;
}

void CConnectionHealthDlg::ShowMonitor() {
    if (GetSafeHwnd() && IsWindowVisible() && !IsIconic()) SaveWindowPosition();
    if (!CreateMonitor()) throw tlp::Error("The Connection Health monitor could not be opened.");
    EnsureVisiblePosition();
    ShowWindow(IsIconic() ? SW_RESTORE : SW_SHOW);
    BringWindowToTop();
    SetForegroundWindow();
}

void CConnectionHealthDlg::EnsureVisiblePosition() {
    CRect position;
    GetWindowRect(&position);
    if (preferences_.windowWidth > 0 && preferences_.windowHeight > 0) {
        position.SetRect(preferences_.windowX, preferences_.windowY,
            preferences_.windowX + preferences_.windowWidth, preferences_.windowY + preferences_.windowHeight);
    }
    HMONITOR monitor = MonitorFromRect(&position, MONITOR_DEFAULTTONULL);
    if (monitor == nullptr) monitor = MonitorFromWindow(owner_->GetSafeHwnd(), MONITOR_DEFAULTTONEAREST);
    MONITORINFO display{};
    display.cbSize = sizeof(display);
    if (!GetMonitorInfo(monitor, &display)) tlp::win::ThrowLastError("Read Connection Health display work area");
    MINMAXINFO limits{};
    OnGetMinMaxInfo(&limits);
    const auto placement = tlp::FitHealthWindow(
        {static_cast<int>(position.left), static_cast<int>(position.top), position.Width(), position.Height()},
        {static_cast<int>(display.rcWork.left), static_cast<int>(display.rcWork.top),
         static_cast<int>(display.rcWork.right - display.rcWork.left), static_cast<int>(display.rcWork.bottom - display.rcWork.top)},
        static_cast<int>(limits.ptMinTrackSize.x), static_cast<int>(limits.ptMinTrackSize.y));
    if (IsIconic()) {
        WINDOWPLACEMENT saved{};
        saved.length = sizeof(saved);
        if (!GetWindowPlacement(&saved)) tlp::win::ThrowLastError("Read Connection Health window placement");
        // WINDOWPLACEMENT uses workspace coordinates for non-tool top-level windows.
        const int offsetX = static_cast<int>(display.rcWork.left - display.rcMonitor.left);
        const int offsetY = static_cast<int>(display.rcWork.top - display.rcMonitor.top);
        saved.rcNormalPosition = {placement.x - offsetX, placement.y - offsetY,
            placement.x + placement.width - offsetX, placement.y + placement.height - offsetY};
        if (!SetWindowPlacement(&saved)) tlp::win::ThrowLastError("Restore Connection Health window placement");
    } else if (!SetWindowPos(nullptr, placement.x, placement.y, placement.width, placement.height, SWP_NOZORDER | SWP_NOACTIVATE)) {
        tlp::win::ThrowLastError("Position Connection Health window");
    }
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
        GetDlgItem(IDC_HEALTH_GRAPH)->Invalidate(FALSE);
    }
}

void CConnectionHealthDlg::OnOK() { PersistWindowState(); ShowWindow(SW_HIDE); }
void CConnectionHealthDlg::OnCancel() { PersistWindowState(); ShowWindow(SW_HIDE); }

void CConnectionHealthDlg::OnClose() {
    OnCancel();
}

void CConnectionHealthDlg::OnSize(UINT type, int cx, int cy) {
    CDialogEx::OnSize(type, cx, cy);
    if (type != SIZE_MINIMIZED && GetDlgItem(IDC_HEALTH_GRAPH)) LayoutGraph(cx, cy);
}

void CConnectionHealthDlg::OnGetMinMaxInfo(MINMAXINFO* info) {
    CDialogEx::OnGetMinMaxInfo(info);
    if (!GetSafeHwnd()) return;
    CRect minimum(0, 0, 440, 300);
    MapDialogRect(&minimum);
    AdjustWindowRectEx(&minimum, static_cast<DWORD>(GetStyle()), FALSE, static_cast<DWORD>(GetExStyle()));
    info->ptMinTrackSize.x = minimum.Width();
    info->ptMinTrackSize.y = minimum.Height();
}

void CConnectionHealthDlg::LayoutGraph(int width, int height) {
    CWnd* graph = GetDlgItem(IDC_HEALTH_GRAPH);
    if (graph == nullptr) return;
    CRect graphDlu(8, 86, 482, 283);
    CRect bottomMarginDlu(0, 0, 0, 6);
    CRect rightMarginDlu(0, 0, 8, 0);
    CRect historyDlu(8, 329, 83, 343);
    CRect topmostDlu(96, 331, 206, 343);
    CRect limitsDlu(412, 328, 482, 344);
    CRect warningDlu(8, 287, 482, 324);
    CRect warningGapDlu(0, 0, 0, 4);
    MapDialogRect(&graphDlu);
    MapDialogRect(&bottomMarginDlu);
    MapDialogRect(&rightMarginDlu);
    MapDialogRect(&historyDlu);
    MapDialogRect(&topmostDlu);
    MapDialogRect(&limitsDlu);
    MapDialogRect(&warningDlu);
    MapDialogRect(&warningGapDlu);
    const int textIds[] = {IDC_HEALTH_STATE, IDC_HEALTH_AUTH, IDC_HEALTH_LATENCY, IDC_HEALTH_PROBES, IDC_HEALTH_TRAFFIC};
    for (int id : textIds) {
        CWnd* text = GetDlgItem(id);
        CRect position;
        text->GetWindowRect(&position);
        ScreenToClient(&position);
        text->SetWindowPos(nullptr, 0, 0, std::max<int>(80, width - static_cast<int>(graphDlu.left) * 2),
            position.Height(), SWP_NOZORDER | SWP_NOMOVE);
    }
    int bottomMargin = bottomMarginDlu.bottom;
    int historyTop = height - bottomMargin - historyDlu.Height();
    int topmostTop = height - bottomMargin - topmostDlu.Height();
    int limitsTop = height - bottomMargin - limitsDlu.Height();
    int warningBottom = std::min<int>({historyTop, topmostTop, limitsTop}) - static_cast<int>(warningGapDlu.bottom);
    int warningTop = warningBottom - warningDlu.Height();
    int graphBottom = warningTop - warningGapDlu.bottom;
    graph->SetWindowPos(nullptr, graphDlu.left, graphDlu.top, std::max<int>(80, static_cast<int>(width - graphDlu.left * 2)),
                        std::max<int>(30, static_cast<int>(graphBottom - graphDlu.top)), SWP_NOZORDER);
    GetDlgItem(IDC_HEALTH_WARNING)->SetWindowPos(nullptr, warningDlu.left, warningTop, std::max<int>(80, static_cast<int>(width - warningDlu.left * 2)),
                                                  warningDlu.Height(), SWP_NOZORDER);
    CRect dropdownDlu(0, 0, 0, 70);
    MapDialogRect(&dropdownDlu);
    GetDlgItem(IDC_HEALTH_HISTORY)->SetWindowPos(nullptr, historyDlu.left, historyTop, historyDlu.Width(), dropdownDlu.Height(), SWP_NOZORDER);
    GetDlgItem(IDC_HEALTH_TOPMOST)->SetWindowPos(nullptr, topmostDlu.left, topmostTop, topmostDlu.Width(), topmostDlu.Height(), SWP_NOZORDER);
    GetDlgItem(IDC_HEALTH_THRESHOLDS)->SetWindowPos(nullptr, width - limitsDlu.Width() - rightMarginDlu.right, limitsTop,
                                                    limitsDlu.Width(), limitsDlu.Height(), SWP_NOZORDER);
}

void CConnectionHealthDlg::OnHistoryChanged() {
    preferences_.historySeconds = history_.GetCurSel() == 1 ? 300 : 60;
    SavePreferences();
    GetDlgItem(IDC_HEALTH_GRAPH)->Invalidate(FALSE);
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
    DrawConnectionHealthGraph(dc, CRect(drawItem->rcItem), snapshot_, preferences_.historySeconds);
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
    SetWindowPos(preferences_.alwaysOnTop ? &wndTopMost : &wndNoTopMost, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
}

void CConnectionHealthDlg::RefreshText() {
    if (!GetSafeHwnd()) return;
    std::string state = tlp::HealthyDurationText(snapshot_);
    SetDlgItemText(IDC_HEALTH_STATE, Widen(state).c_str());
    SetDlgItemText(IDC_HEALTH_AUTH, Widen(tlp::ConnectedDurationText(snapshot_) +
        " | Authorisation remaining: " + authorization(snapshot_)).c_str());

    std::string latency = measurement(snapshot_.latencyMs, "ms");
    std::string jitter = measurement(snapshot_.jitterMs, "ms");
    SetDlgItemText(IDC_HEALTH_LATENCY, Widen("TCP RTT: " + latency + "   Jitter: " + jitter).c_str());
    std::string success = snapshot_.probeSuccessPercent ? measurement(snapshot_.probeSuccessPercent, "%") : "Unknown";
    std::string failure = snapshot_.probeFailurePercent ? measurement(snapshot_.probeFailurePercent, "%") : "Unknown";
    SetDlgItemText(IDC_HEALTH_PROBES, Widen("App probes: " + success + " ok / " + failure + " failed").c_str());
    std::string rates = "Rx (download) " + rate(snapshot_.receiveBytesPerSecond) +
        "   Tx (upload) " + rate(snapshot_.transmitBytesPerSecond) + "   Handshake ";
    rates += snapshot_.handshakeAgeSeconds ? std::to_string(*snapshot_.handshakeAgeSeconds) + " s ago" : "Unknown";
    SetDlgItemText(IDC_HEALTH_TRAFFIC, Widen(rates).c_str());
    std::string warning = "Application probes are not packet loss; traffic is not bandwidth capacity.";
    if (snapshot_.consecutiveFailures > 0) {
        warning = std::to_string(snapshot_.consecutiveFailures) + " app failures; not packet loss; SSH stays open.";
    } else if (snapshot_.deterioration) {
        warning = "Latency/probe trend worsening; congestion not measured.";
    }
    warning += "\r\nTraffic source: " + (snapshot_.trafficSource.empty() ? std::string("Unknown") : snapshot_.trafficSource);
    if (!snapshot_.telemetryReason.empty()) warning += ". WireGuard telemetry: " + snapshot_.telemetryReason;
    SetDlgItemText(IDC_HEALTH_WARNING, Widen(warning).c_str());
    if (GetSafeHwnd() && GetDlgItem(IDC_HEALTH_GRAPH)) GetDlgItem(IDC_HEALTH_GRAPH)->Invalidate(FALSE);
}
