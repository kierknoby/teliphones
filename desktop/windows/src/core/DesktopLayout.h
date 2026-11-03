#pragma once

#include <algorithm>
#include <array>

namespace tlp {

struct LayoutRect {
    int x = 0, y = 0, width = 0, height = 0;
    int bottom() const { return y + height; }
};

enum class DesktopSlot {
    PbxHeading, Profiles, Add, Remove, Support, Grant, SessionLabel, Session,
    Details, ConnectionHeading, State, Guidance, Summary, History, Plot, Graph,
    PopOut, Log, Count
};

struct DesktopLayout {
    std::array<LayoutRect, static_cast<int>(DesktopSlot::Count)> content{};
    std::array<LayoutRect, 6> actions{};
    LayoutRect viewport;
    LayoutRect wireguard;
    int contentHeight = 0;
};

// Logical (96 DPI) coordinates. The native adapter scales edges, not accumulated widths.
inline DesktopLayout ArrangeDesktop(int width, int height) {
    DesktopLayout layout;
    const int margin = 12, gap = 8;
    const int actionWidth = std::max(1, width - margin * 2);
    const int columns = std::clamp((actionWidth + gap) / 120, 1, 6);
    const int rows = (6 + columns - 1) / columns;
    const int footerHeight = rows * 32 + (rows - 1) * gap + margin * 2;
    for (int i = 0; i < 6; ++i) {
        const int col = i % columns, row = i / columns;
        const int cell = (actionWidth - (columns - 1) * gap) / columns;
        layout.actions[i] = {margin + col * (cell + gap), height - footerHeight + margin + row * 40, cell, 32};
    }
    layout.wireguard = {margin, margin, actionWidth, 24};
    layout.viewport = {0, 44, width, std::max(1, height - footerHeight - 44)};
    const bool landscape = width >= 820;
    const int leftWidth = landscape ? std::clamp(width * 38 / 100, 300, 440) : actionWidth;
    const int rightX = landscape ? margin + leftWidth + 16 : margin;
    const int rightWidth = landscape ? width - rightX - margin : actionWidth;
    const int leftHeight = landscape ? std::max(450, layout.viewport.height) : 450;
    const int rightTop = landscape ? 0 : leftHeight + 16;
    const int rightHeight = landscape ? std::max(450, layout.viewport.height) : 450;
    auto place = [&](DesktopSlot slot, int x, int y, int w, int h) {
        layout.content[static_cast<int>(slot)] = {x, y, w, h};
    };
    const int listHeight = leftHeight - 300;
    place(DesktopSlot::PbxHeading, margin, 8, leftWidth, 24);
    place(DesktopSlot::Profiles, margin, 40, leftWidth, listHeight);
    const int management = 48 + listHeight;
    const int half = (leftWidth - gap) / 2;
    place(DesktopSlot::Add, margin, management, half, 30);
    place(DesktopSlot::Remove, margin + half + gap, management, half, 30);
    place(DesktopSlot::Support, margin, management + 38, half, 30);
    place(DesktopSlot::Grant, margin + half + gap, management + 38, half, 30);
    place(DesktopSlot::SessionLabel, margin, management + 80, leftWidth, 20);
    place(DesktopSlot::Session, margin, management + 104, leftWidth, 28);
    place(DesktopSlot::Details, margin, management + 140, leftWidth, 100);
    place(DesktopSlot::ConnectionHeading, rightX, rightTop + 8, rightWidth, 24);
    place(DesktopSlot::State, rightX, rightTop + 40, rightWidth, 28);
    place(DesktopSlot::Guidance, rightX, rightTop + 76, rightWidth, 48);
    place(DesktopSlot::Summary, rightX, rightTop + 132, rightWidth, 104);
    const int historyWidth = std::min(124, (rightWidth - gap) / 2);
    place(DesktopSlot::History, rightX, rightTop + 244, historyWidth, 28);
    place(DesktopSlot::Plot, rightX + historyWidth + gap, rightTop + 244, rightWidth - historyWidth - gap, 28);
    place(DesktopSlot::Graph, rightX, rightTop + 280, rightWidth, rightHeight - 332);
    place(DesktopSlot::PopOut, rightX, rightTop + rightHeight - 42, (rightWidth - gap) / 2, 30);
    place(DesktopSlot::Log, rightX + (rightWidth - gap) / 2 + gap, rightTop + rightHeight - 42, (rightWidth - gap) / 2, 30);
    layout.contentHeight = rightTop + rightHeight;
    return layout;
}

}  // namespace tlp
