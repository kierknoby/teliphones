#include "Appearance.h"

#include <dwmapi.h>
#include <uxtheme.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.UI.h>
#include <winrt/Windows.UI.ViewManagement.h>

#include <algorithm>
#include <array>
#include <cwchar>
#include <cwctype>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "../platform/Win.h"
#include "resource.h"

namespace tlp::ui {
namespace {

constexpr UINT kEnvironmentChanged = WM_APP + 40;
constexpr UINT_PTR kSubclass = 0x544C5041;
constexpr wchar_t kComboList[] = L"TELIPHONES.Appearance.ComboList";
LRESULT CALLBACK WindowProcedure(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);

bool IsClass(HWND window, const wchar_t* name) {
    wchar_t text[64]{};
    GetClassNameW(window, text, static_cast<int>(std::size(text)));
    return _wcsicmp(text, name) == 0;
}

void SizeComboItems(HWND window) {
    HDC dc = GetDC(window);
    const auto font = reinterpret_cast<HFONT>(SendMessageW(window, WM_GETFONT, 0, 0));
    const auto oldFont = font ? SelectObject(dc, font) : nullptr;
    TEXTMETRICW metrics{};
    GetTextMetricsW(dc, &metrics);
    if (oldFont) SelectObject(dc, oldFont);
    ReleaseDC(window, dc);
    const int height = static_cast<int>(metrics.tmHeight) + MulDiv(4, static_cast<int>(GetDpiForWindow(window)), 96);
    SendMessageW(window, CB_SETITEMHEIGHT, 0, height);
    SendMessageW(window, CB_SETITEMHEIGHT, static_cast<WPARAM>(-1), height);
}

bool IsHighContrast() {
    HIGHCONTRASTW settings{sizeof(settings)};
    if (!SystemParametersInfoW(SPI_GETHIGHCONTRAST, sizeof(settings), &settings, 0))
        win::ThrowLastError("Read Windows accessibility appearance");
    return (settings.dwFlags & HCF_HIGHCONTRASTON) != 0;
}

AppearancePalette AccessiblePalette() {
    const auto text = GetSysColor(COLOR_WINDOWTEXT);
    const auto accent = GetSysColor(COLOR_HIGHLIGHT);
    return {GetSysColor(COLOR_3DFACE), GetSysColor(COLOR_WINDOW), text, GetSysColor(COLOR_GRAYTEXT),
        GetSysColor(COLOR_WINDOWFRAME), GetSysColor(COLOR_BTNFACE), GetSysColor(COLOR_BTNFACE),
        accent, GetSysColor(COLOR_HIGHLIGHTTEXT), GetSysColor(COLOR_WINDOW), GetSysColor(COLOR_GRAYTEXT),
        text, text, text, text, text, text};
}

struct MenuItem {
    HMENU menu;
    UINT position;
    UINT type;
    ULONG_PTR data;
    std::wstring text;
};

class AppearanceManager {
public:
    ~AppearanceManager() {
        if (settings_) settings_.ColorValuesChanged(colourToken_);
        settings_ = nullptr;
        if (notification_) DestroyWindow(notification_);
        if (apartment_) winrt::uninit_apartment();
        if (background_) DeleteObject(background_);
        if (surface_) DeleteObject(surface_);
    }

    void Initialize() {
        if (notification_) return;
        WNDCLASSW type{};
        type.hInstance = AfxGetInstanceHandle();
        type.lpszClassName = L"TELIPHONES.Appearance";
        type.lpfnWndProc = Notification;
        if (!RegisterClassW(&type) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
            win::ThrowLastError("Register TELIPHONES appearance notifications");
        notification_ = CreateWindowExW(0, type.lpszClassName, L"", 0, 0, 0, 0, 0,
            HWND_MESSAGE, nullptr, type.hInstance, nullptr);
        if (!notification_) win::ThrowLastError("Create TELIPHONES appearance notifications");
        try {
#ifdef TELIPHONES_APPEARANCE_TESTING
            if (!environmentOverride_)
#endif
            {
                winrt::init_apartment(winrt::apartment_type::single_threaded);
                apartment_ = true;
                settings_ = winrt::Windows::UI::ViewManagement::UISettings();
                const HWND target = notification_;
                // UISettings delivers on a worker thread. GDI/window work stays on the UI thread.
                colourToken_ = settings_.ColorValuesChanged([target](const auto&, const auto&) {
                    PostMessageW(target, kEnvironmentChanged, 0, 0);
                });
            }
            Refresh();
        } catch (const winrt::hresult_error& error) {
            if (settings_) settings_.ColorValuesChanged(colourToken_);
            settings_ = nullptr;
            DestroyWindow(notification_);
            notification_ = nullptr;
            if (apartment_) { winrt::uninit_apartment(); apartment_ = false; }
            throw std::runtime_error("Windows appearance notifications could not be initialized: " +
                winrt::to_string(error.message()));
        } catch (const std::exception&) {
            if (settings_) settings_.ColorValuesChanged(colourToken_);
            settings_ = nullptr;
            DestroyWindow(notification_);
            notification_ = nullptr;
            if (apartment_) { winrt::uninit_apartment(); apartment_ = false; }
            throw;
        }
    }

    void Refresh() {
        if (updating_) return;
        bool highContrast = IsHighContrast();
        bool systemDark = false;
        if (settings_) {
            try {
                const auto colour = settings_.GetColorValue(winrt::Windows::UI::ViewManagement::UIColorType::Foreground);
                systemDark = (5 * colour.G + 2 * colour.R + colour.B) > 8 * 128;
            } catch (const winrt::hresult_error& error) {
                throw std::runtime_error("Windows application appearance could not be read: " +
                    winrt::to_string(error.message()));
            }
        }
#ifdef TELIPHONES_APPEARANCE_TESTING
        if (environmentOverride_) {
            systemDark = environmentOverride_->first;
            highContrast = environmentOverride_->second;
        }
#endif
        const bool dark = UseDarkAppearance(mode_, systemDark, highContrast);
        const auto next = highContrast ? AccessiblePalette() : PaletteFor(dark);
        if (background_ && highContrast == highContrast_ && dark == dark_ && next.Values() == palette_.Values()) return;
        HBRUSH background = CreateSolidBrush(next.background);
        HBRUSH surface = CreateSolidBrush(next.surface);
        if (!background || !surface) {
            if (background) DeleteObject(background);
            if (surface) DeleteObject(surface);
            win::ThrowLastError("Create TELIPHONES appearance brushes");
        }
        updating_ = true;
        highContrast_ = highContrast;
        dark_ = dark;
        palette_ = next;
        HBRUSH oldBackground = background_, oldSurface = surface_;
        background_ = background;
        surface_ = surface;
        if (highContrast_) while (!menus_.empty()) RestoreMenu(menus_.begin()->first);
        for (auto& item : menus_) {
            MENUINFO info{sizeof(info), MIM_BACKGROUND};
            info.hbrBack = background_;
            SetMenuInfo(item.first, &info);
        }
        try {
            for (HWND root : roots_) {
                const bool visible = IsWindowVisible(root) != FALSE;
                if (visible) SendMessageW(root, WM_SETREDRAW, FALSE, 0);
                try {
                    ApplyTree(root);
                } catch (const std::exception&) {
                    if (visible) SendMessageW(root, WM_SETREDRAW, TRUE, 0);
                    throw;
                }
                if (visible) SendMessageW(root, WM_SETREDRAW, TRUE, 0);
                RedrawWindow(root, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN);
            }
        } catch (const std::exception&) {
            if (oldBackground) DeleteObject(oldBackground);
            if (oldSurface) DeleteObject(oldSurface);
            updating_ = false;
            throw;
        }
        if (oldBackground) DeleteObject(oldBackground);
        if (oldSurface) DeleteObject(oldSurface);
        updating_ = false;
    }

    void Add(HWND window) {
        Initialize();
        ApplyTree(window);
        roots_.insert(window);
    }

    void ApplyTree(HWND window) {
        if (!Apply(window)) win::ThrowLastError("Theme TELIPHONES window");
        struct Traversal { AppearanceManager* manager; bool success = true; } traversal{this};
        EnumChildWindows(window, [](HWND child, LPARAM value) -> BOOL {
            auto& state = *reinterpret_cast<Traversal*>(value);
            state.success = state.manager->Apply(child);
            return state.success ? TRUE : FALSE;
        }, reinterpret_cast<LPARAM>(&traversal));
        if (!traversal.success) win::ThrowLastError("Theme TELIPHONES control");
    }

    bool Apply(HWND window) {
        if (!SetWindowSubclass(window, WindowProcedure, kSubclass, 0)) return false;
        const auto style = GetWindowLongPtrW(window, GWL_STYLE);
        const bool nativeFrame = (style & WS_CAPTION) == WS_CAPTION;
        // Empty theme names use supported classic rendering underneath our painting;
        // captioned windows must retain Windows-owned frames and caption buttons.
        const bool nativeTheme = highContrast_ || nativeFrame;
        SetWindowTheme(window, nativeTheme ? nullptr : L"", nativeTheme ? nullptr : L"");
        if (IsClass(window, WC_LISTVIEWW)) {
            ListView_SetBkColor(window, palette_.surface);
            ListView_SetTextBkColor(window, palette_.surface);
            ListView_SetTextColor(window, palette_.text);
            if (HWND header = ListView_GetHeader(window)) { if (!Apply(header)) return false; }
            if (HWND tip = ListView_GetToolTips(window)) { if (!Apply(tip)) return false; }
        } else if (IsClass(window, WC_COMBOBOXW)) {
            COMBOBOXINFO combo{sizeof(combo)};
            if (GetComboBoxInfo(window, &combo) && combo.hwndList) {
                if (!SetPropW(combo.hwndList, kComboList, window) || !Apply(combo.hwndList)) return false;
            }
            SizeComboItems(window);
        } else if (IsClass(window, TOOLTIPS_CLASSW)) {
            SendMessageW(window, TTM_SETTIPBKCOLOR, palette_.surface, 0);
            SendMessageW(window, TTM_SETTIPTEXTCOLOR, palette_.text, 0);
        }
        if ((style & WS_CHILD) == 0 && (style & WS_CAPTION) == WS_CAPTION) {
            const BOOL dark = dark_ && !highContrast_;
            // This documented attribute is optional on older Windows 10 builds.
            DwmSetWindowAttribute(window, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
        }
        return true;
    }

    void EnvironmentChanged() noexcept {
        try {
            Refresh();
        } catch (const std::exception& error) {
            AfxMessageBox(win::Widen(error.what()).c_str(), MB_ICONERROR);
        }
    }

    void PrepareMenu(HMENU menu) {
        if (highContrast_ || menus_.count(menu)) return;
        MENUINFO old{sizeof(old), MIM_BACKGROUND};
        if (!GetMenuInfo(menu, &old)) return;
        menus_[menu] = old.hbrBack;
        MENUINFO background{sizeof(background), MIM_BACKGROUND};
        background.hbrBack = background_;
        SetMenuInfo(menu, &background);
        for (int i = 0; i < GetMenuItemCount(menu); ++i) {
            wchar_t text[512]{};
            MENUITEMINFOW info{sizeof(info)};
            info.fMask = MIIM_FTYPE | MIIM_DATA | MIIM_STRING | MIIM_BITMAP;
            info.dwTypeData = text;
            info.cch = static_cast<UINT>(std::size(text));
            if (!GetMenuItemInfoW(menu, i, TRUE, &info) || (info.fType & MFT_OWNERDRAW) || info.hbmpItem) continue;
            auto item = std::make_unique<MenuItem>(MenuItem{menu, static_cast<UINT>(i), info.fType, info.dwItemData, text});
            info.fMask = MIIM_FTYPE | MIIM_DATA;
            info.fType |= MFT_OWNERDRAW;
            info.dwItemData = reinterpret_cast<ULONG_PTR>(item.get());
            if (SetMenuItemInfoW(menu, i, TRUE, &info)) menuItems_.emplace(info.dwItemData, std::move(item));
        }
    }

    void RestoreMenu(HMENU menu) {
        auto background = menus_.find(menu);
        if (background == menus_.end()) return;
        for (auto it = menuItems_.begin(); it != menuItems_.end();) {
            const auto& item = *it->second;
            if (item.menu != menu) { ++it; continue; }
            MENUITEMINFOW info{sizeof(info)};
            info.fMask = MIIM_FTYPE | MIIM_DATA;
            info.fType = item.type;
            info.dwItemData = item.data;
            SetMenuItemInfoW(menu, item.position, TRUE, &info);
            it = menuItems_.erase(it);
        }
        MENUINFO info{sizeof(info), MIM_BACKGROUND};
        info.hbrBack = background->second;
        SetMenuInfo(menu, &info);
        menus_.erase(background);
    }

    LRESULT MenuCharacter(wchar_t character, HMENU menu) const {
        std::vector<UINT> matches;
        UINT highlighted = static_cast<UINT>(-1);
        for (const auto& entry : menuItems_) {
            const auto& item = *entry.second;
            if (item.menu != menu || (item.type & MFT_SEPARATOR)) continue;
            MENUITEMINFOW info{sizeof(info)};
            info.fMask = MIIM_STATE;
            if (!GetMenuItemInfoW(menu, item.position, TRUE, &info)) continue;
            if (info.fState & MFS_HILITE) highlighted = item.position;
            if (info.fState & (MFS_DISABLED | MFS_GRAYED)) continue;
            for (std::size_t i = 0; i + 1 < item.text.size(); ++i) {
                if (item.text[i] != L'&') continue;
                if (item.text[i + 1] == L'&') { ++i; continue; }
                if (std::towupper(item.text[i + 1]) == std::towupper(character)) matches.push_back(item.position);
                break;
            }
        }
        if (matches.empty()) return MAKELRESULT(0, MNC_IGNORE);
        std::sort(matches.begin(), matches.end());
        const auto next = std::upper_bound(matches.begin(), matches.end(), highlighted);
        return MAKELRESULT(next == matches.end() ? matches.front() : *next,
            matches.size() == 1 ? MNC_EXECUTE : MNC_SELECT);
    }

    Appearance mode_ = Appearance::System;
    AppearancePalette palette_ = PaletteFor(false);
    bool highContrast_ = false, dark_ = false, updating_ = false;
    HBRUSH background_ = nullptr, surface_ = nullptr;
    std::set<HWND> roots_;
    std::map<ULONG_PTR, std::unique_ptr<MenuItem>> menuItems_;
#ifdef TELIPHONES_APPEARANCE_TESTING
    std::optional<std::pair<bool, bool>> environmentOverride_;
    void PostEnvironmentChange() { PostMessageW(notification_, kEnvironmentChanged, 0, 0); }
#endif

private:
    static LRESULT CALLBACK Notification(HWND window, UINT message, WPARAM wparam, LPARAM lparam);
    HWND notification_ = nullptr;
    bool apartment_ = false;
    winrt::Windows::UI::ViewManagement::UISettings settings_{nullptr};
    winrt::event_token colourToken_{};
    std::map<HMENU, HBRUSH> menus_;
};

AppearanceManager& Manager() { static AppearanceManager instance; return instance; }

LRESULT CALLBACK AppearanceManager::Notification(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == kEnvironmentChanged) { Manager().EnvironmentChanged(); return 0; }
    return DefWindowProcW(window, message, wparam, lparam);
}

int Scale(HWND window, int value) { return MulDiv(value, static_cast<int>(GetDpiForWindow(window)), 96); }

void Fill(HDC dc, RECT rectangle, COLORREF colour) {
    const COLORREF old = SetDCBrushColor(dc, colour);
    FillRect(dc, &rectangle, static_cast<HBRUSH>(GetStockObject(DC_BRUSH)));
    SetDCBrushColor(dc, old);
}

void Border(HDC dc, RECT rectangle, COLORREF colour) {
    const COLORREF old = SetDCBrushColor(dc, colour);
    FrameRect(dc, &rectangle, static_cast<HBRUSH>(GetStockObject(DC_BRUSH)));
    SetDCBrushColor(dc, old);
}

void Arrow(HDC dc, RECT rectangle, COLORREF colour, int direction) {
    const int x = (rectangle.left + rectangle.right) / 2, y = (rectangle.top + rectangle.bottom) / 2;
    const int d = std::max<int>(2, std::min<int>(rectangle.right - rectangle.left, rectangle.bottom - rectangle.top) / 5);
    POINT points[3];
    if (direction == 0) { points[0] = {x - d, y + d / 2}; points[1] = {x + d, y + d / 2}; points[2] = {x, y - d}; }
    else if (direction == 1) { points[0] = {x - d, y - d / 2}; points[1] = {x + d, y - d / 2}; points[2] = {x, y + d}; }
    else if (direction == 2) { points[0] = {x + d / 2, y - d}; points[1] = {x + d / 2, y + d}; points[2] = {x - d, y}; }
    else { points[0] = {x - d / 2, y - d}; points[1] = {x - d / 2, y + d}; points[2] = {x + d, y}; }
    const auto oldBrush = SelectObject(dc, GetStockObject(DC_BRUSH));
    const auto oldPen = SelectObject(dc, GetStockObject(NULL_PEN));
    const auto oldColour = SetDCBrushColor(dc, colour);
    Polygon(dc, points, 3);
    SetDCBrushColor(dc, oldColour);
    SelectObject(dc, oldPen);
    SelectObject(dc, oldBrush);
}

void CheckMark(HDC dc, RECT box, COLORREF colour, int thickness) {
    HPEN pen = CreatePen(PS_SOLID, thickness, colour);
    const auto previous = SelectObject(dc, pen);
    const int width = box.right - box.left, height = box.bottom - box.top;
    MoveToEx(dc, box.left + width / 5, box.top + height / 2, nullptr);
    LineTo(dc, box.left + width * 2 / 5, box.top + height * 3 / 4);
    LineTo(dc, box.left + width * 4 / 5, box.top + height / 4);
    SelectObject(dc, previous);
    DeleteObject(pen);
}

bool DrawComboItem(UINT message, LPARAM lparam);

void PaintControl(HWND window, HDC dc, bool hot) {
    const auto& p = Manager().palette_;
    const int saved = SaveDC(dc);
    const HFONT font = reinterpret_cast<HFONT>(SendMessageW(window, WM_GETFONT, 0, 0));
    if (font) SelectObject(dc, font);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, IsWindowEnabled(window) ? p.text : p.disabled);
    RECT rect{};
    GetClientRect(window, &rect);
    const DWORD style = static_cast<DWORD>(GetWindowLongPtrW(window, GWL_STYLE));
    const UINT textFlags = (SendMessageW(window, WM_QUERYUISTATE, 0, 0) & UISF_HIDEACCEL) ? DT_HIDEPREFIX : 0;
    if (IsClass(window, L"Button")) {
        wchar_t text[1024]{};
        GetWindowTextW(window, text, static_cast<int>(std::size(text)));
        const DWORD type = style & BS_TYPEMASK;
        const auto state = SendMessageW(window, BM_GETSTATE, 0, 0);
        const bool check = type == BS_AUTOCHECKBOX || type == BS_CHECKBOX || type == BS_AUTO3STATE || type == BS_3STATE;
        const bool radio = type == BS_AUTORADIOBUTTON || type == BS_RADIOBUTTON;
        if (type == BS_GROUPBOX) {
            for (HWND sibling = GetWindow(GetParent(window), GW_CHILD); sibling; sibling = GetWindow(sibling, GW_HWNDNEXT)) {
                if (sibling == window || !IsWindowVisible(sibling)) continue;
                RECT occupied{};
                GetWindowRect(sibling, &occupied);
                MapWindowPoints(nullptr, window, reinterpret_cast<POINT*>(&occupied), 2);
                ExcludeClipRect(dc, occupied.left, occupied.top, occupied.right, occupied.bottom);
            }
        }
        Fill(dc, rect, type == BS_GROUPBOX || check || radio ? p.background :
            (state & BST_PUSHED) ? p.selection : hot && IsWindowEnabled(window) ? p.hover : p.button);
        if (type == BS_GROUPBOX) {
            RECT frame = rect;
            frame.top += Scale(window, 7);
            Border(dc, frame, p.border);
            RECT label{Scale(window, 10), 0, rect.right - Scale(window, 10), Scale(window, 18)};
            RECT measure = label;
            DrawTextW(dc, text, -1, &measure, DT_CALCRECT | DT_SINGLELINE);
            label.right = measure.right + Scale(window, 4);
            Fill(dc, label, p.background);
            DrawTextW(dc, text, -1, &label, DT_SINGLELINE | textFlags);
        } else {
            RECT label = rect;
            InflateRect(&label, -Scale(window, 7), -Scale(window, 2));
            if (check || radio) {
                const int size = Scale(window, 13);
                RECT box{Scale(window, 2), (rect.bottom - size) / 2, Scale(window, 2) + size, (rect.bottom + size) / 2};
                Fill(dc, box, p.surface);
                if (radio) {
                    const auto oldPen = SelectObject(dc, GetStockObject(DC_PEN));
                    const auto oldBrush = SelectObject(dc, GetStockObject(DC_BRUSH));
                    SetDCPenColor(dc, p.border); SetDCBrushColor(dc, p.surface);
                    Ellipse(dc, box.left, box.top, box.right, box.bottom);
                    if (SendMessageW(window, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                        InflateRect(&box, -Scale(window, 3), -Scale(window, 3));
                        SetDCBrushColor(dc, p.text);
                        Ellipse(dc, box.left, box.top, box.right, box.bottom);
                    }
                    SelectObject(dc, oldBrush); SelectObject(dc, oldPen);
                } else {
                    Border(dc, box, IsWindowEnabled(window) ? p.border : p.disabled);
                    const auto checked = SendMessageW(window, BM_GETCHECK, 0, 0);
                    if (checked == BST_INDETERMINATE) {
                        InflateRect(&box, -Scale(window, 3), -Scale(window, 3));
                        Fill(dc, box, IsWindowEnabled(window) ? p.text : p.disabled);
                    } else if (checked == BST_CHECKED) {
                        CheckMark(dc, box, IsWindowEnabled(window) ? p.text : p.disabled, std::max(1, Scale(window, 2)));
                    }
                }
                label.left = size + Scale(window, 8);
            } else {
                Border(dc, rect, GetFocus() == window || type == BS_DEFPUSHBUTTON ? p.selection : p.border);
                if (state & BST_PUSHED) SetTextColor(dc, p.selectedText);
            }
            DrawTextW(dc, text, -1, &label, DT_VCENTER | textFlags |
                ((style & BS_MULTILINE) ? DT_WORDBREAK : DT_SINGLELINE) | (check || radio ? DT_LEFT : DT_CENTER));
            if (GetFocus() == window && !(SendMessageW(window, WM_QUERYUISTATE, 0, 0) & UISF_HIDEFOCUS)) {
                RECT focus = rect;
                InflateRect(&focus, -Scale(window, 3), -Scale(window, 3));
                DrawFocusRect(dc, &focus);
            }
        }
    } else if (IsClass(window, WC_COMBOBOXW)) {
        Fill(dc, rect, p.surface);
        Border(dc, rect, GetFocus() == window ? p.selection : p.border);
        const int arrowWidth = GetSystemMetricsForDpi(SM_CXVSCROLL, GetDpiForWindow(window));
        RECT arrow{rect.right - arrowWidth, rect.top + 1, rect.right - 1, rect.bottom - 1};
        Fill(dc, arrow, hot ? p.hover : p.button);
        Arrow(dc, arrow, IsWindowEnabled(window) ? p.text : p.disabled, 1);
        COMBOBOXINFO info{sizeof(info)};
        if (GetComboBoxInfo(window, &info)) {
            DRAWITEMSTRUCT selection{};
            selection.CtlType = ODT_COMBOBOX;
            selection.itemID = static_cast<UINT>(SendMessageW(window, CB_GETCURSEL, 0, 0));
            selection.itemAction = ODA_DRAWENTIRE;
            selection.itemState = ODS_COMBOBOXEDIT;
            if (GetFocus() == window) selection.itemState |= ODS_FOCUS;
            if (!IsWindowEnabled(window)) selection.itemState |= ODS_DISABLED;
            selection.hwndItem = window;
            selection.hDC = dc;
            selection.rcItem = info.rcItem;
            DrawComboItem(WM_DRAWITEM, reinterpret_cast<LPARAM>(&selection));
        }
    } else if (IsClass(window, WC_HEADERW)) {
        Fill(dc, rect, p.button);
        const int count = Header_GetItemCount(window);
        for (int i = 0; i < count; ++i) {
            RECT cell{};
            Header_GetItemRect(window, i, &cell);
            Border(dc, cell, p.border);
            wchar_t text[256]{};
            HDITEMW item{};
            item.mask = HDI_TEXT;
            item.pszText = text;
            item.cchTextMax = static_cast<int>(std::size(text));
            Header_GetItem(window, i, &item);
            InflateRect(&cell, -Scale(window, 7), 0);
            DrawTextW(dc, text, -1, &cell, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
        }
    }
    RestoreDC(dc, saved);
}

void PaintScrollbars(HWND window) {
    const auto& p = Manager().palette_;
    HDC dc = GetWindowDC(window);
    if (!dc) return;
    const int saved = SaveDC(dc);
    RECT bounds{}, client{};
    GetWindowRect(window, &bounds);
    GetClientRect(window, &client);
    MapWindowPoints(window, nullptr, reinterpret_cast<POINT*>(&client), 2);
    OffsetRect(&client, -bounds.left, -bounds.top);
    ExcludeClipRect(dc, client.left, client.top, client.right, client.bottom);
    RECT frame{0, 0, bounds.right - bounds.left, bounds.bottom - bounds.top};
    Fill(dc, frame, p.background);
    Border(dc, frame, p.border);
    for (bool vertical : {true, false}) {
        SCROLLBARINFO info{sizeof(info)};
        if (!GetScrollBarInfo(window, vertical ? OBJID_VSCROLL : OBJID_HSCROLL, &info) ||
            (info.rgstate[0] & (STATE_SYSTEM_INVISIBLE | STATE_SYSTEM_OFFSCREEN))) continue;
        RECT bar = info.rcScrollBar;
        OffsetRect(&bar, -bounds.left, -bounds.top);
        Fill(dc, bar, p.background);
        RECT first = bar, last = bar, thumb = bar;
        if (vertical) {
            first.bottom = first.top + info.dxyLineButton;
            last.top = last.bottom - info.dxyLineButton;
            thumb.top = bar.top + info.xyThumbTop;
            thumb.bottom = bar.top + info.xyThumbBottom;
            InflateRect(&thumb, -Scale(window, 3), 0);
        } else {
            first.right = first.left + info.dxyLineButton;
            last.left = last.right - info.dxyLineButton;
            thumb.left = bar.left + info.xyThumbTop;
            thumb.right = bar.left + info.xyThumbBottom;
            InflateRect(&thumb, 0, -Scale(window, 3));
        }
        const bool enabled = IsWindowEnabled(window) && !(info.rgstate[0] & STATE_SYSTEM_UNAVAILABLE);
        Arrow(dc, first, enabled ? p.text : p.disabled, vertical ? 0 : 2);
        Arrow(dc, last, enabled ? p.text : p.disabled, vertical ? 1 : 3);
        if (enabled && info.xyThumbBottom > info.xyThumbTop) Fill(dc, thumb, p.border);
    }
    RestoreDC(dc, saved);
    ReleaseDC(window, dc);
}

LRESULT ListDraw(NMLVCUSTOMDRAW* draw) {
    if (draw->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
    if (draw->nmcd.dwDrawStage != CDDS_ITEMPREPAINT) return CDRF_DODEFAULT;
    const HWND list = draw->nmcd.hdr.hwndFrom;
    const int row = static_cast<int>(draw->nmcd.dwItemSpec);
    const bool selected = (ListView_GetItemState(list, row, LVIS_SELECTED) & LVIS_SELECTED) != 0;
    const auto& p = Manager().palette_;
    const int saved = SaveDC(draw->nmcd.hdc);
    Fill(draw->nmcd.hdc, draw->nmcd.rc, selected ? p.selection : p.surface);
    SetTextColor(draw->nmcd.hdc, selected ? p.selectedText : !IsWindowEnabled(list) ? p.disabled : p.text);
    SetBkMode(draw->nmcd.hdc, TRANSPARENT);
    const auto font = reinterpret_cast<HFONT>(SendMessageW(list, WM_GETFONT, 0, 0));
    if (font) SelectObject(draw->nmcd.hdc, font);
    const int count = Header_GetItemCount(ListView_GetHeader(list));
    for (int column = 0; column < count; ++column) {
        RECT cell{};
        // Subitem zero's label rectangle can cover the entire row. Header bounds
        // provide the actual column width/order, including horizontal scrolling.
        const HWND header = ListView_GetHeader(list);
        if (!Header_GetItemRect(header, column, &cell)) continue;
        MapWindowPoints(header, list, reinterpret_cast<POINT*>(&cell), 2);
        cell.top = draw->nmcd.rc.top;
        cell.bottom = draw->nmcd.rc.bottom;
        wchar_t text[1024]{};
        ListView_GetItemText(list, row, column, text, static_cast<int>(std::size(text)));
        InflateRect(&cell, -Scale(list, 6), 0);
        DrawTextW(draw->nmcd.hdc, text, -1, &cell, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    }
    if (GetFocus() == list && (ListView_GetItemState(list, row, LVIS_FOCUSED) & LVIS_FOCUSED))
        DrawFocusRect(draw->nmcd.hdc, &draw->nmcd.rc);
    RestoreDC(draw->nmcd.hdc, saved);
    return CDRF_SKIPDEFAULT;
}

bool DrawComboItem(UINT message, LPARAM lparam) {
    if (message != WM_DRAWITEM || !lparam) return false;
    const auto draw = reinterpret_cast<DRAWITEMSTRUCT*>(lparam);
    if (draw->CtlType != ODT_COMBOBOX) return false;
    const auto& p = Manager().palette_;
    const bool closedField = (draw->itemState & ODS_COMBOBOXEDIT) != 0;
    const bool selected = !closedField && (draw->itemState & ODS_SELECTED) != 0 && !(draw->itemState & ODS_DISABLED);
    const int saved = SaveDC(draw->hDC);
    IntersectClipRect(draw->hDC, draw->rcItem.left, draw->rcItem.top, draw->rcItem.right, draw->rcItem.bottom);
    Fill(draw->hDC, draw->rcItem, selected ? p.selection : p.surface);
    SetBkMode(draw->hDC, TRANSPARENT);
    SetTextColor(draw->hDC, draw->itemState & ODS_DISABLED ? p.disabled : selected ? p.selectedText : p.text);
    const auto font = reinterpret_cast<HFONT>(SendMessageW(draw->hwndItem, WM_GETFONT, 0, 0));
    if (font) SelectObject(draw->hDC, font);
    RECT text = draw->rcItem;
    InflateRect(&text, -Scale(draw->hwndItem, 6), 0);
    const auto length = draw->itemID == static_cast<UINT>(-1) ? CB_ERR :
        SendMessageW(draw->hwndItem, CB_GETLBTEXTLEN, draw->itemID, 0);
    if (length >= 0) {
        std::vector<wchar_t> value(static_cast<std::size_t>(length) + 1);
        SendMessageW(draw->hwndItem, CB_GETLBTEXT, draw->itemID, reinterpret_cast<LPARAM>(value.data()));
        DrawTextW(draw->hDC, value.data(), -1, &text, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    }
    const bool hideFocus = (SendMessageW(draw->hwndItem, WM_QUERYUISTATE, 0, 0) & UISF_HIDEFOCUS) != 0;
    if ((draw->itemState & ODS_FOCUS) && !(draw->itemState & ODS_NOFOCUSRECT) && !hideFocus) {
        RECT focus = draw->rcItem;
        InflateRect(&focus, -Scale(draw->hwndItem, 2), -Scale(draw->hwndItem, 2));
        DrawFocusRect(draw->hDC, &focus);
    }
    RestoreDC(draw->hDC, saved);
    return true;
}

LRESULT CALLBACK WindowProcedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam, UINT_PTR, DWORD_PTR hot) {
    auto& manager = Manager();
    if (message == WM_NCDESTROY) {
        manager.roots_.erase(window);
        RemovePropW(window, kComboList);
        RemoveWindowSubclass(window, WindowProcedure, kSubclass);
        return DefSubclassProc(window, message, wparam, lparam);
    }
    if (message == WM_SETTINGCHANGE || message == WM_SYSCOLORCHANGE || message == WM_THEMECHANGED)
        manager.EnvironmentChanged();
    if ((message == WM_SETFONT || message == WM_DPICHANGED_AFTERPARENT) && IsClass(window, WC_COMBOBOXW)) {
        const LRESULT result = DefSubclassProc(window, message, wparam, lparam);
        SizeComboItems(window);
        return result;
    }
    if (DrawComboItem(message, lparam)) return TRUE;
    if (manager.highContrast_) return DefSubclassProc(window, message, wparam, lparam);

    const bool painted = IsClass(window, L"Button") || IsClass(window, WC_HEADERW) ||
        (IsClass(window, WC_COMBOBOXW) && (GetWindowLongPtrW(window, GWL_STYLE) & CBS_DROPDOWNLIST) == CBS_DROPDOWNLIST);
    if (painted && (message == WM_PAINT || message == WM_PRINTCLIENT)) {
        PAINTSTRUCT paint{};
        HDC dc = message == WM_PAINT ? BeginPaint(window, &paint) : reinterpret_cast<HDC>(wparam);
        PaintControl(window, dc, hot != 0);
        if (message == WM_PAINT) EndPaint(window, &paint);
        return 0;
    }
    if (painted && message == WM_ERASEBKGND) return 1;
    if (message >= WM_CTLCOLORMSGBOX && message <= WM_CTLCOLORSTATIC) {
        DefSubclassProc(window, message, wparam, lparam);
        const HWND child = reinterpret_cast<HWND>(lparam);
        const auto dc = reinterpret_cast<HDC>(wparam);
        const auto& p = manager.palette_;
        const int id = GetDlgCtrlID(child);
        if (id != IDC_STATE && id != IDC_HEALTH_STATE)
            SetTextColor(dc, IsWindowEnabled(child) ? p.text : p.disabled);
        const bool surface = IsClass(child, L"Edit") || message == WM_CTLCOLORLISTBOX;
        SetBkColor(dc, surface ? p.surface : p.background);
        return reinterpret_cast<LRESULT>(surface ? manager.surface_ : manager.background_);
    }
    if (message == WM_ERASEBKGND && (manager.roots_.count(window) || GetDlgCtrlID(window) == IDC_CONTENT_VIEWPORT)) {
        RECT rect{};
        GetClientRect(window, &rect);
        FillRect(reinterpret_cast<HDC>(wparam), &rect, manager.background_);
        return 1;
    }
    if (message == WM_NOTIFY) {
        const auto header = reinterpret_cast<NMHDR*>(lparam);
        if (header && header->code == NM_CUSTOMDRAW && IsClass(header->hwndFrom, WC_LISTVIEWW))
            return ListDraw(reinterpret_cast<NMLVCUSTOMDRAW*>(lparam));
    }
    const bool nonclient = ((GetWindowLongPtrW(window, GWL_STYLE) & WS_CHILD) != 0 || GetPropW(window, kComboList)) &&
        (GetWindowLongPtrW(window, GWL_STYLE) & (WS_VSCROLL | WS_HSCROLL | WS_BORDER) ||
         GetWindowLongPtrW(window, GWL_EXSTYLE) & WS_EX_CLIENTEDGE);
    if (nonclient && message == WM_NCPAINT) { PaintScrollbars(window); return 0; }
    if (message == WM_INITMENUPOPUP) manager.PrepareMenu(reinterpret_cast<HMENU>(wparam));
    if (message == WM_UNINITMENUPOPUP) manager.RestoreMenu(reinterpret_cast<HMENU>(wparam));
    if (message == WM_MENUCHAR) return manager.MenuCharacter(static_cast<wchar_t>(LOWORD(wparam)), reinterpret_cast<HMENU>(lparam));
    if (message == WM_MEASUREITEM) {
        auto measure = reinterpret_cast<MEASUREITEMSTRUCT*>(lparam);
        auto item = manager.menuItems_.find(measure->itemData);
        if (measure->CtlType == ODT_MENU && item != manager.menuItems_.end()) {
            const bool separator = (item->second->type & MFT_SEPARATOR) != 0;
            HDC dc = GetDC(window);
            NONCLIENTMETRICSW metrics{sizeof(metrics)};
            SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0, GetDpiForWindow(window));
            HFONT font = CreateFontIndirectW(&metrics.lfMenuFont);
            const auto previous = SelectObject(dc, font);
            SIZE size{};
            GetTextExtentPoint32W(dc, item->second->text.c_str(), static_cast<int>(item->second->text.size()), &size);
            SelectObject(dc, previous); DeleteObject(font); ReleaseDC(window, dc);
            measure->itemWidth = size.cx + Scale(window, 60);
            measure->itemHeight = separator ? Scale(window, 8) : std::max<int>(size.cy + Scale(window, 10), Scale(window, 26));
            return TRUE;
        }
    }
    if (message == WM_DRAWITEM) {
        auto draw = reinterpret_cast<DRAWITEMSTRUCT*>(lparam);
        auto found = manager.menuItems_.find(draw->itemData);
        if (draw->CtlType == ODT_MENU && found != manager.menuItems_.end()) {
            const auto& p = manager.palette_;
            const int saved = SaveDC(draw->hDC);
            const bool disabled = (draw->itemState & (ODS_DISABLED | ODS_GRAYED)) != 0;
            Fill(draw->hDC, draw->rcItem, draw->itemState & ODS_SELECTED ? (disabled ? p.button : p.selection) : p.background);
            RECT text = draw->rcItem;
            if (found->second->type & MFT_SEPARATOR) {
                text.top = (text.top + text.bottom) / 2;
                text.bottom = text.top + 1;
                Fill(draw->hDC, text, p.border);
            } else {
                NONCLIENTMETRICSW metrics{sizeof(metrics)};
                SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0, GetDpiForWindow(window));
                HFONT font = CreateFontIndirectW(&metrics.lfMenuFont);
                const auto oldFont = SelectObject(draw->hDC, font);
                SetBkMode(draw->hDC, TRANSPARENT);
                SetTextColor(draw->hDC, draw->itemState & (ODS_DISABLED | ODS_GRAYED) ? p.disabled :
                    draw->itemState & ODS_SELECTED ? p.selectedText : p.text);
                text.left += Scale(window, 26); text.right -= Scale(window, 20);
                const auto& label = found->second->text;
                const auto tab = label.find(L'\t');
                const UINT flags = DT_SINGLELINE | DT_VCENTER | (draw->itemState & ODS_NOACCEL ? DT_HIDEPREFIX : 0);
                DrawTextW(draw->hDC, label.c_str(), tab == std::wstring::npos ? -1 : static_cast<int>(tab), &text, flags);
                if (tab != std::wstring::npos) DrawTextW(draw->hDC, label.c_str() + tab + 1, -1, &text, flags | DT_RIGHT);
                if (draw->itemState & ODS_CHECKED) {
                    RECT mark = draw->rcItem;
                    mark.right = mark.left + Scale(window, 20);
                    CheckMark(draw->hDC, mark, disabled ? p.disabled : draw->itemState & ODS_SELECTED ? p.selectedText : p.text,
                        std::max(1, Scale(window, 2)));
                }
                MENUITEMINFOW info{sizeof(info)};
                info.fMask = MIIM_SUBMENU;
                if (GetMenuItemInfoW(found->second->menu, found->second->position, TRUE, &info) && info.hSubMenu) {
                    RECT arrow = draw->rcItem;
                    arrow.left = arrow.right - Scale(window, 18);
                    Arrow(draw->hDC, arrow, disabled ? p.disabled : p.text, 3);
                }
                SelectObject(draw->hDC, oldFont);
                DeleteObject(font);
            }
            RestoreDC(draw->hDC, saved);
            return TRUE;
        }
    }
    const LRESULT result = DefSubclassProc(window, message, wparam, lparam);
    if (painted && message == WM_MOUSEMOVE && !hot) {
        TRACKMOUSEEVENT track{sizeof(track), TME_LEAVE, window, 0};
        TrackMouseEvent(&track);
        SetWindowSubclass(window, WindowProcedure, kSubclass, 1);
        InvalidateRect(window, nullptr, FALSE);
    } else if (painted && message == WM_MOUSELEAVE) {
        SetWindowSubclass(window, WindowProcedure, kSubclass, 0);
        InvalidateRect(window, nullptr, FALSE);
    }
    if (painted && (message == WM_ENABLE || message == WM_SETFOCUS || message == WM_KILLFOCUS ||
        message == BM_SETCHECK || message == BM_SETSTATE || message == CB_SETCURSEL ||
        message == WM_UPDATEUISTATE || message == WM_SETTEXT))
        InvalidateRect(window, nullptr, FALSE);
    if (nonclient && (message == WM_VSCROLL || message == WM_HSCROLL || message == WM_MOUSEWHEEL ||
        message == WM_NCMOUSEMOVE || message == WM_NCLBUTTONDOWN || message == WM_NCLBUTTONUP ||
        message == WM_CAPTURECHANGED || message == WM_NCACTIVATE || message == WM_PAINT ||
        message == WM_KEYDOWN || message == WM_SETTEXT || message == WM_SIZE))
        PaintScrollbars(window);
    return result;
}

}  // namespace

void SetAppearance(Appearance mode) {
    AppearanceName(mode);
    Manager().Initialize();
    const auto previous = Manager().mode_;
    Manager().mode_ = mode;
    try {
        Manager().Refresh();
    } catch (const std::exception&) {
        Manager().mode_ = previous;
        throw;
    }
}

Appearance CurrentAppearance() { return Manager().mode_; }
const AppearancePalette& Colours() { return Manager().palette_; }
bool HighContrast() { return Manager().highContrast_; }
void ThemeWindow(HWND window) { Manager().Add(window); }
#ifdef TELIPHONES_APPEARANCE_TESTING
void SimulateSystemAppearance(bool dark, bool highContrast) {
    Manager().environmentOverride_ = {dark, highContrast};
    Manager().Initialize();
    Manager().PostEnvironmentChange();
}
#endif

namespace {

class CAppearanceMessage : public CAppearanceDialog {
public:
    CAppearanceMessage(LPCTSTR text, UINT flags, CWnd* parent)
        : CAppearanceDialog(IDD_APP_MESSAGE, parent), text_(text), flags_(flags) {}

protected:
    BOOL OnInitDialog() override {
        CAppearanceDialog::OnInitDialog();
        SetDlgItemText(IDC_MESSAGE_TEXT, text_);
        const UINT type = flags_ & MB_TYPEMASK;
        if (type == MB_YESNO) {
            if (CMenu* menu = GetSystemMenu(FALSE)) menu->EnableMenuItem(SC_CLOSE, MF_BYCOMMAND | MF_GRAYED);
        }
        if (type == MB_YESNO || type == MB_YESNOCANCEL) {
            buttons_ = {{IDYES, L"Yes"}, {IDNO, L"No"}};
            if (type == MB_YESNOCANCEL) buttons_.push_back({IDCANCEL, L"Cancel"});
        } else if (type == MB_RETRYCANCEL) {
            buttons_ = {{IDRETRY, L"Retry"}, {IDCANCEL, L"Cancel"}};
        } else {
            buttons_ = {{IDOK, L"OK"}};
            if (type == MB_OKCANCEL) buttons_.push_back({IDCANCEL, L"Cancel"});
        }
        const int defaultButton = std::min<int>(static_cast<int>(buttons_.size()) - 1,
            static_cast<int>((flags_ & MB_DEFMASK) >> 8));
        for (int i = 0; i < 3; ++i) {
            CWnd* button = GetDlgItem(IDC_MESSAGE_FIRST + i);
            button->ShowWindow(i < static_cast<int>(buttons_.size()) ? SW_SHOW : SW_HIDE);
            if (i < static_cast<int>(buttons_.size())) button->SetWindowText(buttons_[i].second);
        }
        try {
            FitMessage();
        } catch (const std::exception& error) {
            OutputDebugStringW(win::Widen(std::string("TELIPHONES message layout failed: ") + error.what() + "\n").c_str());
            EndDialog(-1);
            return FALSE;
        }
        SendMessage(DM_SETDEFID, IDC_MESSAGE_FIRST + defaultButton);
        GetDlgItem(IDC_MESSAGE_FIRST + defaultButton)->SetFocus();
        const UINT iconType = flags_ & MB_ICONMASK;
        LPCWSTR icon = iconType == MB_ICONERROR ? IDI_ERROR : iconType == MB_ICONWARNING ? IDI_WARNING :
            iconType == MB_ICONQUESTION ? IDI_QUESTION : IDI_INFORMATION;
        static_cast<CStatic*>(GetDlgItem(IDC_MESSAGE_ICON))->SetIcon(LoadIconW(nullptr, icon));
        return FALSE;
    }

    BOOL OnCommand(WPARAM wparam, LPARAM lparam) override {
        const int index = LOWORD(wparam) - IDC_MESSAGE_FIRST;
        if (index >= 0 && index < static_cast<int>(buttons_.size()) && HIWORD(wparam) == BN_CLICKED) {
            EndDialog(buttons_[index].first);
            return TRUE;
        }
        return CAppearanceDialog::OnCommand(wparam, lparam);
    }
    void OnOK() override {
        const int index = std::min<int>(static_cast<int>(buttons_.size()) - 1, static_cast<int>((flags_ & MB_DEFMASK) >> 8));
        EndDialog(buttons_[index].first);
    }
    void OnCancel() override {
        const UINT type = flags_ & MB_TYPEMASK;
        if (type != MB_YESNO) EndDialog(type == MB_OK ? IDOK : IDCANCEL);
    }

private:
    void FitMessage() {
        MONITORINFO monitor{sizeof(monitor)};
        if (!GetMonitorInfoW(MonitorFromWindow(m_hWnd, MONITOR_DEFAULTTONEAREST), &monitor))
            win::ThrowLastError("Find TELIPHONES message work area");
        CRect rectangle;
        GetWindowRect(&rectangle);
        const int width = std::min<int>(rectangle.Width(), monitor.rcWork.right - monitor.rcWork.left);
        const int height = std::min<int>(rectangle.Height(), monitor.rcWork.bottom - monitor.rcWork.top);
        const int x = std::clamp<int>(rectangle.left, monitor.rcWork.left, monitor.rcWork.right - width);
        const int y = std::clamp<int>(rectangle.top, monitor.rcWork.top, monitor.rcWork.bottom - height);
        SetWindowPos(nullptr, x, y, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
        CRect client;
        GetClientRect(&client);
        const int margin = Scale(m_hWnd, 10), gap = Scale(m_hWnd, 8);
        const int buttonWidth = std::min(Scale(m_hWnd, 88), std::max(1, client.Width() - margin * 2));
        const int buttonHeight = Scale(m_hWnd, 28);
        const int columns = std::max(1, (client.Width() - margin * 2 + gap) / (buttonWidth + gap));
        const int count = static_cast<int>(buttons_.size());
        const int rows = (count + columns - 1) / columns;
        const int footer = client.Height() - margin - rows * (buttonHeight + gap);
        for (int i = 0; i < count; ++i) {
            GetDlgItem(IDC_MESSAGE_FIRST + i)->MoveWindow(margin + (i % columns) * (buttonWidth + gap),
                footer + (i / columns) * (buttonHeight + gap), buttonWidth, buttonHeight);
        }
        const int textLeft = Scale(m_hWnd, 46);
        GetDlgItem(IDC_MESSAGE_ICON)->MoveWindow(margin, margin, Scale(m_hWnd, 32), Scale(m_hWnd, 32));
        GetDlgItem(IDC_MESSAGE_TEXT)->MoveWindow(textLeft, margin, std::max(1, client.Width() - textLeft - margin),
            std::max(1, footer - margin - gap));
    }

    CString text_;
    UINT flags_;
    std::vector<std::pair<int, LPCWSTR>> buttons_;
};

}  // namespace

int ShowMessage(LPCTSTR text, UINT flags) {
    CAppearanceMessage dialog(text, flags, CWnd::GetActiveWindow());
    if (flags & MB_ICONMASK) MessageBeep(flags & MB_ICONMASK);
    const INT_PTR result = dialog.DoModal();
    if (result == -1) {
        OutputDebugStringW(L"TELIPHONES: themed message dialog creation failed; displaying the Windows message box.\n");
        return AfxMessageBox(text, flags);
    }
    return static_cast<int>(result);
}

}  // namespace tlp::ui

BOOL CAppearanceDialog::OnInitDialog() {
    const BOOL result = CDialogEx::OnInitDialog();
    try {
        tlp::ui::ThemeWindow(m_hWnd);
    } catch (const std::exception& error) {
        AfxMessageBox(tlp::win::Widen(error.what()).c_str(), MB_ICONERROR);
    }

    return result;
}

LRESULT CAppearanceDialog::WindowProc(UINT message, WPARAM wparam, LPARAM lparam) {
    if (tlp::ui::DrawComboItem(message, lparam)) return TRUE;
    if (message == WM_MEASUREITEM && lparam) {
        auto item = reinterpret_cast<MEASUREITEMSTRUCT*>(lparam);
        if (item->CtlType == ODT_COMBOBOX) {
            item->itemHeight = MulDiv(20, static_cast<int>(GetDpiForWindow(m_hWnd)), 96);
            return TRUE;
        }
    }
    return CDialogEx::WindowProc(message, wparam, lparam);
}
