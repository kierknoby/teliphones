#include "SshTerminalDlg.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cwchar>
#include <cstring>
#include <functional>
#include <regex>
#include <utility>

#include "../core/Encoding.h"
#include "../core/TerminalEmulator.h"
#include "../platform/Win.h"
#include "resource.h"
#include "Version.h"

namespace {
constexpr COLORREF kTerminalBackground = RGB(10, 10, 10);
constexpr std::size_t kMaximumPasteCharacters = 65536;
constexpr ULONGLONG kSessionIdleTimeoutMs = 30ULL * 60ULL * 1000ULL;
class ClipboardLock final {
public:
    explicit ClipboardLock(HWND owner) {
        if (!OpenClipboard(owner)) throw tlp::Error("Windows could not open the clipboard.");
        open_ = true;
    }
    ~ClipboardLock() { if (open_) CloseClipboard(); }
    ClipboardLock(const ClipboardLock&) = delete;
    ClipboardLock& operator=(const ClipboardLock&) = delete;
private:
    bool open_ = false;
};

void CopyClipboard(HWND owner, const std::wstring& text) {
    ClipboardLock clipboard(owner);
    if (!EmptyClipboard()) throw tlp::Error("Windows could not clear the clipboard.");
    const SIZE_T bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!memory) throw tlp::Error("Windows could not allocate clipboard memory.");
    void* target = GlobalLock(memory);
    if (!target) {
        GlobalFree(memory);
        throw tlp::Error("Windows could not access clipboard memory.");
    }
    memcpy(target, text.c_str(), bytes);
    GlobalUnlock(memory);
    if (!SetClipboardData(CF_UNICODETEXT, memory)) {
        GlobalFree(memory);
        throw tlp::Error("Windows could not copy the terminal text.");
    }
}

std::wstring ReadClipboard(HWND owner) {
    ClipboardLock clipboard(owner);
    HANDLE data = GetClipboardData(CF_UNICODETEXT);
    if (!data) throw tlp::Error("The clipboard does not contain text.");
    const SIZE_T bytes = GlobalSize(data);
    if (bytes < sizeof(wchar_t) || bytes % sizeof(wchar_t) != 0)
        throw tlp::Error("The clipboard text has an invalid Windows Unicode buffer.");
    const auto* text = static_cast<const wchar_t*>(GlobalLock(data));
    if (!text) throw tlp::Error("Windows could not read clipboard text.");
    const auto capacity = bytes / sizeof(wchar_t);
    std::size_t length = 0;
    while (length < capacity && text[length] != L'\0') ++length;
    if (length == capacity) {
        GlobalUnlock(data);
        throw tlp::Error("The clipboard text is not null-terminated.");
    }
    std::wstring result(text, length);
    GlobalUnlock(data);
    if (result.size() > kMaximumPasteCharacters)
        throw tlp::Error("Clipboard text is too large for one terminal paste.");
    return result;
}

bool HasTextClipboard(HWND owner) {
    (void)owner;
    return IsClipboardFormatAvailable(CF_UNICODETEXT) != FALSE;
}

std::u32string utf32(const std::wstring& text) {
    std::u32string result;
    for (std::size_t index = 0; index < text.size(); ++index) {
        const auto first = static_cast<std::uint32_t>(text[index]);
        if (first >= 0xd800 && first <= 0xdbff && index + 1 < text.size()) {
            const auto second = static_cast<std::uint32_t>(text[index + 1]);
            if (second >= 0xdc00 && second <= 0xdfff) {
                result.push_back(static_cast<char32_t>(0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)));
                ++index;
                continue;
            }
        }
        if (first >= 0xd800 && first <= 0xdfff) result.push_back(U'\ufffd');
        else result.push_back(static_cast<char32_t>(first));
    }
    return result;
}

std::wstring utf16(const std::u32string& text) {
    std::wstring result;
    for (const auto raw : text) {
        const auto codepoint = static_cast<std::uint32_t>(raw);
        if (codepoint <= 0xffff) result.push_back(static_cast<wchar_t>(codepoint));
        else {
            const auto scalar = codepoint - 0x10000;
            result.push_back(static_cast<wchar_t>(0xd800 + (scalar >> 10)));
            result.push_back(static_cast<wchar_t>(0xdc00 + (scalar & 0x3ff)));
        }
    }
    return result;
}

COLORREF terminalColor(std::uint32_t color) {
    return RGB((color >> 16) & 0xff, (color >> 8) & 0xff, color & 0xff);
}

std::wstring trimTerminalLine(std::wstring line) {
    while (!line.empty() && line.back() == L' ') line.pop_back();
    return line;
}
}

class CTerminalView final : public CWnd {
public:
    using ResizeCallback = std::function<void(int, int)>;
    CTerminalView(tlp::TerminalEmulator& terminal, ResizeCallback resize)
        : terminal_(terminal), resize_(std::move(resize)) {}

    BOOL Create(CWnd* parent, UINT id) {
        const auto className = AfxRegisterWndClass(CS_HREDRAW | CS_VREDRAW, ::LoadCursor(nullptr, IDC_IBEAM));
        return CWnd::CreateEx(WS_EX_CLIENTEDGE, className, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL,
                              CRect(0, 0, 1, 1), parent, id);
    }

    void Refresh() { Invalidate(FALSE); }
    int CellWidth() const noexcept { return cellWidth_; }
    int CellHeight() const noexcept { return cellHeight_; }
    bool AtLiveBottom() const noexcept { return scrollOffset_ == 0; }
    void SetCursorBlink(bool visible) { cursorBlinkVisible_ = visible; Invalidate(FALSE); }
    void ClearHistory() {
        terminal_.ClearScrollback();
        terminal_.Feed("\x1b[2J\x1b[H");
        scrollOffset_ = 0;
        UpdateScrollbar();
        Invalidate(FALSE);
    }
    void CopyAll() { CopyClipboard(m_hWnd, utf16(utf32FromUtf8(terminal_.TextAllForCopy()))); }
    void PasteClipboard() {
        const auto text = ReadClipboard(m_hWnd);
        terminal_.Paste(utf32(text));
        if (const auto parent = GetParent()) parent->SendMessage(WM_APP + 0x414, 0, 0);
        SetFocus();
    }
    std::wstring LogicalLine(int row) const { return trimTerminalLine(utf16(terminal_.LogicalLineAt(row))); }
    int CursorRow() const { int row = 0, column = 0; bool visible = false; terminal_.Cursor(row, column, visible); return row; }
    int CursorColumn() const { int row = 0, column = 0; bool visible = false; terminal_.Cursor(row, column, visible); return column; }

protected:
    afx_msg void OnPaint() {
        CPaintDC dc(this);
        CRect client;
        GetClientRect(&client);
        dc.FillSolidRect(client, kTerminalBackground);
        dc.SelectObject(&font_);
        dc.SetBkMode(OPAQUE);
        int cursorRow = 0, cursorColumn = 0;
        bool cursorVisible = false;
        terminal_.Cursor(cursorRow, cursorColumn, cursorVisible);
        const auto history = terminal_.ScrollbackRows();
        const auto firstRow = static_cast<long long>(history) - scrollOffset_;
        for (int screenRow = 0; screenRow < rows_; ++screenRow) {
            const auto historyRow = firstRow + screenRow;
            for (int column = 0; column < columns_; ++column) {
                const auto cell = historyRow < 0
                    ? tlp::TerminalCell{}
                    : static_cast<std::size_t>(historyRow) < history
                        ? terminal_.ScrollbackCellAt(static_cast<std::size_t>(historyRow), column)
                        : terminal_.CellAt(static_cast<int>(historyRow - static_cast<long long>(history)), column);
                if (cell.wideContinuation) continue;
                const int cellWidth = cell.width > 1 ? cellWidth_ * cell.width : cellWidth_;
                const int left = column * cellWidth_;
                const int top = screenRow * cellHeight_;
                CRect rectangle(left, top, left + cellWidth, top + cellHeight_);
                const auto foreground = terminalColor(cell.foreground);
                const auto background = terminalColor(cell.background);
                dc.SetTextColor(foreground);
                dc.SetBkColor(background);
                dc.SelectObject(FontFor(cell));
                const auto text = utf16(cell.text);
                const auto drawText = text.empty() ? L" " : text.c_str();
                dc.ExtTextOutW(left, top, ETO_OPAQUE, rectangle, drawText, static_cast<UINT>(wcslen(drawText)), nullptr);
                if (cell.underline) {
                    dc.FillSolidRect(left, top + cellHeight_ - 2, cellWidth, 1, foreground);
                }
                if (cell.strike) {
                    dc.FillSolidRect(left, top + cellHeight_ / 2, cellWidth, 1, foreground);
                }
            }
        }
        const auto totalRows = static_cast<long long>(history) + terminal_.Rows();
        const auto liveTop = totalRows - terminal_.Rows() - scrollOffset_;
        if (cursorVisible && GetFocus() != this && scrollOffset_ == 0 && cursorRow >= 0 && cursorRow < rows_ &&
            cursorColumn >= 0 && cursorColumn < columns_) {
            CRect cursor(cursorColumn * cellWidth_, cursorRow * cellHeight_,
                         (cursorColumn + 1) * cellWidth_, (cursorRow + 1) * cellHeight_);
            if (liveTop + cursorRow >= static_cast<long long>(history)) dc.InvertRect(cursor);
        }
        if (GetFocus() == this && cursorVisible && cursorBlinkVisible_ && scrollOffset_ == 0 &&
            cursorRow >= 0 && cursorRow < rows_ && cursorColumn >= 0 && cursorColumn < columns_) {
            CRect cursor(cursorColumn * cellWidth_, cursorRow * cellHeight_,
                         (cursorColumn + 1) * cellWidth_, (cursorRow + 1) * cellHeight_);
            dc.InvertRect(cursor);
        }
    }

    afx_msg BOOL OnEraseBkgnd(CDC*) { return TRUE; }
    afx_msg void OnSize(UINT type, int width, int height) {
        CWnd::OnSize(type, width, height);
        // Exceptions must not leave a window procedure: MFC would terminate TELIPHONES.
        try {
            RecalculateGrid(width, height);
        } catch (const std::exception& error) {
            if (CWnd* parent = GetParent())
                parent->SetDlgItemText(IDC_SSH_TERMINAL_STATUS,
                                       tlp::win::Widen(std::string("SSH console display error: ") + error.what()).c_str());
        }
    }
    afx_msg void OnVScroll(UINT code, UINT position, CScrollBar* scrollbar) {
        const int previousScrollOffset = scrollOffset_;
        const int maximum = static_cast<int>(terminal_.ScrollbackRows());
        switch (code) {
            case SB_LINEUP: scrollOffset_ = std::min(maximum, scrollOffset_ + 1); break;
            case SB_LINEDOWN: scrollOffset_ = std::max(0, scrollOffset_ - 1); break;
            case SB_PAGEUP: scrollOffset_ = std::min(maximum, scrollOffset_ + rows_); break;
            case SB_PAGEDOWN: scrollOffset_ = std::max(0, scrollOffset_ - rows_); break;
            case SB_THUMBTRACK:
            case SB_THUMBPOSITION: scrollOffset_ = maximum - static_cast<int>(position); break;
            case SB_TOP: scrollOffset_ = maximum; break;
            case SB_BOTTOM: scrollOffset_ = 0; break;
            default: break;
        }
        UpdateScrollbar();
        Invalidate(FALSE);
        if (scrollOffset_ != previousScrollOffset)
            if (const auto parent = GetParent()) parent->SendMessage(WM_APP + 0x415, 1, 0);
        CWnd::OnVScroll(code, position, scrollbar);
    }
    afx_msg BOOL OnMouseWheel(UINT flags, short delta, CPoint point) {
        const int previousScrollOffset = scrollOffset_;
        const auto steps = delta / WHEEL_DELTA;
        scrollOffset_ = std::clamp(scrollOffset_ + steps * 3, 0, static_cast<int>(terminal_.ScrollbackRows()));
        UpdateScrollbar();
        Invalidate(FALSE);
        if (scrollOffset_ != previousScrollOffset)
            if (const auto parent = GetParent()) parent->SendMessage(WM_APP + 0x415, 1, 0);
        (void)flags;
        (void)point;
        return TRUE;
    }
    afx_msg UINT OnGetDlgCode() { return DLGC_WANTALLKEYS | DLGC_WANTARROWS | DLGC_WANTCHARS; }
    afx_msg void OnKeyDown(UINT key, UINT repeat, UINT flags) {
        if ((GetKeyState(VK_CONTROL) & 0x8000) && (GetKeyState(VK_SHIFT) & 0x8000)) {
            if (key == 'C') {
                CopyAll();
                return;
            }
            if (key == 'V') {
                try { PasteClipboard(); }
                catch (const std::exception& error) {
                    if (const auto parent = GetParent()) parent->SendMessage(WM_APP + 0x416, 0,
                        reinterpret_cast<LPARAM>(&error));
                }
                return;
            }
        }
        const bool control = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
        const bool shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
        const bool alt = (GetKeyState(VK_MENU) & 0x8000) != 0;
        const unsigned modifiers = (control ? VTERM_MOD_CTRL : 0) |
                                   (shift ? VTERM_MOD_SHIFT : 0) |
                                   (alt ? VTERM_MOD_ALT : 0);
        if (control && key >= 'A' && key <= 'Z') {
            terminal_.Character(static_cast<std::uint32_t>(key - 'A' + 'a'), VTERM_MOD_CTRL);
        } else {
            VTermKey terminalKey = VTERM_KEY_NONE;
            switch (key) {
                case VK_RETURN: terminalKey = VTERM_KEY_ENTER; break;
                case VK_TAB: terminalKey = VTERM_KEY_TAB; break;
                case VK_BACK: terminalKey = VTERM_KEY_BACKSPACE; break;
                case VK_ESCAPE: terminalKey = VTERM_KEY_ESCAPE; break;
                case VK_UP: terminalKey = VTERM_KEY_UP; break;
                case VK_DOWN: terminalKey = VTERM_KEY_DOWN; break;
                case VK_LEFT: terminalKey = VTERM_KEY_LEFT; break;
                case VK_RIGHT: terminalKey = VTERM_KEY_RIGHT; break;
                case VK_INSERT: terminalKey = VTERM_KEY_INS; break;
                case VK_DELETE: terminalKey = VTERM_KEY_DEL; break;
                case VK_HOME: terminalKey = VTERM_KEY_HOME; break;
                case VK_END: terminalKey = VTERM_KEY_END; break;
                case VK_PRIOR: terminalKey = VTERM_KEY_PAGEUP; break;
                case VK_NEXT: terminalKey = VTERM_KEY_PAGEDOWN; break;
                default:
                    if (key >= VK_F1 && key <= VK_F24)
                        terminalKey = static_cast<VTermKey>(
                            VTERM_KEY_FUNCTION(static_cast<int>(key - VK_F1 + 1)));
                    break;
            }
            if (terminalKey != VTERM_KEY_NONE) terminal_.Key(terminalKey, modifiers);
            else {
                CWnd::OnKeyDown(key, repeat, flags);
                return;
            }
        }
        if (const auto parent = GetParent()) parent->SendMessage(WM_APP + 0x414, 0, 0);
        scrollOffset_ = 0;
        Invalidate(FALSE);
    }
    afx_msg void OnSysKeyDown(UINT key, UINT repeat, UINT flags) {
        if (key == VK_F4 && (flags & KF_ALTDOWN)) {
            if (CWnd* parent = GetParent()) parent->SendMessage(WM_SYSCOMMAND, SC_CLOSE);
            return;
        }
        OnKeyDown(key, repeat, flags);
    }
    afx_msg void OnChar(UINT character, UINT repeat, UINT flags) {
        if (character >= 0x20 && character != 0x7f) {
            if (character >= 0xd800 && character <= 0xdbff) {
                pendingHighSurrogate_ = static_cast<wchar_t>(character);
                return;
            }
            std::uint32_t codepoint = character;
            if (character >= 0xdc00 && character <= 0xdfff) {
                if (!pendingHighSurrogate_) codepoint = 0xfffd;
                else {
                    codepoint = 0x10000 + ((pendingHighSurrogate_ - 0xd800) << 10) + (character - 0xdc00);
                    pendingHighSurrogate_ = 0;
                }
            } else if (pendingHighSurrogate_) {
                terminal_.Character(0xfffd, VTERM_MOD_NONE);
                pendingHighSurrogate_ = 0;
            }
            terminal_.Character(codepoint, VTERM_MOD_NONE);
            if (const auto parent = GetParent()) parent->SendMessage(WM_APP + 0x414, 0, 0);
            scrollOffset_ = 0;
            Invalidate(FALSE);
            return;
        }
        CWnd::OnChar(character, repeat, flags);
    }
    afx_msg void OnSetFocus(CWnd* previous) {
        CWnd::OnSetFocus(previous);
        Invalidate(FALSE);
    }
    afx_msg void OnKillFocus(CWnd* next) {
        CWnd::OnKillFocus(next);
        Invalidate(FALSE);
    }
    DECLARE_MESSAGE_MAP()

private:
    std::u32string utf32FromUtf8(const std::string& input) const {
        std::u32string result;
        for (std::size_t index = 0; index < input.size();) {
            const auto start = index;
            const auto first = static_cast<unsigned char>(input[index++]);
            std::uint32_t codepoint = first;
            std::uint32_t minimum = 0;
            int continuation = 0;
            if (first >= 0xc2 && first <= 0xdf) {
                codepoint = first & 0x1f;
                minimum = 0x80;
                continuation = 1;
            } else if (first >= 0xe0 && first <= 0xef) {
                codepoint = first & 0x0f;
                minimum = 0x800;
                continuation = 2;
            } else if (first >= 0xf0 && first <= 0xf4) {
                codepoint = first & 0x07;
                minimum = 0x10000;
                continuation = 3;
            } else if (first >= 0x80) {
                result.push_back(U'\ufffd');
                continue;
            }
            bool valid = index + static_cast<std::size_t>(continuation) <= input.size();
            for (int offset = 0; valid && offset < continuation; ++offset) {
                const auto next = static_cast<unsigned char>(input[index++]);
                if ((next & 0xc0) != 0x80) {
                    valid = false;
                    index = start + 1;
                }
                else codepoint = (codepoint << 6) | (next & 0x3f);
            }
            if (!valid || codepoint < minimum || codepoint > 0x10ffff ||
                (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
                result.push_back(U'\ufffd');
                continue;
            }
            result.push_back(static_cast<char32_t>(codepoint));
        }
        return result;
    }

    void RecalculateGrid(int width, int height) {
        if (!GetSafeHwnd()) return;
        CClientDC dc(this);
        if (!font_.GetSafeHandle()) {
            LOGFONTW font{};
            font.lfHeight = -MulDiv(11, dc.GetDeviceCaps(LOGPIXELSY), 72);
            font.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
            wcscpy_s(font.lfFaceName, L"Consolas");
            if (!font_.CreateFontIndirectW(&font)) throw tlp::Error("Unable to create the terminal font.");
        }
        CFont* oldFont = dc.SelectObject(&font_);
        TEXTMETRICW metrics{};
        dc.GetTextMetricsW(&metrics);
        dc.SelectObject(oldFont);
        cellWidth_ = std::max(1, static_cast<int>(metrics.tmAveCharWidth));
        cellHeight_ = std::max(1, static_cast<int>(metrics.tmHeight + metrics.tmExternalLeading));
        columns_ = std::clamp(width / cellWidth_, 2, 500);
        rows_ = std::clamp(height / cellHeight_, 2, 300);
        terminal_.Resize(columns_, rows_);
        UpdateScrollbar();
        try {
            resize_(columns_, rows_);
        } catch (const std::exception& error) {
            tlp::ui::ShowMessage(tlp::win::Widen(std::string("PTY resize failed: ") + error.what()).c_str(), MB_ICONERROR);
        }
        Invalidate(FALSE);
    }

    CFont* FontFor(const tlp::TerminalCell& cell) {
        const unsigned style = (cell.bold ? 1u : 0u) | (cell.italic ? 2u : 0u);
        auto& selected = fonts_[style];
        if (selected.GetSafeHandle()) return &selected;
        LOGFONTW description{};
        font_.GetLogFont(&description);
        description.lfWeight = cell.bold ? FW_BOLD : FW_NORMAL;
        description.lfItalic = cell.italic;
        if (!selected.CreateFontIndirectW(&description)) return &font_;
        return &selected;
    }

    void UpdateScrollbar() {
        if (!GetSafeHwnd()) return;
        SCROLLINFO info{sizeof(info), SIF_RANGE | SIF_PAGE | SIF_POS};
        const auto history = static_cast<int>(terminal_.ScrollbackRows());
        info.nMin = 0;
        info.nMax = history + std::max(0, rows_ - 1);
        info.nPage = static_cast<UINT>(std::max(1, rows_));
        info.nPos = history - scrollOffset_;
        SetScrollInfo(SB_VERT, &info, TRUE);
    }

    tlp::TerminalEmulator& terminal_;
    ResizeCallback resize_;
    CFont font_;
    std::array<CFont, 4> fonts_;
    int cellWidth_ = 9;
    int cellHeight_ = 18;
    int columns_ = 80;
    int rows_ = 24;
    int scrollOffset_ = 0;
    wchar_t pendingHighSurrogate_ = 0;
    bool cursorBlinkVisible_ = true;
};

BEGIN_MESSAGE_MAP(CTerminalView, CWnd)
    ON_WM_PAINT()
    ON_WM_ERASEBKGND()
    ON_WM_SIZE()
    ON_WM_VSCROLL()
    ON_WM_MOUSEWHEEL()
    ON_WM_GETDLGCODE()
    ON_WM_KEYDOWN()
    ON_WM_SYSKEYDOWN()
    ON_WM_CHAR()
    ON_WM_SETFOCUS()
    ON_WM_KILLFOCUS()
END_MESSAGE_MAP()

BEGIN_MESSAGE_MAP(CSshTerminalDlg, CAppearanceDialog)
    ON_WM_SIZE()
    ON_WM_TIMER()
    ON_WM_MOUSEWHEEL()
    ON_WM_MOVE()
    ON_MESSAGE(WM_APP + 0x414, &CSshTerminalDlg::OnTerminalInput)
    ON_MESSAGE(WM_APP + 0x415, &CSshTerminalDlg::OnTerminalScroll)
    ON_MESSAGE(WM_APP + 0x416, &CSshTerminalDlg::OnPasteError)
    ON_BN_CLICKED(IDC_SSH_TERMINAL_COPY, &CSshTerminalDlg::OnCopyAll)
    ON_BN_CLICKED(IDC_SSH_TERMINAL_CLEAR, &CSshTerminalDlg::OnClearAll)
    ON_BN_CLICKED(IDC_SSH_TERMINAL_PASTE, &CSshTerminalDlg::OnPaste)
    ON_BN_CLICKED(IDC_SSH_TERMINAL_RECONNECT, &CSshTerminalDlg::OnReconnect)
    ON_BN_CLICKED(IDC_SSH_TERMINAL_DISCONNECT, &CSshTerminalDlg::OnDisconnect)
END_MESSAGE_MAP()

CSshTerminalDlg::CSshTerminalDlg(const tlp::Profile& profile,
                                 std::shared_ptr<tlp::win::ManagedSshConsole> console, CWnd* parent)
    : CAppearanceDialog(IDD_SSH_TERMINAL, parent), profile_(profile), console_(std::move(console)) {}

CSshTerminalDlg::~CSshTerminalDlg() = default;

BOOL CSshTerminalDlg::OnInitDialog() {
    CAppearanceDialog::OnInitDialog();
    try {
        return InitializeConsole();
    } catch (const std::exception& error) {
        // Exceptions must not leave a window procedure; the caller verifies SSH teardown after the dialog closes.
        StopConsole();
        tlp::ui::ShowMessage(tlp::win::Widen(std::string("The SSH console could not be opened: ") + error.what()).c_str(),
                             MB_ICONERROR);
        EndDialog(IDABORT);
        return FALSE;
    }
}

BOOL CSshTerminalDlg::InitializeConsole() {
    if ((profile_.sshUser.empty() ? profile_.pairing.sshUser : profile_.sshUser).empty())
        throw tlp::Error("The PBX has not approved an SSH account for this workstation.");
    SetWindowTextW(L"Console");
    SetDlgItemText(IDC_SSH_TERMINAL_STATUS, L"Connecting · SSH authentication not yet confirmed");
    for (const int id : {IDC_SSH_TERMINAL_OUTPUT, IDC_SSH_TERMINAL_INPUT, IDC_SSH_TERMINAL_SEND})
        if (CWnd* control = GetDlgItem(id)) {
            if (id == IDC_SSH_TERMINAL_OUTPUT) control->DestroyWindow();
            else control->ShowWindow(SW_HIDE);
        }
    GetDlgItem(IDC_SSH_TERMINAL_PASTE)->ShowWindow(SW_HIDE);
    terminal_ = std::make_unique<tlp::TerminalEmulator>(80, 24, [this](const std::string& bytes) {
        try {
            if (console_ && console_->IsAlive()) console_->WriteInput(bytes);
            else if (console_) throw tlp::Error("The SSH session is no longer connected.");
        } catch (const std::exception& error) {
            SetDlgItemText(IDC_SSH_TERMINAL_STATUS,
                           tlp::win::Widen(std::string("SSH input failed: ") + error.what()).c_str());
            if (terminalView_) terminalView_->EnableWindow(FALSE);
            if (console_) {
                try {
                    console_->Disconnect();
                    console_.reset();
                } catch (...) {
                    // Keep the session handle so dialog close can retry cleanup.
                }
            }
        }
    });
    terminalView_ = std::make_unique<CTerminalView>(*terminal_, [this](int columns, int rows) {
        if (console_ && console_->IsAlive()) console_->Resize(columns, rows);
    });
    if (!terminalView_->Create(this, IDC_SSH_TERMINAL_OUTPUT))
        throw tlp::Error("Unable to create the VT terminal display.");
    GetDlgItem(IDC_SSH_TERMINAL_CLEAR)->SetWindowTextW(L"Clear All");
    SetDlgItemText(IDC_SSH_TERMINAL_COPY, L"Copy All");
    CRect client;
    GetClientRect(&client);
    OnSize(SIZE_RESTORED, client.Width(), client.Height());
    terminalView_->SetFocus();
    GetDlgItem(IDC_SSH_TERMINAL_STATUS)->SetWindowTextW(L"Connecting · SSH authentication not yet confirmed");
    std::string footer = "FreePBX UK Console v" TELIPHONES_VERSION_BASE;
#if TELIPHONES_VERSION_BUILD_IS_ASSIGNED
    footer += "." TELIPHONES_STRINGIFY(TELIPHONES_VERSION_BUILD);
#endif
    const auto footerText = tlp::win::Widen(footer);
    SetDlgItemText(IDC_SSH_TERMINAL_FOOTER, footerText.c_str());
    SetTimer(1, 100, nullptr);
    SetTimer(3, 500, nullptr);
    lastInputTick_ = GetTickCount64();
    return FALSE;
}

BOOL CSshTerminalDlg::PreTranslateMessage(MSG* message) {
    return CAppearanceDialog::PreTranslateMessage(message);
}

void CSshTerminalDlg::OnSize(UINT type, int width, int height) {
    CAppearanceDialog::OnSize(type, width, height);
    if (!GetSafeHwnd() || !terminalView_ || !GetDlgItem(IDC_SSH_TERMINAL_STATUS)) return;
    constexpr int margin = 12, buttonWidth = 82, buttonGap = 7, buttonHeight = 24;
    const int top = 43;
    const int bottom = std::max(top + 50, height - 62);
    const int viewWidth = std::max(100, width - margin * 2);
    GetDlgItem(IDC_SSH_TERMINAL_STATUS)->MoveWindow(margin, 10, viewWidth, 22);
    terminalView_->MoveWindow(margin, top, viewWidth, std::max(50, bottom - top - 8));
    GetDlgItem(IDC_SSH_TERMINAL_FOOTER)->MoveWindow(margin, height - 14, viewWidth, 12);
    const int row = height - 40;
    const std::array<int, 6> controls{IDC_SSH_TERMINAL_COPY, IDC_SSH_TERMINAL_CLEAR, IDC_SSH_TERMINAL_PASTE,
                                     IDC_SSH_TERMINAL_RECONNECT, IDC_SSH_TERMINAL_DISCONNECT, IDCANCEL};
    const int available = std::max(0, width - margin * 2);
    const int gap = available < buttonWidth * static_cast<int>(controls.size())
        ? 3 : buttonGap;
    const int eachWidth = std::max(48, std::min(buttonWidth,
        (available - gap * (static_cast<int>(controls.size()) - 1)) / static_cast<int>(controls.size())));
    int x = margin;
    for (const int id : controls) {
        if (CWnd* button = GetDlgItem(id)) {
            button->MoveWindow(x, row, eachWidth, buttonHeight);
            x += eachWidth + gap;
        }
    }
    ResizeTerminal();
    UpdatePasteButton();
}

void CSshTerminalDlg::ResizeTerminal() {
    if (terminalView_ && terminalView_->GetSafeHwnd()) terminalView_->Invalidate(FALSE);
}

void CSshTerminalDlg::OnTimer(UINT_PTR timerId) {
    if (timerId == 3) {
        cursorBlinkVisible_ = !cursorBlinkVisible_;
        if (terminalView_) terminalView_->SetCursorBlink(cursorBlinkVisible_);
        CAppearanceDialog::OnTimer(timerId);
        return;
    }
    if (timerId == feedbackTimer_) {
        KillTimer(feedbackTimer_);
        feedbackTimer_ = 0;
        if (CWnd* button = GetDlgItem(IDC_SSH_TERMINAL_COPY)) button->SetWindowTextW(L"Copy All");
        if (CWnd* button = GetDlgItem(IDC_SSH_TERMINAL_CLEAR)) button->SetWindowTextW(L"Clear All");
        CAppearanceDialog::OnTimer(timerId);
        return;
    }
    if (timerId == reconnectTimer_) {
        KillTimer(reconnectTimer_);
        reconnectTimer_ = 0;
        try {
            if (console_) {
                StopConsole();
                if (console_) throw tlp::Error("The previous SSH session did not clean up; reconnect was not started.");
            }
            console_ = tlp::win::StartManagedSshConsole(profile_);
            authenticated_ = false;
            terminalView_->EnableWindow(TRUE);
            SetDlgItemText(IDC_SSH_TERMINAL_STATUS, L"Reconnecting · SSH authentication not yet confirmed");
            terminalView_->Refresh();
        } catch (const std::exception& error) {
            ScheduleAutomaticReconnect(std::string("Reconnect failed: ") + error.what());
        }
        CAppearanceDialog::OnTimer(timerId);
        return;
    }
    if (timerId != 1 || !console_) return;
    try {
        if (!inactivityTimedOut_ && GetTickCount64() - lastInputTick_ >= kSessionIdleTimeoutMs) {
            inactivityTimedOut_ = true;
            SetDlgItemText(IDC_SSH_TERMINAL_STATUS, L"Session timed out after 30 minutes of inactivity");
            if (terminal_) terminal_->Feed("\r\n\x1b[33mSession timed out after 30 minutes of inactivity\x1b[0m\r\n");
            StopConsole();
            terminalView_->EnableWindow(FALSE);
            return;
        }
        const auto session = console_;
        for (int count = 0; session && count < 16; ++count) {
            const auto bytes = session->ReadAvailable();
            if (bytes.empty()) break;
            terminal_->Feed(bytes);
        }
        if (!console_) return;
        if (!authenticated_ && console_->IsAuthenticated()) {
            authenticated_ = true;
            automaticReconnectAttempts_ = 0;
            const auto account = profile_.sshUser.empty() ? profile_.pairing.sshUser : profile_.sshUser;
            SetDlgItemText(IDC_SSH_TERMINAL_STATUS,
                           tlp::win::Widen("Connected · " + account +
                               " · authenticated SSH; encrypted keepalive every 15 seconds").c_str());
        }
        if (console_ && console_->IsFinished()) {
            const bool replaced = console_->WasReplaced();
            SetDlgItemText(IDC_SSH_TERMINAL_STATUS, replaced
                ? L"Session replaced by a new Console for this PBX profile"
                : authenticated_
                    ? L"Disconnected · SSH session ended · Select Reconnect to try again"
                    : L"Connection ended · SSH authentication was not confirmed · Select Reconnect to try again");
            terminalView_->EnableWindow(FALSE);
            const bool retryable = !replaced && !inactivityTimedOut_ && automaticReconnectAttempts_ < 5;
            try {
                console_->Disconnect();
                console_.reset();
            } catch (const std::exception& error) {
                SetDlgItemText(IDC_SSH_TERMINAL_STATUS,
                               tlp::win::Widen(std::string("SSH cleanup is unverified: ") + error.what()).c_str());
            }
            if (retryable && console_ == nullptr) ScheduleAutomaticReconnect("SSH connection ended");
        } else if (console_) {
            terminalView_->Refresh();
        } else {
            terminalView_->EnableWindow(FALSE);
        }
        UpdatePasteButton();
    } catch (const std::exception& error) {
        SetDlgItemText(IDC_SSH_TERMINAL_STATUS,
                       tlp::win::Widen(std::string("SSH console error: ") + error.what()).c_str());
    }
    CAppearanceDialog::OnTimer(timerId);
}

BOOL CSshTerminalDlg::OnMouseWheel(UINT flags, short delta, CPoint point) {
    const BOOL result = CAppearanceDialog::OnMouseWheel(flags, delta, point);
    UpdatePasteButton();
    return result;
}

void CSshTerminalDlg::OnMove(int x, int y) {
    CAppearanceDialog::OnMove(x, y);
    UpdatePasteButton();
}

void CSshTerminalDlg::OnCopyAll() {
    try {
        terminalView_->CopyAll();
        ShowButtonFeedback(IDC_SSH_TERMINAL_COPY, L"Copied!", L"Copy All");
        terminalView_->SetFocus();
    }
    catch (const std::exception& error) {
        ShowButtonFeedback(IDC_SSH_TERMINAL_COPY, L"Copy failed", L"Copy All");
        SetDlgItemText(IDC_SSH_TERMINAL_STATUS, tlp::win::Widen(error.what()).c_str());
    }
}

void CSshTerminalDlg::OnClearAll() {
    if (!console_ || !console_->IsAlive()) return;
    try {
        console_->WriteInput("clear\r");
        lastInputTick_ = GetTickCount64();
        inactivityTimedOut_ = false;
        if (terminalView_) terminalView_->SetFocus();
        ShowButtonFeedback(IDC_SSH_TERMINAL_CLEAR, L"Cleared!", L"Clear All");
    } catch (const std::exception& error) {
        SetDlgItemText(IDC_SSH_TERMINAL_STATUS, tlp::win::Widen(std::string("Clear command failed: ") + error.what()).c_str());
    }
}

void CSshTerminalDlg::OnPaste() {
    try { terminalView_->PasteClipboard(); }
    catch (const std::exception& error) {
        OnPasteError(0, reinterpret_cast<LPARAM>(&error));
    }
}

void CSshTerminalDlg::OnReconnect() {
    try {
        if (reconnectTimer_) { KillTimer(reconnectTimer_); reconnectTimer_ = 0; }
        automaticReconnectAttempts_ = 0;
        if (console_) {
            StopConsole();
            if (console_) throw tlp::Error("The previous SSH session did not clean up; reconnect was not started.");
        }
        terminal_->Feed("\x1b" "c");
        terminalView_->ClearHistory();
        console_ = tlp::win::StartManagedSshConsole(profile_);
        terminalView_->EnableWindow(TRUE);
        authenticated_ = false;
        inactivityTimedOut_ = false;
        lastInputTick_ = GetTickCount64();
        SetDlgItemText(IDC_SSH_TERMINAL_STATUS, L"Reconnecting · SSH authentication not yet confirmed");
        ResizeTerminal();
    } catch (const std::exception& error) {
        SetDlgItemText(IDC_SSH_TERMINAL_STATUS,
                       tlp::win::Widen(std::string("Reconnect failed: ") + error.what()).c_str());
        ScheduleAutomaticReconnect(std::string("Reconnect failed: ") + error.what());
    }
}

LRESULT CSshTerminalDlg::OnTerminalInput(WPARAM, LPARAM) {
    lastInputTick_ = GetTickCount64();
    inactivityTimedOut_ = false;
    UpdatePasteButton();
    return 0;
}

LRESULT CSshTerminalDlg::OnTerminalScroll(WPARAM, LPARAM) {
    UpdatePasteButton();
    return 0;
}

LRESULT CSshTerminalDlg::OnPasteError(WPARAM, LPARAM detail) {
    const auto* error = reinterpret_cast<const std::exception*>(detail);
    if (terminalView_) terminalView_->SetFocus();
    tlp::ui::ShowMessage(L"Clipboard access was blocked. Use right-click Paste or Ctrl+Shift+V.", MB_ICONERROR);
    SetDlgItemText(IDC_SSH_TERMINAL_STATUS,
                   tlp::win::Widen(error ? error->what() : "Clipboard paste failed.").c_str());
    return 0;
}

void CSshTerminalDlg::ShowButtonFeedback(int controlId, const wchar_t* temporary, const wchar_t* normal) {
    if (feedbackTimer_) KillTimer(feedbackTimer_);
    GetDlgItem(controlId)->SetWindowTextW(temporary);
    feedbackTimer_ = SetTimer(2, 1500, nullptr);
    if (!feedbackTimer_) GetDlgItem(controlId)->SetWindowTextW(normal);
}

void CSshTerminalDlg::ScheduleAutomaticReconnect(const std::string& reason) {
    if (reconnectTimer_ || automaticReconnectAttempts_ >= 5 || !GetSafeHwnd()) {
        if (automaticReconnectAttempts_ >= 5)
            SetDlgItemText(IDC_SSH_TERMINAL_STATUS, L"Connection failed. Use Reconnect to try again.");
        return;
    }
    static constexpr UINT delays[] = {1000, 2000, 4000, 8000, 15000};
    const int index = automaticReconnectAttempts_++;
    SetDlgItemText(IDC_SSH_TERMINAL_STATUS, tlp::win::Widen(reason + " · reconnecting automatically").c_str());
    reconnectTimer_ = SetTimer(10 + index, delays[index], nullptr);
    if (!reconnectTimer_ && automaticReconnectAttempts_ >= 5)
        SetDlgItemText(IDC_SSH_TERMINAL_STATUS, L"Connection failed. Use Reconnect to try again.");
}

bool CSshTerminalDlg::ShellPromptVisible(int& promptRow, int& cursorColumn) const {
    if (!authenticated_ || !terminal_ || !terminalView_ || terminal_->IsAlternateScreen()) return false;
    if (!terminalView_->AtLiveBottom()) return false;
    int row = 0, column = 0;
    bool visible = false;
    terminal_->Cursor(row, column, visible);
    if (!visible || row < 0 || row >= terminal_->Rows()) return false;
    static const std::wregex prompt(LR"(^(?:[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+(?::[^#]{0,160})?[#$]|[#$])(?: |$))");
    if (!std::regex_search(terminalView_->LogicalLine(row), prompt)) return false;
    promptRow = row;
    cursorColumn = column;
    return true;
}

void CSshTerminalDlg::UpdatePasteButton() {
    CWnd* button = GetDlgItem(IDC_SSH_TERMINAL_PASTE);
    if (!button || !terminalView_ || !console_ || !console_->IsAlive()) {
        if (button) button->ShowWindow(SW_HIDE);
        pastePositionValid_ = false;
        return;
    }
    int row = 0, column = 0;
    if (!ShellPromptVisible(row, column)) {
        button->ShowWindow(SW_HIDE);
        pastePositionValid_ = false;
        return;
    }
    CRect viewRect;
    terminalView_->GetWindowRect(&viewRect);
    ScreenToClient(&viewRect);
    const int cellWidth = std::max(1, terminalView_->CellWidth());
    const int cellHeight = std::max(1, terminalView_->CellHeight());
    const int maximumX = std::max(viewRect.left + 4, viewRect.right - 78);
    const int x = std::clamp(viewRect.left + column * cellWidth, viewRect.left + 4, maximumX);
    const int cursorScreenY = viewRect.top + row * cellHeight;
    const int maximumY = std::max(viewRect.top + 4, viewRect.bottom - 28);
    const int y = std::clamp(cursorScreenY + cellHeight + 3, viewRect.top + 4, maximumY);
    button->MoveWindow(x, y, 74, 22);
    button->ShowWindow(HasTextClipboard(m_hWnd) ? SW_SHOWNA : SW_HIDE);
    pastePosition_ = CPoint(x, y);
    pastePositionValid_ = true;
}

void CSshTerminalDlg::StopConsole() {
    if (!console_) return;
    try {
        console_->Disconnect();
        console_.reset();
    } catch (const std::exception& error) {
        // Closing continues; CMainDlg verifies with CloseManagedSsh and reports a session that did not end.
        if (GetSafeHwnd())
            SetDlgItemText(IDC_SSH_TERMINAL_STATUS,
                           tlp::win::Widen(std::string("SSH disconnect error: ") + error.what()).c_str());
    }
}

void CSshTerminalDlg::OnDisconnect() {
    inactivityTimedOut_ = true;
    if (reconnectTimer_) { KillTimer(reconnectTimer_); reconnectTimer_ = 0; }
    StopConsole();
    if (terminalView_) terminalView_->EnableWindow(FALSE);
    UpdatePasteButton();
    if (!console_) SetDlgItemText(IDC_SSH_TERMINAL_STATUS, L"Disconnected");
}

void CSshTerminalDlg::OnCancel() {
    inactivityTimedOut_ = true;
    if (reconnectTimer_) { KillTimer(reconnectTimer_); reconnectTimer_ = 0; }
    StopConsole();
    CDialogEx::OnCancel();
}
