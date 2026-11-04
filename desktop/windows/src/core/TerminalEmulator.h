#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#ifdef small
#pragma push_macro("small")
#undef small
#include <vterm.h>
#pragma pop_macro("small")
#else
#include <vterm.h>
#endif

namespace tlp {

struct TerminalCell {
    std::u32string text;
    std::uint32_t foreground = 0xD0D0D0;
    std::uint32_t background = 0x101010;
    bool bold = false;
    bool italic = false;
    bool underline = false;
    bool strike = false;
    bool reverse = false;
    bool wideContinuation = false;
    int width = 1;
};

class TerminalEmulator final {
public:
    using Output = std::function<void(const std::string&)>;

    TerminalEmulator(int columns, int rows, Output output);
    ~TerminalEmulator();
    TerminalEmulator(const TerminalEmulator&) = delete;
    TerminalEmulator& operator=(const TerminalEmulator&) = delete;

    void Feed(const std::string& bytes);
    void Resize(int columns, int rows);
    void Key(int key, unsigned modifiers);
    void Character(std::uint32_t codepoint, unsigned modifiers);
    void Paste(const std::u32string& text);
    void ClearScrollback();
    TerminalCell CellAt(int row, int column) const;
    TerminalCell ScrollbackCellAt(std::size_t row, int column) const;
    std::string TextAll() const;
    void Cursor(int& row, int& column, bool& visible) const;
    int Columns() const noexcept { return columns_; }
    int Rows() const noexcept { return rows_; }
    std::size_t ScrollbackRows() const noexcept { return scrollback_.size(); }

private:
    static int Damage(VTermRect rect, void* user);
    static int MoveRect(VTermRect dest, VTermRect src, void* user);
    static int MoveCursor(VTermPos pos, VTermPos oldpos, int visible, void* user);
    static int ResizeCallback(int rows, int columns, void* user);
    static int PushLine(int columns, const VTermScreenCell* cells, void* user);
    static int PopLine(int columns, VTermScreenCell* cells, void* user);
    static int ClearScrollbackCallback(void* user);
    static void OutputCallback(const char* bytes, std::size_t size, void* user);
    static TerminalCell ConvertCell(const VTermScreenCell& cell, const VTermScreen* screen);
    static std::string EncodeUtf8(const std::u32string& text);

    VTerm* terminal_ = nullptr;
    VTermScreen* screen_ = nullptr;
    VTermState* state_ = nullptr;
    Output output_;
    std::string pendingUtf8_;
    std::deque<std::vector<TerminalCell>> scrollback_;
    int columns_;
    int rows_;
    int cursorRow_ = 0;
    int cursorColumn_ = 0;
    bool cursorVisible_ = true;
};

}  // namespace tlp
