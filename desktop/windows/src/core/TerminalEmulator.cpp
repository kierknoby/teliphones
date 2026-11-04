#include "TerminalEmulator.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace tlp {
namespace {
constexpr std::size_t kMaximumScrollbackRows = 10000;

std::uint32_t colorValue(const VTermColor& value, const VTermScreen* screen) {
    VTermColor color = value;
    vterm_screen_convert_color_to_rgb(screen, &color);
    if (!VTERM_COLOR_IS_RGB(&color)) return 0xD0D0D0;
    return (static_cast<std::uint32_t>(color.rgb.red) << 16) |
           (static_cast<std::uint32_t>(color.rgb.green) << 8) |
           static_cast<std::uint32_t>(color.rgb.blue);
}

std::uint32_t safeCodepoint(std::uint32_t codepoint) {
    if (codepoint > 0x10ffff || (codepoint >= 0xd800 && codepoint <= 0xdfff)) return 0xfffd;
    return codepoint;
}

std::size_t incompleteUtf8Suffix(const std::string& bytes) {
    if (bytes.empty()) return 0;
    std::size_t start = bytes.size();
    while (start > 0 &&
           (static_cast<unsigned char>(bytes[start - 1]) & 0xc0) == 0x80) {
        --start;
    }
    if (start == bytes.size()) start = bytes.size() - 1;
    const auto lead = static_cast<unsigned char>(bytes[start]);
    std::size_t expected = 0;
    if (lead >= 0xc2 && lead <= 0xdf) expected = 2;
    else if (lead >= 0xe0 && lead <= 0xef) expected = 3;
    else if (lead >= 0xf0 && lead <= 0xf4) expected = 4;
    if (!expected || bytes.size() - start >= expected) return bytes.size();
    if (start + 1 < bytes.size()) {
        const auto second = static_cast<unsigned char>(bytes[start + 1]);
        if ((lead == 0xe0 && second < 0xa0) || (lead == 0xed && second > 0x9f) ||
            (lead == 0xf0 && second < 0x90) || (lead == 0xf4 && second > 0x8f)) {
            return bytes.size();
        }
    }
    return start;
}
}

TerminalEmulator::TerminalEmulator(int columns, int rows, Output output)
    : output_(std::move(output)), columns_(std::max(2, columns)), rows_(std::max(2, rows)) {
    terminal_ = vterm_new(rows_, columns_);
    if (!terminal_) throw std::runtime_error("Unable to create the VT terminal state.");
    vterm_set_utf8(terminal_, 1);
    vterm_output_set_callback(terminal_, &TerminalEmulator::OutputCallback, this);
    screen_ = vterm_obtain_screen(terminal_);
    state_ = vterm_obtain_state(terminal_);
    if (!screen_ || !state_) {
        vterm_free(terminal_);
        terminal_ = nullptr;
        throw std::runtime_error("Unable to create the VT screen state.");
    }
    static const VTermScreenCallbacks callbacks{
        &Damage, &MoveRect, &MoveCursor, nullptr, nullptr, &ResizeCallback,
        &PushLine, &PopLine, &ClearScrollbackCallback
    };
    vterm_screen_set_callbacks(screen_, &callbacks, this);
    vterm_screen_set_damage_merge(screen_, VTERM_DAMAGE_ROW);
    vterm_screen_enable_altscreen(screen_, 1);
    VTermColor foreground{}, background{};
    vterm_color_rgb(&foreground, 208, 208, 208);
    vterm_color_rgb(&background, 16, 16, 16);
    vterm_state_set_default_colors(state_, &foreground, &background);
    vterm_screen_reset(screen_, 1);
}

TerminalEmulator::~TerminalEmulator() {
    if (terminal_) vterm_free(terminal_);
}

void TerminalEmulator::Feed(const std::string& bytes) {
    pendingUtf8_.append(bytes);
    const auto completeSize = incompleteUtf8Suffix(pendingUtf8_);
    std::size_t offset = 0;
    while (offset < completeSize) {
        const auto count = vterm_input_write(terminal_, pendingUtf8_.data() + offset, completeSize - offset);
        if (!count) throw std::runtime_error("VT parser stopped before consuming terminal output.");
        offset += count;
    }
    pendingUtf8_.erase(0, completeSize);
    vterm_screen_flush_damage(screen_);
}

void TerminalEmulator::Resize(int columns, int rows) {
    columns_ = std::clamp(columns, 2, 500);
    rows_ = std::clamp(rows, 2, 300);
    vterm_set_size(terminal_, rows_, columns_);
    vterm_screen_flush_damage(screen_);
}

void TerminalEmulator::Key(int key, unsigned modifiers) {
    vterm_keyboard_key(terminal_, static_cast<VTermKey>(key), static_cast<VTermModifier>(modifiers));
}

void TerminalEmulator::Character(std::uint32_t codepoint, unsigned modifiers) {
    vterm_keyboard_unichar(terminal_, safeCodepoint(codepoint), static_cast<VTermModifier>(modifiers));
}

void TerminalEmulator::Paste(const std::u32string& text) {
    vterm_keyboard_start_paste(terminal_);
    for (const auto codepoint : text) Character(codepoint, VTERM_MOD_NONE);
    vterm_keyboard_end_paste(terminal_);
}

void TerminalEmulator::ClearScrollback() {
    scrollback_.clear();
}

TerminalCell TerminalEmulator::CellAt(int row, int column) const {
    VTermScreenCell cell{};
    if (row < 0 || row >= rows_ || column < 0 || column >= columns_ ||
        !vterm_screen_get_cell(screen_, VTermPos{row, column}, &cell)) return {};
    return ConvertCell(cell, screen_);
}

TerminalCell TerminalEmulator::ScrollbackCellAt(std::size_t row, int column) const {
    if (row >= scrollback_.size() || column < 0 ||
        static_cast<std::size_t>(column) >= scrollback_[row].size()) return {};
    return scrollback_[row][static_cast<std::size_t>(column)];
}

std::string TerminalEmulator::TextAll() const {
    std::string result;
    const auto appendRow = [&result](const auto& cellAt, int columns) {
        std::u32string line;
        for (int column = 0; column < columns; ++column) {
            const auto cell = cellAt(column);
            if (cell.wideContinuation) continue;
            line += cell.text.empty() ? U" " : cell.text;
        }
        while (!line.empty() && line.back() == U' ') line.pop_back();
        result += EncodeUtf8(line);
        result += '\n';
    };
    for (std::size_t row = 0; row < scrollback_.size(); ++row) {
        appendRow([this, row](int column) { return ScrollbackCellAt(row, column); }, columns_);
    }
    for (int row = 0; row < rows_; ++row) {
        appendRow([this, row](int column) { return CellAt(row, column); }, columns_);
    }
    return result;
}

void TerminalEmulator::Cursor(int& row, int& column, bool& visible) const {
    VTermPos cursor{};
    vterm_state_get_cursorpos(state_, &cursor);
    row = cursor.row;
    column = cursor.col;
    visible = cursorVisible_;
}

int TerminalEmulator::Damage(VTermRect, void*) { return 1; }
int TerminalEmulator::MoveRect(VTermRect, VTermRect, void*) { return 1; }
int TerminalEmulator::MoveCursor(VTermPos pos, VTermPos, int visible, void* user) {
    auto* self = static_cast<TerminalEmulator*>(user);
    self->cursorRow_ = pos.row;
    self->cursorColumn_ = pos.col;
    self->cursorVisible_ = visible != 0;
    return 1;
}
int TerminalEmulator::ResizeCallback(int rows, int columns, void* user) {
    auto* self = static_cast<TerminalEmulator*>(user);
    self->rows_ = rows;
    self->columns_ = columns;
    return 1;
}
int TerminalEmulator::PushLine(int columns, const VTermScreenCell* cells, void* user) {
    auto* self = static_cast<TerminalEmulator*>(user);
    std::vector<TerminalCell> line;
    line.reserve(static_cast<std::size_t>(columns));
    for (int column = 0; column < columns; ++column) line.push_back(ConvertCell(cells[column], self->screen_));
    if (self->scrollback_.size() == kMaximumScrollbackRows) self->scrollback_.pop_front();
    self->scrollback_.push_back(std::move(line));
    return 1;
}
int TerminalEmulator::PopLine(int columns, VTermScreenCell* cells, void* user) {
    auto* self = static_cast<TerminalEmulator*>(user);
    if (self->scrollback_.empty()) return 0;
    const auto line = std::move(self->scrollback_.back());
    self->scrollback_.pop_back();
    for (int column = 0; column < columns; ++column) {
        const auto& cell = static_cast<std::size_t>(column) < line.size() ? line[static_cast<std::size_t>(column)] : TerminalCell{};
        VTermScreenCell value{};
        value.width = cell.wideContinuation ? 0 : static_cast<char>(cell.width);
        for (std::size_t index = 0; index < cell.text.size() && index < VTERM_MAX_CHARS_PER_CELL; ++index)
            value.chars[index] = static_cast<std::uint32_t>(cell.text[index]);
        value.attrs.bold = cell.bold;
        value.attrs.italic = cell.italic;
        value.attrs.underline = cell.underline ? VTERM_UNDERLINE_SINGLE : VTERM_UNDERLINE_OFF;
        vterm_color_rgb(&value.fg, static_cast<std::uint8_t>(cell.foreground >> 16),
                        static_cast<std::uint8_t>(cell.foreground >> 8), static_cast<std::uint8_t>(cell.foreground));
        vterm_color_rgb(&value.bg, static_cast<std::uint8_t>(cell.background >> 16),
                        static_cast<std::uint8_t>(cell.background >> 8), static_cast<std::uint8_t>(cell.background));
        cells[column] = value;
    }
    return 1;
}
int TerminalEmulator::ClearScrollbackCallback(void* user) {
    static_cast<TerminalEmulator*>(user)->ClearScrollback();
    return 1;
}
void TerminalEmulator::OutputCallback(const char* bytes, std::size_t size, void* user) {
    auto* self = static_cast<TerminalEmulator*>(user);
    if (self->output_) self->output_(std::string(bytes, size));
}

TerminalCell TerminalEmulator::ConvertCell(const VTermScreenCell& cell, const VTermScreen* screen) {
    TerminalCell result;
    for (const auto codepoint : cell.chars) {
        if (!codepoint) break;
        result.text.push_back(static_cast<char32_t>(safeCodepoint(codepoint)));
    }
    result.foreground = colorValue(cell.fg, screen);
    result.background = colorValue(cell.bg, screen);
    result.bold = cell.attrs.bold != 0;
    result.italic = cell.attrs.italic != 0;
    result.underline = cell.attrs.underline != 0;
    result.strike = cell.attrs.strike != 0;
    result.reverse = cell.attrs.reverse != 0;
    result.wideContinuation = cell.width == 0;
    result.width = std::max(1, static_cast<int>(cell.width));
    if (result.reverse) std::swap(result.foreground, result.background);
    if (cell.attrs.conceal) result.foreground = result.background;
    return result;
}

std::string TerminalEmulator::EncodeUtf8(const std::u32string& text) {
    std::string output;
    for (const auto raw : text) {
        const auto codepoint = safeCodepoint(static_cast<std::uint32_t>(raw));
        if (codepoint < 0x80) output.push_back(static_cast<char>(codepoint));
        else if (codepoint < 0x800) {
            output.push_back(static_cast<char>(0xc0 | (codepoint >> 6)));
            output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        } else if (codepoint < 0x10000) {
            output.push_back(static_cast<char>(0xe0 | (codepoint >> 12)));
            output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        } else {
            output.push_back(static_cast<char>(0xf0 | (codepoint >> 18)));
            output.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        }
    }
    return output;
}

}  // namespace tlp
