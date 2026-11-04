#include "TerminalEmulator.h"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {
void check(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}
}

int main() {
    std::string input;
    tlp::TerminalEmulator terminal(12, 4, [&input](const std::string& bytes) { input += bytes; });

    terminal.Feed("hello");
    check(terminal.CellAt(0, 0).text == U"h" && terminal.CellAt(0, 4).text == U"o",
          "plain output is placed into screen cells");
    terminal.Feed("\x1b[2;3H");
    terminal.Feed("\x1b[31mR");
    const auto red = terminal.CellAt(1, 2);
    check(red.text == U"R" && ((red.foreground >> 16) & 0xff) > 150 && (red.foreground & 0xffff) == 0,
          "cursor positioning and ANSI indexed colour are rendered");
    terminal.Feed("\x1b[0m\x1b[2J\x1b[H");
    check(terminal.CellAt(0, 0).text.empty(), "screen erase clears cells");

    terminal.Feed(std::string("\xe2", 1));
    terminal.Feed(std::string("\x82\xac", 2));
    check(terminal.CellAt(0, 0).text == U"€", "UTF-8 characters may span output chunks");
    check(terminal.TextAll().find("€") != std::string::npos, "copy-all text preserves UTF-8 characters");

    terminal.Resize(30, 8);
    check(terminal.Columns() == 30 && terminal.Rows() == 8, "resizing updates terminal grid dimensions");

    terminal.Key(VTERM_KEY_UP, VTERM_MOD_NONE);
    check(input == "\x1b[A", "arrow keys are encoded as terminal input");
    input.clear();
    terminal.Key(VTERM_KEY_FUNCTION(1), VTERM_MOD_NONE);
    check(!input.empty(), "function keys are encoded as terminal input");
    input.clear();
    terminal.Character('c', VTERM_MOD_CTRL);
    check(input == "\x03", "Ctrl+C is passed as ETX");
    input.clear();
    terminal.Character('d', VTERM_MOD_CTRL);
    check(input == "\x04", "Ctrl+D is passed as EOT");
    input.clear();
    terminal.Character(0x20ac, VTERM_MOD_NONE);
    check(input == "\xe2\x82\xac", "Unicode key input is encoded as UTF-8");

    terminal.Feed("\x1b[?2004h");
    terminal.Paste(U"pasted");
    check(input.find("\x1b[200~pasted\x1b[201~") != std::string::npos,
          "paste uses bracketed-paste framing when enabled by the remote terminal");

    tlp::TerminalEmulator scrolling(8, 2, [](const std::string&) {});
    scrolling.Feed("one\r\ntwo\r\nthree\r\nfour");
    check(scrolling.ScrollbackRows() >= 2, "scrolled screen rows are retained in history");
    check(scrolling.TextAll().find("one") != std::string::npos &&
          scrolling.TextAll().find("four") != std::string::npos,
          "copy-all text includes history and the current screen");
    scrolling.ClearScrollback();
    check(scrolling.ScrollbackRows() == 0, "clear-all can discard retained history");

    tlp::TerminalEmulator fullscreen(10, 3, [](const std::string&) {});
    fullscreen.Feed("shell");
    fullscreen.Feed("\x1b[?1049h\x1b[Hvim");
    check(fullscreen.CellAt(0, 0).text == U"v", "alternate-screen applications receive an isolated VT screen");
    fullscreen.Feed("\x1b[?1049l");
    check(fullscreen.CellAt(0, 0).text == U"s", "leaving the alternate screen restores the shell screen");

    std::cout << "VT terminal emulator tests passed.\n";
}
