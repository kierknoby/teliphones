#include <cstdint>
#include <cstdlib>
#include <deque>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#define small char
#include "TerminalEmulator.h"
#ifndef small
#error "TerminalEmulator.h must restore the Windows small macro after including libvterm."
#endif
#undef small

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
        check(red.text == U"R" && red.foreground == 0xff6b73,
            "cursor positioning and Console ANSI indexed colour are rendered");
    terminal.Feed("\x1b[0m\x1b[2J\x1b[H");
    check(terminal.CellAt(0, 0).text.empty(), "screen erase clears cells");

    terminal.Feed(std::string("\xe2", 1));
    terminal.Feed(std::string("\x82\xac", 2));
    check(terminal.CellAt(0, 0).text == U"€", "UTF-8 characters may span output chunks");
    check(terminal.TextAll().find("€") != std::string::npos, "copy-all text preserves UTF-8 characters");

    tlp::TerminalEmulator palette(20, 2, [](const std::string&) {});
    palette.Feed("\x1b[31mR\x1b[32mG\x1b[34mB");
    check(palette.CellAt(0, 0).foreground == 0xff6b73 &&
              palette.CellAt(0, 1).foreground == 0xa8e38c &&
              palette.CellAt(0, 2).foreground == 0x75c7ff,
          "ANSI base colors follow the Console palette");

    struct Utf8Case {
        std::string bytes;
        char32_t codepoint;
    };
    const std::vector<Utf8Case> utf8Cases{
        {std::string("\xc2\xa2", 2), U'¢'},
        {std::string("\xe2\x82\xac", 3), U'€'},
        {std::string("\xf0\x9f\x92\xa9", 4), U'💩'}
    };
    for (const auto& test : utf8Cases) {
        for (std::size_t split = 1; split < test.bytes.size(); ++split) {
            tlp::TerminalEmulator fragmented(20, 4, [](const std::string&) {});
            fragmented.Feed(test.bytes.substr(0, split));
            check(fragmented.CellAt(0, 0).text.empty(),
                  "incomplete UTF-8 prefixes remain buffered until the codepoint is complete");
            fragmented.Feed(test.bytes.substr(split) + "\x1b[2;4H!");
            check(fragmented.CellAt(0, 0).text == std::u32string(1, test.codepoint) &&
                      fragmented.CellAt(1, 3).text == U"!",
                  "UTF-8 characters split at every byte boundary survive adjacent VT escapes");
        }

        tlp::TerminalEmulator repeated(20, 4, [](const std::string&) {});
        for (std::size_t index = 0; index + 1 < test.bytes.size(); ++index) {
            repeated.Feed(test.bytes.substr(index, 1));
            if (index == 0) repeated.Resize(24, 6);
        }
        repeated.Feed(test.bytes.substr(test.bytes.size() - 1));
        check(repeated.CellAt(0, 0).text == std::u32string(1, test.codepoint),
              "UTF-8 characters survive repeated partial reads and terminal resizing");
    }

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
        check(scrolling.TextAllForCopy().find("one\ntwo\nthree\nfour") != std::string::npos,
            "Copy All preserves explicit hard line breaks in scrollback and the live screen");
    scrolling.ClearScrollback();
    check(scrolling.ScrollbackRows() == 0, "clear-all can discard retained history");

        tlp::TerminalEmulator wrapped(5, 3, [](const std::string&) {});
        wrapped.Feed("abcdefghij");
          check(wrapped.TextAllForCopy().find("abcdefghij") != std::string::npos &&
              wrapped.TextAllForCopy().find("abcde\nfghij") == std::string::npos,
            "Copy All joins rows that libvterm marks as soft-wrapped");
        for (int index = 0; index < 33000; ++index) wrapped.Feed("\r\n.");
        check(wrapped.ScrollbackRows() == 32767, "terminal scrollback is capped at the original 32,767 rows");

        tlp::TerminalEmulator hardAndSoft(5, 3, [](const std::string&) {});
        hardAndSoft.Feed("abcdef\r\nxy");
        const auto copiedMixed = hardAndSoft.TextAllForCopy();
        check(copiedMixed.find("abcdef\nxy") != std::string::npos,
            "Copy All retains hard line breaks after joining preceding soft-wrapped rows");

    tlp::TerminalEmulator fullscreen(10, 3, [](const std::string&) {});
    fullscreen.Feed("shell");
    fullscreen.Feed("\x1b[?1049h\x1b[Hvim");
        check(fullscreen.CellAt(0, 0).text == U"v" && fullscreen.IsAlternateScreen(),
            "alternate-screen applications receive an isolated VT screen and expose buffer state");
    fullscreen.Feed("\x1b[?1049l");
        check(fullscreen.CellAt(0, 0).text == U"s" && !fullscreen.IsAlternateScreen(),
            "leaving the alternate screen restores the shell screen and buffer state");
    tlp::TerminalEmulator fragmentedMode(12, 2, [](const std::string&) {});
    fragmentedMode.Feed("\x1b[?104");
    fragmentedMode.Feed("9h");
    check(fragmentedMode.IsAlternateScreen(), "alternate-screen mode is detected across fragmented SSH reads");
    fragmentedMode.Feed("\x1b[?47;1049l");
    check(!fragmentedMode.IsAlternateScreen(), "combined DEC mode resets exit the alternate screen");
    tlp::TerminalEmulator alternateCopy(12, 2, [](const std::string&) {});
    alternateCopy.Feed("normal history\r\n");
    alternateCopy.Feed("\x1b[?1049h\x1b[Halt-screen");
    check(alternateCopy.TextAllForCopy().find("alt-screen") != std::string::npos &&
              alternateCopy.TextAllForCopy().find("normal history") == std::string::npos,
          "Copy All reads the active alternate buffer rather than unrelated normal-buffer history");

    std::cout << "VT terminal emulator tests passed.\n";
}
