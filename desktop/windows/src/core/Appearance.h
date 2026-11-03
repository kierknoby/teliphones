#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "Json.h"

namespace tlp {

enum class Appearance { System, Light, Dark };

inline const char* AppearanceName(Appearance mode) {
    switch (mode) {
        case Appearance::System: return "system";
        case Appearance::Light: return "light";
        case Appearance::Dark: return "dark";
    }
    throw Error("Invalid TELIPHONES appearance.");
}

inline Appearance ParseAppearance(const std::string& value) {
    if (value == "system") return Appearance::System;
    if (value == "light") return Appearance::Light;
    if (value == "dark") return Appearance::Dark;
    throw Error("Invalid TELIPHONES appearance.");
}

inline bool UseDarkAppearance(Appearance mode, bool systemDark, bool highContrast) {
    return !highContrast && (mode == Appearance::Dark || (mode == Appearance::System && systemDark));
}

using Colour = std::uint32_t;
constexpr Colour Rgb(unsigned r, unsigned g, unsigned b) { return r | (g << 8) | (b << 16); }

struct AppearancePalette {
    Colour background, surface, text, disabled, border, button, hover, selection, selectedText;
    Colour graph, grid, latency, success, warning, error, download, upload;

    std::array<Colour, 17> Values() const {
        return {background, surface, text, disabled, border, button, hover, selection, selectedText,
            graph, grid, latency, success, warning, error, download, upload};
    }
};

inline AppearancePalette PaletteFor(bool dark) {
    if (dark) {
        return {Rgb(28, 31, 36), Rgb(36, 40, 46), Rgb(236, 239, 244), Rgb(168, 177, 190),
            Rgb(115, 128, 145), Rgb(48, 54, 63), Rgb(63, 74, 88), Rgb(42, 91, 150), Rgb(255, 255, 255),
            Rgb(24, 28, 34), Rgb(65, 75, 89), Rgb(199, 161, 255), Rgb(100, 220, 150),
            Rgb(255, 204, 102), Rgb(255, 137, 144), Rgb(115, 193, 255), Rgb(255, 185, 105)};
    }
    return {Rgb(243, 245, 248), Rgb(255, 255, 255), Rgb(30, 39, 52), Rgb(90, 101, 116),
        Rgb(112, 125, 143), Rgb(232, 236, 242), Rgb(216, 228, 244), Rgb(32, 90, 160), Rgb(255, 255, 255),
        Rgb(250, 252, 254), Rgb(219, 225, 233), Rgb(112, 62, 165), Rgb(20, 115, 60),
        Rgb(134, 83, 0), Rgb(180, 35, 45), Rgb(20, 105, 185), Rgb(166, 76, 0)};
}

}  // namespace tlp
