#pragma once

#include "framework.h"
#include "../core/Appearance.h"

namespace tlp::ui {

void SetAppearance(Appearance mode);
Appearance CurrentAppearance();
const AppearancePalette& Colours();
bool HighContrast();
void ThemeWindow(HWND window);
int ShowMessage(LPCTSTR text, UINT flags = MB_OK);
#ifdef TELIPHONES_APPEARANCE_TESTING
// Simulates notification inputs only; never changes the runner's Windows settings.
void SimulateSystemAppearance(bool dark, bool highContrast);
#endif

}  // namespace tlp::ui

// All application dialogs use this base, including future dialogs. OS-owned file
// pickers, UAC and credential prompts deliberately retain Windows' own rendering.
class CAppearanceDialog : public CDialogEx {
public:
    explicit CAppearanceDialog(UINT resource, CWnd* parent = nullptr) : CDialogEx(resource, parent) {}

protected:
    BOOL OnInitDialog() override;
    LRESULT WindowProc(UINT message, WPARAM wparam, LPARAM lparam) override;
};
