#pragma once
#include "framework.h"
#include <functional>
#include "../core/DesktopLayout.h"

class CDesktopContent : public CWnd {
public:
    CWnd* controller = nullptr;
    std::function<void()> changed;
    int offset = 0;
    int extent = 0;
    void ScrollTo(int position);
    void RevealFocus();
protected:
    LRESULT WindowProc(UINT message, WPARAM wparam, LPARAM lparam) override;
};

class CDesktopLayout {
public:
    void Initialize(CWnd& window);
    void Arrange();
    void SetDpi(UINT dpi);
    void RevealFocus() { content_.RevealFocus(); }
    BOOL Wheel(short delta);
    CWnd* Find(int id) const;
    void InitialPosition();
private:
    CWnd* window_ = nullptr;
    CDesktopContent content_;
    CFont font_;
    CFont headingFont_;
    UINT dpi_ = 96;
    int wheelRemainder_ = 0;
    bool arranging_ = false;
};
