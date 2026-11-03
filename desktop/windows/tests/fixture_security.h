#pragma once
#include <windows.h>

// Test-only Win32 security/Task Scheduler inspection. Does not launch PowerShell.
int FixtureSecurityCommand(int argc, char** argv);
[[noreturn]] void FixtureWin32Error(const char* operation, DWORD error = GetLastError());
