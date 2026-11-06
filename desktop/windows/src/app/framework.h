// MFC configuration shared by the TELIPHONES desktop application. MFC is linked statically (no _AFXDLL).
#pragma once

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <sdkddkver.h>

#define _AFX_ALL_WARNINGS
#include <afxwin.h>
#include <afxext.h>
#include <afxdialogex.h>
#include <afxcmn.h>

#define WM_APP_OPERATION_DONE (WM_APP + 1)
#define WM_APP_PROBE_DONE     (WM_APP + 2)
#define WM_APP_FIRST_RUN      (WM_APP + 3)
#define WM_APP_SETUP_PROGRESS (WM_APP + 4)
#define WM_APP_SETUP_DONE     (WM_APP + 5)
#define WM_APP_STARTUP_NOTICES (WM_APP + 6)
#define WM_APP_NETWORK_CHANGED (WM_APP + 7)
