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
