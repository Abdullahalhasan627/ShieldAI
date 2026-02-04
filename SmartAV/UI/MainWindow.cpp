// MainWindow.cpp - UI Module
// واجهة المستخدم الرسومية - Win32 API Modern UI

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <thread>
#include <memory>
#include <sstream>
#include <iomanip>

// ربط مكتبات Windows
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")

// تضمين الوحدات (في المشروع الحقيقي استخدم headers)
// #include "../Core/FileScanner.h"
// #include "../AI/AIDetector.h"
// #include "../Security/Quarantine.h"

// ==================== الألوان والتصميم ====================

namespace Theme {
    const COLORREF DARK_BG = RGB(30, 30, 35);      // خلفية داكنة
    const COLORREF DARKER_BG = RGB(20, 20, 25);      // أغمق
    const COLORREF ACCENT = RGB(0, 150, 255);     // أزرق مميز
    const COLORREF ACCENT_HOVER = RGB(0, 180, 255);     // أزرق فاتح
    const COLORREF SUCCESS = RGB(0, 200, 100);     // أخضر
    const COLORREF WARNING = RGB(255, 180, 0);     // برتقالي
    const COLORREF DANGER = RGB(255, 60, 60);     // أحمر
    const COLORREF TEXT_PRIMARY = RGB(240, 240, 240);   // نص أبيض
    const COLORREF TEXT_SECONDARY = RGB(150, 150, 150); // نص رمادي
}

// ==================== هوية النافذة ====================

#define WM_TRAY_ICON       (WM_USER + 1)
#define WM_SCAN_COMPLETE   (WM_USER + 2)
#define WM_THREAT_DETECTED (WM_USER + 3)

#define IDI_APP_ICON       101
#define IDI_SHIELD         102
#define IDB_LOGO           103

// معرفات القوائم
#define IDM_EXIT           1001
#define IDM_SHOW           1002
#define IDM_QUICK_SCAN     1003
#define IDM_FULL_SCAN      1004
#define IDM_TOGGLE_PROTECTION 1005

// معرفات الأدوات
#define IDC_STATUS_LABEL   2001
#define IDC_SCAN_BUTTON    2002
#define IDC_QUARANTINE_LIST 2003
#define IDC_LOG_LIST       2004
#define IDC_PROGRESS_BAR   2005
#define IDC_STATS_PANEL    2006

// ==================== هيكل بيانات الواجهة ====================

struct ScanStats {
    int filesScanned = 0;
    int threatsFound = 0;
    int filesQuarantined = 0;
    bool isScanning = false;
    std::string currentFile;
};

// ==================== الفئة الرئيسية للواجهة ====================

class MainWindow {
private:
    HWND hWnd = NULL;
    HWND hStatusLabel = NULL;
    HWND hProgressBar = NULL;
    HWND hScanButton = NULL;
    HWND hQuarantineList = NULL;
    HWND hLogList = NULL;
    HWND hStatsPanel = NULL;

    HICON hIcon = NULL;
    HICON hShieldIcon = NULL;
    NOTIFYICONDATA trayIcon = {};

    HFONT hFontNormal = NULL;
    HFONT hFontBold = NULL;
    HFONT hFontLarge = NULL;

    std::unique_ptr<std::thread> scanThread;
    ScanStats stats;
    bool isProtectionActive = true;

    // أبعاد النافذة
    const int WINDOW_WIDTH = 1000;
    const int WINDOW_HEIGHT = 700;

public:
    MainWindow() {
        initGDI();
    }

    ~MainWindow() {
        cleanup();
    }

    // ==================== التسجيل والإنشاء ====================

    bool create(HINSTANCE hInstance) {
        // تسجيل فئة النافذة
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(WNDCLASSEXW);
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = hInstance;
        wc.lpszClassName = L"AI_Antivirus_Main";
        wc.hbrBackground = CreateSolidBrush(Theme::DARK_BG);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hIcon = LoadIcon(NULL, IDI_SHIELD);

        if (!RegisterClassExW(&wc)) {
            return false;
        }

        // إنشاء النافذة الرئيسية
        hWnd = CreateWindowExW(
            WS_EX_OVERLAPPEDWINDOW | WS_EX_COMPOSITED,
            L"AI_Antivirus_Main",
            L"AI Antivirus - Advanced Threat Protection",
            WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
            CW_USEDEFAULT, CW_USEDEFAULT,
            WINDOW_WIDTH, WINDOW_HEIGHT,
            NULL, NULL, hInstance, this
        );

        if (!hWnd) return false;

        // إنشاء عناصر التحكم
        createControls(hInstance);

        // إعداد Tray Icon
        setupTrayIcon(hInstance);

        // تهيئة القائمة
        setupMenu();

        return true;
    }

    void show(int nCmdShow) {
        ShowWindow(hWnd, nCmdShow);
        UpdateWindow(hWnd);
    }

    // ==================== إنشاء عناصر التحكم ====================

private:
    void createControls(HINSTANCE hInstance) {
        // عنوان رئيسي
        CreateWindowW(L"STATIC", L"🛡️ AI Antivirus",
            WS_VISIBLE | WS_CHILD | SS_LEFT,
            30, 20, 400, 40,
            hWnd, NULL, hInstance, NULL);

        SetWindowFont(GetDlgItem(hWnd, -1), hFontLarge, TRUE);

        // لوحة الحالة (يسار)
        createStatusPanel(hInstance);

        // لوحة الإجراءات (يمين)
        createActionPanel(hInstance);

        // شريط التقدم
        hProgressBar = CreateWindowExW(0, PROGRESS_CLASSW, NULL,
            WS_VISIBLE | WS_CHILD | PBS_SMOOTH,
            30, 150, 940, 20,
            hWnd, (HMENU)IDC_PROGRESS_BAR, hInstance, NULL);
        SendMessage(hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessage(hProgressBar, PBM_SETBARCOLOR, 0, Theme::ACCENT);

        // قائمة السجل (أسفل)
        createLogPanel(hInstance);

        // قائمة الحجر الصحي (وسط)
        createQuarantinePanel(hInstance);
    }

    void createStatusPanel(HINSTANCE hInstance) {
        // إطار الحالة
        HWND hFrame = CreateWindowW(L"BUTTON", L"System Status",
            WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
            30, 80, 450, 200,
            hWnd, NULL, hInstance, NULL);
        SetWindowFont(hFrame, hFontBold, TRUE);

        // مؤشر الحماية الفعلية
        hStatusLabel = CreateWindowW(L"STATIC",
            L"● Real-Time Protection: ACTIVE\n"
            L"● AI Engine: Ready\n"
            L"● Last Scan: Never\n"
            L"● Threats Blocked: 0",
            WS_VISIBLE | WS_CHILD | SS_LEFT,
            50, 110, 400, 150,
            hWnd, (HMENU)IDC_STATUS_LABEL, hInstance, NULL);
        SetWindowFont(hStatusLabel, hFontNormal, TRUE);

        // تحديث لون النص
        SetTextColor(hStatusLabel, Theme::SUCCESS);
    }

    void createActionPanel(HINSTANCE hInstance) {
        int btnX = 520;
        int btnY = 90;
        int btnW = 200;
        int btnH = 45;

        // زر الفحص السريع
        hScanButton = createStyledButton(L"⚡ Quick Scan", btnX, btnY, btnW, btnH,
            IDC_SCAN_BUTTON, hInstance);

        // زر الفحص الكامل
        createStyledButton(L"🔍 Full Scan", btnX + 220, btnY, btnW, btnH,
            3001, hInstance);

        // زر فحص مخصص
        createStyledButton(L"📂 Custom Scan", btnX, btnY + 60, btnW, btnH,
            3002, hInstance);

        // زر تحديث
        createStyledButton(L"🔄 Update", btnX + 220, btnY + 60, btnW, btnH,
            3003, hInstance);

        // زر الحجر الصحي
        createStyledButton(L"🚫 Quarantine", btnX, btnY + 120, btnW, btnH,
            3004, hInstance);

        // زر الإعدادات
        createStyledButton(L"⚙️ Settings", btnX + 220, btnY + 120, btnW, btnH,
            3005, hInstance);
    }

    HWND createStyledButton(const wchar_t* text, int x, int y, int w, int h,
        int id, HINSTANCE hInstance) {
        HWND hBtn = CreateWindowW(L"BUTTON", text,
            WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_OWNERDRAW,
            x, y, w, h,
            hWnd, (HMENU)id, hInstance, NULL);

        SetWindowFont(hBtn, hFontNormal, TRUE);
        return hBtn;
    }

    void createLogPanel(HINSTANCE hInstance) {
        // عنوان
        HWND hLabel = CreateWindowW(L"STATIC", L"📋 Activity Log:",
            WS_VISIBLE | WS_CHILD | SS_LEFT,
            30, 500, 200, 25,
            hWnd, NULL, hInstance, NULL);
        SetWindowFont(hLabel, hFontBold, TRUE);

        // قائمة السجل
        hLogList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", NULL,
            WS_VISIBLE | WS_CHILD | LBS_NOTIFY |
            WS_VSCROLL | LBS_NOINTEGRALHEIGHT,
            30, 530, 940, 130,
            hWnd, (HMENU)IDC_LOG_LIST, hInstance, NULL);

        SetWindowFont(hLogList, hFontNormal, TRUE);
    }

    void createQuarantinePanel(HINSTANCE hInstance) {
        // عنوان
        HWND hLabel = CreateWindowW(L"STATIC", L"🛡️ Quarantine:",
            WS_VISIBLE | WS_CHILD | SS_LEFT,
            30, 300, 200, 25,
            hWnd, NULL, hInstance, NULL);
        SetWindowFont(hLabel, hFontBold, TRUE);

        // قائمة الحجر الصحي
        hQuarantineList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", NULL,
            WS_VISIBLE | WS_CHILD | LBS_NOTIFY |
            WS_VSCROLL | LBS_NOINTEGRALHEIGHT,
            30, 330, 700, 150,
            hWnd, (HMENU)IDC_QUARANTINE_LIST,
            hInstance, NULL);

        SetWindowFont(hQuarantineList, hFontNormal, TRUE);

        // أزرار الحجر
        createSmallButton(L"Restore", 750, 330, 100, 30, 4001, hInstance);
        createSmallButton(L"Delete", 750, 370, 100, 30, 4002, hInstance);
        createSmallButton(L"Clear All", 750, 410, 100, 30, 4003, hInstance);
    }

    HWND createSmallButton(const wchar_t* text, int x, int y, int w, int h,
        int id, HINSTANCE hInstance) {
        return CreateWindowW(L"BUTTON", text,
            WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            x, y, w, h,
            hWnd, (HMENU)id, hInstance, NULL);
    }

    // ==================== Tray Icon ====================

    void setupTrayIcon(HINSTANCE hInstance) {
        trayIcon.cbSize = sizeof(NOTIFYICONDATA);
        trayIcon.hWnd = hWnd;
        trayIcon.uID = 1;
        trayIcon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        trayIcon.uCallbackMessage = WM_TRAY_ICON;
        trayIcon.hIcon = LoadIcon(NULL, IDI_SHIELD);
        wcscpy_s(trayIcon.szTip, L"AI Antivirus - Protected");

        Shell_NotifyIcon(NIM_ADD, &trayIcon);
    }

    void setupMenu() {
        HMENU hMenu = CreateMenu();
        HMENU hFileMenu = CreatePopupMenu();
        HMENU hScanMenu = CreatePopupMenu();
        HMENU hToolsMenu = CreatePopupMenu();

        AppendMenuW(hFileMenu, MF_STRING, IDM_SHOW, L"&Show");
        AppendMenuW(hFileMenu, MF_SEPARATOR, 0, NULL);
        AppendMenuW(hFileMenu, MF_STRING, IDM_EXIT, L"E&xit");

        AppendMenuW(hScanMenu, MF_STRING, IDM_QUICK_SCAN, L"&Quick Scan\tF5");
        AppendMenuW(hScanMenu, MF_STRING, IDM_FULL_SCAN, L"&Full Scan\tF6");

        AppendMenuW(hToolsMenu, MF_STRING, IDM_TOGGLE_PROTECTION,
            L"&Toggle Protection");

        AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hFileMenu, L"&File");
        AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hScanMenu, L"&Scan");
        AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hToolsMenu, L"&Tools");

        SetMenu(hWnd, hMenu);
    }

    // ==================== GDI Initialization ====================

    void initGDI() {
        hFontNormal = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

        hFontBold = CreateFontW(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

        hFontLarge = CreateFontW(28, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    }

    void cleanup() {
        Shell_NotifyIcon(NIM_DELETE, &trayIcon);

        DeleteObject(hFontNormal);
        DeleteObject(hFontBold);
        DeleteObject(hFontLarge);
    }

    // ==================== معالجة الرسائل ====================

public:
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam,
        LPARAM lParam) {
        MainWindow* pThis = nullptr;

        if (msg == WM_NCCREATE) {
            CREATESTRUCT* pCS = reinterpret_cast<CREATESTRUCT*>(lParam);
            pThis = reinterpret_cast<MainWindow*>(pCS->lpCreateParams);
            SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
        }
        else {
            pThis = reinterpret_cast<MainWindow*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
        }

        if (pThis) {
            return pThis->handleMessage(hwnd, msg, wParam, lParam);
        }

        return DefWindowProc(hwnd, msg, wParam, lParam);
    }

    LRESULT handleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
        case WM_CREATE:
            return onCreate();

        case WM_CLOSE:
            minimizeToTray();
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        case WM_PAINT:
            return onPaint();

        case WM_DRAWITEM:
            return onDrawItem(lParam);

        case WM_CTLCOLORSTATIC:
            SetTextColor((HDC)wParam, Theme::TEXT_PRIMARY);
            SetBkColor((HDC)wParam, Theme::DARK_BG);
            return (LRESULT)GetStockObject(NULL_BRUSH);

        case WM_COMMAND:
            return onCommand(LOWORD(wParam));

        case WM_TRAY_ICON:
            return onTrayIcon(lParam);

        case WM_SCAN_COMPLETE:
            return onScanComplete();

        case WM_THREAT_DETECTED:
            return onThreatDetected((wchar_t*)lParam);

        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
        }
    }

    // ==================== معالجي الأحداث ====================

    LRESULT onCreate() {
        addLog(L"System initialized successfully");
        addLog(L"Real-time protection: ACTIVE");
        return 0;
    }

    LRESULT onPaint() {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        // رسم خلفية مخصصة إذا لزم الأمر

        EndPaint(hWnd, &ps);
        return 0;
    }

    LRESULT onDrawItem(LPARAM lParam) {
        DRAWITEMSTRUCT* pDIS = reinterpret_cast<DRAWITEMSTRUCT*>(lParam);

        if (pDIS->CtlType == ODT_BUTTON) {
            // رسم أزرار مخصصة
            bool isHover = (pDIS->itemState & ODS_SELECTED) ||
                (pDIS->itemState & ODS_HOTLIGHT);

            COLORREF bgColor = isHover ? Theme::ACCENT_HOVER : Theme::ACCENT;
            COLORREF textColor = Theme::TEXT_PRIMARY;

            HBRUSH hBrush = CreateSolidBrush(bgColor);
            FillRect(pDIS->hDC, &pDIS->rcItem, hBrush);
            DeleteObject(hBrush);

            // النص
            WCHAR text[256];
            GetWindowTextW(pDIS->hwndItem, text, 256);

            SetTextColor(pDIS->hDC, textColor);
            SetBkMode(pDIS->hDC, TRANSPARENT);

            DrawTextW(pDIS->hDC, text, -1, &pDIS->rcItem,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            // إطار
            if (pDIS->itemState & ODS_FOCUS) {
                DrawFocusRect(pDIS->hDC, &pDIS->rcItem);
            }

            return TRUE;
        }

        return FALSE;
    }

    LRESULT onCommand(int id) {
        switch (id) {
        case IDM_EXIT:
            DestroyWindow(hWnd);
            break;

        case IDM_SHOW:
            ShowWindow(hWnd, SW_SHOW);
            break;

        case IDC_SCAN_BUTTON:
        case IDM_QUICK_SCAN:
            startQuickScan();
            break;

        case IDM_FULL_SCAN:
            startFullScan();
            break;

        case IDM_TOGGLE_PROTECTION:
            toggleProtection();
            break;

        case 3002: // Custom Scan
            browseForScan();
            break;

        case 3003: // Update
            checkForUpdates();
            break;

        case 3004: // Quarantine
            refreshQuarantineList();
            break;

        case 3005: // Settings
            showSettings();
            break;

        case 4001: // Restore
            restoreSelected();
            break;

        case 4002: // Delete
            deleteSelected();
            break;

        case 4003: // Clear All
            clearQuarantine();
            break;
        }
        return 0;
    }

    LRESULT onTrayIcon(LPARAM lParam) {
        if (lParam == WM_LBUTTONDBLCLK) {
            ShowWindow(hWnd, SW_SHOW);
        }
        else if (lParam == WM_RBUTTONUP) {
            showTrayMenu();
        }
        return 0;
    }

    // ==================== وظائف الفحص ====================

    void startQuickScan() {
        if (stats.isScanning) {
            MessageBoxW(hWnd, L"Scan already in progress!", L"Info", MB_OK);
            return;
        }

        SetWindowTextW(hScanButton, L"⏹ Stop Scan");
        stats.isScanning = true;

        addLog(L"Starting Quick Scan...");

        scanThread = std::make_unique<std::thread>([this]() {
            // محاكاة الفحص
            for (int i = 0; i <= 100; i += 5) {
                if (!stats.isScanning) break;

                SendMessage(hProgressBar, PBM_SETPOS, i, 0);
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }

            SendMessage(hWnd, WM_SCAN_COMPLETE, 0, 0);
            });
    }

    void startFullScan() {
        MessageBoxW(hWnd, L"Full system scan will take several minutes.\nContinue?",
            L"Full Scan", MB_YESNO | MB_ICONQUESTION);
    }

    void stopScan() {
        stats.isScanning = false;
        if (scanThread && scanThread->joinable()) {
            scanThread->join();
        }
        SetWindowTextW(hScanButton, L"⚡ Quick Scan");
        SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
    }

    LRESULT onScanComplete() {
        stopScan();
        addLog(L"Scan completed. No threats found.");
        MessageBoxW(hWnd, L"Scan Complete!\n\nFiles scanned: 1,247\nThreats found: 0",
            L"Scan Result", MB_OK | MB_ICONINFORMATION);
        return 0;
    }

    LRESULT onThreatDetected(wchar_t* filePath) {
        addLog(std::wstring(L"THREAT DETECTED: ") + filePath);

        // إظهار إشعار منبثق
        trayIcon.uFlags |= NIF_INFO;
        wcscpy_s(trayIcon.szInfoTitle, L"🚨 Threat Detected!");
        wcscpy_s(trayIcon.szInfo, L"AI Antivirus blocked a threat");
        trayIcon.dwInfoFlags = NIIF_ERROR;
        Shell_NotifyIcon(NIM_MODIFY, &trayIcon);

        return 0;
    }

    // ==================== وظائف مساعدة ====================

    void browseForScan() {
        BROWSEINFOW bi = {};
        bi.lpszTitle = L"Select folder to scan:";
        bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

        LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
        if (pidl) {
            WCHAR path[MAX_PATH];
            SHGetPathFromIDListW(pidl, path);
            CoTaskMemFree(pidl);

            std::wstring msg = L"Scan folder: ";
            msg += path;
            addLog(msg);
        }
    }

    void checkForUpdates() {
        addLog(L"Checking for updates...");
        SetTimer(hWnd, 1, 2000, [](HWND hwnd, UINT msg, UINT_PTR id, DWORD time) {
            KillTimer(hwnd, id);
            MessageBoxW(hwnd, L"You are using the latest version (2.0.0).",
                L"Update Check", MB_OK);
            });
    }

    void toggleProtection() {
        isProtectionActive = !isProtectionActive;
        std::wstring status = isProtectionActive ?
            L"● Real-Time Protection: ACTIVE\n● AI Engine: Ready" :
            L"● Real-Time Protection: PAUSED\n● AI Engine: Standby";

        SetWindowTextW(hStatusLabel, status.c_str());
        addLog(isProtectionActive ? L"Protection enabled" : L"Protection paused");
    }

    void refreshQuarantineList() {
        SendMessageW(hQuarantineList, LB_RESETCONTENT, 0, 0);
        SendMessageW(hQuarantineList, LB_ADDSTRING, 0,
            (LPARAM)L"Trojan.Win32.Generic - C:\\Users\\...\\file.exe");
        SendMessageW(hQuarantineList, LB_ADDSTRING, 0,
            (LPARAM)L"Ransomware.Cryptolocker - C:\\Temp\\...\\evil.dll");
    }

    void restoreSelected() {
        int sel = SendMessageW(hQuarantineList, LB_GETCURSEL, 0, 0);
        if (sel != LB_ERR) {
            MessageBoxW(hWnd, L"File restored successfully.", L"Restore", MB_OK);
        }
    }

    void deleteSelected() {
        int sel = SendMessageW(hQuarantineList, LB_GETCURSEL, 0, 0);
        if (sel != LB_ERR) {
            if (MessageBoxW(hWnd, L"Permanently delete this file?",
                L"Confirm", MB_YESNO | MB_ICONWARNING) == IDYES) {
                SendMessageW(hQuarantineList, LB_DELETESTRING, sel, 0);
                addLog(L"File deleted from quarantine");
            }
        }
    }

    void clearQuarantine() {
        if (MessageBoxW(hWnd, L"Delete all quarantined files?",
            L"Clear Quarantine", MB_YESNO | MB_ICONWARNING) == IDYES) {
            SendMessageW(hQuarantineList, LB_RESETCONTENT, 0, 0);
            addLog(L"Quarantine cleared");
        }
    }

    void showSettings() {
        MessageBoxW(hWnd,
            L"Settings:\n\n"
            L"☑ Real-time protection\n"
            L"☑ AI-powered detection\n"
            L"☑ Automatic updates\n"
            L"☐ Silent mode\n"
            L"☐ Advanced heuristics",
            L"Settings", MB_OK);
    }

    // ==================== أدوات مساعدة ====================

    void addLog(const std::wstring& message) {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);

        std::wstringstream ss;
        ss << std::put_time(std::localtime(&time), L"[%H:%M:%S] ");
        ss << message;

        SendMessageW(hLogList, LB_ADDSTRING, 0, (LPARAM)ss.str().c_str());
        SendMessageW(hLogList, LB_SETTOPINDEX,
            SendMessageW(hLogList, LB_GETCOUNT, 0, 0) - 1, 0);
    }

    void minimizeToTray() {
        ShowWindow(hWnd, SW_HIDE);
        trayIcon.uFlags |= NIF_INFO;
        wcscpy_s(trayIcon.szInfoTitle, L"AI Antivirus");
        wcscpy_s(trayIcon.szInfo, L"Running in background");
        trayIcon.dwInfoFlags = NIIF_INFO;
        Shell_NotifyIcon(NIM_MODIFY, &trayIcon);
    }

    void showTrayMenu() {
        POINT pt;
        GetCursorPos(&pt);

        HMENU hMenu = CreatePopupMenu();
        AppendMenuW(hMenu, MF_STRING, IDM_SHOW, L"&Open");
        AppendMenuW(hMenu, MF_STRING, IDM_QUICK_SCAN, L"&Quick Scan");
        AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
        AppendMenuW(hMenu, MF_STRING, IDM_EXIT, L"E&xit");

        SetForegroundWindow(hWnd);
        TrackPopupMenu(hMenu, TPM_RIGHTALIGN, pt.x, pt.y, 0, hWnd, NULL);
        DestroyMenu(hMenu);
    }

    // ==================== حلقة الرسائل ====================

public:
    int run() {
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        return (int)msg.wParam;
    }
};

// ==================== نقطة البداية للواجهة ====================

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpCmdLine, int nCmdShow) {
    // تهيئة Common Controls
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icc);

    // إنشاء النافذة
    MainWindow window;

    if (!window.create(hInstance)) {
        MessageBoxW(NULL, L"Failed to create window!", L"Error", MB_OK);
        return 1;
    }

    window.show(nCmdShow);
    return window.run();
}

// ==================== ربط مع main.cpp القديم ====================

// للاستخدام المشترك، يمكن استدعاء هذا من main():
void launchGUI(HINSTANCE hInstance) {
    WinMain(hInstance, NULL, "", SW_SHOW);
}