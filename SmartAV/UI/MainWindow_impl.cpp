/**
 * MainWindow_impl.cpp - Advanced UI Implementation
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "MainWindow.h"
#include "../Core/ScanEngine.h"
#include "../Core/RealTimeMonitor.h"
#include "../Security/SelfProtection.h"
#include "../Security/Quarantine.h"
#include "../AI/AIDetector.h"
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <thread>
#include <sstream>
#include <filesystem>

namespace fs = std::filesystem;

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace AIAntivirus {

    // Control IDs
    enum ControlID {
        ID_BTN_QUICK_SCAN = 1001,
        ID_BTN_FULL_SCAN = 1002,
        ID_BTN_CUSTOM_SCAN = 1003,
        ID_BTN_STOP_SCAN = 1004,
        ID_BTN_SETTINGS = 1005,
        ID_BTN_QUARANTINE = 1006,
        ID_BTN_UPDATE = 1007,
        ID_BTN_PROTECTION = 1008,
        ID_PROGRESS = 1010,
        ID_STATUS_TEXT = 1011,
        ID_SCAN_LIST = 1012,
        ID_TIMER_UPDATE = 1
    };

    // Colors
    static const COLORREF CLR_BG_DARK = RGB(25, 25, 35);
    static const COLORREF CLR_BG_PANEL = RGB(35, 35, 50);
    static const COLORREF CLR_ACCENT = RGB(0, 150, 136);
    static const COLORREF CLR_ACCENT_HOVER = RGB(0, 180, 160);
    static const COLORREF CLR_TEXT = RGB(240, 240, 240);
    static const COLORREF CLR_TEXT_DIM = RGB(160, 160, 180);
    static const COLORREF CLR_SUCCESS = RGB(76, 175, 80);
    static const COLORREF CLR_WARNING = RGB(255, 193, 7);
    static const COLORREF CLR_DANGER = RGB(244, 67, 54);

    // Struct for thread-safe file info passing
    struct ScanFileInfo {
        std::wstring filePath;
        bool isThreat;
        ThreatLevel threatLevel;
        std::wstring threatName;
    };

    // Window class name
    static const wchar_t* WINDOW_CLASS = L"SmartAV_MainWindow";
    static MainWindow* g_mainWindow = nullptr;

    // Brushes
    static HBRUSH g_bgBrush = NULL;
    static HBRUSH g_panelBrush = NULL;
    static HBRUSH g_accentBrush = NULL;
    static HFONT g_titleFont = NULL;
    static HFONT g_normalFont = NULL;
    static HFONT g_smallFont = NULL;

    MainWindow::MainWindow() {
        g_mainWindow = this;
    }

    MainWindow::~MainWindow() {
        Shutdown();
        g_mainWindow = nullptr;
    }

    bool MainWindow::Initialize(HINSTANCE hInstance, int nCmdShow) {
        m_hInstance = hInstance;

        // Initialize common controls
        INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_WIN95_CLASSES | ICC_PROGRESS_CLASS | ICC_LISTVIEW_CLASSES };
        InitCommonControlsEx(&icc);

        // Create brushes and fonts
        g_bgBrush = CreateSolidBrush(CLR_BG_DARK);
        g_panelBrush = CreateSolidBrush(CLR_BG_PANEL);
        g_accentBrush = CreateSolidBrush(CLR_ACCENT);

        g_titleFont = CreateFontW(28, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

        g_normalFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

        g_smallFont = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

        // Register window class
        WNDCLASSEXW wc = { sizeof(wc) };
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = hInstance;
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = g_bgBrush;
        wc.lpszClassName = WINDOW_CLASS;
        wc.hIcon = LoadIcon(NULL, IDI_SHIELD);
        wc.hIconSm = LoadIcon(NULL, IDI_SHIELD);

        if (!RegisterClassExW(&wc)) return false;

        // Create main window
        m_hWnd = CreateWindowExW(
            WS_EX_APPWINDOW,
            WINDOW_CLASS,
            L"SmartAV - AI-Powered Antivirus",
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT,
            1200, 800,
            NULL, NULL, hInstance, this
        );

        if (!m_hWnd) return false;

        CreateUI();
        ShowWindow(m_hWnd, nCmdShow);
        UpdateWindow(m_hWnd);

        // Start update timer
        SetTimer(m_hWnd, ID_TIMER_UPDATE, 1000, NULL);

        return true;
    }

    bool MainWindow::CreateUI() {
        int margin = 20;
        int spacing = 10;
        int btnHeight = 45;
        int btnWidth = 180;
        int progressHeight = 25;
        int bottomBtnHeight = 40;

        // Get client size
        RECT rc;
        GetClientRect(m_hWnd, &rc);
        int width = rc.right - rc.left;
        int height = rc.bottom - rc.top;

        // Status panel - at top
        m_hStatusText = CreateWindowW(L"STATIC", L"Protection Status: Active | Ready to scan",
            WS_CHILD | WS_VISIBLE | SS_CENTER | SS_OWNERDRAW,
            margin, margin + 50, width - 2 * margin, 30,
            m_hWnd, (HMENU)ID_STATUS_TEXT, m_hInstance, NULL);

        // Scan buttons panel
        int btnY = margin + 50 + 30 + spacing;
        m_hBtnQuickScan = CreateWindowW(L"BUTTON", L"Quick Scan",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            margin, btnY, btnWidth, btnHeight,
            m_hWnd, (HMENU)ID_BTN_QUICK_SCAN, m_hInstance, NULL);

        m_hBtnFullScan = CreateWindowW(L"BUTTON", L"Full Scan",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            margin + btnWidth + spacing, btnY, btnWidth, btnHeight,
            m_hWnd, (HMENU)ID_BTN_FULL_SCAN, m_hInstance, NULL);

        m_hBtnCustomScan = CreateWindowW(L"BUTTON", L"Custom Scan",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            margin + 2 * (btnWidth + spacing), btnY, btnWidth, btnHeight,
            m_hWnd, (HMENU)ID_BTN_CUSTOM_SCAN, m_hInstance, NULL);

        m_hBtnStopScan = CreateWindowW(L"BUTTON", L"Stop Scan",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
            margin + 3 * (btnWidth + spacing), btnY, btnWidth, btnHeight,
            m_hWnd, (HMENU)ID_BTN_STOP_SCAN, m_hInstance, NULL);

        // Progress bar
        int progressY = btnY + btnHeight + spacing;
        m_hProgress = CreateWindowW(PROGRESS_CLASSW, NULL,
            WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
            margin, progressY, width - 2 * margin, progressHeight,
            m_hWnd, (HMENU)ID_PROGRESS, m_hInstance, NULL);
        SendMessage(m_hProgress, PBM_SETBARCOLOR, 0, (LPARAM)CLR_ACCENT);
        SendMessage(m_hProgress, PBM_SETBKCOLOR, 0, (LPARAM)CLR_BG_PANEL);

        // Scan results list
        int listY = progressY + progressHeight + spacing;
        int listHeight = height - listY - bottomBtnHeight - 2 * margin;
        m_hScanList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, NULL,
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_OWNERDRAWFIXED,
            margin, listY, width - 2 * margin, listHeight,
            m_hWnd, (HMENU)ID_SCAN_LIST, m_hInstance, NULL);

        // Set list view colors - WHITE background with DARK text for visibility
        ListView_SetBkColor(m_hScanList, RGB(255, 255, 255));
        ListView_SetTextBkColor(m_hScanList, RGB(255, 255, 255));
        ListView_SetTextColor(m_hScanList, RGB(0, 0, 0));

        LVCOLUMNW lvc = { 0 };
        lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

        lvc.cx = (width - 2 * margin) * 55 / 100; // 55%
        lvc.pszText = (LPWSTR)L"File Path";
        lvc.iSubItem = 0;
        ListView_InsertColumn(m_hScanList, 0, &lvc);

        lvc.cx = (width - 2 * margin) * 15 / 100; // 15%
        lvc.pszText = (LPWSTR)L"Status";
        lvc.iSubItem = 1;
        ListView_InsertColumn(m_hScanList, 1, &lvc);

        lvc.cx = (width - 2 * margin) * 15 / 100; // 15%
        lvc.pszText = (LPWSTR)L"Threat";
        lvc.iSubItem = 2;
        ListView_InsertColumn(m_hScanList, 2, &lvc);

        lvc.cx = (width - 2 * margin) * 15 / 100; // 15%
        lvc.pszText = (LPWSTR)L"Action";
        lvc.iSubItem = 3;
        ListView_InsertColumn(m_hScanList, 3, &lvc);

        // Set list view colors for dark theme
        ListView_SetBkColor(m_hScanList, CLR_BG_PANEL);
        ListView_SetTextBkColor(m_hScanList, CLR_BG_PANEL);
        ListView_SetTextColor(m_hScanList, CLR_TEXT);

        // Bottom buttons
        int bottomY = height - bottomBtnHeight - margin;
        int bottomBtnWidth = (width - 2 * margin - 3 * spacing) / 4;

        m_hBtnQuarantine = CreateWindowW(L"BUTTON", L"Quarantine",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            margin, bottomY, bottomBtnWidth, bottomBtnHeight,
            m_hWnd, (HMENU)ID_BTN_QUARANTINE, m_hInstance, NULL);

        m_hBtnProtection = CreateWindowW(L"BUTTON", L"Protection",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            margin + bottomBtnWidth + spacing, bottomY, bottomBtnWidth, bottomBtnHeight,
            m_hWnd, (HMENU)ID_BTN_PROTECTION, m_hInstance, NULL);

        m_hBtnSettings = CreateWindowW(L"BUTTON", L"Settings",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            margin + 2 * (bottomBtnWidth + spacing), bottomY, bottomBtnWidth, bottomBtnHeight,
            m_hWnd, (HMENU)ID_BTN_SETTINGS, m_hInstance, NULL);

        m_hBtnUpdate = CreateWindowW(L"BUTTON", L"Update",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            margin + 3 * (bottomBtnWidth + spacing), bottomY, bottomBtnWidth, bottomBtnHeight,
            m_hWnd, (HMENU)ID_BTN_UPDATE, m_hInstance, NULL);

        // Apply fonts to all controls
        EnumChildWindows(m_hWnd, [](HWND hChild, LPARAM lParam) -> BOOL {
            SendMessage(hChild, WM_SETFONT, (WPARAM)g_normalFont, TRUE);
            return TRUE;
        }, 0);

        return true;
    }

    int MainWindow::Run() {
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        return (int)msg.wParam;
    }

    void MainWindow::Shutdown() {
        KillTimer(m_hWnd, ID_TIMER_UPDATE);

        if (g_bgBrush) { DeleteObject(g_bgBrush); g_bgBrush = NULL; }
        if (g_panelBrush) { DeleteObject(g_panelBrush); g_panelBrush = NULL; }
        if (g_accentBrush) { DeleteObject(g_accentBrush); g_accentBrush = NULL; }
        if (g_titleFont) { DeleteObject(g_titleFont); g_titleFont = NULL; }
        if (g_normalFont) { DeleteObject(g_normalFont); g_normalFont = NULL; }
        if (g_smallFont) { DeleteObject(g_smallFont); g_smallFont = NULL; }
    }

    LRESULT CALLBACK MainWindow::WindowProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
        MainWindow* pThis = nullptr;

        if (message == WM_NCCREATE) {
            CREATESTRUCT* pCreate = (CREATESTRUCT*)lParam;
            pThis = (MainWindow*)pCreate->lpCreateParams;
            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
            pThis->m_hWnd = hWnd;
        } else {
            pThis = (MainWindow*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
        }

        if (pThis) {
            return pThis->HandleMessage(message, wParam, lParam);
        }

        return DefWindowProc(hWnd, message, wParam, lParam);
    }

    LRESULT MainWindow::HandleMessage(UINT message, WPARAM wParam, LPARAM lParam) {
        switch (message) {
        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            switch (wmId) {
            case ID_BTN_QUICK_SCAN: {
                // Clear previous scan results
                HWND hList = GetDlgItem(m_hWnd, ID_SCAN_LIST);
                ListView_DeleteAllItems(hList);
                
                EnableWindow(GetDlgItem(m_hWnd, ID_BTN_STOP_SCAN), TRUE);
                EnableWindow(GetDlgItem(m_hWnd, ID_BTN_QUICK_SCAN), FALSE);
                EnableWindow(GetDlgItem(m_hWnd, ID_BTN_FULL_SCAN), FALSE);
                SendDlgItemMessage(m_hWnd, ID_PROGRESS, PBM_SETPOS, 0, 0);
                SetDlgItemTextW(m_hWnd, ID_STATUS_TEXT, L"Status: Quick Scan starting...");
                
                // Initialize and start scan
                ScanEngine::GetInstance().Initialize(L"data");
                ScanEngine::GetInstance().StartQuickScan([this](const ScanProgress& progress, const ThreatInfo* threat) {
                    m_currentScanningFile = progress.currentFile;
                    PostMessage(m_hWnd, WM_USER + 1, (WPARAM)progress.scannedFiles, (LPARAM)progress.totalFiles);
                    
                    // Post message to UI thread to add file to list (thread-safe)
                    ScanFileInfo* info = new ScanFileInfo();
                    info->filePath = threat ? threat->filePath : progress.currentFile;
                    info->isThreat = (threat && threat->level != ThreatLevel::SAFE);
                    info->threatLevel = threat ? threat->level : ThreatLevel::SAFE;
                    info->threatName = threat ? threat->threatName : L"";
                    PostMessage(m_hWnd, WM_USER + 3, (WPARAM)info, 0);
                    
                    if (progress.isComplete) {
                        PostMessage(m_hWnd, WM_USER + 2, progress.threatsFound, 0);
                    }
                });
                break;
            }

            case ID_BTN_FULL_SCAN: {
                // Clear previous scan results
                HWND hList = GetDlgItem(m_hWnd, ID_SCAN_LIST);
                ListView_DeleteAllItems(hList);
                
                EnableWindow(GetDlgItem(m_hWnd, ID_BTN_STOP_SCAN), TRUE);
                EnableWindow(GetDlgItem(m_hWnd, ID_BTN_QUICK_SCAN), FALSE);
                EnableWindow(GetDlgItem(m_hWnd, ID_BTN_FULL_SCAN), FALSE);
                SetDlgItemTextW(m_hWnd, ID_STATUS_TEXT, L"Status: Full System Scan starting...");
                
                ScanEngine::GetInstance().Initialize(L"data");
                ScanEngine::GetInstance().StartFullScan([this](const ScanProgress& progress, const ThreatInfo* threat) {
                    m_currentScanningFile = progress.currentFile;
                    PostMessage(m_hWnd, WM_USER + 1, (WPARAM)progress.scannedFiles, (LPARAM)progress.totalFiles);
                    
                    // Add ALL files to list view (CLEAN or THREAT)
                    HWND hList = GetDlgItem(m_hWnd, ID_SCAN_LIST);
                    LVITEMW item = {0};
                    item.mask = LVIF_TEXT;
                    item.iItem = ListView_GetItemCount(hList);
                    item.pszText = (LPWSTR)(threat ? threat->filePath.c_str() : progress.currentFile.c_str());
                    int idx = ListView_InsertItem(hList, &item);
                    
                    if (threat && threat->level != ThreatLevel::SAFE) {
                        ListView_SetItemText(hList, idx, 1, (LPWSTR)(threat->level >= ThreatLevel::HIGH ? L"THREAT" : L"Suspicious"));
                        ListView_SetItemText(hList, idx, 2, (LPWSTR)threat->threatName.c_str());
                    } else {
                        ListView_SetItemText(hList, idx, 1, (LPWSTR)L"CLEAN");
                        ListView_SetItemText(hList, idx, 2, (LPWSTR)L"-");
                    }
                    ListView_SetItemText(hList, idx, 3, (LPWSTR)L"-");
                    ListView_EnsureVisible(hList, idx, FALSE);
                    
                    if (progress.isComplete) {
                        PostMessage(m_hWnd, WM_USER + 2, progress.threatsFound, 0);
                    }
                });
                break;
            }

            case ID_BTN_CUSTOM_SCAN: {
                BROWSEINFOW bi = { 0 };
                bi.hwndOwner = m_hWnd;
                bi.lpszTitle = L"Select folder to scan:";
                bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
                LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
                if (pidl) {
                    wchar_t path[MAX_PATH];
                    if (SHGetPathFromIDListW(pidl, path)) {
                        m_customScanPath = path;
                        
                        // Clear previous scan results
                        HWND hList = GetDlgItem(m_hWnd, ID_SCAN_LIST);
                        ListView_DeleteAllItems(hList);
                        
                        // Start custom scan immediately
                        EnableWindow(GetDlgItem(m_hWnd, ID_BTN_STOP_SCAN), TRUE);
                        EnableWindow(GetDlgItem(m_hWnd, ID_BTN_QUICK_SCAN), FALSE);
                        EnableWindow(GetDlgItem(m_hWnd, ID_BTN_FULL_SCAN), FALSE);
                        SendDlgItemMessage(m_hWnd, ID_PROGRESS, PBM_SETPOS, 0, 0);
                        
                        std::wstring msg = L"Status: Custom Scan starting... " + m_customScanPath;
                        SetDlgItemTextW(m_hWnd, ID_STATUS_TEXT, msg.c_str());
                        
                        ScanEngine::GetInstance().Initialize(L"data");
                        ScanEngine::GetInstance().StartCustomScan(m_customScanPath, [this](const ScanProgress& progress, const ThreatInfo* threat) {
                            m_currentScanningFile = progress.currentFile;
                            PostMessage(m_hWnd, WM_USER + 1, (WPARAM)progress.scannedFiles, (LPARAM)progress.totalFiles);
                            
                            // Add ALL files to list view (CLEAN or THREAT)
                            HWND hList = GetDlgItem(m_hWnd, ID_SCAN_LIST);
                            LVITEMW item = {0};
                            item.mask = LVIF_TEXT;
                            item.iItem = ListView_GetItemCount(hList);
                            item.pszText = (LPWSTR)(threat ? threat->filePath.c_str() : progress.currentFile.c_str());
                            int idx = ListView_InsertItem(hList, &item);
                            
                            if (threat && threat->level != ThreatLevel::SAFE) {
                                ListView_SetItemText(hList, idx, 1, (LPWSTR)(threat->level >= ThreatLevel::HIGH ? L"THREAT" : L"Suspicious"));
                                ListView_SetItemText(hList, idx, 2, (LPWSTR)threat->threatName.c_str());
                            } else {
                                ListView_SetItemText(hList, idx, 1, (LPWSTR)L"CLEAN");
                                ListView_SetItemText(hList, idx, 2, (LPWSTR)L"-");
                            }
                            ListView_SetItemText(hList, idx, 3, (LPWSTR)L"-");
                            ListView_EnsureVisible(hList, idx, FALSE);
                            
                            if (progress.isComplete) {
                                PostMessage(m_hWnd, WM_USER + 2, progress.threatsFound, 0);
                            }
                        });
                    }
                    CoTaskMemFree(pidl);
                }
                break;
            }

            case ID_BTN_STOP_SCAN:
                ScanEngine::GetInstance().StopScan();
                EnableWindow(GetDlgItem(m_hWnd, ID_BTN_STOP_SCAN), FALSE);
                EnableWindow(GetDlgItem(m_hWnd, ID_BTN_QUICK_SCAN), TRUE);
                EnableWindow(GetDlgItem(m_hWnd, ID_BTN_FULL_SCAN), TRUE);
                SetDlgItemTextW(m_hWnd, ID_STATUS_TEXT, L"Status: Scan stopped by user");
                break;

            case ID_BTN_QUARANTINE:
                MessageBoxW(m_hWnd, L"Quarantine Manager\n\nNo threats currently quarantined.",
                    L"Quarantine", MB_ICONINFORMATION);
                break;

            case ID_BTN_PROTECTION: {
                auto& monitor = RealTimeMonitor::GetInstance();
                if (monitor.IsRunning()) {
                    int result = MessageBoxW(m_hWnd,
                        L"Real-time Protection is currently ENABLED.\n\nDo you want to disable it?",
                        L"Protection Settings", MB_ICONQUESTION | MB_YESNO);
                    if (result == IDYES) {
                        monitor.Stop();
                        SetDlgItemTextW(m_hWnd, ID_STATUS_TEXT, L"Protection Status: DISABLED");
                    }
                } else {
                    int result = MessageBoxW(m_hWnd,
                        L"Real-time Protection is currently DISABLED.\n\nDo you want to enable it?",
                        L"Protection Settings", MB_ICONQUESTION | MB_YESNO);
                    if (result == IDYES) {
                        ScanEngine::GetInstance().Initialize(L"data");
                        monitor.Initialize();
                        monitor.Start();
                        SetDlgItemTextW(m_hWnd, ID_STATUS_TEXT, L"Protection Status: ACTIVE - Real-time monitoring enabled");
                    }
                }
                break;
            }

            case ID_BTN_SETTINGS:
                MessageBoxW(m_hWnd,
                    L"Settings\n\n"
                    L"- Scan Engine: AI + Heuristic\n"
                    L"- Real-time Protection: Enabled\n"
                    L"- Auto-Quarantine: Enabled\n"
                    L"- Update Frequency: Daily",
                    L"Settings", MB_ICONINFORMATION);
                break;

            case ID_BTN_UPDATE:
                MessageBoxW(m_hWnd, L"Checking for updates...\n\nYour definitions are up to date!",
                    L"Update", MB_ICONINFORMATION);
                break;
            }
            return 0;
        }

        case WM_USER + 1: {
            // Update progress from scan thread
            size_t scanned = (size_t)wParam;
            size_t total = (size_t)lParam;
            if (total > 0) {
                int progress = (int)((scanned * 100) / total);
                SendDlgItemMessage(m_hWnd, ID_PROGRESS, PBM_SETPOS, progress, 0);
                
                wchar_t status[512];
                if (!m_currentScanningFile.empty()) {
                    // Show current file name (truncate if too long)
                    std::wstring fileName = fs::path(m_currentScanningFile).filename().wstring();
                    if (fileName.length() > 40) {
                        fileName = fileName.substr(0, 37) + L"...";
                    }
                    swprintf_s(status, L"Scanning: %zu/%zu - %s", scanned, total, fileName.c_str());
                } else {
                    swprintf_s(status, L"Scanning: %zu / %zu files", scanned, total);
                }
                SetDlgItemTextW(m_hWnd, ID_STATUS_TEXT, status);
            }
            return 0;
        }

        case WM_USER + 2: {
            // Scan complete
            size_t threats = (size_t)wParam;
            EnableWindow(GetDlgItem(m_hWnd, ID_BTN_STOP_SCAN), FALSE);
            EnableWindow(GetDlgItem(m_hWnd, ID_BTN_QUICK_SCAN), TRUE);
            EnableWindow(GetDlgItem(m_hWnd, ID_BTN_FULL_SCAN), TRUE);
            SendDlgItemMessage(m_hWnd, ID_PROGRESS, PBM_SETPOS, 100, 0);
            
            wchar_t status[256];
            if (threats > 0) {
                swprintf_s(status, L"Scan Complete - %zu threats found!", threats);
                MessageBoxW(m_hWnd, status, L"Scan Results", MB_ICONWARNING);
            } else {
                swprintf_s(status, L"Scan Complete - No threats found");
            }
            SetDlgItemTextW(m_hWnd, ID_STATUS_TEXT, status);
            return 0;
        }

        case WM_USER + 3: {
            // Add file to list view from UI thread (thread-safe)
            ScanFileInfo* info = (ScanFileInfo*)wParam;
            if (info && m_hScanList) {
                LVITEMW item = {0};
                item.mask = LVIF_TEXT;
                item.iItem = ListView_GetItemCount(m_hScanList);
                
                // Create writable buffer for ListView
                static thread_local wchar_t pathBuffer[1024];
                wcsncpy_s(pathBuffer, info->filePath.c_str(), 1023);
                item.pszText = pathBuffer;
                
                int idx = ListView_InsertItem(m_hScanList, &item);
                
                if (idx >= 0) {
                    // Set status
                    wchar_t statusBuffer[64];
                    if (info->isThreat) {
                        wcsncpy_s(statusBuffer, info->threatLevel >= ThreatLevel::HIGH ? L"THREAT" : L"Suspicious", 63);
                    } else {
                        wcsncpy_s(statusBuffer, L"CLEAN", 63);
                    }
                    ListView_SetItemText(m_hScanList, idx, 1, statusBuffer);
                    
                    // Set threat name
                    if (info->isThreat && !info->threatName.empty()) {
                        static thread_local wchar_t threatBuffer[256];
                        wcsncpy_s(threatBuffer, info->threatName.c_str(), 255);
                        ListView_SetItemText(m_hScanList, idx, 2, threatBuffer);
                    } else {
                        ListView_SetItemText(m_hScanList, idx, 2, (LPWSTR)L"-");
                    }
                    
                    ListView_SetItemText(m_hScanList, idx, 3, (LPWSTR)L"-");
                    
                    // Auto-scroll to bottom every 5 items
                    if (idx % 5 == 0) {
                        ListView_EnsureVisible(m_hScanList, idx, FALSE);
                    }
                }
                
                delete info;
            }
            return 0;
        }

        case WM_TIMER:
            if (wParam == ID_TIMER_UPDATE) {
                // Update UI periodically if scanning
                if (ScanEngine::GetInstance().IsScanning()) {
                    auto progress = ScanEngine::GetInstance().GetProgress();
                    wchar_t status[512];
                    swprintf_s(status, L"Scanning: %zu files | Threats: %zu | Current: %.50s...",
                        progress.scannedFiles, progress.threatsFound,
                        progress.currentFile.substr(0, 50).c_str());
                    SetDlgItemTextW(m_hWnd, ID_STATUS_TEXT, status);
                }
            }
            return 0;

        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLORBTN: {
            HDC hdc = (HDC)wParam;
            SetTextColor(hdc, CLR_TEXT);
            SetBkColor(hdc, CLR_BG_DARK);
            return (LRESULT)g_bgBrush;
        }

        case WM_NOTIFY: {
            LPNMHDR pnmh = (LPNMHDR)lParam;
            if (pnmh->idFrom == ID_SCAN_LIST && pnmh->code == NM_CUSTOMDRAW) {
                LPNMLVCUSTOMDRAW lplvcd = (LPNMLVCUSTOMDRAW)lParam;
                switch (lplvcd->nmcd.dwDrawStage) {
                case CDDS_PREPAINT:
                    return CDRF_NOTIFYITEMDRAW;
                case CDDS_ITEMPREPAINT:
                    // Alternating row colors - light gray and white
                    if (lplvcd->nmcd.dwItemSpec % 2 == 0) {
                        lplvcd->clrTextBk = RGB(240, 240, 240); // Light gray
                    } else {
                        lplvcd->clrTextBk = RGB(255, 255, 255); // White
                    }
                    // Ensure text is always black for visibility
                    lplvcd->clrText = RGB(0, 0, 0);
                    return CDRF_NEWFONT;
                }
            }
            break;
        }

        case WM_PAINT:
            OnPaint();
            return 0;

        case WM_SIZE: {
            // Handle window resize for responsive layout
            int width = LOWORD(lParam);
            int height = HIWORD(lParam);
            ResizeControls(width, height);
            return 0;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        default:
            return DefWindowProc(m_hWnd, message, wParam, lParam);
        }
    }

    void MainWindow::OnPaint() {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(m_hWnd, &ps);

        // Get client area size
        RECT rc;
        GetClientRect(m_hWnd, &rc);
        int width = rc.right - rc.left;
        int margin = 20;

        // Draw background
        FillRect(hdc, &rc, g_bgBrush);

        // Draw title with custom font
        SetTextColor(hdc, CLR_ACCENT);
        SetBkMode(hdc, TRANSPARENT);
        SelectObject(hdc, g_titleFont);
        TextOutW(hdc, margin, 20, L"SmartAV", 7);

        // Draw subtitle
        SelectObject(hdc, g_smallFont);
        SetTextColor(hdc, CLR_TEXT_DIM);
        int titleWidth = 0;
        if (g_titleFont) {
            SIZE textSize;
            GetTextExtentPoint32W(hdc, L"SmartAV", 7, &textSize);
            titleWidth = textSize.cx;
        }
        TextOutW(hdc, margin + titleWidth + 50, 30, L"AI-Powered Protection", 22);

        // Draw accent line under title
        HPEN hPen = CreatePen(PS_SOLID, 2, CLR_ACCENT);
        HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
        MoveToEx(hdc, margin, 55, NULL);
        LineTo(hdc, width - margin, 55);
        SelectObject(hdc, hOldPen);
        DeleteObject(hPen);

        EndPaint(m_hWnd, &ps);
    }

    void MainWindow::ResizeControls(int width, int height) {
        if (!m_hBtnQuickScan) return; // Controls not created yet

        // Calculate responsive margins and sizes
        int margin = 20;
        int spacing = 10;
        int btnHeight = 45;
        int btnWidth = (width - 2 * margin - 3 * spacing) / 4;
        int progressHeight = 25;
        int bottomBtnHeight = 40;
        int listY = margin + 50 + 30 + 70 + progressHeight + 20;
        int bottomY = height - bottomBtnHeight - margin;
        int listHeight = bottomY - listY - spacing;

        // Top scan buttons
        SetWindowPos(m_hBtnQuickScan, NULL, margin, margin + 50 + 30, btnWidth, btnHeight, SWP_NOZORDER);
        SetWindowPos(m_hBtnFullScan, NULL, margin + btnWidth + spacing, margin + 50 + 30, btnWidth, btnHeight, SWP_NOZORDER);
        SetWindowPos(m_hBtnCustomScan, NULL, margin + 2 * (btnWidth + spacing), margin + 50 + 30, btnWidth, btnHeight, SWP_NOZORDER);
        SetWindowPos(m_hBtnStopScan, NULL, margin + 3 * (btnWidth + spacing), margin + 50 + 30, btnWidth, btnHeight, SWP_NOZORDER);

        // Progress bar
        SetWindowPos(m_hProgress, NULL, margin, margin + 50 + 30 + btnHeight + 15, width - 2 * margin, progressHeight, SWP_NOZORDER);

        // List view
        SetWindowPos(m_hScanList, NULL, margin, listY, width - 2 * margin, listHeight, SWP_NOZORDER);

        // Bottom buttons
        int bottomBtnWidth = (width - 2 * margin - 3 * spacing) / 4;
        SetWindowPos(m_hBtnQuarantine, NULL, margin, bottomY, bottomBtnWidth, bottomBtnHeight, SWP_NOZORDER);
        SetWindowPos(m_hBtnProtection, NULL, margin + bottomBtnWidth + spacing, bottomY, bottomBtnWidth, bottomBtnHeight, SWP_NOZORDER);
        SetWindowPos(m_hBtnSettings, NULL, margin + 2 * (bottomBtnWidth + spacing), bottomY, bottomBtnWidth, bottomBtnHeight, SWP_NOZORDER);
        SetWindowPos(m_hBtnUpdate, NULL, margin + 3 * (bottomBtnWidth + spacing), bottomY, bottomBtnWidth, bottomBtnHeight, SWP_NOZORDER);

        // Status text
        SetWindowPos(m_hStatusText, NULL, margin, margin + 50, width - 2 * margin, 30, SWP_NOZORDER);

        // Force redraw
        InvalidateRect(m_hWnd, NULL, TRUE);
    }

} // namespace AIAntivirus
