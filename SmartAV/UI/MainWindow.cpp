/**
 * MainWindow.cpp
 *
 * الواجهة الرسومية الرئيسية - Main User Interface
 *
 * المسؤوليات:
 * - عرض Dashboard تفاعلي لحالة الحماية
 - إرسال أوامر الفحص للخدمة عبر IPC (Named Pipes)
 * - عرض نتائج الفحص والملفات المعزولة
 * - إدارة الإعدادات والتفضيلات
 * - عرض التنبيهات والإشعارات
 * - التواصل الآمن مع الخدمة فقط (لا فحص مباشر)
 *
 * التقنيات:
 * - Win32 API (Native, بدون إطارات خارجية)
 * - Custom Drawing للـ Modern UI
 * - Named Pipes للـ IPC
 * - Threading للـ UI Responsiveness
 *
 * متطلبات: C++17, Windows 10/11, Visual Studio 2022
 */

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <dwmapi.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <memory>
#include <functional>

 // TODO: تضمين مكتبات IPC والبروتوكول
 // #include "../IPC/Protocol.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "dwmapi.lib")

// إعدادات Visual Styles
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace AIAntivirus {

    // ==================== تعريفات الأنواع ====================

    /**
     * حالة الاتصال بالخدمة
     */
    enum class ServiceStatus {
        DISCONNECTED,       // غير متصل
        CONNECTING,         // جاري الاتصال
        CONNECTED,          // متصل
        ERROR               // خطأ في الاتصال
    };

    /**
     * حالة الحماية الكلية
     */
    enum class ProtectionStatus {
        SECURE,             // آمن
        WARNING,            // تحذير (تحديث مطلوب)
        THREAT_DETECTED,    // تم اكتشاف تهديد
        DISABLED,           // معطل
        UNKNOWN             // غير معروف
    };

    /**
     * معلومات Dashboard
     */
    struct DashboardInfo {
        ProtectionStatus status;
        std::string statusText;
        uint64_t filesScanned;
        uint64_t threatsBlocked;
        uint64_t filesQuarantined;
        std::string lastScanTime;
        std::string definitionsVersion;
        bool realTimeProtection;
        bool behavioralProtection;
        bool aiProtection;
    };

    /**
     * نتيجة فحص (للعرض)
     */
    struct ScanResultUI {
        std::wstring filePath;
        std::wstring threatName;
        std::string scanType;
        std::chrono::system_clock::time_point scanTime;
        bool isThreat;
        float confidence;
    };

    /**
     * إعدادات النافذة
     */
    struct UIConfig {
        bool startMinimized = false;
        bool showNotifications = true;
        std::string language = "ar"; // Arabic default
        COLORREF accentColor = RGB(0, 120, 215); // Windows Blue
        bool darkMode = true;
    };

    // ==================== IPC Protocol Definitions ====================

    enum class IPCCommand : uint32_t {
        PING = 0,
        GET_STATUS,
        START_QUICK_SCAN,
        START_FULL_SCAN,
        START_CUSTOM_SCAN,
        STOP_SCAN,
        GET_QUARANTINE_LIST,
        RESTORE_FILE,
        DELETE_FILE,
        UPDATE_SETTINGS,
        GET_LOGS
    };

    struct IPCMessage {
        IPCCommand command;
        uint32_t dataSize;
        std::vector<uint8_t> data;
    };

    // ==================== الفئة الرئيسية: MainWindow ====================

    class MainWindow {
    public:
        MainWindow();
        ~MainWindow();

        // منع النسخ
        MainWindow(const MainWindow&) = delete;
        MainWindow& operator=(const MainWindow&) = delete;

        // ==================== واجهة التشغيل ====================

        /**
         * تهيئة النافذة
         */
        bool Initialize(HINSTANCE hInstance, int nCmdShow);

        /**
         * تشغيل حلقة الرسائل
         */
        int Run();

        /**
         * إيقاف النافذة
         */
        void Shutdown();

        // ==================== التحكم في الحالة ====================

        /**
         * تحديث حالة الاتصال
         */
        void SetServiceStatus(ServiceStatus status);

        /**
         * تحديث Dashboard
         */
        void UpdateDashboard(const DashboardInfo& info);

        /**
         * إضافة نتيجة فحص
         */
        void AddScanResult(const ScanResultUI& result);

        /**
         * عرض تنبيه
         */
        void ShowNotification(const std::wstring& title,
            const std::wstring& message,
            bool isWarning = false);

        // ==================== الإعدادات ====================

        void SetConfig(const UIConfig& config) { m_config = config; }
        UIConfig GetConfig() const { return m_config; }

    private:
        // ==================== الأعضاء الخاصة ====================

        // Windows Handles
        HINSTANCE m_hInstance;
        HWND m_hWnd;
        HWND m_hWndStatusBar;
        HWND m_hWndTabControl;

        // الأقسام
        HWND m_hDashboardPage;
        HWND m_hScanPage;
        HWND m_hQuarantinePage;
        HWND m_hSettingsPage;
        HWND m_hLogsPage;

        // الألوان والأشكال
        COLORREF m_bgColor;
        COLORREF m_textColor;
        HBRUSH m_hBgBrush;
        HFONT m_hFontRegular;
        HFONT m_hFontBold;
        HFONT m_hFontLarge;

        // الحالة
        std::atomic<bool> m_running{ false };
        ServiceStatus m_serviceStatus{ ServiceStatus::DISCONNECTED };
        DashboardInfo m_dashboardInfo;
        std::vector<ScanResultUI> m_scanResults;

        // IPC
        HANDLE m_hPipe;
        std::thread m_ipcThread;
        std::mutex m_ipcMutex;
        std::queue<IPCMessage> m_ipcQueue;

        // إعدادات
        UIConfig m_config;

        // ==================== وظائف النافذة ====================

        /**
         * تسجيل فئة النافذة
         */
        bool RegisterWindowClass();

        /**
         * إنشاء عناصر UI
         */
        bool CreateUI();

        /**
         * إنشاء صفحة Dashboard
         */
        void CreateDashboardPage();

        /**
         * إنشاء صفحة الفحص
         */
        void CreateScanPage();

        /**
         * إنشاء صفحة الحجر
         */
        void CreateQuarantinePage();

        /**
         * إنشاء صفحة الإعدادات
         */
        void CreateSettingsPage();

        /**
         * إنشاء صفحة السجلات
         */
        void CreateLogsPage();

        // ==================== الرسم المخصص ====================

        /**
         * رسم Dashboard
         */
        void DrawDashboard(HDC hdc, const RECT& rect);

        /**
         * رسم Status Circle
         */
        void DrawStatusCircle(HDC hdc, int x, int y, int radius,
            ProtectionStatus status);

        /**
         * رسم Button مخصص
         */
        void DrawCustomButton(HDC hdc, const RECT& rect,
            const std::wstring& text, bool hovered);

        /**
         * رسم Progress Bar
         */
        void DrawProgressBar(HDC hdc, const RECT& rect,
            float progress, const std::wstring& text);

        // ==================== IPC Communication ====================

        /**
         * Thread الاتصال بالخدمة
         */
        void IPCThreadFunc();

        /**
         * الاتصال بالـ Pipe
         */
        bool ConnectToPipe();

        /**
         * إرسال رسالة
         */
        bool SendIPCMessage(const IPCMessage& msg);

        /**
         * استقبال رسالة
         */
        bool ReceiveIPCMessage(IPCMessage& msg);

        /**
         * معالجة رسالة مستلمة
         */
        void HandleIPCMessage(const IPCMessage& msg);

        // ==================== معالجة الأحداث ====================

        /**
         * معالج الرسائل الرئيسي (Static)
         */
        static LRESULT CALLBACK WindowProc(HWND hWnd, UINT message,
            WPARAM wParam, LPARAM lParam);

        /**
         * معالج الرسائل (Instance)
         */
        LRESULT HandleMessage(UINT message, WPARAM wParam, LPARAM lParam);

        /**
         * معالج أمر
         */
        void OnCommand(int id);

        /**
         * تغيير حجم
         */
        void OnResize();

        /**
         * رسم
         */
        void OnPaint();

        /**
         * مؤشر الماوس
         */
        void OnMouseMove(int x, int y);

        /**
         * نقرة
         */
        void OnClick(int x, int y);

        // ==================== أوامر UI ====================

        void OnQuickScan();
        void OnFullScan();
        void OnCustomScan();
        void OnStopScan();
        void OnOpenQuarantine();
        void OnRestoreFile();
        void OnDeleteFile();
        void OnSettingsChanged();
        void OnAbout();

        // ==================== وظائف مساعدة ====================

        /**
         إنشاء Font
         */
        HFONT CreateAppFont(int size, bool bold);

        /**
         * تحميل الأيقونات
         */
        HICON LoadAppIcon();

        /**
         * تطبيق Dark Mode
         */
        void ApplyDarkMode();

        /**
         * تحديث Status Bar
         */
        void UpdateStatusBar();

        /**
         * تغيير الصفحة
         */
        void SwitchToPage(int pageIndex);

        /**
         * تحديث نص بعربي
         */
        std::wstring GetLocalizedString(const std::string& key);
    };

    // ==================== الثوابت ====================

    constexpr int WINDOW_WIDTH = 1000;
    constexpr int WINDOW_HEIGHT = 700;
    constexpr int SIDEBAR_WIDTH = 200;
    constexpr int HEADER_HEIGHT = 60;

    constexpr int ID_BUTTON_QUICKSCAN = 1001;
    constexpr int ID_BUTTON_FULLSCAN = 1002;
    constexpr int ID_BUTTON_CUSTOMSCAN = 1003;
    constexpr int ID_BUTTON_STOPSCAN = 1004;
    constexpr int ID_LIST_SCANRESULTS = 1005;
    constexpr int ID_LIST_QUARANTINE = 1006;
    constexpr int ID_BUTTON_RESTORE = 1007;
    constexpr int ID_BUTTON_DELETE = 1008;
    constexpr int ID_TAB_CONTROL = 1009;

    // ==================== التنفيذ (Implementation) ====================

    MainWindow::MainWindow()
        : m_hInstance(NULL)
        , m_hWnd(NULL)
        , m_hPipe(INVALID_HANDLE_VALUE)
        , m_bgColor(RGB(32, 32, 32))
        , m_textColor(RGB(255, 255, 255)) {
    }

    MainWindow::~MainWindow() {
        Shutdown();
    }

    bool MainWindow::Initialize(HINSTANCE hInstance, int nCmdShow) {
        m_hInstance = hInstance;

        // تهيئة Common Controls
        INITCOMMONCONTROLSEX iccex;
        iccex.dwSize = sizeof(iccex);
        iccex.dwICC = ICC_STANDARD_CLASSES | ICC_TAB_CLASSES;
        InitCommonControlsEx(&iccex);

        // تسجيل فئة النافذة
        if (!RegisterWindowClass()) {
            return false;
        }

        // إنشاء النافذة
        std::wstring className = L"AI_Antivirus_MainWindow";
        std::wstring title = L"AI Antivirus - الحماية الذكية";

        DWORD style = WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME;

        m_hWnd = CreateWindowExW(
            WS_EX_NOREDIRECTIONBITMAP | WS_EX_COMPOSITED,
            className.c_str(),
            title.c_str(),
            style,
            CW_USEDEFAULT, CW_USEDEFAULT,
            WINDOW_WIDTH, WINDOW_HEIGHT,
            NULL, NULL, hInstance, this
        );

        if (!m_hWnd) {
            return false;
        }

        // تطبيق Dark Mode
        ApplyDarkMode();

        // إنشاء UI
        if (!CreateUI()) {
            return false;
        }

        // بدء IPC Thread
        m_ipcThread = std::thread(&MainWindow::IPCThreadFunc, this);

        // إظهار النافذة
        ShowWindow(m_hWnd, m_config.startMinimized ? SW_MINIMIZE : nCmdShow);
        UpdateWindow(m_hWnd);

        m_running = true;
        return true;
    }

    bool MainWindow::RegisterWindowClass() {
        WNDCLASSEXW wcex = { 0 };
        wcex.cbSize = sizeof(wcex);
        wcex.style = CS_HREDRAW | CS_VREDRAW;
        wcex.lpfnWndProc = WindowProc;
        wcex.cbClsExtra = 0;
        wcex.cbWndExtra = 0;
        wcex.hInstance = m_hInstance;
        wcex.hIcon = LoadIcon(NULL, IDI_SHIELD);
        wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
        wcex.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
        wcex.lpszMenuName = NULL;
        wcex.lpszClassName = L"AI_Antivirus_MainWindow";
        wcex.hIconSm = LoadIcon(NULL, IDI_SHIELD);

        return RegisterClassExW(&wcex) != 0;
    }

    bool MainWindow::CreateUI() {
        // إنشاء Fonts
        m_hFontRegular = CreateAppFont(10, false);
        m_hFontBold = CreateAppFont(10, true);
        m_hFontLarge = CreateAppFont(24, true);

        // إنشاء Tab Control
        RECT rcClient;
        GetClientRect(m_hWnd, &rcClient);

        m_hWndTabControl = CreateWindowExW(
            0, WC_TABCONTROLW, NULL,
            WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE | TCS_OWNERDRAWFIXED,
            0, 0, rcClient.right, rcClient.bottom,
            m_hWnd, (HMENU)ID_TAB_CONTROL, m_hInstance, NULL
        );

        if (!m_hWndTabControl) return false;

        // إضافة Tabs
        TCITEM tie;
        tie.mask = TCIF_TEXT;

        std::wstring tabs[] = { L"الرئيسية", L"الفحص", L"الحجر", L"الإعدادات", L"السجلات" };
        for (int i = 0; i < 5; i++) {
            tie.pszText = const_cast<LPWSTR>(tabs[i].c_str());
            TabCtrl_InsertItem(m_hWndTabControl, i, &tie);
        }

        // إنشاء الصفحات
        CreateDashboardPage();
        CreateScanPage();
        CreateQuarantinePage();
        CreateSettingsPage();
        CreateLogsPage();

        // إنشاء Status Bar
        m_hWndStatusBar = CreateWindowExW(
            0, STATUSCLASSNAMEW, NULL,
            WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
            0, 0, 0, 0,
            m_hWnd, NULL, m_hInstance, NULL
        );

        UpdateStatusBar();

        return true;
    }

    void MainWindow::CreateDashboardPage() {
        RECT rc;
        GetClientRect(m_hWndTabControl, &rc);
        TabCtrl_AdjustRect(m_hWndTabControl, FALSE, &rc);

        m_hDashboardPage = CreateWindowExW(
            WS_EX_CONTROLPARENT, L"STATIC", NULL,
            WS_CHILD | WS_VISIBLE,
            rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
            m_hWndTabControl, NULL, m_hInstance, NULL
        );

        // سيتم الرسم في OnPaint/DrawDashboard
    }

    void MainWindow::CreateScanPage() {
        RECT rc;
        GetClientRect(m_hWndTabControl, &rc);
        TabCtrl_AdjustRect(m_hWndTabControl, FALSE, &rc);

        m_hScanPage = CreateWindowExW(
            WS_EX_CONTROLPARENT, L"STATIC", NULL,
            WS_CHILD,
            rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
            m_hWndTabControl, NULL, m_hInstance, NULL
        );

        // أزرار الفحص
        CreateWindowW(L"BUTTON", L"فحص سريع",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            50, 50, 150, 40,
            m_hScanPage, (HMENU)ID_BUTTON_QUICKSCAN, m_hInstance, NULL);

        CreateWindowW(L"BUTTON", L"فحص كامل",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            220, 50, 150, 40,
            m_hScanPage, (HMENU)ID_BUTTON_FULLSCAN, m_hInstance, NULL);

        CreateWindowW(L"BUTTON", L"فحص مخصص...",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            390, 50, 150, 40,
            m_hScanPage, (HMENU)ID_BUTTON_CUSTOMSCAN, m_hInstance, NULL);

        CreateWindowW(L"BUTTON", L"إيقاف",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
            560, 50, 100, 40,
            m_hScanPage, (HMENU)ID_BUTTON_STOPSCAN, m_hInstance, NULL);

        // قائمة النتائج
        m_hScanResultsList = CreateWindowExW(
            WS_EX_CLIENTEDGE, WC_LISTVIEWW, NULL,
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
            50, 120, rc.right - rc.left - 100, rc.bottom - rc.top - 180,
            m_hScanPage, (HMENU)ID_LIST_SCANRESULTS, m_hInstance, NULL
        );

        // إعداد أعمدة القائمة
        LVCOLUMN lvc;
        lvc.mask = LVCF_TEXT | LVCF_WIDTH;

        lvc.pszText = const_cast<LPWSTR>(L"الملف");
        lvc.cx = 300;
        ListView_InsertColumn(m_hScanResultsList, 0, &lvc);

        lvc.pszText = const_cast<LPWSTR>(L"التهديد");
        lvc.cx = 200;
        ListView_InsertColumn(m_hScanResultsList, 1, &lvc);

        lvc.pszText = const_cast<LPWSTR>(L"الثقة");
        lvc.cx = 100;
        ListView_InsertColumn(m_hScanResultsList, 2, &lvc);
    }

    void MainWindow::CreateQuarantinePage() {
        RECT rc;
        GetClientRect(m_hWndTabControl, &rc);
        TabCtrl_AdjustRect(m_hWndTabControl, FALSE, &rc);

        m_hQuarantinePage = CreateWindowExW(
            WS_EX_CONTROLPARENT, L"STATIC", NULL,
            WS_CHILD,
            rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
            m_hWndTabControl, NULL, m_hInstance, NULL
        );

        // قائمة الملفات المعزولة
        m_hQuarantineList = CreateWindowExW(
            WS_EX_CLIENTEDGE, WC_LISTVIEWW, NULL,
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
            50, 50, rc.right - rc.left - 100, rc.bottom - rc.top - 150,
            m_hQuarantinePage, (HMENU)ID_LIST_QUARANTINE, m_hInstance, NULL
        );

        // أعمدة
        LVCOLUMN lvc;
        lvc.mask = LVCF_TEXT | LVCF_WIDTH;

        lvc.pszText = const_cast<LPWSTR>(L"اسم الملف");
        lvc.cx = 200;
        ListView_InsertColumn(m_hQuarantineList, 0, &lvc);

        lvc.pszText = const_cast<LPWSTR>(L"التهديد");
        lvc.cx = 150;
        ListView_InsertColumn(m_hQuarantineList, 1, &lvc);

        lvc.pszText = const_cast<LPWSTR>(L"تاريخ العزل");
        lvc.cx = 150;
        ListView_InsertColumn(m_hQuarantineList, 2, &lvc);

        // أزرار
        CreateWindowW(L"BUTTON", L"استعادة",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            50, rc.bottom - rc.top - 80, 120, 35,
            m_hQuarantinePage, (HMENU)ID_BUTTON_RESTORE, m_hInstance, NULL);

        CreateWindowW(L"BUTTON", L"حذف نهائي",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            190, rc.bottom - rc.top - 80, 120, 35,
            m_hQuarantinePage, (HMENU)ID_BUTTON_DELETE, m_hInstance, NULL);
    }

    void MainWindow::CreateSettingsPage() {
        RECT rc;
        GetClientRect(m_hWndTabControl, &rc);
        TabCtrl_AdjustRect(m_hWndTabControl, FALSE, &rc);

        m_hSettingsPage = CreateWindowExW(
            WS_EX_CONTROLPARENT, L"STATIC", NULL,
            WS_CHILD,
            rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
            m_hWndTabControl, NULL, m_hInstance, NULL
        );

        // Checkboxes للإعدادات
        CreateWindowW(L"BUTTON", L"الحماية اللحظية",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            50, 50, 200, 20,
            m_hSettingsPage, NULL, m_hInstance, NULL);

        CreateWindowW(L"BUTTON", L"الحماية السلوكية",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            50, 80, 200, 20,
            m_hSettingsPage, NULL, m_hInstance, NULL);

        CreateWindowW(L"BUTTON", L"الحماية بالذكاء الاصطناعي",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            50, 110, 200, 20,
            m_hSettingsPage, NULL, m_hInstance, NULL);
    }

    void MainWindow::CreateLogsPage() {
        RECT rc;
        GetClientRect(m_hWndTabControl, &rc);
        TabCtrl_AdjustRect(m_hWndTabControl, FALSE, &rc);

        m_hLogsPage = CreateWindowExW(
            WS_EX_CONTROLPARENT, L"EDIT", NULL,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE |
            ES_READONLY | ES_AUTOVSCROLL,
            rc.left + 20, rc.top + 20,
            rc.right - rc.left - 40, rc.bottom - rc.top - 40,
            m_hWndTabControl, NULL, m_hInstance, NULL
        );

        // تعيين Font monospace للسجلات
        HFONT hMonoFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
            FIXED_PITCH | FF_MODERN, L"Consolas");
        SendMessage(m_hLogsPage, WM_SETFONT, (WPARAM)hMonoFont, TRUE);
    }

    void MainWindow::DrawDashboard(HDC hdc, const RECT& rect) {
        // رسم خلفية
        FillRect(hdc, &rect, m_hBgBrush);

        // عنوان
        SetTextColor(hdc, m_textColor);
        SetBkMode(hdc, TRANSPARENT);
        SelectObject(hdc, m_hFontLarge);

        std::wstring title = L"حالة الحماية";
        TextOutW(hdc, rect.left + 50, rect.top + 30, title.c_str(), title.length());

        // دائرة الحالة
        int circleX = rect.left + 150;
        int circleY = rect.top + 150;
        int circleRadius = 80;

        DrawStatusCircle(hdc, circleX, circleY, circleRadius, m_dashboardInfo.status);

        // نص الحالة
        SelectObject(hdc, m_hFontBold);
        std::wstring statusText = std::wstring(m_dashboardInfo.statusText.begin(),
            m_dashboardInfo.statusText.end());
        TextOutW(hdc, circleX - 50, circleY + circleRadius + 20,
            statusText.c_str(), statusText.length());

        // إحصائيات
        SelectObject(hdc, m_hFontRegular);
        int y = rect.top + 300;

        std::wstringstream ss;
        ss << L"الملفات المفحوصة: " << m_dashboardInfo.filesScanned;
        TextOutW(hdc, rect.left + 50, y, ss.str().c_str(), ss.str().length());

        y += 30;
        ss.str(L"");
        ss << L"التهديدات المحجوبة: " << m_dashboardInfo.threatsBlocked;
        TextOutW(hdc, rect.left + 50, y, ss.str().c_str(), ss.str().length());

        y += 30;
        ss.str(L"");
        ss << L"الملفات المعزولة: " << m_dashboardInfo.filesQuarantined;
        TextOutW(hdc, rect.left + 50, y, ss.str().c_str(), ss.str().length());

        // أزرار سريعة
        RECT btnRect = { rect.right - 200, rect.top + 100, rect.right - 50, rect.top + 140 };
        DrawCustomButton(hdc, btnRect, L"فحص الآن", false);

        btnRect.top += 60; btnRect.bottom += 60;
        DrawCustomButton(hdc, btnRect, L"تحديث", false);
    }

    void MainWindow::DrawStatusCircle(HDC hdc, int x, int y, int radius,
        ProtectionStatus status) {
        COLORREF color;
        switch (status) {
        case ProtectionStatus::SECURE: color = RGB(0, 200, 0); break;
        case ProtectionStatus::WARNING: color = RGB(255, 200, 0); break;
        case ProtectionStatus::THREAT_DETECTED: color = RGB(255, 0, 0); break;
        case ProtectionStatus::DISABLED: color = RGB(128, 128, 128); break;
        default: color = RGB(100, 100, 100);
        }

        // رسم الدائرة
        HBRUSH hBrush = CreateSolidBrush(color);
        HPEN hPen = CreatePen(PS_SOLID, 3, color);

        HGDIOBJ oldBrush = SelectObject(hdc, hBrush);
        HGDIOBJ oldPen = SelectObject(hdc, hPen);

        Ellipse(hdc, x - radius, y - radius, x + radius, y + radius);

        SelectObject(hdc, oldBrush);
        SelectObject(hdc, oldPen);

        DeleteObject(hBrush);
        DeleteObject(hPen);

        // أيقونة داخل الدائرة
        SelectObject(hdc, m_hFontLarge);
        SetTextColor(hdc, RGB(255, 255, 255));

        std::wstring icon = (status == ProtectionStatus::SECURE) ? L"✓" : L"!";
        int tw = LOWORD(GetTextExtentPoint32W(hdc, icon.c_str(), icon.length()));
        TextOutW(hdc, x - tw / 2, y - 15, icon.c_str(), icon.length());
    }

    void MainWindow::DrawCustomButton(HDC hdc, const RECT& rect,
        const std::wstring& text, bool hovered) {
        COLORREF bgColor = hovered ? RGB(0, 100, 200) : m_config.accentColor;
        COLORREF borderColor = RGB(255, 255, 255);

        // خلفية
        HBRUSH hBrush = CreateSolidBrush(bgColor);
        FillRect(hdc, &rect, hBrush);
        DeleteObject(hBrush);

        // حدود
        HPEN hPen = CreatePen(PS_SOLID, 1, borderColor);
        HGDIOBJ oldPen = SelectObject(hdc, hPen);
        SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Rectangle(hdc, rect.left, rect.top, rect.right, rect.bottom);
        SelectObject(hdc, oldPen);
        DeleteObject(hPen);

        // نص
        SetTextColor(hdc, RGB(255, 255, 255));
        SetBkMode(hdc, TRANSPARENT);
        SelectObject(hdc, m_hFontBold);

        int tw = LOWORD(GetTextExtentPoint32W(hdc, text.c_str(), text.length()));
        int th = HIWORD(GetTextExtentPoint32W(hdc, text.c_str(), text.length()));

        int tx = rect.left + (rect.right - rect.left - tw) / 2;
        int ty = rect.top + (rect.bottom - rect.top - th) / 2;

        TextOutW(hdc, tx, ty, text.c_str(), text.length());
    }

    void MainWindow::IPCThreadFunc() {
        while (m_running) {
            if (m_serviceStatus == ServiceStatus::DISCONNECTED) {
                if (ConnectToPipe()) {
                    SetServiceStatus(ServiceStatus::CONNECTED);
                }
                else {
                    SetServiceStatus(ServiceStatus::ERROR);
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    continue;
                }
            }

            // استقبال الرسائل
            IPCMessage msg;
            if (ReceiveIPCMessage(msg)) {
                HandleIPCMessage(msg);
            }
            else {
                // فقد الاتصال
                CloseHandle(m_hPipe);
                m_hPipe = INVALID_HANDLE_VALUE;
                SetServiceStatus(ServiceStatus::DISCONNECTED);
            }
        }
    }

    bool MainWindow::ConnectToPipe() {
        m_hPipe = CreateFileW(
            L"\\\\.\\pipe\\SmartAV_Service",
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL
        );

        if (m_hPipe != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_MESSAGE;
            SetNamedPipeHandleState(m_hPipe, &mode, NULL, NULL);
            return true;
        }

        return false;
    }

    bool MainWindow::SendIPCMessage(const IPCMessage& msg) {
        std::lock_guard<std::mutex> lock(m_ipcMutex);

        if (m_hPipe == INVALID_HANDLE_VALUE) return false;

        DWORD written;
        // Send header
        if (!WriteFile(m_hPipe, &msg.command, sizeof(msg.command), &written, NULL))
            return false;
        if (!WriteFile(m_hPipe, &msg.dataSize, sizeof(msg.dataSize), &written, NULL))
            return false;

        // Send data
        if (msg.dataSize > 0 && !msg.data.empty()) {
            if (!WriteFile(m_hPipe, msg.data.data(), msg.dataSize, &written, NULL))
                return false;
        }

        return true;
    }

    void MainWindow::OnQuickScan() {
        IPCMessage msg;
        msg.command = IPCCommand::START_QUICK_SCAN;
        msg.dataSize = 0;

        if (SendIPCMessage(msg)) {
            ShowNotification(L"الفحص", L"بدأ الفحص السريع...");
        }
    }

    void MainWindow::OnFullScan() {
        IPCMessage msg;
        msg.command = IPCCommand::START_FULL_SCAN;
        msg.dataSize = 0;

        if (SendIPCMessage(msg)) {
            ShowNotification(L"الفحص", L"بدأ الفحص الكامل...");
        }
    }

    void MainWindow::SetServiceStatus(ServiceStatus status) {
        m_serviceStatus = status;
        UpdateStatusBar();
    }

    void MainWindow::UpdateStatusBar() {
        if (!m_hWndStatusBar) return;

        std::wstring text;
        switch (m_serviceStatus) {
        case ServiceStatus::CONNECTED:
            text = L"متصل بالخدمة | Protection Active";
            break;
        case ServiceStatus::DISCONNECTED:
            text = L"غير متصل | Protection Inactive";
            break;
        case ServiceStatus::CONNECTING:
            text = L"جاري الاتصال...";
            break;
        case ServiceStatus::ERROR:
            text = L"خطأ في الاتصال";
            break;
        }

        SendMessage(m_hWndStatusBar, SB_SETTEXT, 0, (LPARAM)text.c_str());
    }

    void MainWindow::ShowNotification(const std::wstring& title,
        const std::wstring& message,
        bool isWarning) {
        // استخدام Windows Toast Notifications (Stub)
        // أو MessageBox بسيط
        MessageBoxW(m_hWnd, message.c_str(), title.c_str(),
            isWarning ? MB_ICONWARNING : MB_ICONINFORMATION);
    }

    LRESULT CALLBACK MainWindow::WindowProc(HWND hWnd, UINT message,
        WPARAM wParam, LPARAM lParam) {
        MainWindow* pThis = nullptr;

        if (message == WM_CREATE) {
            CREATESTRUCT* pCreate = reinterpret_cast<CREATESTRUCT*>(lParam);
            pThis = reinterpret_cast<MainWindow*>(pCreate->lpCreateParams);
            SetWindowLongPtr(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
        }
        else {
            pThis = reinterpret_cast<MainWindow*>(GetWindowLongPtr(hWnd, GWLP_USERDATA));
        }

        if (pThis) {
            return pThis->HandleMessage(message, wParam, lParam);
        }

        return DefWindowProc(hWnd, message, wParam, lParam);
    }

    LRESULT MainWindow::HandleMessage(UINT message, WPARAM wParam, LPARAM lParam) {
        switch (message) {
        case WM_PAINT:
            OnPaint();
            return 0;

        case WM_SIZE:
            OnResize();
            return 0;

        case WM_COMMAND:
            OnCommand(LOWORD(wParam));
            return 0;

        case WM_NOTIFY: {
            LPNMHDR pnmh = reinterpret_cast<LPNMHDR>(lParam);
            if (pnmh->idFrom == ID_TAB_CONTROL && pnmh->code == TCN_SELCHANGE) {
                int page = TabCtrl_GetCurSel(m_hWndTabControl);
                SwitchToPage(page);
            }
            return 0;
        }

        case WM_DRAWITEM: {
            // Custom drawing for tabs and buttons
            return 0;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        case WM_CLOSE:
            if (m_config.showNotifications) {
                // Minimize to tray instead of closing
                ShowWindow(m_hWnd, SW_MINIMIZE);
                return 0;
            }
            break;
        }

        return DefWindowProc(m_hWnd, message, wParam, lParam);
    }

    void MainWindow::OnPaint() {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(m_hWnd, &ps);

        // Get current page
        int page = TabCtrl_GetCurSel(m_hWndTabControl);

        if (page == 0) { // Dashboard
            RECT rc;
            GetClientRect(m_hDashboardPage, &rc);
            DrawDashboard(hdc, rc);
        }

        EndPaint(m_hWnd, &ps);
    }

    void MainWindow::OnResize() {
        RECT rc;
        GetClientRect(m_hWnd, &rc);

        // Resize tab control
        SetWindowPos(m_hWndTabControl, NULL, 0, 0, rc.right, rc.bottom - 25,
            SWP_NOZORDER);

        // Resize status bar
        SendMessage(m_hWndStatusBar, WM_SIZE, 0, 0);

        // Update pages
        RECT rcTab;
        GetClientRect(m_hWndTabControl, &rcTab);
        TabCtrl_AdjustRect(m_hWndTabControl, FALSE, &rcTab);

        SetWindowPos(m_hDashboardPage, NULL, rcTab.left, rcTab.top,
            rcTab.right - rcTab.left, rcTab.bottom - rcTab.top,
            SWP_NOZORDER);
        SetWindowPos(m_hScanPage, NULL, rcTab.left, rcTab.top,
            rcTab.right - rcTab.left, rcTab.bottom - rcTab.top,
            SWP_NOZORDER);
        SetWindowPos(m_hQuarantinePage, NULL, rcTab.left, rcTab.top,
            rcTab.right - rcTab.left, rcTab.bottom - rcTab.top,
            SWP_NOZORDER);
    }

    void MainWindow::OnCommand(int id) {
        switch (id) {
        case ID_BUTTON_QUICKSCAN: OnQuickScan(); break;
        case ID_BUTTON_FULLSCAN: OnFullScan(); break;
        case ID_BUTTON_CUSTOMSCAN: /* TODO */ break;
        case ID_BUTTON_STOPSCAN: OnStopScan(); break;
        case ID_BUTTON_RESTORE: OnRestoreFile(); break;
        case ID_BUTTON_DELETE: OnDeleteFile(); break;
        }
    }

    void MainWindow::SwitchToPage(int pageIndex) {
        ShowWindow(m_hDashboardPage, SW_HIDE);
        ShowWindow(m_hScanPage, SW_HIDE);
        ShowWindow(m_hQuarantinePage, SW_HIDE);
        ShowWindow(m_hSettingsPage, SW_HIDE);
        ShowWindow(m_hLogsPage, SW_HIDE);

        switch (pageIndex) {
        case 0: ShowWindow(m_hDashboardPage, SW_SHOW); break;
        case 1: ShowWindow(m_hScanPage, SW_SHOW); break;
        case 2: ShowWindow(m_hQuarantinePage, SW_SHOW); break;
        case 3: ShowWindow(m_hSettingsPage, SW_SHOW); break;
        case 4: ShowWindow(m_hLogsPage, SW_SHOW); break;
        }

        InvalidateRect(m_hWnd, NULL, TRUE);
    }

    void MainWindow::ApplyDarkMode() {
        // تفعيل Dark Mode لـ Windows 10/11
        BOOL darkMode = TRUE;
        DwmSetWindowAttribute(m_hWnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
            &darkMode, sizeof(darkMode));

        // خلفية النافذة
        m_hBgBrush = CreateSolidBrush(m_bgColor);
    }

    HFONT MainWindow::CreateAppFont(int size, bool bold) {
        return CreateFontW(size * 2, 0, 0, 0, bold ? FW_BOLD : FW_NORMAL,
            FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS,
            L"Segoe UI");
    }

    int MainWindow::Run() {
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        return static_cast<int>(msg.wParam);
    }

    void MainWindow::Shutdown() {
        m_running = false;

        if (m_ipcThread.joinable()) {
            m_ipcThread.join();
        }

        if (m_hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(m_hPipe);
        }

        DestroyWindow(m_hWnd);
    }

} // namespace AIAntivirus