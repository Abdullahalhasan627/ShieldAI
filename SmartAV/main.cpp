/**
 * main.cpp
 *
 * نقطة الدخول الرئيسية - Application Entry Point
 *
 * المسؤوليات:
 * - تحديد وضع التشغيل (Service vs GUI) بناءً على Arguments
 * - تهيئة البنية التحتية المشتركة (Logging, Config, etc.)
 * - توجيه التنفيذ إلى الوحدة المناسبة
 * - معالجة الأخطاء العامة والاستثناءات
 * - إدارة دورة حياة التطبيق بالكامل
 *
 * أوضاع التشغيل:
 * 1. --service    : تشغيل كـ Windows Service (في الخلفية)
 * 2. --gui        : تشغيل واجهة المستخدم (افتراضي إذا لم يُحدد)
 * 3. --install    : تثبيت الخدمة
 * 4. --uninstall  : إلغاء تثبيت الخدمة
 * 5. --console    : تشغيل كـ Console App (للتصحيح)
 * 6. --help       : عرض المساعدة
 *
 * متطلبات: C++17, Windows 10/11, Visual Studio 2022
 */

#include <windows.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <exception>
#include <memory>

 // تضمين الوحدات
#include "Service/ServiceModule.h"
#include "UI/MainWindow.h"
#include "Security/SelfProtection.h"

#pragma comment(lib, "shell32.lib")

// ==================== الإعدادات العامة ====================

namespace AIAntivirus {

    /**
     * إعدادات التطبيق العامة
     */
    struct ApplicationConfig {
        std::wstring appName = L"AI Antivirus";
        std::wstring version = L"1.0.0";
        std::wstring company = L"AI Security Solutions";

        // المسارات
        std::wstring installDir = L"C:\\Program Files\\AIAntivirus\\";
        std::wstring dataDir = L"C:\\ProgramData\\AIAntivirus\\";
        std::wstring logDir = L"C:\\ProgramData\\AIAntivirus\\Logs\\";
        std::wstring configFile = L"C:\\ProgramData\\AIAntivirus\\config.ini";

        // إعدادات الخدمة
        std::wstring serviceName = L"SmartAVService";
        std::wstring serviceDisplayName = L"AI Antivirus Service";
        std::wstring pipeName = L"\\\\.\\pipe\\SmartAV_Service";

        // إعدادات UI
        bool startMinimized = false;
        bool autoStartGUI = true;
        std::string language = "ar";
    };

    /**
     * مدير التطبيق الرئيسي
     */
    class Application {
    public:
        static Application& GetInstance() {
            static Application instance;
            return instance;
        }

        Application(const Application&) = delete;
        Application& operator=(const Application&) = delete;

        /**
         * نقطة الدخول الرئيسية
         */
        int Run(HINSTANCE hInstance, int nCmdShow, const std::vector<std::wstring>& args);

        /**
         * الحصول على الإعدادات
         */
        ApplicationConfig& GetConfig() { return m_config; }

        /**
         * إيقاف التطبيق
         */
        void Shutdown(int exitCode = 0);

        /**
         * التحقق من وجود خدمة عاملة
         */
        bool IsServiceRunning();

        /**
         * الحصول على مسار التنفيذي
         */
        std::wstring GetExecutablePath() const;

        /**
         * الحصول على مجلد التثبيت
         */
        std::wstring GetInstallDirectory() const;

    private:
        Application() = default;
        ~Application() = default;

        ApplicationConfig m_config;
        HINSTANCE m_hInstance;
        int m_exitCode = 0;
        bool m_running = false;

        // ==================== أوضاع التشغيل ====================

        int RunAsService();
        int RunAsGUI(int nCmdShow);
        int RunAsConsole();
        int InstallService();
        int UninstallService();
        int ShowHelp();

        // ==================== وظائف مساعدة ====================

        bool ParseArguments(const std::vector<std::wstring>& args);
        bool InitializeLogging();
        bool CheckPrivileges();
        void SetupCrashHandler();
        void LogStartupInfo();

        /**
         * عرض رسالة خطأ
         */
        void ShowError(const std::wstring& title, const std::wstring& message);

        /**
         * عرض رسالة معلومات
         */
        void ShowInfo(const std::wstring& title, const std::wstring& message);
    };

    // ==================== Implementation ====================

    int Application::Run(HINSTANCE hInstance, int nCmdShow,
        const std::vector<std::wstring>& args) {
        m_hInstance = hInstance;
        m_running = true;

        try {
            // إعداد معالج الأعطال
            SetupCrashHandler();

            // تهيئة التسجيل
            InitializeLogging();

            // تسجيل بدء التشغيل
            LogStartupInfo();

            // تحليل Arguments
            if (!ParseArguments(args)) {
                return ShowHelp();
            }

            // التحقق من الصلاحيات عند الحاجة
            if (args.empty() || (args.size() == 1 && args[0].find(L"--") != 0)) {
                // وضع GUI الافتراضي - تحقق من وجود خدمة
                if (!IsServiceRunning() && m_config.autoStartGUI) {
                    // محاولة تشغيل الخدمة أو الانتقال إلى وضع محدود
                    ShowInfo(L"تنبيه",
                        L"الخدمة غير نشطة. بعض الميزات قد لا تعمل.\n"
                        L"يرجى تشغيل الخدمة كمسؤول: --install ثم net start SmartAVService");
                }
            }

            // توجيه التنفيذ حسب الوضع
            if (args.empty()) {
                // افتراضي: GUI
                return RunAsGUI(nCmdShow);
            }

            const std::wstring& mode = args[0];

            if (mode == L"--service") {
                return RunAsService();
            }
            else if (mode == L"--gui") {
                return RunAsGUI(nCmdShow);
            }
            else if (mode == L"--console") {
                return RunAsConsole();
            }
            else if (mode == L"--install") {
                return InstallService();
            }
            else if (mode == L"--uninstall") {
                return UninstallService();
            }
            else if (mode == L"--help" || mode == L"/?" || mode == L"-h") {
                return ShowHelp();
            }
            else {
                std::wcerr << L"Unknown argument: " << mode << std::endl;
                return ShowHelp();
            }
        }
        catch (const std::exception& e) {
            std::string error = "Fatal error: ";
            error += e.what();

            std::wstring wError(error.begin(), error.end());
            ShowError(L"خطأ فادح", wError);

            return 1;
        }
        catch (...) {
            ShowError(L"خطأ فادح", L"حدث خطأ غير معروف");
            return 1;
        }

        return m_exitCode;
    }

    int Application::RunAsService() {
        std::cout << "Starting as Windows Service..." << std::endl;

        // التحقق من الصلاحيات
        if (!CheckPrivileges()) {
            std::cerr << "Service mode requires Administrator privileges!" << std::endl;
            return 1;
        }

        // تهيئة Self-Protection فوراً
        auto& selfProtection = SelfProtection::GetInstance();
        SelfProtectionConfig spConfig;
        spConfig.protectService = true;
        spConfig.protectFiles = true;
        spConfig.antiDebugging = true;
        spConfig.autoRestart = true;

        if (!selfProtection.Initialize(spConfig)) {
            std::cerr << "Failed to initialize self-protection!" << std::endl;
            // استمرر بدون حماية ذاتية (غير مستحسن)
        }
        else {
            selfProtection.EnableProtection();
        }

        // تسجيل معالج التحكم في الخدمة
        SERVICE_TABLE_ENTRYW dispatchTable[] = {
            { const_cast<LPWSTR>(m_config.serviceName.c_str()),
              ServiceModule::ServiceMain },
            { NULL, NULL }
        };

        // هذا الاستدعاء لا يعود حتى تتوقف الخدمة
        if (!StartServiceCtrlDispatcherW(dispatchTable)) {
            DWORD error = GetLastError();

            if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
                // لم يتم تشغيله من SCM
                std::cerr << "Not running as a service. Use --console for debugging." << std::endl;
                return 1;
            }

            std::cerr << "StartServiceCtrlDispatcher failed: " << error << std::endl;
            return 1;
        }

        return 0;
    }

    int Application::RunAsGUI(int nCmdShow) {
        std::cout << "Starting GUI..." << std::endl;

        // التحقق من وجود نسخة أخرى
        HANDLE hMutex = CreateMutexW(NULL, TRUE, L"AI_Antivirus_GUI_SingleInstance");
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            // تفعيل النافذة الموجودة
            HWND hWnd = FindWindowW(L"AI_Antivirus_MainWindow", NULL);
            if (hWnd) {
                ShowWindow(hWnd, SW_RESTORE);
                SetForegroundWindow(hWnd);
            }
            return 0;
        }

        // تهيئة النافذة
        MainWindow window;
        UIConfig uiConfig;
        uiConfig.startMinimized = m_config.startMinimized;
        uiConfig.language = m_config.language;
        window.SetConfig(uiConfig);

        if (!window.Initialize(m_hInstance, nCmdShow)) {
            ShowError(L"خطأ في التشغيل", L"فشل في تهيئة واجهة المستخدم");
            return 1;
        }

        // حلقة الرسائل
        int result = window.Run();

        // تنظيف
        if (hMutex) {
            ReleaseMutex(hMutex);
            CloseHandle(hMutex);
        }

        return result;
    }

    int Application::RunAsConsole() {
        // فتح Console إذا لم يكن مفتوحاً
        if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
            AllocConsole();
        }

        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
        freopen("CONIN$", "r", stdin);

        std::cout << "========================================" << std::endl;
        std::cout << "  AI Antivirus - Console Debug Mode" << std::endl;
        std::cout << "  Version: 1.0.0" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << std::endl;

        // التحقق من الصلاحيات
        if (!CheckPrivileges()) {
            std::cout << "WARNING: Running without Administrator privileges!" << std::endl;
            std::cout << "Some features may not work correctly." << std::endl << std::endl;
        }

        // عرض قائمة الأوامر
        std::cout << "Available commands:" << std::endl;
        std::cout << "  1. start-service    - Start service components" << std::endl;
        std::cout << "  2. quick-scan       - Run quick scan" << std::endl;
        std::cout << "  3. full-scan        - Run full scan" << std::endl;
        std::cout << "  4. status           - Show protection status" << std::endl;
        std::cout << "  5. test-ai          - Test AI detection" << std::endl;
        std::cout << "  6. exit             - Exit console" << std::endl;
        std::cout << std::endl;

        // حلقة الأوامر
        std::string command;
        bool serviceStarted = false;

        while (true) {
            std::cout << "AI-AV> ";
            std::getline(std::cin, command);

            if (command == "exit" || command == "quit") {
                break;
            }
            else if (command == "start-service") {
                if (serviceStarted) {
                    std::cout << "Service already running!" << std::endl;
                    continue;
                }

                std::cout << "Initializing service components..." << std::endl;

                auto& service = ServiceModule::GetInstance();
                if (service.Initialize()) {
                    serviceStarted = true;
                    std::cout << "Service started successfully!" << std::endl;
                }
                else {
                    std::cout << "Failed to start service!" << std::endl;
                }
            }
            else if (command == "quick-scan") {
                if (!serviceStarted) {
                    std::cout << "Please start service first!" << std::endl;
                    continue;
                }

                std::cout << "Starting quick scan..." << std::endl;

                auto& service = ServiceModule::GetInstance();
                if (service.StartScan(ScanType::QUICK)) {
                    std::cout << "Quick scan started." << std::endl;

                    // انتظار النتيجة (blocking للتبسيط)
                    while (service.GetScanStatus().isScanning) {
                        std::this_thread::sleep_for(std::chrono::seconds(1));
                        std::cout << "." << std::flush;
                    }
                    std::cout << std::endl << "Scan completed!" << std::endl;
                }
            }
            else if (command == "full-scan") {
                std::cout << "Full scan would start here..." << std::endl;
            }
            else if (command == "status") {
                if (!serviceStarted) {
                    std::cout << "Service not running." << std::endl;
                }
                else {
                    auto stats = ServiceModule::GetInstance().GetStatistics();
                    std::cout << "Files scanned: " << stats.totalFilesScanned << std::endl;
                    std::cout << "Threats blocked: " << stats.totalThreatsBlocked << std::endl;
                    std::cout << "Uptime: " << stats.uptimeHours << " hours" << std::endl;
                }
            }
            else if (command == "test-ai") {
                std::cout << "Testing AI detection..." << std::endl;
                // TODO: اختبار سريع
            }
            else if (!command.empty()) {
                std::cout << "Unknown command: " << command << std::endl;
            }
        }

        // إيقاف الخدمة إذا كانت عاملة
        if (serviceStarted) {
            std::cout << "Shutting down service..." << std::endl;
            ServiceModule::GetInstance().Shutdown();
        }

        std::cout << "Goodbye!" << std::endl;

        // إغلاق Console
        FreeConsole();

        return 0;
    }

    int Application::InstallService() {
        std::cout << "Installing service..." << std::endl;

        if (!CheckPrivileges()) {
            // محاولة رفع الصلاحيات
            std::wstring exePath = GetExecutablePath();
            std::wstring params = L"--install";

            SHELLEXECUTEINFOW sei = { 0 };
            sei.cbSize = sizeof(sei);
            sei.lpVerb = L"runas"; // UAC prompt
            sei.lpFile = exePath.c_str();
            sei.lpParameters = params.c_str();
            sei.nShow = SW_NORMAL;

            if (ShellExecuteExW(&sei)) {
                return 0; // سيتم إعادة التشغيل كمسؤول
            }
            else {
                ShowError(L"خطأ", L"يتطلب التثبيت صلاحيات المسؤول");
                return 1;
            }
        }

        ServiceConfig svcConfig;
        svcConfig.serviceName = m_config.serviceName;
        svcConfig.displayName = m_config.serviceDisplayName;
        svcConfig.startType = SERVICE_AUTO_START;
        svcConfig.autoRestart = true;

        if (ServiceModule::Install(svcConfig)) {
            std::cout << "Service installed successfully!" << std::endl;
            std::cout << "Use 'net start " << std::string(m_config.serviceName.begin(),
                m_config.serviceName.end())
                << "' to start the service." << std::endl;

            ShowInfo(L"تم التثبيت",
                L"تم تثبيت الخدمة بنجاح.\n"
                L"استخدم: net start SmartAVService\n"
                L"لبدء الخدمة");
            return 0;
        }
        else {
            std::cerr << "Failed to install service!" << std::endl;
            ShowError(L"خطأ", L"فشل في تثبيت الخدمة");
            return 1;
        }
    }

    int Application::UninstallService() {
        std::cout << "Uninstalling service..." << std::endl;

        if (!CheckPrivileges()) {
            // محاولة رفع الصلاحيات
            std::wstring exePath = GetExecutablePath();
            std::wstring params = L"--uninstall";

            SHELLEXECUTEINFOW sei = { 0 };
            sei.cbSize = sizeof(sei);
            sei.lpVerb = L"runas";
            sei.lpFile = exePath.c_str();
            sei.lpParameters = params.c_str();
            sei.nShow = SW_NORMAL;

            if (ShellExecuteExW(&sei)) {
                return 0;
            }
            else {
                ShowError(L"خطأ", L"يتطلب الإلغاء صلاحيات المسؤول");
                return 1;
            }
        }

        if (ServiceModule::Uninstall(m_config.serviceName)) {
            std::cout << "Service uninstalled successfully!" << std::endl;
            ShowInfo(L"تم الإلغاء", L"تم إلغاء تثبيت الخدمة بنجاح");
            return 0;
        }
        else {
            std::cerr << "Failed to uninstall service (may not exist)!" << std::endl;
            return 1;
        }
    }

    int Application::ShowHelp() {
        const wchar_t* helpText = LR"(
AI Antivirus - نظام الحماية الذكي
=====================================

Usage: SmartAV.exe [option]

Options:
  --service      تشغيل كـ Windows Service (في الخلفية)
  --gui          تشغيل واجهة المستخدم (الافتراضي)
  --console      تشغيل وضع Console للتصحيح
  --install      تثبيت الخدمة (يحتاج Admin)
  --uninstall    إلغاء تثبيت الخدمة (يحتاج Admin)
  --help         عرض هذه المساعدة

Examples:
  SmartAV.exe                    تشغيل الواجهة
  SmartAV.exe --install          تثبيت الخدمة
  net start SmartAVService       بدء الخدمة
  SmartAV.exe --console          وضع التصحيح

For support: support@ai-antivirus.com
)";

        // إظهار في Console إذا كان متاحاً
        if (AttachConsole(ATTACH_PARENT_PROCESS) || AllocConsole()) {
            std::wcout << helpText << std::endl;
            FreeConsole();
        }
        else {
            // إظهار في MessageBox
            MessageBoxW(NULL, helpText, L"AI Antivirus - Help", MB_OK | MB_ICONINFORMATION);
        }

        return 0;
    }

    bool Application::ParseArguments(const std::vector<std::wstring>& args) {
        // TODO: تحليل إعدادات متقدمة من Arguments
        // مثل: --config path\to\config.ini
        //      --lang en
        //      --minimized

        return true;
    }

    bool Application::InitializeLogging() {
        try {
            // إنشاء مجلد Logs
            CreateDirectoryW(m_config.logDir.c_str(), NULL);

            // ملف Log رئيسي
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);

            std::wstringstream ss;
            ss << m_config.logDir << L"application_"
                << std::put_time(std::localtime(&time_t), L"%Y%m%d") << L".log";

            // TODO: إعداد نظام تسجيل أكثر تطوراً (مثل spdlog)

            return true;
        }
        catch (...) {
            return false;
        }
    }

    bool Application::CheckPrivileges() {
        BOOL elevated = FALSE;
        HANDLE hToken = NULL;

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_Elevation elevation;
            DWORD size;
            if (GetTokenInformation(hToken, TokenElevation, &elevation,
                sizeof(elevation), &size)) {
                elevated = elevation.TokenIsElevated;
            }
            CloseHandle(hToken);
        }

        return elevated == TRUE;
    }

    void Application::SetupCrashHandler() {
        // TODO: إعداد معالج أعطال شامل (Exception Handler)
        // يمكن استخدام Google Breakpad أو Crashpad
    }

    void Application::LogStartupInfo() {
        // تسجيل معلومات بدء التشغيل
        std::wstring exePath = GetExecutablePath();
        std::wstring cmdLine = GetCommandLineW();

        // TODO: كتابة في Log
    }

    void Application::ShowError(const std::wstring& title, const std::wstring& message) {
        MessageBoxW(NULL, message.c_str(), title.c_str(), MB_OK | MB_ICONERROR);
    }

    void Application::ShowInfo(const std::wstring& title, const std::wstring& message) {
        MessageBoxW(NULL, message.c_str(), title.c_str(), MB_OK | MB_ICONINFORMATION);
    }

    bool Application::IsServiceRunning() {
        SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        if (!hSCM) return false;

        SC_HANDLE hService = OpenServiceW(hSCM, m_config.serviceName.c_str(), SERVICE_QUERY_STATUS);
        if (!hService) {
            CloseServiceHandle(hSCM);
            return false;
        }

        SERVICE_STATUS status;
        BOOL result = QueryServiceStatus(hService, &status);

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);

        return result && (status.dwCurrentState == SERVICE_RUNNING);
    }

    std::wstring Application::GetExecutablePath() const {
        WCHAR path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        return path;
    }

    std::wstring Application::GetInstallDirectory() const {
        std::wstring exePath = GetExecutablePath();
        size_t pos = exePath.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            return exePath.substr(0, pos);
        }
        return exePath;
    }

    void Application::Shutdown(int exitCode) {
        m_exitCode = exitCode;
        m_running = false;
    }

} // namespace AIAntivirus

// ==================== WinMain (GUI) ====================

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPWSTR lpCmdLine, int nCmdShow) {
    UNREFERENCED_PARAMETER(hPrevInstance);

    // تحويل Command Line إلى Vector
    int argc;
    LPWSTR* argv = CommandLineToArgvW(lpCmdLine, &argc);

    std::vector<std::wstring> args;
    for (int i = 0; i < argc; i++) {
        args.push_back(argv[i]);
    }
    LocalFree(argv);

    // تشغيل التطبيق
    return AIAntivirus::Application::GetInstance().Run(hInstance, nCmdShow, args);
}

// ==================== main (Console) ====================

int wmain(int argc, wchar_t* argv[]) {
    std::vector<std::wstring> args;
    for (int i = 1; i < argc; i++) {
        args.push_back(argv[i]);
    }

    // في Console mode، نستخدم GetModuleHandle(NULL) للـ HINSTANCE
    HINSTANCE hInstance = GetModuleHandle(NULL);

    return AIAntivirus::Application::GetInstance().Run(hInstance, SW_SHOW, args);
}