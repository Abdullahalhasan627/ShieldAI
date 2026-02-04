/**
 * ServiceModule.cpp
 *
 * وحدة الخدمة الرئيسية - Windows Service Core
 *
 * المسؤوليات:
 * - التسجيل والتشغيل كـ Windows Service بصلاحيات SYSTEM
 * - إدارة دورة حياة الخدمة (Start, Stop, Pause, Continue)
 * - تهيئة وإدارة جميع المكونات (Core, AI, Security)
 * - استقبال الأوامر من الواجهة عبر Named Pipes
 * - تنفيذ الفحوصات (Quick, Full, Custom) في Threads منفصلة
 * - الحماية اللحظية (Real-Time Protection)
 * - تسجيل الأحداث في Windows Event Log
 * - إعادة التشغيل التلقائي عند الأعطال (Recovery)
 * - التواصل مع العمليات الأخرى (UI, Tray, etc.)
 *
 * هيكل الخدمة:
 * - Main Thread: Service Control Handler
 * - IPC Thread: Named Pipe Server
 * - Worker Threads: Scanning, Monitoring, Analysis
 * - Watchdog Thread: Health Monitoring
 *
 * متطلبات: C++17, Windows API, صلاحيات SYSTEM/LocalService
 */

#include <windows.h>
#include <winsvc.h>
#include <sddl.h>
#include <aclapi.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <map>
#include <memory>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <functional>
#include <algorithm>

 // تضمين المكونات
#include "../Core/FileScanner.h"
#include "../Core/RealTimeMonitor.h"
#include "../Core/ProcessAnalyzer.h"
#include "../AI/AIDetector.h"
#include "../Security/Quarantine.h"
#include "../Security/SelfProtection.h"

#pragma comment(lib, "advapi32.lib")

namespace fs = std::filesystem;

namespace AIAntivirus {

    // ==================== تعريفات الأنواع ====================

    /**
     * حالة الخدمة الداخلية
     */
    enum class ServiceState {
        STOPPED,
        STARTING,
        RUNNING,
        STOPPING,
        PAUSED,
        ERROR
    };

    /**
     * أنواع الفحوصات
     */
    enum class ScanType {
        NONE,
        QUICK,
        FULL,
        CUSTOM,
        REALTIME
    };

    /**
     * أمر من الواجهة
     */
    struct ServiceCommand {
        uint32_t commandId;
        std::vector<uint8_t> data;
        HANDLE hResponsePipe;   // Pipe للرد
    };

    /**
     * نتيجة فحص
     */
    struct ScanTask {
        ScanType type;
        std::wstring targetPath;
        std::function<void(const std::string&)> progressCallback;
        std::function<void(bool)> completionCallback;
    };

    /**
     * إعدادات الخدمة
     */
    struct ServiceConfig {
        std::wstring serviceName = L"SmartAVService";
        std::wstring displayName = L"AI Antivirus Service";
        std::wstring description = L"Core protection service with AI-powered threat detection";
        DWORD startType = SERVICE_AUTO_START;
        bool autoRestart = true;
        int restartDelaySeconds = 60;
        bool interactWithDesktop = false;
        std::wstring logPath = L"C:\\ProgramData\\AIAntivirus\\Logs\\";
        std::wstring pipeName = L"\\\\.\\pipe\\SmartAV_Service";
    };

    // ==================== IPC Protocol ====================

    enum class IPCCommand : uint32_t {
        // أوامر الفحص
        START_QUICK_SCAN = 0x1001,
        START_FULL_SCAN = 0x1002,
        START_CUSTOM_SCAN = 0x1003,
        STOP_SCAN = 0x1004,
        GET_SCAN_STATUS = 0x1005,

        // أوامر الحجر
        GET_QUARANTINE_LIST = 0x2001,
        RESTORE_FILE = 0x2002,
        DELETE_FILE = 0x2003,
        ADD_TO_QUARANTINE = 0x2004,

        // أوامر الحالة
        GET_STATUS = 0x3001,
        GET_STATISTICS = 0x3002,
        GET_LOGS = 0x3003,

        // أوامر الإعدادات
        UPDATE_SETTINGS = 0x4001,
        RELOAD_CONFIG = 0x4002,

        // أوامر التحكم
        PING = 0x5001,
        SHUTDOWN_SERVICE = 0x5002
    };

    // ==================== الفئة الرئيسية: ServiceModule ====================

    class ServiceModule {
    public:
        // ==================== Singleton ====================

        static ServiceModule& GetInstance() {
            static ServiceModule instance;
            return instance;
        }

        ServiceModule(const ServiceModule&) = delete;
        ServiceModule& operator=(const ServiceModule&) = delete;

        // ==================== Entry Points ====================

        /**
         * نقطة الدخول الرئيسية للخدمة
         */
        static void WINAPI ServiceMain(DWORD argc, LPWSTR* argv);

        /**
         * معالج التحكم في الخدمة
         */
        static void WINAPI ControlHandler(DWORD control);

        // ==================== التهيئة والتشغيل ====================

        /**
         * تسجيل الخدمة في النظام (للتثبيت)
         */
        static bool Install(const ServiceConfig& config = ServiceConfig{});

        /**
         * إلغاء تسجيل الخدمة (للإلغاء)
         */
        static bool Uninstall(const std::wstring& serviceName);

        /**
         * بدء الخدمة كـ Console App (للتصحيح)
         */
        bool RunAsConsole();

        /**
         * تهيئة الخدمة
         */
        bool Initialize();

        /**
         * إيقاف الخدمة
         */
        void Shutdown();

        // ==================== واجهة الأوامر ====================

        /**
         * إرسال أمر للتنفيذ
         */
        bool ExecuteCommand(const ServiceCommand& cmd);

        /**
         * بدء فحص
         */
        bool StartScan(ScanType type, const std::wstring& path = L"");

        /**
         * إيقاف الفحص الحالي
         */
        bool StopScan();

        /**
         * الحصول على حالة الفحص
         */
        struct ScanStatus {
            bool isScanning;
            ScanType currentType;
            std::wstring currentFile;
            size_t filesScanned;
            size_t totalFiles;
            size_t threatsFound;
            double progressPercent;
        };
        ScanStatus GetScanStatus() const;

        // ==================== واجهة الاستعلام ====================

        /**
         * الحصول على إحصائيات الحماية
         */
        struct ProtectionStats {
            uint64_t totalFilesScanned;
            uint64_t totalThreatsBlocked;
            uint64_t totalFilesQuarantined;
            uint64_t totalProcessesAnalyzed;
            std::chrono::system_clock::time_point serviceStartTime;
            double uptimeHours;
        };
        ProtectionStats GetStatistics() const;

        /**
         * الحصول على السجلات
         */
        std::vector<std::string> GetLogs(int count = 100);

        // ==================== الإعدادات ====================

        void SetConfig(const ServiceConfig& config) { m_config = config; }
        ServiceConfig GetConfig() const { return m_config; }

    private:
        // ==================== الأعضاء الخاصة ====================

        ServiceModule() = default;
        ~ServiceModule() { Shutdown(); }

        // Service Handles
        SERVICE_STATUS m_serviceStatus;
        SERVICE_STATUS_HANDLE m_statusHandle = NULL;

        // الحالة
        std::atomic<ServiceState> m_state{ ServiceState::STOPPED };
        ServiceConfig m_config;

        // المكونات
        std::unique_ptr<FileScanner> m_fileScanner;
        std::unique_ptr<RealTimeMonitor> m_realTimeMonitor;
        std::unique_ptr<ProcessAnalyzer> m_processAnalyzer;
        std::unique_ptr<AIDetector> m_aiDetector;
        std::unique_ptr<QuarantineManager> m_quarantineManager;
        std::unique_ptr<SelfProtection> m_selfProtection;

        // Threads
        std::thread m_ipcThread;
        std::thread m_scanThread;
        std::thread m_watchdogThread;
        std::vector<std::thread> m_workerThreads;

        // التزامن
        std::mutex m_commandMutex;
        std::condition_variable m_commandCV;
        std::queue<ServiceCommand> m_commandQueue;

        std::mutex m_scanMutex;
        std::atomic<bool> m_scanRunning{ false };
        ScanTask m_currentScan;

        // IPC
        HANDLE m_hStopEvent = NULL;
        HANDLE m_hPipe = INVALID_HANDLE_VALUE;

        // الإحصائيات
        mutable std::mutex m_statsMutex;
        ProtectionStats m_stats{};

        // ==================== وظائف الخدمة ====================

        /**
         * تحديث حالة الخدمة لـ SCM
         */
        void SetServiceStatus(DWORD state, DWORD exitCode = 0, DWORD waitHint = 0);

        /**
         * إعداد معالج التحكم
         */
        void SetupControlHandler();

        /**
         * تهيئة جميع المكونات
         */
        bool InitializeComponents();

        /**
         * إيقاف جميع المكونات
         */
        void ShutdownComponents();

        // ==================== IPC Communication ====================

        /**
         * Thread خادم الـ Named Pipe
         */
        void IPCServerThread();

        /**
         * إنشاء Pipe
         */
        bool CreateIPCPipe();

        /**
         * معالجة اتصال عميل
         */
        void HandleClientConnection(HANDLE hPipe);

        /**
         * قراءة رسالة
         */
        bool ReadIPCMessage(HANDLE hPipe, ServiceCommand& cmd);

        /**
         * إرسال رد
         */
        bool SendIPCResponse(HANDLE hPipe, const std::vector<uint8_t>& data);

        /**
         * تنفيذ أمر
         */
        void ProcessCommand(const ServiceCommand& cmd);

        // ==================== معالجة الأوامر ====================

        void OnStartQuickScan(HANDLE hResponsePipe);
        void OnStartFullScan(HANDLE hResponsePipe);
        void OnStartCustomScan(const std::wstring& path, HANDLE hResponsePipe);
        void OnStopScan(HANDLE hResponsePipe);
        void OnGetStatus(HANDLE hResponsePipe);
        void OnGetQuarantineList(HANDLE hResponsePipe);
        void OnRestoreFile(const std::wstring& quarantineId, HANDLE hResponsePipe);
        void OnDeleteFile(const std::wstring& quarantineId, HANDLE hResponsePipe);
        void OnGetStatistics(HANDLE hResponsePipe);
        void OnUpdateSettings(const std::vector<uint8_t>& data, HANDLE hResponsePipe);
        void OnShutdown(HANDLE hResponsePipe);

        // ==================== الفحص ====================

        /**
         * Thread تنفيذ الفحص
         */
        void ScanWorkerThread();

        /**
         * تنفيذ فحص فعلي
         */
        void ExecuteScan(const ScanTask& task);

        /**
         * Callback تقدم الفحص
         */
        void OnScanProgress(const std::wstring& currentFile,
            size_t scanned, size_t total,
            const ScanReport& report);

        /**
         * Callback اكتمال الفحص
         */
        void OnScanComplete(bool success);

        // ==================== المراقبة ====================

        /**
         * Thread المراقبة (Watchdog)
         */
        void WatchdogThread();

        /**
         * التحقق من صحة المكونات
         */
        bool HealthCheck();

        // ==================== التسجيل ====================

        /**
         * تسجيل في Event Log
         */
        void LogEvent(WORD type, const std::string& message,
            DWORD eventId = 0);

        /**
         * تسجيل في ملف
         */
        void LogToFile(const std::string& message);

        // ==================== وظائف مساعدة ====================

        /**
         * التحقق من صلاحيات المسؤول
         */
        bool IsElevated() const;

        /**
         * رفع الصلاحيات إن أمكن
         */
        bool ElevatePrivileges();

        /**
         * إنشاء المجلدات اللازمة
         */
        bool CreateRequiredDirectories();

        /**
         * تحميل الإعدادات
         */
        bool LoadConfiguration();

        /**
         * حفظ الإعدادات
         */
        bool SaveConfiguration();
    };

    // ==================== Implementation ====================

    void WINAPI ServiceModule::ServiceMain(DWORD argc, LPWSTR* argv) {
        auto& service = GetInstance();

        // تهيئة الحالة
        service.m_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        service.m_serviceStatus.dwCurrentState = SERVICE_START_PENDING;
        service.m_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP |
            SERVICE_ACCEPT_PAUSE_CONTINUE |
            SERVICE_ACCEPT_SHUTDOWN;
        service.m_serviceStatus.dwWin32ExitCode = 0;
        service.m_serviceStatus.dwServiceSpecificExitCode = 0;
        service.m_serviceStatus.dwCheckPoint = 0;
        service.m_serviceStatus.dwWaitHint = 5000;

        // تسجيل معالج التحكم
        service.m_statusHandle = RegisterServiceCtrlHandlerW(
            service.m_config.serviceName.c_str(),
            ControlHandler
        );

        if (!service.m_statusHandle) {
            return;
        }

        // بدء التهيئة
        service.SetServiceStatus(SERVICE_START_PENDING, 0, 10000);

        if (!service.Initialize()) {
            service.SetServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
            return;
        }

        // التشغيل
        service.SetServiceStatus(SERVICE_RUNNING);
        service.m_state = ServiceState::RUNNING;

        // الانتظار حتى إشارة الإيقاف
        WaitForSingleObject(service.m_hStopEvent, INFINITE);

        // الإيقاف
        service.Shutdown();
        service.SetServiceStatus(SERVICE_STOPPED);
    }

    void WINAPI ServiceModule::ControlHandler(DWORD control) {
        auto& service = GetInstance();

        switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            service.SetServiceStatus(SERVICE_STOP_PENDING);
            service.m_state = ServiceState::STOPPING;
            SetEvent(service.m_hStopEvent);
            break;

        case SERVICE_CONTROL_PAUSE:
            service.SetServiceStatus(SERVICE_PAUSE_PENDING);
            service.m_state = ServiceState::PAUSED;
            // TODO: إيقاف مؤقت للمراقبة
            service.SetServiceStatus(SERVICE_PAUSED);
            break;

        case SERVICE_CONTROL_CONTINUE:
            service.SetServiceStatus(SERVICE_CONTINUE_PENDING);
            service.m_state = ServiceState::RUNNING;
            // TODO: استئناف المراقبة
            service.SetServiceStatus(SERVICE_RUNNING);
            break;

        case SERVICE_CONTROL_INTERROGATE:
            // مجرد إرجاع الحالة الحالية
            break;

        default:
            break;
        }
    }

    bool ServiceModule::Install(const ServiceConfig& config) {
        SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
        if (!hSCM) return false;

        // الحصول على مسار التنفيذي
        WCHAR path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);

        // إنشاء الخدمة
        SC_HANDLE hService = CreateServiceW(
            hSCM,
            config.serviceName.c_str(),
            config.displayName.c_str(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            config.startType,
            SERVICE_ERROR_NORMAL,
            path,
            NULL, NULL, NULL, NULL, NULL
        );

        if (!hService) {
            DWORD err = GetLastError();
            CloseServiceHandle(hSCM);
            return (err == ERROR_SERVICE_EXISTS);
        }

        // تعيين الوصف
        SERVICE_DESCRIPTIONW desc;
        desc.lpDescription = const_cast<LPWSTR>(config.description.c_str());
        ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &desc);

        // إعداد Recovery (إعادة التشغيل التلقائي)
        SC_ACTION actions[3];
        actions[0].Type = SC_ACTION_RESTART;
        actions[0].Delay = config.restartDelaySeconds * 1000;
        actions[1].Type = SC_ACTION_RESTART;
        actions[1].Delay = config.restartDelaySeconds * 1000;
        actions[2].Type = SC_ACTION_NONE;

        SERVICE_FAILURE_ACTIONSW failureActions;
        failureActions.dwResetPeriod = 86400; // 24 hours
        failureActions.lpRebootMsg = NULL;
        failureActions.lpCommand = NULL;
        failureActions.cActions = 3;
        failureActions.lpsaActions = actions;

        ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions);

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);

        return true;
    }

    bool ServiceModule::Uninstall(const std::wstring& serviceName) {
        SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        if (!hSCM) return false;

        SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(), DELETE | SERVICE_STOP);
        if (!hService) {
            CloseServiceHandle(hSCM);
            return false;
        }

        // إيقاف الخدمة أولاً
        SERVICE_STATUS status;
        ControlService(hService, SERVICE_CONTROL_STOP, &status);

        // حذف الخدمة
        BOOL result = DeleteService(hService);

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);

        return result == TRUE;
    }

    bool ServiceModule::RunAsConsole() {
        // تشغيل كـ Console App للتصحيح
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);

        printf("Running in console mode for debugging...\n");

        if (!Initialize()) {
            printf("Initialization failed!\n");
            return false;
        }

        printf("Service initialized. Press Enter to stop...\n");
        getchar();

        Shutdown();
        return true;
    }

    bool ServiceModule::Initialize() {
        m_state = ServiceState::STARTING;

        // إنشاء Event الإيقاف
        m_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!m_hStopEvent) return false;

        // إنشاء المجلدات
        if (!CreateRequiredDirectories()) {
            return false;
        }

        // تحميل الإعدادات
        LoadConfiguration();

        // تهيئة المكونات
        if (!InitializeComponents()) {
            return false;
        }

        // بدء Threads
        m_ipcThread = std::thread(&ServiceModule::IPCServerThread, this);
        m_watchdogThread = std::thread(&ServiceModule::WatchdogThread, this);

        // تسجيل بدء التشغيل
        {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.serviceStartTime = std::chrono::system_clock::now();
        }

        LogEvent(EVENTLOG_INFORMATION_TYPE, "Service started successfully", 1000);
        return true;
    }

    bool ServiceModule::InitializeComponents() {
        try {
            // 1. الحماية الذاتية أولاً
            m_selfProtection = std::make_unique<SelfProtection>();
            SelfProtectionConfig spConfig;
            spConfig.protectService = true;
            spConfig.protectFiles = true;
            m_selfProtection->Initialize(spConfig);
            m_selfProtection->EnableProtection();

            // 2. مدير الحجر
            m_quarantineManager = std::make_unique<QuarantineManager>();
            QuarantineConfig qConfig;
            m_quarantineManager->Initialize(qConfig);

            // 3. كاشف الذكاء الاصطناعي
            m_aiDetector = std::make_unique<AIDetector>();
            DetectorConfig aiConfig;
            // TODO: تحديد مسار النموذج
            m_aiDetector->Initialize(aiConfig);

            // 4. محلل العمليات
            m_processAnalyzer = std::make_unique<ProcessAnalyzer>();
            AnalyzerConfig paConfig;
            m_processAnalyzer->SetConfig(paConfig);

            // 5. المراقبة اللحظية
            m_realTimeMonitor = std::make_unique<RealTimeMonitor>();
            MonitorConfig rtConfig;
            rtConfig.autoQuarantine = true;

            // ربط Callback للعزل التلقائي
            m_realTimeMonitor->SetEventCallback(
                [this](const MonitorEvent& event, ResponseAction action) {
                    if (action == ResponseAction::QUARANTINE) {
                        auto result = m_quarantineManager->QuarantineFile(
                            event.path,
                            "Real-Time Detection",
                            "Monitor",
                            0.95f
                        );

                        if (result == QuarantineResult::SUCCESS) {
                            LogEvent(EVENTLOG_WARNING_TYPE,
                                "File auto-quarantined: " +
                                std::string(event.path.begin(), event.path.end()), 2001);
                        }
                    }
                }
            );

            m_realTimeMonitor->Initialize(rtConfig);
            m_realTimeMonitor->Start();

            // 6. ماسح الملفات
            m_fileScanner = std::make_unique<FileScanner>();

            return true;
        }
        catch (const std::exception& e) {
            LogEvent(EVENTLOG_ERROR_TYPE, std::string("Component initialization failed: ") + e.what(), 5000);
            return false;
        }
    }

    void ServiceModule::Shutdown() {
        m_state = ServiceState::STOPPING;

        // إشارة الإيقاف
        SetEvent(m_hStopEvent);

        // إيقاف الفحص إن كان يعمل
        StopScan();

        // إيقاف المراقبة
        if (m_realTimeMonitor) {
            m_realTimeMonitor->Stop();
        }

        // انتظار Threads
        if (m_ipcThread.joinable()) m_ipcThread.join();
        if (m_scanThread.joinable()) m_scanThread.join();
        if (m_watchdogThread.joinable()) m_watchdogThread.join();

        // إيقاف المكونات
        ShutdownComponents();

        // تنظيف
        if (m_hStopEvent) {
            CloseHandle(m_hStopEvent);
            m_hStopEvent = NULL;
        }

        LogEvent(EVENTLOG_INFORMATION_TYPE, "Service stopped", 1001);
    }

    void ServiceModule::ShutdownComponents() {
        m_selfProtection.reset();
        m_realTimeMonitor.reset();
        m_processAnalyzer.reset();
        m_aiDetector.reset();
        m_quarantineManager.reset();
        m_fileScanner.reset();
    }

    void ServiceModule::IPCServerThread() {
        while (m_state != ServiceState::STOPPING) {
            // إنشاء Pipe جديد لكل اتصال
            HANDLE hPipe = CreateNamedPipeW(
                m_config.pipeName.c_str(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096, 4096,
                0,
                NULL
            );

            if (hPipe == INVALID_HANDLE_VALUE) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }

            // انتظار اتصال
            BOOL connected = ConnectNamedPipe(hPipe, NULL) ?
                TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

            if (connected && m_state != ServiceState::STOPPING) {
                // معالجة الاتصال في Thread منفصل
                std::thread clientThread(&ServiceModule::HandleClientConnection,
                    this, hPipe);
                clientThread.detach();
            }
            else {
                CloseHandle(hPipe);
            }
        }
    }

    void ServiceModule::HandleClientConnection(HANDLE hPipe) {
        while (m_state == ServiceState::RUNNING) {
            ServiceCommand cmd;
            cmd.hResponsePipe = hPipe;

            if (!ReadIPCMessage(hPipe, cmd)) {
                break; // انقطع الاتصال
            }

            ProcessCommand(cmd);
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    bool ServiceModule::ReadIPCMessage(HANDLE hPipe, ServiceCommand& cmd) {
        DWORD read;
        uint32_t cmdId, dataSize;

        // قراءة Header
        if (!ReadFile(hPipe, &cmdId, sizeof(cmdId), &read, NULL) || read != sizeof(cmdId)) {
            return false;
        }

        if (!ReadFile(hPipe, &dataSize, sizeof(dataSize), &read, NULL) ||
            read != sizeof(dataSize)) {
            return false;
        }

        cmd.commandId = cmdId;

        // قراءة البيانات
        if (dataSize > 0) {
            cmd.data.resize(dataSize);
            DWORD totalRead = 0;
            while (totalRead < dataSize) {
                DWORD bytesRead;
                if (!ReadFile(hPipe, cmd.data.data() + totalRead,
                    dataSize - totalRead, &bytesRead, NULL)) {
                    return false;
                }
                totalRead += bytesRead;
            }
        }

        return true;
    }

    void ServiceModule::ProcessCommand(const ServiceCommand& cmd) {
        switch (static_cast<IPCCommand>(cmd.commandId)) {
        case IPCCommand::START_QUICK_SCAN:
            OnStartQuickScan(cmd.hResponsePipe);
            break;

        case IPCCommand::START_FULL_SCAN:
            OnStartFullScan(cmd.hResponsePipe);
            break;

        case IPCCommand::START_CUSTOM_SCAN:
            if (cmd.data.size() >= sizeof(wchar_t)) {
                std::wstring path(reinterpret_cast<const wchar_t*>(cmd.data.data()),
                    cmd.data.size() / sizeof(wchar_t));
                OnStartCustomScan(path, cmd.hResponsePipe);
            }
            break;

        case IPCCommand::STOP_SCAN:
            OnStopScan(cmd.hResponsePipe);
            break;

        case IPCCommand::GET_STATUS:
            OnGetStatus(cmd.hResponsePipe);
            break;

        case IPCCommand::GET_QUARANTINE_LIST:
            OnGetQuarantineList(cmd.hResponsePipe);
            break;

        case IPCCommand::RESTORE_FILE:
            if (cmd.data.size() >= sizeof(wchar_t)) {
                std::wstring id(reinterpret_cast<const wchar_t*>(cmd.data.data()),
                    cmd.data.size() / sizeof(wchar_t));
                OnRestoreFile(id, cmd.hResponsePipe);
            }
            break;

        case IPCCommand::DELETE_FILE:
            if (cmd.data.size() >= sizeof(wchar_t)) {
                std::wstring id(reinterpret_cast<const wchar_t*>(cmd.data.data()),
                    cmd.data.size() / sizeof(wchar_t));
                OnDeleteFile(id, cmd.hResponsePipe);
            }
            break;

        case IPCCommand::GET_STATISTICS:
            OnGetStatistics(cmd.hResponsePipe);
            break;

        case IPCCommand::PING:
            SendIPCResponse(cmd.hResponsePipe, { 1 }); // Pong
            break;

        case IPCCommand::SHUTDOWN_SERVICE:
            OnShutdown(cmd.hResponsePipe);
            break;

        default:
            SendIPCResponse(cmd.hResponsePipe, { 0 }); // Unknown command
            break;
        }
    }

    void ServiceModule::OnStartQuickScan(HANDLE hResponsePipe) {
        if (m_scanRunning) {
            SendIPCResponse(hResponsePipe, { 0 }); // Busy
            return;
        }

        StartScan(ScanType::QUICK);
        SendIPCResponse(hResponsePipe, { 1 }); // Started
    }

    void ServiceModule::OnStartFullScan(HANDLE hResponsePipe) {
        if (m_scanRunning) {
            SendIPCResponse(hResponsePipe, { 0 });
            return;
        }

        StartScan(ScanType::FULL);
        SendIPCResponse(hResponsePipe, { 1 });
    }

    void ServiceModule::OnStartCustomScan(const std::wstring& path, HANDLE hResponsePipe) {
        if (m_scanRunning) {
            SendIPCResponse(hResponsePipe, { 0 });
            return;
        }

        StartScan(ScanType::CUSTOM, path);
        SendIPCResponse(hResponsePipe, { 1 });
    }

    void ServiceModule::OnStopScan(HANDLE hResponsePipe) {
        bool stopped = StopScan();
        SendIPCResponse(hResponsePipe, { stopped ? 1 : 0 });
    }

    void ServiceModule::OnGetStatus(HANDLE hResponsePipe) {
        // تسلسل الحالة
        auto status = GetScanStatus();

        std::vector<uint8_t> data;
        data.push_back(status.isScanning ? 1 : 0);
        data.push_back(static_cast<uint8_t>(status.currentType));

        // TODO: تسلسل كامل للبيانات

        SendIPCResponse(hResponsePipe, data);
    }

    void ServiceModule::OnGetQuarantineList(HANDLE hResponsePipe) {
        auto list = m_quarantineManager->GetQuarantinedFiles();

        // تسلسل القائمة
        std::stringstream ss;
        ss << list.size() << "\n";
        for (const auto& entry : list) {
            ss << std::string(entry.quarantineId.begin(), entry.quarantineId.end()) << "|"
                << std::string(entry.fileName.begin(), entry.fileName.end()) << "|"
                << entry.threatName << "\n";
        }

        std::string data = ss.str();
        SendIPCResponse(hResponsePipe,
            std::vector<uint8_t>(data.begin(), data.end()));
    }

    void ServiceModule::OnRestoreFile(const std::wstring& id, HANDLE hResponsePipe) {
        auto result = m_quarantineManager->RestoreFile(id);
        SendIPCResponse(hResponsePipe,
            { result == QuarantineResult::SUCCESS ? 1 : 0 });
    }

    void ServiceModule::OnDeleteFile(const std::wstring& id, HANDLE hResponsePipe) {
        auto result = m_quarantineManager->DeletePermanently(id, true);
        SendIPCResponse(hResponsePipe,
            { result == QuarantineResult::SUCCESS ? 1 : 0 });
    }

    void ServiceModule::OnGetStatistics(HANDLE hResponsePipe) {
        auto stats = GetStatistics();

        std::stringstream ss;
        ss << stats.totalFilesScanned << "|"
            << stats.totalThreatsBlocked << "|"
            << stats.totalFilesQuarantined << "|"
            << stats.uptimeHours;

        std::string data = ss.str();
        SendIPCResponse(hResponsePipe,
            std::vector<uint8_t>(data.begin(), data.end()));
    }

    void ServiceModule::OnShutdown(HANDLE hResponsePipe) {
        SendIPCResponse(hResponsePipe, { 1 });
        SetEvent(m_hStopEvent);
    }

    bool ServiceModule::StartScan(ScanType type, const std::wstring& path) {
        if (m_scanRunning.exchange(true)) {
            return false; // Already running
        }

        ScanTask task;
        task.type = type;
        task.targetPath = path;
        task.progressCallback = [this](const std::string& msg) {
            // TODO: Broadcast to UI clients
            };
        task.completionCallback = [this](bool success) {
            m_scanRunning = false;
            OnScanComplete(success);
            };

        {
            std::lock_guard<std::mutex> lock(m_scanMutex);
            m_currentScan = task;
        }

        m_scanThread = std::thread(&ServiceModule::ScanWorkerThread, this);
        return true;
    }

    bool ServiceModule::StopScan() {
        if (!m_scanRunning) return false;

        if (m_fileScanner) {
            m_fileScanner->StopScan();
        }

        if (m_scanThread.joinable()) {
            m_scanThread.join();
        }

        m_scanRunning = false;
        return true;
    }

    void ServiceModule::ScanWorkerThread() {
        ScanTask task;
        {
            std::lock_guard<std::mutex> lock(m_scanMutex);
            task = m_currentScan;
        }

        ExecuteScan(task);
    }

    void ServiceModule::ExecuteScan(const ScanTask& task) {
        auto startTime = std::chrono::steady_clock::now();

        ProgressCallback progressCb =
            [this, &task](const std::wstring& file, size_t done, size_t total,
                const ScanReport& report) {
                    OnScanProgress(file, done, total, report);
            };

        size_t filesScanned = 0;
        size_t threatsFound = 0;

        switch (task.type) {
        case ScanType::QUICK:
            filesScanned = m_fileScanner->QuickScan(progressCb);
            break;

        case ScanType::FULL:
            filesScanned = m_fileScanner->FullScan(progressCb);
            break;

        case ScanType::CUSTOM:
            if (!task.targetPath.empty()) {
                filesScanned = m_fileScanner->ScanDirectory(task.targetPath,
                    progressCb, true);
            }
            break;

        default:
            break;
        }

        auto endTime = std::chrono::steady_clock::now();
        double duration = std::chrono::duration<double>(endTime - startTime).count();

        // تحديث الإحصائيات
        {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.totalFilesScanned += filesScanned;
        }

        // تسجيل
        std::stringstream ss;
        ss << "Scan completed: " << filesScanned << " files scanned in "
            << duration << " seconds. Threats found: " << threatsFound;
        LogEvent(EVENTLOG_INFORMATION_TYPE, ss.str(), 1002);

        if (task.completionCallback) {
            task.completionCallback(true);
        }
    }

    void ServiceModule::OnScanProgress(const std::wstring& currentFile,
        size_t scanned, size_t total,
        const ScanReport& report) {
        // تحديث الإحصائيات المؤقتة

        // إذا كان تهديداً، عزله تلقائياً
        if (report.result == ScanResult::MALICIOUS ||
            report.result == ScanResult::SUSPICIOUS) {

            auto qResult = m_quarantineManager->QuarantineFile(
                currentFile,
                std::string(report.threatName.begin(), report.threatName.end()),
                report.detectionMethod,
                report.confidenceScore
            );

            if (qResult == QuarantineResult::SUCCESS) {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalThreatsBlocked++;
                m_stats.totalFilesQuarantined++;
            }
        }
    }

    void ServiceModule::OnScanComplete(bool success) {
        m_scanRunning = false;

        // TODO: إعلام جميع عملاء UI
    }

    ServiceModule::ScanStatus ServiceModule::GetScanStatus() const {
        ScanStatus status{};
        status.isScanning = m_scanRunning.load();

        if (status.isScanning) {
            std::lock_guard<std::mutex> lock(m_scanMutex);
            status.currentType = m_currentScan.type;
        }

        // TODO: إكمال بيانات التقدم الفعلية من FileScanner

        return status;
    }

    ServiceModule::ProtectionStats ServiceModule::GetStatistics() const {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        auto stats = m_stats;

        // حساب Uptime
        auto now = std::chrono::system_clock::now();
        auto uptime = std::chrono::duration<double>(now - stats.serviceStartTime).count();
        stats.uptimeHours = uptime / 3600.0;

        return stats;
    }

    void ServiceModule::WatchdogThread() {
        while (m_state != ServiceState::STOPPING) {
            std::this_thread::sleep_for(std::chrono::seconds(30));

            if (!HealthCheck()) {
                LogEvent(EVENTLOG_ERROR_TYPE, "Health check failed, attempting recovery", 5001);

                // محاولة استرداد
                // TODO: إعادة تهيئة المكونات المعطلة
            }
        }
    }

    bool ServiceModule::HealthCheck() {
        // التحقق من جميع المكونات
        if (!m_selfProtection || !m_selfProtection->IsActive()) return false;
        if (!m_realTimeMonitor || !m_realTimeMonitor->IsRunning()) return false;
        if (!m_aiDetector || !m_aiDetector->IsInitialized()) return false;

        return true;
    }

    void ServiceModule::SetServiceStatus(DWORD state, DWORD exitCode, DWORD waitHint) {
        m_serviceStatus.dwCurrentState = state;
        m_serviceStatus.dwWin32ExitCode = exitCode;
        m_serviceStatus.dwWaitHint = waitHint;

        if (state == SERVICE_RUNNING || state == SERVICE_STOPPED) {
            m_serviceStatus.dwCheckPoint = 0;
        }
        else {
            m_serviceStatus.dwCheckPoint++;
        }

        SetServiceStatus(m_statusHandle, &m_serviceStatus);
    }

    void ServiceModule::LogEvent(WORD type, const std::string& message, DWORD eventId) {
        // TODO: Windows Event Log
        // RegisterEventSource, ReportEvent

        // مؤقتاً: ملف نصي
        LogToFile(message);
    }

    void ServiceModule::LogToFile(const std::string& message) {
        try {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);

            std::stringstream filename;
            filename << m_config.logPath << "service_"
                << std::put_time(std::localtime(&time_t), "%Y%m%d") << ".log";

            std::ofstream file(filename.str(), std::ios::app);
            if (file.is_open()) {
                file << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S")
                    << " [" << GetCurrentThreadId() << "] " << message << "\n";
            }
        }
        catch (...) {
            // تجاهل أخطاء التسجيل
        }
    }

    bool ServiceModule::CreateRequiredDirectories() {
        try {
            fs::create_directories(m_config.logPath);
            fs::create_directories(L"C:\\ProgramData\\AIAntivirus\\Quarantine\\");
            fs::create_directories(L"C:\\ProgramData\\AIAntivirus\\Config\\");
            return true;
        }
        catch (...) {
            return false;
        }
    }

    bool ServiceModule::LoadConfiguration() {
        // TODO: قراءة من Registry أو ملف Config
        return true;
    }

    bool ServiceModule::SendIPCResponse(HANDLE hPipe, const std::vector<uint8_t>& data) {
        DWORD written;
        uint32_t size = static_cast<uint32_t>(data.size());

        if (!WriteFile(hPipe, &size, sizeof(size), &written, NULL)) {
            return false;
        }

        if (size > 0) {
            return WriteFile(hPipe, data.data(), size, &written, NULL) == TRUE;
        }

        return true;
    }

} // namespace AIAntivirus

// ==================== Entry Point ====================

int wmain(int argc, wchar_t* argv[]) {
    using namespace AIAntivirus;

    // تحليل Arguments
    if (argc > 1) {
        std::wstring arg = argv[1];

        if (arg == L"--install") {
            if (ServiceModule::Install()) {
                std::wcout << L"Service installed successfully.\n";
                return 0;
            }
            else {
                std::wcerr << L"Failed to install service.\n";
                return 1;
            }
        }
        else if (arg == L"--uninstall") {
            if (ServiceModule::Uninstall(L"SmartAVService")) {
                std::wcout << L"Service uninstalled successfully.\n";
                return 0;
            }
            else {
                std::wcerr << L"Failed to uninstall service.\n";
                return 1;
            }
        }
        else if (arg == L"--console") {
            // تشغيل كـ Console للتصحيح
            return ServiceModule::GetInstance().RunAsConsole() ? 0 : 1;
        }
        else if (arg == L"--service") {
            // تشغيل كـ Service
            SERVICE_TABLE_ENTRYW dispatchTable[] = {
                { const_cast<LPWSTR>(L"SmartAVService"),
                  ServiceModule::ServiceMain },
                { NULL, NULL }
            };
            StartServiceCtrlDispatcherW(dispatchTable);
            return 0;
        }
    }

    // افتراضي: محاولة التشغيل كـ Service
    SERVICE_TABLE_ENTRYW dispatchTable[] = {
        { const_cast<LPWSTR>(L"SmartAVService"), ServiceModule::ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcherW(dispatchTable)) {
        // فشل، ربما نعمل كـ Console
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            std::wcout << L"Running in console mode...\n";
            return ServiceModule::GetInstance().RunAsConsole() ? 0 : 1;
        }
        return 1;
    }

    return 0;
}