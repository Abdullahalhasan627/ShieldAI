/**
 * RealTimeMonitor.cpp
 *
 * وحدة المراقبة اللحظية - Real-Time Protection Module
 *
 * المسؤوليات:
 * - مراقبة إنشاء الملفات الجديدة في الوقت الفعلي
 * - مراقبة تنفيذ الملفات التنفيذية
 * - مراقبة التعديلات في المسارات الحساسة
 * - التفاعل الفوري مع التهديدات (عزل تلقائي)
 * - العمل في Thread مستقل بشكل مستقر وفعال
 *
 * التقنيات المستخدمة:
 * - ReadDirectoryChangesW: للمراقبة الفعالة للمجلدات
 * - File System Minifilter (Stub): للحماية على مستوى Kernel (مستقبلاً)
 * - ETW (Event Tracing for Windows): لمراقبة العمليات
 * - Thread Pool: لمعالجة الأحداث بكفاءة
 *
 * متطلبات: C++17, Windows 10+, Visual Studio 2022
 */

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <unordered_set>
#include <unordered_map>
#include <functional>
#include <chrono>
#include <filesystem>
#include <sstream>

 // TODO: تضمين الموديولات الأخرى عند ربطها
 // #include "FileScanner.h"
 // #include "AIDetector.h"
 // #include "../Security/Quarantine.h"

namespace fs = std::filesystem;

namespace AIAntivirus {

    // ==================== تعريفات الأنواع ====================

    /**
     * أنواع الأحداث المرصودة
     */
    enum class MonitorEventType {
        FILE_CREATED,           // إنشاء ملف جديد
        FILE_MODIFIED,          // تعديل ملف
        FILE_RENAMED,           // إعادة تسمية
        FILE_DELETED,           // حذف ملف
        PROCESS_CREATED,        // تشغيل عملية جديدة
        PROCESS_TERMINATED,     // إنهاء عملية
        REGISTRY_MODIFIED,      // تعديل في الريجستري (مستقبلي)
        NETWORK_ACTIVITY        // نشاط شبكي (مستقبلي)
    };

    /**
     * حدث مراقبة واحد
     */
    struct MonitorEvent {
        MonitorEventType type;
        std::wstring path;              // مسار الملف/العملية
        std::wstring targetPath;        // للـ Renamed (المسار الجديد)
        uint64_t timestamp;             // وقت الحدث
        uint32_t processId;             // معرف العملية المسؤولة
        std::wstring processName;       // اسم العملية

        // بيانات إضافية
        bool isDirectory;
        uint64_t fileSize;
    };

    /**
     * قرار الاستجابة للحدث
     */
    enum class ResponseAction {
        ALLOW,              // السماح
        BLOCK,              // منع
        QUARANTINE,         // عزل فوري
        SCAN_AND_DECIDE     // فحص ثم قرار
    };

    /**
     * إعدادات المراقبة
     */
    struct MonitorConfig {
        bool autoQuarantine = true;         // العزل التلقائي
        bool scanOnAccess = true;           // الفحص عند الوصول
        bool monitorNetworkDrives = false;  // مراقبة محركات الشبكة
        bool monitorRemovableMedia = true;  // مراقبة USB
        int maxQueueSize = 1000;            // حد طول قائمة الانتظار
        int scanTimeoutMs = 30000;           // مهلة الفحص (30 ثانية)
    };

    // ==================== الفئة الرئيسية: RealTimeMonitor ====================

    class RealTimeMonitor {
    public:
        RealTimeMonitor();
        ~RealTimeMonitor();

        // منع النسخ
        RealTimeMonitor(const RealTimeMonitor&) = delete;
        RealTimeMonitor& operator=(const RealTimeMonitor&) = delete;

        // ==================== واجهة التحكم ====================

        /**
         * تهيئة المراقبة
         */
        bool Initialize(const MonitorConfig& config = MonitorConfig{});

        /**
         * بدء المراقبة في Thread منفصل
         */
        bool Start();

        /**
         * إيقاف المراقبة
         */
        void Stop();

        /**
         * إضافة مسار للمراقبة ديناميكياً
         */
        bool AddWatchPath(const std::wstring& path);

        /**
         * إزالة مسار من المراقبة
         */
        bool RemoveWatchPath(const std::wstring& path);

        /**
         * التحقق من حالة المراقبة
         */
        bool IsRunning() const { return m_isRunning.load(); }

        /**
         * تسجيل callback للأحداث
         */
        using EventCallback = std::function<void(const MonitorEvent& event,
            ResponseAction action)>;
        void SetEventCallback(EventCallback callback);

        /**
         * إضافة استثناء (Whitelist)
         */
        void AddException(const std::wstring& path);

        /**
         * إزالة استثناء
         */
        void RemoveException(const std::wstring& path);

        /**
         * الحصول على إحصائيات
         */
        struct MonitorStats {
            uint64_t totalEvents;
            uint64_t threatsBlocked;
            uint64_t filesQuarantined;
            uint64_t scanErrors;
            double uptimeSeconds;
        };
        MonitorStats GetStatistics() const;

    private:
        // ==================== الأعضاء الخاصة ====================

        // حالة المراقبة
        std::atomic<bool> m_isRunning{ false };
        std::atomic<bool> m_stopRequested{ false };
        MonitorConfig m_config;

        // Threads
        std::vector<std::thread> m_monitorThreads;
        std::thread m_eventProcessorThread;
        std::thread m_processMonitorThread; // لـ ETW

        // المسارات المراقبة
        std::unordered_set<std::wstring> m_watchedPaths;
        std::mutex m_pathsMutex;

        // الاستثناءات (Whitelist)
        std::unordered_set<std::wstring> m_exceptions;
        std::shared_mutex m_exceptionsMutex; // C++17 shared_mutex للقراءات المتعددة

        // قائمة انتظار الأحداث (Thread-safe queue)
        struct EventQueue {
            std::queue<MonitorEvent> queue;
            std::mutex mutex;
            std::condition_variable cv;
        } m_eventQueue;

        // Callbacks
        EventCallback m_eventCallback;
        std::mutex m_callbackMutex;

        // الإحصائيات
        mutable std::mutex m_statsMutex;
        MonitorStats m_stats{ 0, 0, 0, 0, 0.0 };
        std::chrono::steady_clock::time_point m_startTime;

        // ==================== وظائف المراقبة ====================

        /**
         * Thread وظيفته مراقبة مجلد واحد
         */
        void DirectoryMonitorThread(const std::wstring& path);

        /**
         * Thread معالجة الأحداث (القارئ من Queue)
         */
        void EventProcessorThread();

        /**
         * Thread مراقبة العمليات (ETW)
         */
        void ProcessMonitorThread();

        /**
         * معالجة حدث واحد
         */
        ResponseAction ProcessEvent(const MonitorEvent& event);

        /**
         * فحص ملف مشبوه
         */
        ResponseAction ScanAndDecide(const std::wstring& filePath);

        /**
         * تنفيذ الاستجابة (Block/Quarantine)
         */
        bool ExecuteResponse(const MonitorEvent& event, ResponseAction action);

        /**
         * التحقق من الاستثناءات
         */
        bool IsException(const std::wstring& path) const;

        /**
         * الحصول على المسارات الحساسة الافتراضية
         */
        static std::vector<std::wstring> GetDefaultWatchPaths();

        /**
         * تحويل أعلام Windows إلى نوع الحدث
         */
        static MonitorEventType ConvertNotifyActionToEvent(DWORD action, bool isDirectory);

        /**
         * الحصول على اسم العملية من PID
         */
        static std::wstring GetProcessNameById(DWORD processId);

        /**
         * حذف ملف (للاستجابة السريعة)
         */
        static bool DeleteFileImmediate(const std::wstring& path);

        /**
         * منع تشغيل ملف (تجريبي)
         */
        static bool BlockFileExecution(const std::wstring& path);
    };

    // ==================== التنفيذ (Implementation) ====================

    RealTimeMonitor::RealTimeMonitor() {
        // تهيئة افتراضية
    }

    RealTimeMonitor::~RealTimeMonitor() {
        Stop();
    }

    bool RealTimeMonitor::Initialize(const MonitorConfig& config) {
        m_config = config;

        // إضافة المسارات الافتراضية
        auto defaultPaths = GetDefaultWatchPaths();
        for (const auto& path : defaultPaths) {
            if (fs::exists(path)) {
                AddWatchPath(path);
            }
        }

        // TODO: تهيئة ETW Session لمراقبة العمليات
        // TODO: تهيئة IPC مع الخدمة

        return true;
    }

    bool RealTimeMonitor::Start() {
        if (m_isRunning.exchange(true)) {
            return false; // Already running
        }

        m_stopRequested = false;
        m_startTime = std::chrono::steady_clock::now();

        // إنشاء Threads للمسارات المراقبة
        {
            std::lock_guard<std::mutex> lock(m_pathsMutex);
            for (const auto& path : m_watchedPaths) {
                m_monitorThreads.emplace_back(&RealTimeMonitor::DirectoryMonitorThread, this, path);
            }
        }

        // Thread معالجة الأحداث
        m_eventProcessorThread = std::thread(&RealTimeMonitor::EventProcessorThread, this);

        // Thread مراقبة العمليات (ETW)
        m_processMonitorThread = std::thread(&RealTimeMonitor::ProcessMonitorThread, this);

        return true;
    }

    void RealTimeMonitor::Stop() {
        if (!m_isRunning.exchange(false)) {
            return;
        }

        m_stopRequested = true;

        // إيقاف جميع Threads
        for (auto& thread : m_monitorThreads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        m_monitorThreads.clear();

        // إيقاف معالج الأحداث
        {
            std::lock_guard<std::mutex> lock(m_eventQueue.mutex);
            m_eventQueue.cv.notify_all();
        }
        if (m_eventProcessorThread.joinable()) {
            m_eventProcessorThread.join();
        }

        // إيقاف مراقب العمليات
        if (m_processMonitorThread.joinable()) {
            m_processMonitorThread.join();
        }

        // تحديث الإحصائيات
        auto endTime = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lock(m_statsMutex);
        m_stats.uptimeSeconds = std::chrono::duration<double>(endTime - m_startTime).count();
    }

    bool RealTimeMonitor::AddWatchPath(const std::wstring& path) {
        if (!fs::exists(path) || !fs::is_directory(path)) {
            return false;
        }

        std::lock_guard<std::mutex> lock(m_pathsMutex);

        if (m_watchedPaths.find(path) != m_watchedPaths.end()) {
            return false; // Already watching
        }

        m_watchedPaths.insert(path);

        // إذا كان يعمل، أضف Thread جديد
        if (m_isRunning) {
            m_monitorThreads.emplace_back(&RealTimeMonitor::DirectoryMonitorThread, this, path);
        }

        return true;
    }

    bool RealTimeMonitor::RemoveWatchPath(const std::wstring& path) {
        std::lock_guard<std::mutex> lock(m_pathsMutex);
        return m_watchedPaths.erase(path) > 0;
        // TODO: إيقاف Thread المحدد بأمان (يتطلب آلية إضافية)
    }

    void RealTimeMonitor::DirectoryMonitorThread(const std::wstring& path) {
        HANDLE hDirectory = CreateFileW(
            path.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            NULL
        );

        if (hDirectory == INVALID_HANDLE_VALUE) {
            // TODO: تسجيل الخطأ
            return;
        }

        // إعداد Overlapped I/O للأداء الأفضل
        OVERLAPPED overlapped = { 0 };
        overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

        const DWORD bufferSize = 64 * 1024; // 64KB buffer
        std::vector<BYTE> buffer(bufferSize);

        while (!m_stopRequested.load()) {
            DWORD bytesReturned = 0;

            // بدء عملية القراءة غير المتزامنة
            BOOL success = ReadDirectoryChangesW(
                hDirectory,
                buffer.data(),
                bufferSize,
                TRUE, // Watch subtree
                FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_DIR_NAME |
                FILE_NOTIFY_CHANGE_ATTRIBUTES |
                FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_LAST_WRITE |
                FILE_NOTIFY_CHANGE_SECURITY,
                &bytesReturned,
                &overlapped,
                NULL
            );

            if (!success && GetLastError() != ERROR_IO_PENDING) {
                break;
            }

            // انتظار الحدث مع مهلة للتحقق من m_stopRequested
            DWORD waitResult = WaitForSingleObject(overlapped.hEvent, 1000);

            if (waitResult == WAIT_OBJECT_0) {
                // الحصول على النتيجة
                DWORD transferred;
                if (GetOverlappedResult(hDirectory, &overlapped, &transferred, FALSE)) {
                    // معالجة الأحداث
                    FILE_NOTIFY_INFORMATION* notify =
                        reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer.data());

                    while (notify) {
                        std::wstring fileName(notify->FileName,
                            notify->FileNameLength / sizeof(WCHAR));
                        std::wstring fullPath = path + L"\\" + fileName;

                        // تجاهل الاستثناءات
                        if (!IsException(fullPath)) {
                            MonitorEvent event;
                            event.type = ConvertNotifyActionToEvent(notify->Action, false);
                            event.path = fullPath;
                            event.timestamp = GetTickCount64();
                            event.processId = 0; // TODO: الحصول على PID من ETW
                            event.isDirectory = false; // TODO: التحقق

                            // إضافة للـ Queue
                            {
                                std::lock_guard<std::mutex> lock(m_eventQueue.mutex);
                                if (m_eventQueue.queue.size() < m_config.maxQueueSize) {
                                    m_eventQueue.queue.push(event);
                                    m_eventQueue.cv.notify_one();
                                }
                            }
                        }

                        if (notify->NextEntryOffset == 0) break;
                        notify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                            reinterpret_cast<BYTE*>(notify) + notify->NextEntryOffset);
                    }
                }

                // إعادة تعيين الحدث
                ResetEvent(overlapped.hEvent);
            }
        }

        CloseHandle(overlapped.hEvent);
        CloseHandle(hDirectory);
    }

    void RealTimeMonitor::EventProcessorThread() {
        while (!m_stopRequested.load()) {
            MonitorEvent event;

            // انتظار حدث في Queue
            {
                std::unique_lock<std::mutex> lock(m_eventQueue.mutex);
                m_eventQueue.cv.wait(lock, [this] {
                    return !m_eventQueue.queue.empty() || m_stopRequested.load();
                    });

                if (m_stopRequested.load()) break;

                if (!m_eventQueue.queue.empty()) {
                    event = m_eventQueue.queue.front();
                    m_eventQueue.queue.pop();
                }
            }

            // معالجة الحدث
            if (!event.path.empty()) {
                ResponseAction action = ProcessEvent(event);

                // استدعاء callback إذا موجود
                {
                    std::lock_guard<std::mutex> lock(m_callbackMutex);
                    if (m_eventCallback) {
                        m_eventCallback(event, action);
                    }
                }

                // تنفيذ الاستجابة
                if (action != ResponseAction::ALLOW) {
                    ExecuteResponse(event, action);
                }

                // تحديث الإحصائيات
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalEvents++;
                if (action == ResponseAction::BLOCK) m_stats.threatsBlocked++;
                if (action == ResponseAction::QUARANTINE) m_stats.filesQuarantined++;
            }
        }
    }

    ResponseAction RealTimeMonitor::ProcessEvent(const MonitorEvent& event) {
        // فقط الأحداث المتعلقة بالملفات الجديدة أو المعدلة
        if (event.type != MonitorEventType::FILE_CREATED &&
            event.type != MonitorEventType::FILE_MODIFIED &&
            event.type != MonitorEventType::FILE_RENAMED) {
            return ResponseAction::ALLOW;
        }

        // التحقق من الامتدادات الخطرة
        std::wstring ext = fs::path(event.path).extension().wstring();
        static const std::unordered_set<std::wstring> dangerousExts = {
            L".exe", L".dll", L".scr", L".bat", L".cmd", L".ps1",
            L".vbs", L".js", L".jar", L".zip", L".rar"
        };

        if (dangerousExts.find(ext) == dangerousExts.end()) {
            // إذا لم يكن امتداداً خطراً، اسمح (مع فحص اختياري)
            if (m_config.scanOnAccess) {
                return ScanAndDecide(event.path);
            }
            return ResponseAction::ALLOW;
        }

        // للملفات الخطرة: فحص فوري
        return ScanAndDecide(event.path);
    }

    ResponseAction RealTimeMonitor::ScanAndDecide(const std::wstring& filePath) {
        // TODO: ربط FileScanner.cpp
        // هذا تنفيذ مؤقت يعتمد على Heuristics

        try {
            // 1. التحقق من الحجم
            uintmax_t size = fs::file_size(filePath);
            if (size == 0) return ResponseAction::ALLOW; // ملف فارغ

            // 2. التحقق من الـ Entropy (مؤشر الضغط/التشفير)
            // TODO: حساب Entropy

            // 3. فحص سريع باستخدام FileScanner (عند الربط لاحقاً)
            /*
            FileScanner scanner;
            ScanReport report;
            if (scanner.ScanSingleFile(filePath, report)) {
                if (report.result == ScanResult::MALICIOUS) {
                    return m_config.autoQuarantine ?
                        ResponseAction::QUARANTINE : ResponseAction::BLOCK;
                }
                if (report.result == ScanResult::SUSPICIOUS) {
                    return ResponseAction::BLOCK;
                }
            }
            */

            // 4. Heuristic بسيط: الملفات التنفيذية في Temp
            if (filePath.find(L"\\Temp\\") != std::wstring::npos ||
                filePath.find(L"\\tmp\\") != std::wstring::npos) {
                // TODO: فحص أعمق
            }

            return ResponseAction::ALLOW;

        }
        catch (...) {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.scanErrors++;
            return ResponseAction::ALLOW; // Fail open للأمان؟ أو BLOCK حسب السياسة
        }
    }

    bool RealTimeMonitor::ExecuteResponse(const MonitorEvent& event, ResponseAction action) {
        switch (action) {
        case ResponseAction::BLOCK:
            // محاولة حذف الملف إذا كان جديداً
            if (event.type == MonitorEventType::FILE_CREATED) {
                return DeleteFileImmediate(event.path);
            }
            // TODO: منع التنفيذ إذا كان process
            break;

        case ResponseAction::QUARANTINE:
            // TODO: ربط Quarantine.cpp
            // QuarantineManager::Instance().AddFile(event.path, event.processName);

            // مؤقتاً: نقل لمجلد خاص
        {
            std::wstring quarantinePath = L"C:\\ProgramData\\AIAntivirus\\Quarantine\\";
            CreateDirectoryW(quarantinePath.c_str(), NULL);

            std::wstring fileName = fs::path(event.path).filename().wstring();
            std::wstring destPath = quarantinePath + fileName + L".quarantined";

            MoveFileW(event.path.c_str(), destPath.c_str());
        }
        break;

        default:
            break;
        }
        return true;
    }

    void RealTimeMonitor::ProcessMonitorThread() {
        // TODO: تنفيذ ETW (Event Tracing for Windows) لمراقبة:
        // - Process Creation (Event ID 1 في Microsoft-Windows-Kernel-Process)
        // - Process Termination
        // - Image Load (DLL Injection detection)
        // - Network Connections

        // هذا يتطلب:
        // 1. StartTrace()
        // 2. EnableTraceEx2() لتفعيل Provider
        // 3. ProcessTrace() في loop
        // 4. Callback عند استلام Event

        // حالياً: Stub يتحقق من العمليات الجديدة باستخدام WMI أو polling بسيط
        // (غير فعال، يحتاج ETW للإنتاج)

        while (!m_stopRequested.load()) {
            // Polling بسيط كل 5 ثواني (مؤقت جداً)
            std::this_thread::sleep_for(std::chrono::seconds(5));

            // TODO: فحص العمليات الجديدة ضد blacklist
            // TODO: التحقق من injection attempts
        }
    }

    void RealTimeMonitor::SetEventCallback(EventCallback callback) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_eventCallback = callback;
    }

    void RealTimeMonitor::AddException(const std::wstring& path) {
        std::unique_lock<std::shared_mutex> lock(m_exceptionsMutex);
        m_exceptions.insert(path);
    }

    void RealTimeMonitor::RemoveException(const std::wstring& path) {
        std::unique_lock<std::shared_mutex> lock(m_exceptionsMutex);
        m_exceptions.erase(path);
    }

    bool RealTimeMonitor::IsException(const std::wstring& path) const {
        std::shared_lock<std::shared_mutex> lock(m_exceptionsMutex);

        // التحقق المباشر
        if (m_exceptions.find(path) != m_exceptions.end()) {
            return true;
        }

        // التحقق من المسارات الأب
        fs::path p = path;
        while (p.has_parent_path()) {
            p = p.parent_path();
            if (m_exceptions.find(p.wstring()) != m_exceptions.end()) {
                return true;
            }
        }

        return false;
    }

    RealTimeMonitor::MonitorStats RealTimeMonitor::GetStatistics() const {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        return m_stats;
    }

    // ==================== وظائف مساعدة (Static) ====================

    std::vector<std::wstring> RealTimeMonitor::GetDefaultWatchPaths() {
        std::vector<std::wstring> paths;

        // مجلدات النظام الحساسة
        paths.push_back(LR"(C:\Windows\System32)");
        paths.push_back(LR"(C:\Windows\SysWOW64)");
        paths.push_back(LR"(C:\Windows\Temp)");

        // مجلدات المستخدم
        wchar_t userProfile[MAX_PATH];
        if (GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH)) {
            paths.push_back(std::wstring(userProfile) + L"\\Downloads");
            paths.push_back(std::wstring(userProfile) + L"\\AppData\\Roaming");
            paths.push_back(std::wstring(userProfile) + L"\\AppData\\Local\\Temp");
        }

        // مجلدات البرامج
        paths.push_back(LR"(C:\Program Files)");
        paths.push_back(LR"(C:\Program Files (x86))");

        // مجلدات البداية
        paths.push_back(LR"(C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup)");

        wchar_t startupPath[MAX_PATH];
        if (SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, startupPath) == S_OK) {
            paths.push_back(startupPath);
        }

        return paths;
    }

    MonitorEventType RealTimeMonitor::ConvertNotifyActionToEvent(DWORD action, bool isDirectory) {
        switch (action) {
        case FILE_ACTION_ADDED:
            return MonitorEventType::FILE_CREATED;
        case FILE_ACTION_REMOVED:
            return MonitorEventType::FILE_DELETED;
        case FILE_ACTION_MODIFIED:
            return MonitorEventType::FILE_MODIFIED;
        case FILE_ACTION_RENAMED_OLD_NAME:
        case FILE_ACTION_RENAMED_NEW_NAME:
            return MonitorEventType::FILE_RENAMED;
        default:
            return MonitorEventType::FILE_MODIFIED;
        }
    }

    std::wstring RealTimeMonitor::GetProcessNameById(DWORD processId) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, processId);
        if (!hProcess) return L"";

        wchar_t processName[MAX_PATH] = L"";
        DWORD size = MAX_PATH;

        if (QueryFullProcessImageNameW(hProcess, 0, processName, &size)) {
            CloseHandle(hProcess);
            return fs::path(processName).filename().wstring();
        }

        CloseHandle(hProcess);
        return L"";
    }

    bool RealTimeMonitor::DeleteFileImmediate(const std::wstring& path) {
        // محاولة حذف فوري
        if (DeleteFileW(path.c_str())) {
            return true;
        }

        // إذا فشل (مشغول)، حاول إعادة تسمية ثم حذف
        std::wstring tempPath = path + L".tmpdelete";
        if (MoveFileExW(path.c_str(), tempPath.c_str(), MOVEFILE_REPLACE_EXISTING)) {
            // جدولة الحذف عند إعادة التشغيل إذا لزم الأمر
            MoveFileExW(tempPath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
            return true;
        }

        return false;
    }

    bool RealTimeMonitor::BlockFileExecution(const std::wstring& path) {
        // TODO: استخدام Windows Defender Application Control (WDAC) 
        // أو AppLocker APIs لمنع التنفيذ
        // أو حقن code في العملية لمنع الـ CreateProcess (غير موصى به)

        // حالياً: إضافة للـ Windows Disallowed Policy (بسيطة)
        // يتطلب صلاحيات admin

        return false; // Stub
    }

} // namespace AIAntivirus