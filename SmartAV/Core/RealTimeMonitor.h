/**
 * RealTimeMonitor.h
 *
 * وحدة المراقبة اللحظية - Real-Time Protection Module
 *
 * المسؤوليات:
 * - مراقبة إنشاء الملفات الجديدة في الوقت الفعلي
 * - مراقبة تنفيذ الملفات التنفيذية
 * - مراقبة التعديلات في المسارات الحساسة
 * - التفاعل الفوري مع التهديدات
 *
 * متطلبات: C++17, Windows 10+
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <queue>
#include <unordered_set>
#include <functional>
#include <chrono>

namespace AIAntivirus {

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
        REGISTRY_MODIFIED,      // تعديل في الريجستري
        NETWORK_ACTIVITY        // نشاط شبكي
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
        int scanTimeoutMs = 30000;          // مهلة الفحص (30 ثانية)
    };

    /**
     * إحصائيات المراقبة
     */
    struct MonitorStats {
        uint64_t totalEvents;
        uint64_t threatsBlocked;
        uint64_t filesQuarantined;
        uint64_t scanErrors;
        double uptimeSeconds;
    };

    /**
     * الفئة الرئيسية: RealTimeMonitor
     */
    class RealTimeMonitor {
    public:
        static RealTimeMonitor& GetInstance();
        
        RealTimeMonitor(const RealTimeMonitor&) = delete;
        RealTimeMonitor& operator=(const RealTimeMonitor&) = delete;

        // ==================== واجهة التحكم ====================

        /**
         * تهيئة المراقبة
         */
        bool Initialize(const MonitorConfig& config = MonitorConfig{});
        
        /**
         * إيقاف التهيئة
         */
        void Shutdown();

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
        using EventCallback = std::function<void(const MonitorEvent& event, ResponseAction action)>;
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
        MonitorStats GetStatistics() const;

    private:
        RealTimeMonitor() = default;
        ~RealTimeMonitor() = default;
        
        // حالة المراقبة
        std::atomic<bool> m_isRunning{ false };
        std::atomic<bool> m_stopRequested{ false };
        MonitorConfig m_config;

        bool m_isInitialized = false;
        
        // Threads
        std::thread m_monitorThread;
        std::chrono::steady_clock::time_point m_startTime;

        // المسارات المراقبة
        std::unordered_set<std::wstring> m_watchedPaths;
        std::mutex m_pathsMutex;

        // الاستثناءات (Whitelist)
        std::unordered_set<std::wstring> m_exceptions;
        mutable std::shared_mutex m_exceptionsMutex;

        // قائمة انتظار الأحداث
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

        // ==================== وظائف المراقبة ====================

        void MonitorDirectories();
        void ProcessDirectoryChanges(const std::wstring& basePath, void* buffer, DWORD bytesReturned);
        bool IsException(const std::wstring& path) const;
    };

} // namespace AIAntivirus
