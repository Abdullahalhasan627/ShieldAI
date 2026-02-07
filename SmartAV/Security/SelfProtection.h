/**
 * SelfProtection.h
 *
 * وحدة الحماية الذاتية - Self-Protection Module
 *
 * المسؤوليات:
 * - منع إيقاف خدمة مكافح الفيروسات
 * - حماية ملفات البرنامج من التعديل/الحذف
 * - اكتشاف محاولات التلاعب بالبرنامج
 * - حماية مفاتيح الريجستري الخاصة بالبرنامج
 * - منع إلغاء تثبيت البرنامج بدون صلاحيات
 *
 * متطلبات: C++17, Windows 10+, صلاحيات Administrator
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <mutex>
#include <atomic>
#include <thread>

namespace AIAntivirus {

    /**
     * مستوى الحماية
     */
    enum class ProtectionLevel {
        DISABLED,           // معطل
        BASIC,              // حماية أساسية
        STANDARD,           // حماية عادية
        MAXIMUM             // حماية قصوى
    };

    /**
     * نوع الهجوم المكتشف
     */
    enum class AttackType {
        PROCESS_TERMINATION,    // محاولة إنهاء العملية
        FILE_MODIFICATION,      // محاولة تعديل ملفات البرنامج
        FILE_DELETION,          // محاولة حذف ملفات البرنامج
        REGISTRY_MODIFICATION,  // محاولة تعديل الريجستري
        SERVICE_STOPPING,       // محاولة إيقاف الخدمة (renamed from SERVICE_STOP)
        DLL_INJECTION,          // محاولة حقن DLL
        DEBUGGER_ATTACHED,      // اكتشاف Debugger
        MEMORY_TAMPERING        // تلاعب بالذاكرة
    };

    /**
     * إعدادات الحماية الذاتية
     */
    struct SelfProtectionConfig {
        ProtectionLevel level = ProtectionLevel::STANDARD;
        bool protectProcess = true;         // حماية العملية من الإنهاء
        bool protectFiles = true;           // حماية الملفات
        bool protectRegistry = true;        // حماية الريجستري
        bool antiDebugging = true;          // مكافحة التصحيح
        bool integrityChecks = true;        // فحص سلامة الملفات
        bool serviceProtection = true;      // حماية الخدمة
        int integrityCheckIntervalMs = 60000; // فحص كل دقيقة
    };

    /**
     * حدث هجوم مكتشف
     */
    struct ProtectionEvent {
        AttackType type;
        std::wstring details;
        std::wstring attackerProcess;
        DWORD attackerPID;
        std::chrono::system_clock::time_point timestamp;
        bool wasBlocked;
    };

    /**
     * Callback للإشعار بالهجمات
     */
    using AttackCallback = std::function<void(const ProtectionEvent& event)>;

    /**
     * الفئة الرئيسية: SelfProtection (Singleton)
     */
    class SelfProtection {
    public:
        /**
         * الحصول على المثيل الوحيد
         */
        static SelfProtection& Instance();

        // منع النسخ
        SelfProtection(const SelfProtection&) = delete;
        SelfProtection& operator=(const SelfProtection&) = delete;

        // ==================== واجهة التحكم ====================

        /**
         * تهيئة الحماية الذاتية
         */
        bool Initialize(const SelfProtectionConfig& config = SelfProtectionConfig{});

        /**
         * إيقاف الحماية الذاتية
         */
        void Shutdown();

        /**
         * تفعيل/إيقاف الحماية
         */
        bool EnableProtection();
        bool DisableProtection();
        bool IsProtectionEnabled() const;

        /**
         * التحقق من حالة الحماية
         */
        bool IsEnabled() const { return m_isEnabled.load(); }

        /**
         * تعيين مستوى الحماية
         */
        void SetProtectionLevel(ProtectionLevel level);
        ProtectionLevel GetProtectionLevel() const { return m_config.level; }

        /**
         * تسجيل callback للهجمات
         */
        void SetAttackCallback(AttackCallback callback);

        /**
         * الحصول على سجل الهجمات
         */
        std::vector<ProtectionEvent> GetAttackLog() const;

        /**
         * مسح سجل الهجمات
         */
        void ClearAttackLog();

        // ==================== وظائف الحماية ====================

        /**
         * التحقق من سلامة الملفات
         */
        bool VerifyFileIntegrity();

        /**
         * التحقق من وجود Debugger
         */
        bool IsDebuggerPresent();

        /**
         * حماية العملية الحالية
         */
        bool ProtectCurrentProcess();

        /**
         * إضافة ملف للحماية
         */
        bool AddProtectedFile(const std::wstring& filePath);

        /**
         * إزالة ملف من الحماية
         */
        bool RemoveProtectedFile(const std::wstring& filePath);

    private:
        SelfProtection();
        ~SelfProtection();

        // الإعدادات والحالة
        SelfProtectionConfig m_config;
        std::atomic<bool> m_isEnabled{ false };
        std::atomic<bool> m_isInitialized{ false };

        // سجل الهجمات
        std::vector<ProtectionEvent> m_attackLog;
        mutable std::mutex m_logMutex;

        // Callback
        AttackCallback m_attackCallback;
        std::mutex m_callbackMutex;

        // الملفات المحمية وهاشاتها
        std::vector<std::wstring> m_protectedFiles;
        std::vector<std::string> m_fileHashes;
        std::mutex m_filesMutex;

        // Threads
        std::thread m_integrityThread;
        std::thread m_antiDebugThread;
        std::atomic<bool> m_stopThreads{ false };

        // ==================== وظائف داخلية ====================

        void SetupProcessProtection();
        void SetupFileProtection();
        void SetupRegistryProtection();
        void SetupServiceProtection();
        void IntegrityCheckThread();
        void AntiDebugThread();
        void HandleAttack(const ProtectionEvent& event);
        void LogAttack(const ProtectionEvent& event);
        std::string CalculateFileHash(const std::wstring& filePath);
        bool SetFileACL(const std::wstring& filePath);
        bool SetRegistryACL(HKEY hKey, const std::wstring& subKey);

        // Windows API Helpers
        static bool SetProcessCritical(bool critical);
        static bool SetProcessDEP();
        static bool SetProcessMitigations();
    };

} // namespace AIAntivirus
