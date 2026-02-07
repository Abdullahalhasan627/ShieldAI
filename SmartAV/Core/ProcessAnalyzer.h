/**
 * ProcessAnalyzer.h
 *
 * محلل العمليات - Process Behavior Analyzer
 *
 * المسؤوليات:
 * - تحليل العمليات الجارية في النظام
 * - فحص السلوكيات المشبوهة (API Hooking, Injection, etc.)
 * - تحليل الـ Modules/DLLs المحملة داخل العملية
 * - تقييم درجة الخطورة باستخدام الذكاء الاصطناعي
 * - اكتشاف تقنيات التهديدات المتقدمة (MITRE ATT&CK)
 *
 * متطلبات: C++17, Windows 10+, صلاحيات Administrator لبعض الميزات
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <chrono>

namespace AIAntivirus {

    /**
     * تقنيات MITRE ATT&CK المدعومة
     */
    enum class AttackTechnique {
        UNKNOWN,
        PROCESS_INJECTION,          // T1055
        PROCESS_HOLLOWING,          // T1055.012
        DLL_INJECTION,              // T1055.001
        API_HOOKING,                // T1056.004
        BYPASS_UAC,                 // T1548.002
        PRIVILEGE_ESCALATION,       // various
        DEFENSE_EVASION,            // various
        PERSISTENCE,                // various
        CREDENTIAL_DUMPING,         // T1003
        LATERAL_MOVEMENT            // various
    };

    /**
     * معلومات Module/DLL
     */
    struct ModuleInfo {
        std::wstring name;
        std::wstring fullPath;
        PVOID baseAddress;
        DWORD size;
        bool isSigned;
        std::string signerName;
        std::string hash;           // SHA-256
        bool isSuspicious;
        std::string threatInfo;
    };

    /**
     * معلومات الذاكرة (Memory Region)
     */
    struct MemoryRegion {
        PVOID baseAddress;
        SIZE_T size;
        DWORD state;                // MEM_COMMIT, MEM_RESERVE, MEM_FREE
        DWORD protect;              // PAGE_EXECUTE, PAGE_READWRITE, etc.
        DWORD type;                 // MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE
        bool isExecutable;
        bool isWritable;
        std::string entropy;        // High entropy = suspicious
    };

    /**
     * سلوك عملية واحدة
     */
    struct ProcessBehavior {
        std::vector<std::wstring> createdProcesses;
        std::vector<std::wstring> loadedModules;
        std::vector<std::wstring> networkConnections;
        std::vector<std::wstring> modifiedFiles;
        std::vector<std::wstring> registryChanges;
        bool attemptedEscalation = false;
        bool injectedCode = false;
        bool hookedAPI = false;
    };

    /**
     * تقرير تحليل العملية
     */
    struct ProcessAnalysisReport {
        DWORD processId;
        std::wstring processName;
        std::wstring executablePath;
        std::wstring commandLine;
        DWORD parentProcessId;
        std::wstring parentProcessName;

        // تقييم الخطورة
        float threatScore;              // 0.0 - 1.0
        bool isMalicious;
        std::vector<AttackTechnique> detectedTechniques;
        std::vector<std::string> indicators;

        // تفاصيل فنية
        std::vector<ModuleInfo> loadedModules;
        std::vector<MemoryRegion> memoryRegions;
        ProcessBehavior behavior;

        // معلومات النظام
        std::chrono::system_clock::time_point startTime;
        SIZE_T memoryUsage;
        DWORD threadCount;
        bool isElevated;
        bool isCriticalSystemProcess;
    };

    /**
     * معلومات Thread
     */
    struct ThreadInfo {
        DWORD threadId;
        PVOID startAddress;
        std::wstring moduleName;        // أي module يبدأ منه
        bool isSuspended;
        DWORD priority;
    };

    /**
     * إعدادات المحلل
     */
    struct AnalyzerConfig {
        bool analyzeMemory = true;          // تحليل الذاكرة
        bool checkDigitalSignatures = true; // التحقق من التوقيعات
        bool detectInjection = true;        // اكتشاف الـ Injection
        bool useAI = true;                  // استخدام الذكاء الاصطناعي
        float threatThreshold = 0.7f;       // عتبة التهديد
        int maxAnalysisTimeMs = 5000;       // أقصى وقت للتحليل
    };

    /**
     * الفئة الرئيسية: ProcessAnalyzer
     */
    class ProcessAnalyzer {
    public:
        static ProcessAnalyzer& GetInstance();
        
        bool Initialize(const AnalyzerConfig& config = AnalyzerConfig{});
        void Shutdown();

        // منع النسخ
        ProcessAnalyzer(const ProcessAnalyzer&) = delete;
        ProcessAnalyzer& operator=(const ProcessAnalyzer&) = delete;

        // ==================== واجهة التحليل ====================

        ProcessAnalysisReport AnalyzeProcess(DWORD processId);

        /**
         * تحليل جميع العمليات في النظام
         */
        std::vector<ProcessAnalysisReport> AnalyzeAllProcesses();

        /**
         * تحليل سريع (خفيف) للعملية
         */
        bool QuickAnalyze(DWORD processId, ProcessAnalysisReport& report);

        /**
         * مراقبة عملية معينة بشكل مستمر
         */
        bool StartMonitoringProcess(DWORD processId);
        void StopMonitoringProcess(DWORD processId);

        /**
         * التحقق من وجود Injection في عملية
         */
        bool DetectInjection(DWORD processId, std::vector<std::string>& details);

        /**
         * فحص Process Hollowing
         */
        bool DetectProcessHollowing(DWORD processId);

        /**
         * اكتشاف API Hooking
         */
        bool DetectAPIHooking(DWORD processId, std::map<std::string, bool>& hookedModules);

        // ==================== واجهة التكوين ====================

        void SetConfig(const AnalyzerConfig& config) { m_config = config; }
        AnalyzerConfig GetConfig() const { return m_config; }

        /**
         * الحصول على قائمة العمليات المشبوهة فقط
         */
        std::vector<ProcessAnalysisReport> GetSuspiciousProcesses();

        /**
         * إضافة عملية للقائمة البيضاء
         */
        void WhitelistProcess(const std::wstring& processName);

        /**
         * إضافة Module للقائمة السوداء
         */
        void BlacklistModule(const std::string& moduleHash);

    bool IsProcessSuspicious(DWORD processId, float* riskScore = nullptr);
        bool TerminateProcess(DWORD processId);

    private:
        ProcessAnalyzer() = default;
        ~ProcessAnalyzer() = default;
        
        AnalyzerConfig m_config;
        bool m_isInitialized = false;

        // قائمة العمليات المراقبة
        std::map<DWORD, std::unique_ptr<std::thread>> m_monitoredProcesses;
        std::mutex m_monitorMutex;

        // Whitelist/Blacklist
        std::set<std::wstring> m_whitelistedProcesses;
        std::set<std::string> m_blacklistedModules;
        std::shared_mutex m_listMutex;

        // Cache للنتائج
        std::map<DWORD, ProcessAnalysisReport> m_cache;
        std::mutex m_cacheMutex;

        // ==================== وظائف التحليل الداخلية ====================

        bool GetBasicProcessInfo(DWORD processId, ProcessAnalysisReport& report);
        bool GetCommandLine(DWORD processId, std::wstring& cmdLine);
        bool GetParentProcessId(DWORD processId, DWORD& parentId);
        bool EnumerateModules(DWORD processId, std::vector<ModuleInfo>& modules);
        void AnalyzeModule(ModuleInfo& module);
        bool EnumerateMemoryRegions(DWORD processId, std::vector<MemoryRegion>& regions);
        float CalculateMemoryEntropy(HANDLE hProcess, PVOID address, SIZE_T size);
        bool DetectExecutableMemory(HANDLE hProcess, const std::vector<MemoryRegion>& regions,
            std::vector<std::string>& findings);
        bool AnalyzeThreads(DWORD processId, std::vector<ThreadInfo>& threads);
        float CalculateHeuristicScore(const ProcessAnalysisReport& report);
        float CalculateAIScore(const ProcessAnalysisReport& report);
        void CheckSuspiciousBehaviors(ProcessAnalysisReport& report);
        bool IsCriticalSystemProcess(const std::wstring& processName);
        bool IsWhitelisted(const std::wstring& processName);
        bool IsBlacklisted(const std::string& moduleHash);
        void MonitorThreadFunc(DWORD processId);

        // وظائف مساعدة
        static std::wstring GetFileNameFromPath(const std::wstring& path);
        static std::string BytesToHexString(const BYTE* data, size_t len);
        static bool ReadProcessMemorySafe(HANDLE hProcess, LPCVOID address, LPVOID buffer, SIZE_T size);
    };

} // namespace AIAntivirus
