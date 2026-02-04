/**
 * ProcessAnalyzer.cpp
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
 * التقنيات المستخدمة:
 * - Windows Toolhelp32 API لالتقاط لقطات العمليات
 * - Memory Analysis لـ Injected Code
 * - ETW (Event Tracing for Windows) للأحداث الأمنية
 * - Handle Enumeration للكشف عن Process Hollowing
 *
 * متطلبات: C++17, Windows 10+, صلاحيات Administrator لبعض الميزات
 */

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <algorithm>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <numeric>
#include <functional>

 // TODO: تضمين الموديولات الأخرى عند ربطها
 // #include "FeatureExtractor.h"
 // #include "../AI/AIDetector.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib") // For NtQueryInformationProcess

namespace AIAntivirus {

    // ==================== تعريفات الأنواع ====================

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
        bool attemptedEscalation;
        bool injectedCode;
        bool hookedAPI;
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

    // ==================== الفئة الرئيسية: ProcessAnalyzer ====================

    class ProcessAnalyzer {
    public:
        ProcessAnalyzer();
        ~ProcessAnalyzer();

        // منع النسخ
        ProcessAnalyzer(const ProcessAnalyzer&) = delete;
        ProcessAnalyzer& operator=(const ProcessAnalyzer&) = delete;

        // ==================== واجهة التحليل ====================

        /**
         * تحليل عملية واحدة بالتفصيل
         */
        bool AnalyzeProcess(DWORD processId, ProcessAnalysisReport& report);

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

    private:
        // ==================== الأعضاء الخاصة ====================

        AnalyzerConfig m_config;

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

        /**
         * الحصول على معلومات أساسية عن العملية
         */
        bool GetBasicProcessInfo(DWORD processId, ProcessAnalysisReport& report);

        /**
         * استخراج سطر الأوامر
         */
        bool GetCommandLine(DWORD processId, std::wstring& cmdLine);

        /**
         * الحصول على العملية الأب
         */
        bool GetParentProcessId(DWORD processId, DWORD& parentId);

        /**
         * استخراج الـ Modules المحملة
         */
        bool EnumerateModules(DWORD processId, std::vector<ModuleInfo>& modules);

        /**
         * فحص Module واحد
         */
        void AnalyzeModule(ModuleInfo& module);

        /**
         * استخراج مناطق الذاكرة
         */
        bool EnumerateMemoryRegions(DWORD processId, std::vector<MemoryRegion>& regions);

        /**
         * حساب Entropy لمنطقة ذاكرة
         */
        float CalculateMemoryEntropy(HANDLE hProcess, PVOID address, SIZE_T size);

        /**
         * اكتشاف الذاكرة القابلة للتنفيذ والمشبوهة
         */
        bool DetectExecutableMemory(HANDLE hProcess, const std::vector<MemoryRegion>& regions,
            std::vector<std::string>& findings);

        /**
         * تحليل Threads
         */
        bool AnalyzeThreads(DWORD processId, std::vector<ThreadInfo>& threads);

        /**
         * تقييم الخطورة باستخدام Heuristics
         */
        float CalculateHeuristicScore(const ProcessAnalysisReport& report);

        /**
         * TODO: تقييم الخطورة بالذكاء الاصطناعي
         */
        float CalculateAIScore(const ProcessAnalysisReport& report);

        /**
         * فحص سلوكيات مشبوهة محددة
         */
        void CheckSuspiciousBehaviors(ProcessAnalysisReport& report);

        /**
         * التحقق من أن العملية نظامية حرجة
         */
        bool IsCriticalSystemProcess(const std::wstring& processName);

        /**
         * التحقق من القائمة البيضاء
         */
        bool IsWhitelisted(const std::wstring& processName);

        /**
         * التحقق من القائمة السوداء
         */
        bool IsBlacklisted(const std::string& moduleHash);

        /**
         * Thread مراقبة مستمرة لعملية
         */
        void MonitorThreadFunc(DWORD processId);

        // ==================== وظائف مساعدة ====================

        static std::wstring GetFileNameFromPath(const std::wstring& path);
        static std::string BytesToHexString(const BYTE* data, size_t len);
        static bool ReadProcessMemorySafe(HANDLE hProcess, LPCVOID address,
            LPVOID buffer, SIZE_T size);
    };

    // ==================== التنفيذ (Implementation) ====================

    ProcessAnalyzer::ProcessAnalyzer() {
        // إضافة العمليات النظامية للقائمة البيضاء الافتراضية
        const std::vector<std::wstring> systemProcesses = {
            L"System", L"Registry", L"smss.exe", L"csrss.exe", L"wininit.exe",
            L"services.exe", L"lsass.exe", L"svchost.exe", L"explorer.exe",
            L"taskhostw.exe", L"dwm.exe", L"fontdrvhost.exe"
        };

        for (const auto& proc : systemProcesses) {
            WhitelistProcess(proc);
        }
    }

    ProcessAnalyzer::~ProcessAnalyzer() {
        // إيقاف جميع المراقبات
        {
            std::lock_guard<std::mutex> lock(m_monitorMutex);
            for (auto& [pid, thread] : m_monitoredProcesses) {
                if (thread && thread->joinable()) {
                    // TODO: إشارة إيقاف بدلاً من detachment
                    thread->detach();
                }
            }
        }
    }

    bool ProcessAnalyzer::AnalyzeProcess(DWORD processId, ProcessAnalysisReport& report) {
        if (processId == 0 || processId == 4) { // Idle أو System
            return false;
        }

        auto startTime = std::chrono::steady_clock::now();

        // 1. المعلومات الأساسية
        if (!GetBasicProcessInfo(processId, report)) {
            return false;
        }

        report.processId = processId;

        // التحقق من القائمة البيضاء
        if (IsWhitelisted(report.processName) && !m_config.useAI) {
            report.threatScore = 0.0f;
            report.isMalicious = false;
            return true;
        }

        // 2. Modules
        if (!EnumerateModules(processId, report.loadedModules)) {
            // ليس خطأً fatal - استمر
        }

        // 3. Memory Analysis
        if (m_config.analyzeMemory && processId != GetCurrentProcessId()) {
            EnumerateMemoryRegions(processId, report.memoryRegions);

            // اكتشاف Injection
            if (m_config.detectInjection) {
                std::vector<std::string> injectionDetails;
                if (DetectInjection(processId, injectionDetails)) {
                    report.detectedTechniques.push_back(AttackTechnique::PROCESS_INJECTION);
                    report.indicators.insert(report.indicators.end(),
                        injectionDetails.begin(), injectionDetails.end());
                }
            }
        }

        // 4. Thread Analysis
        std::vector<ThreadInfo> threads;
        if (AnalyzeThreads(processId, threads)) {
            report.threadCount = static_cast<DWORD>(threads.size());

            // التحقق من Threads مشبوهة (Started in suspicious memory)
            for (const auto& thread : threads) {
                if (thread.moduleName.empty() || thread.moduleName == L"UNKNOWN") {
                    report.behavior.injectedCode = true;
                    report.indicators.push_back("Thread with unknown start address: " +
                        std::to_string(thread.threadId));
                }
            }
        }

        // 5. Heuristic Analysis
        float heuristicScore = CalculateHeuristicScore(report);

        // 6. AI Analysis (TODO)
        float aiScore = 0.0f;
        if (m_config.useAI) {
            aiScore = CalculateAIScore(report);
        }

        // 7. Final Score
        report.threatScore = std::max(heuristicScore, aiScore);
        report.isMalicious = (report.threatScore >= m_config.threatThreshold);

        // 8. Check Specific Techniques
        CheckSuspiciousBehaviors(report);

        // تحديث الـ Cache
        {
            std::lock_guard<std::mutex> lock(m_cacheMutex);
            m_cache[processId] = report;
        }

        // التحقق من وقت التنفيذ
        auto duration = std::chrono::steady_clock::now() - startTime;
        if (duration > std::chrono::milliseconds(m_config.maxAnalysisTimeMs)) {
            report.indicators.push_back("Analysis timeout - partial results");
        }

        return true;
    }

    bool ProcessAnalyzer::QuickAnalyze(DWORD processId, ProcessAnalysisReport& report) {
        // نسخة خفيفة: فقط Basic Info + Module Count + Signature Check

        if (!GetBasicProcessInfo(processId, report)) {
            return false;
        }

        report.processId = processId;

        // فحص سريع للـ Modules (فقط الأعداد والتوقيعات)
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, processId);
        if (hProcess) {
            HMODULE hMods[1024];
            DWORD cbNeeded;

            if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                    ModuleInfo mod;
                    wchar_t szModName[MAX_PATH];

                    if (GetModuleFileNameExW(hProcess, hMods[i], szModName,
                        sizeof(szModName) / sizeof(wchar_t))) {
                        mod.name = GetFileNameFromPath(szModName);
                        mod.fullPath = szModName;
                        mod.baseAddress = hMods[i];

                        // فقط التوقيع للملفات غير النظامية
                        if (m_config.checkDigitalSignatures) {
                            // TODO: VerifyDigitalSignature
                        }

                        report.loadedModules.push_back(mod);
                    }
                }
            }

            CloseHandle(hProcess);
        }

        // تقييم سريع
        report.threatScore = CalculateHeuristicScore(report);
        report.isMalicious = (report.threatScore >= m_config.threatThreshold);

        return true;
    }

    std::vector<ProcessAnalysisReport> ProcessAnalyzer::AnalyzeAllProcesses() {
        std::vector<ProcessAnalysisReport> reports;

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return reports;
        }

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                ProcessAnalysisReport report;
                if (QuickAnalyze(pe.th32ProcessID, report)) {
                    reports.push_back(report);
                }
            } while (Process32NextW(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
        return reports;
    }

    bool ProcessAnalyzer::GetBasicProcessInfo(DWORD processId, ProcessAnalysisReport& report) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, processId);
        if (!hProcess) {
            return false;
        }

        // اسم الملف التنفيذي
        wchar_t processPath[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, processPath, &size)) {
            report.executablePath = processPath;
            report.processName = GetFileNameFromPath(processPath);
        }
        else {
            report.processName = L"Unknown";
        }

        // سطر الأوامر
        GetCommandLine(processId, report.commandLine);

        // العملية الأب
        GetParentProcessId(processId, report.parentProcessId);

        if (report.parentProcessId != 0) {
            HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, report.parentProcessId);
            if (hParent) {
                wchar_t parentPath[MAX_PATH];
                DWORD parentSize = MAX_PATH;
                if (QueryFullProcessImageNameW(hParent, 0, parentPath, &parentSize)) {
                    report.parentProcessName = GetFileNameFromPath(parentPath);
                }
                CloseHandle(hParent);
            }
        }

        // استخدام الذاكرة
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
            report.memoryUsage = pmc.WorkingSetSize;
        }

        // هل Elevated؟
        HANDLE hToken;
        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD returnLength;
            if (GetTokenInformation(hToken, TokenElevation, &elevation,
                sizeof(elevation), &returnLength)) {
                report.isElevated = elevation.TokenIsElevated != 0;
            }
            CloseHandle(hToken);
        }

        // هل Critical System Process؟
        report.isCriticalSystemProcess = IsCriticalSystemProcess(report.processName);

        CloseHandle(hProcess);
        return true;
    }

    bool ProcessAnalyzer::GetCommandLine(DWORD processId, std::wstring& cmdLine) {
        // استخدام NtQueryInformationProcess للحصول على PEB ثم قراءة CommandLine
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, processId);
        if (!hProcess) return false;

        // Stub: في التنفيذ الكامل، نستخدم NtQueryInformationProcess مع ProcessBasicInformation
        // ثم نقرأ RTL_USER_PROCESS_PARAMETERS.CommandLine من ذاكرة العملية

        // هذا يتطلب structures من ntdll.h

        cmdLine = L""; // TODO: Implementation
        CloseHandle(hProcess);
        return false; // Stub
    }

    bool ProcessAnalyzer::GetParentProcessId(DWORD processId, DWORD& parentId) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);

        bool found = false;
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == processId) {
                    parentId = pe.th32ParentProcessID;
                    found = true;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
        return found;
    }

    bool ProcessAnalyzer::EnumerateModules(DWORD processId, std::vector<ModuleInfo>& modules) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, processId);
        if (!hProcess) return false;

        HMODULE hMods[1024];
        DWORD cbNeeded;

        if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                ModuleInfo mod;
                wchar_t szModName[MAX_PATH];
                MODULEINFO modInfo;

                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, MAX_PATH) &&
                    GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {

                    mod.name = GetFileNameFromPath(szModName);
                    mod.fullPath = szModName;
                    mod.baseAddress = modInfo.lpBaseOfDll;
                    mod.size = modInfo.SizeOfImage;

                    // تحليل Module
                    AnalyzeModule(mod);

                    modules.push_back(mod);
                }
            }
        }

        CloseHandle(hProcess);
        return true;
    }

    void ProcessAnalyzer::AnalyzeModule(ModuleInfo& module) {
        // 1. التحقق من القائمة السوداء
        // TODO: حساب hash والتحقق

        // 2. التحقق من التوقيع الرقمي
        if (m_config.checkDigitalSignatures) {
            WINTRUST_FILE_INFO fileInfo = { 0 };
            WINTRUST_DATA trustData = { 0 };
            GUID actionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

            fileInfo.cbStruct = sizeof(fileInfo);
            fileInfo.pcwszFilePath = module.fullPath.c_str();

            trustData.cbStruct = sizeof(trustData);
            trustData.dwUIChoice = WTD_UI_NONE;
            trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
            trustData.dwUnionChoice = WTD_CHOICE_FILE;
            trustData.pFile = &fileInfo;
            trustData.dwStateAction = WTD_STATEACTION_VERIFY;

            LONG result = WinVerifyTrust(NULL, &actionGUID, &trustData);
            module.isSigned = (result == ERROR_SUCCESS);

            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NULL, &actionGUID, &trustData);
        }

        // 3. التحقق من الـ Path مشبوه
        static const std::vector<std::wstring> suspiciousPaths = {
            L"\\Temp\\", L"\\tmp\\", L"\\AppData\\Local\\Temp\\",
            L"\\Downloads\\", L"\\Desktop\\"
        };

        for (const auto& susPath : suspiciousPaths) {
            if (module.fullPath.find(susPath) != std::wstring::npos) {
                module.isSuspicious = true;
                module.threatInfo = "Loaded from temporary directory";
                break;
            }
        }

        // 4. التحقق من الاسم المزدوج (Double Extension)
        std::wstring lowerName = module.name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

        if (lowerName.find(L".exe.dll") != std::wstring::npos ||
            lowerName.find(L".pdf.exe") != std::wstring::npos) {
            module.isSuspicious = true;
            module.threatInfo = "Double extension detected";
        }
    }

    bool ProcessAnalyzer::EnumerateMemoryRegions(DWORD processId,
        std::vector<MemoryRegion>& regions) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, processId);
        if (!hProcess) return false;

        MEMORY_BASIC_INFORMATION mbi;
        PVOID address = 0;

        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
            MemoryRegion region;
            region.baseAddress = mbi.BaseAddress;
            region.size = mbi.RegionSize;
            region.state = mbi.State;
            region.protect = mbi.Protect;
            region.type = mbi.Type;

            region.isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            region.isWritable = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE |
                PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;

            // حساب Entropy للمناطق القابلة للتنفيذ والمخصصة
            if (mbi.State == MEM_COMMIT && region.isExecutable && mbi.Type == MEM_PRIVATE) {
                float entropy = CalculateMemoryEntropy(hProcess, mbi.BaseAddress,
                    std::min((SIZE_T)4096, mbi.RegionSize));
                std::stringstream ss;
                ss << std::fixed << std::setprecision(2) << entropy;
                region.entropy = ss.str();
            }
            else {
                region.entropy = "N/A";
            }

            regions.push_back(region);

            address = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
        }

        CloseHandle(hProcess);
        return true;
    }

    float ProcessAnalyzer::CalculateMemoryEntropy(HANDLE hProcess, PVOID address, SIZE_T size) {
        std::vector<BYTE> buffer(size);
        SIZE_T bytesRead;

        if (!ReadProcessMemory(hProcess, address, buffer.data(), size, &bytesRead)) {
            return 0.0f;
        }

        // حساب Entropy بتطبيق Shannon Entropy
        std::map<BYTE, int> frequencies;
        for (BYTE b : buffer) {
            frequencies[b]++;
        }

        float entropy = 0.0f;
        float len = static_cast<float>(bytesRead);

        for (const auto& [byte, count] : frequencies) {
            float p = static_cast<float>(count) / len;
            if (p > 0) {
                entropy -= p * std::log2(p);
            }
        }

        return entropy;
    }

    bool ProcessAnalyzer::DetectInjection(DWORD processId, std::vector<std::string>& details) {
        std::vector<MemoryRegion> regions;
        if (!EnumerateMemoryRegions(processId, regions)) {
            return false;
        }

        bool found = false;

        for (const auto& region : regions) {
            // مؤشرات Injection:

            // 1. Memory Private + Executable + High Entropy
            if (region.type == MEM_PRIVATE && region.isExecutable && !region.entropy.empty()) {
                float entropy = std::stof(region.entropy);
                if (entropy > 7.0f) { // High entropy = likely encrypted/encoded shellcode
                    details.push_back("Executable private memory with high entropy: " +
                        region.entropy + " at " + std::to_string((ULONG_PTR)region.baseAddress));
                    found = true;
                }
            }

            // 2. Executable + Writable (RWX) - شائع في Injection
            if (region.isExecutable && region.isWritable && region.type == MEM_PRIVATE) {
                details.push_back("RWX memory region detected at " +
                    std::to_string((ULONG_PTR)region.baseAddress));
                found = true;
            }

            // 3. Memory committed outside of modules (حاجة لمقارنة مع Modules)
            // TODO: التحقق إذا كان العنوان خارج نطاق أي Module معروف
        }

        return found;
    }

    bool ProcessAnalyzer::DetectProcessHollowing(DWORD processId) {
        // Process Hollowing: إنشاء عملية معلقة، استبدال الصورة، ثم الاستئناف
        // مؤشرات:
        // 1. العملية بدأت معلقة (CREATE_SUSPENDED)
        // 2. UnmapViewOfSection على العملية نفسها
        // 3. WriteProcessMemory لـ ImageBase
        // 4. SetThreadContext
        // 5. ResumeThread

        // TODO: مراقبة هذه APIs عبر ETW أو Hooking

        // تحقق بديل: مقارنة Image في الذاكرة مع Image على القرص
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, processId);
        if (!hProcess) return false;

        // قراءة DOS/NT Headers من الذاكرة والمقارنة مع الملف على القرص
        // TODO: Implementation

        CloseHandle(hProcess);
        return false; // Stub
    }

    bool ProcessAnalyzer::DetectAPIHooking(DWORD processId,
        std::map<std::string, bool>& hookedModules) {
        // فحص IAT (Import Address Table) للتعرف على Hooks

        // TODO: Implementation يتطلب:
        // 1. قراءة PE Headers
        // 2. الاستعراض على Import Directory
        // 3. مقارنة عناوين Functions مع العناوين الحقيقية في DLLs
        // 4. التحقق من Inline Hooks (البحث عن patterns مثل JMP, PUSH RET)

        return false; // Stub
    }

    float ProcessAnalyzer::CalculateHeuristicScore(const ProcessAnalysisReport& report) {
        float score = 0.0f;

        // 1. Parent-Child Relationship مشبوه
        static const std::map<std::wstring, std::vector<std::wstring>> suspiciousRelations = {
            {L"winword.exe", {L"cmd.exe", L"powershell.exe", L"wscript.exe"}},
            {L"excel.exe", {L"cmd.exe", L"powershell.exe"}},
            {L"explorer.exe", {L"mshta.exe", L"regsvr32.exe"}}
        };

        auto it = suspiciousRelations.find(report.parentProcessName);
        if (it != suspiciousRelations.end()) {
            for (const auto& child : it->second) {
                if (report.processName == child) {
                    score += 0.4f;
                    break;
                }
            }
        }

        // 2. Modules مشبوهة
        for (const auto& mod : report.loadedModules) {
            if (mod.isSuspicious) {
                score += 0.3f;
            }
            if (!mod.isSigned && mod.name.find(L".dll") != std::wstring::npos) {
                score += 0.1f;
            }
        }

        // 3. Memory مشبوه
        if (report.behavior.injectedCode) {
            score += 0.5f;
        }

        // 4. Escalation
        if (report.behavior.attemptedEscalation) {
            score += 0.3f;
        }

        // 5. Path مشبوه
        if (report.executablePath.find(L"\\Temp\\") != std::wstring::npos ||
            report.executablePath.find(L"\\AppData\\") != std::wstring::npos) {
            score += 0.2f;
        }

        // 6. Entropy عالي في الاسم (تجنب detection)
        // TODO: حساب entropy لـ processName

        return std::min(score, 1.0f);
    }

    float ProcessAnalyzer::CalculateAIScore(const ProcessAnalysisReport& report) {
        // TODO: ربط مع AIDetector.cpp
        // 1. استخراج Features من Report
        // 2. تجهيز Feature Vector
        // 3. استدعاء ONNX Model

        // Feature Vector مؤقت:
        std::vector<float> features = {
            static_cast<float>(report.loadedModules.size()) / 100.0f,
            static_cast<float>(report.memoryRegions.size()) / 1000.0f,
            report.behavior.injectedCode ? 1.0f : 0.0f,
            report.isElevated ? 1.0f : 0.0f,
            static_cast<float>(report.threadCount) / 100.0f
        };

        // TODO: AIDetector::GetInstance().Predict(features)
        return 0.0f; // Stub
    }

    void ProcessAnalyzer::CheckSuspiciousBehaviors(ProcessAnalysisReport& report) {
        // فحص سلوكيات محددة من MITRE ATT&CK

        // 1. Process Injection مؤشرات
        if (report.behavior.injectedCode) {
            report.detectedTechniques.push_back(AttackTechnique::PROCESS_INJECTION);
        }

        // 2. Privilege Escalation
        if (report.isElevated &&
            (report.processName == L"cmd.exe" || report.processName == L"powershell.exe")) {
            report.detectedTechniques.push_back(AttackTechnique::PRIVILEGE_ESCALATION);
        }

        // 3. Defense Evasion - Masquerading
        std::wstring lowerName = report.processName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

        if (lowerName.find(L"svchost") != std::wstring::npos &&
            report.executablePath.find(L"\\Windows\\System32\\") == std::wstring::npos) {
            report.detectedTechniques.push_back(AttackTechnique::DEFENSE_EVASION);
            report.indicators.push_back("Masquerading as svchost.exe from non-system location");
        }

        // 4. Persistence
        if (report.executablePath.find(L"\\Startup\\") != std::wstring::npos ||
            report.commandLine.find(L"reg add") != std::wstring::npos) {
            report.detectedTechniques.push_back(AttackTechnique::PERSISTENCE);
        }
    }

    bool ProcessAnalyzer::IsCriticalSystemProcess(const std::wstring& processName) {
        static const std::set<std::wstring> critical = {
            L"System", L"Registry", L"smss.exe", L"csrss.exe", L"wininit.exe",
            L"services.exe", L"lsass.exe", L"svchost.exe", L"crss.exe"
        };
        return critical.find(processName) != critical.end();
    }

    bool ProcessAnalyzer::IsWhitelisted(const std::wstring& processName) {
        std::shared_lock<std::shared_mutex> lock(m_listMutex);
        return m_whitelistedProcesses.find(processName) != m_whitelistedProcesses.end();
    }

    bool ProcessAnalyzer::IsBlacklisted(const std::string& moduleHash) {
        std::shared_lock<std::shared_mutex> lock(m_listMutex);
        return m_blacklistedModules.find(moduleHash) != m_blacklistedModules.end();
    }

    void ProcessAnalyzer::WhitelistProcess(const std::wstring& processName) {
        std::unique_lock<std::shared_mutex> lock(m_listMutex);
        m_whitelistedProcesses.insert(processName);
    }

    void ProcessAnalyzer::BlacklistModule(const std::string& moduleHash) {
        std::unique_lock<std::shared_mutex> lock(m_listMutex);
        m_blacklistedModules.insert(moduleHash);
    }

    std::vector<ProcessAnalysisReport> ProcessAnalyzer::GetSuspiciousProcesses() {
        auto allProcesses = AnalyzeAllProcesses();
        std::vector<ProcessAnalysisReport> suspicious;

        for (auto& report : allProcesses) {
            if (report.isMalicious || report.threatScore > 0.5f) {
                suspicious.push_back(report);
            }
        }

        return suspicious;
    }

    bool ProcessAnalyzer::StartMonitoringProcess(DWORD processId) {
        std::lock_guard<std::mutex> lock(m_monitorMutex);

        if (m_monitoredProcesses.find(processId) != m_monitoredProcesses.end()) {
            return false; // Already monitoring
        }

        auto thread = std::make_unique<std::thread>(&ProcessAnalyzer::MonitorThreadFunc,
            this, processId);
        m_monitoredProcesses[processId] = std::move(thread);
        return true;
    }

    void ProcessAnalyzer::StopMonitoringProcess(DWORD processId) {
        std::lock_guard<std::mutex> lock(m_monitorMutex);

        auto it = m_monitoredProcesses.find(processId);
        if (it != m_monitoredProcesses.end()) {
            if (it->second && it->second->joinable()) {
                it->second->detach(); // TODO: استخدام atomic flag للإيقاف النظيف
            }
            m_monitoredProcesses.erase(it);
        }
    }

    void ProcessAnalyzer::MonitorThreadFunc(DWORD processId) {
        // مراقبة مستمرة لعملية معينة
        // TODO: استخدام ETW للحصول على أحداث العملية في الوقت الفعلي

        while (!m_stopRequested.load()) {
            // فحص دوري كل 2 ثانية
            std::this_thread::sleep_for(std::chrono::seconds(2));

            // التحقق من أن العملية لا تزال موجودة
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
            if (!hProcess) {
                break; // Process terminated
            }
            CloseHandle(hProcess);

            // فحص جديد
            ProcessAnalysisReport report;
            if (AnalyzeProcess(processId, report)) {
                if (report.isMalicious && report.threatScore > 0.8f) {
                    // TODO: إعلام RealTimeMonitor أو Quarantine
                    // إرسال حدث خطير
                }
            }
        }

        // تنظيف
        std::lock_guard<std::mutex> lock(m_monitorMutex);
        m_monitoredProcesses.erase(processId);
    }

    // ==================== وظائف Static مساعدة ====================

    std::wstring ProcessAnalyzer::GetFileNameFromPath(const std::wstring& path) {
        size_t pos = path.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            return path.substr(pos + 1);
        }
        return path;
    }

    std::string ProcessAnalyzer::BytesToHexString(const BYTE* data, size_t len) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < len; ++i) {
            ss << std::setw(2) << static_cast<int>(data[i]);
        }
        return ss.str();
    }

    bool ProcessAnalyzer::ReadProcessMemorySafe(HANDLE hProcess, LPCVOID address,
        LPVOID buffer, SIZE_T size) {
        SIZE_T bytesRead;
        return ReadProcessMemory(hProcess, address, buffer, size, &bytesRead) &&
            bytesRead == size;
    }

} // namespace AIAntivirus