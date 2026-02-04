// ProcessAnalyzer.cpp - Core Module
// محلل العمليات وكشف السلوك الضار

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <thread>
#include <mutex>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <iphlpapi.h>
#include <netioapi.h>

// ربط مكتبات الشبكة
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")

// ==================== هيكل معلومات العملية ====================

struct ProcessInfo {
    DWORD pid;
    DWORD parentPid;
    std::wstring name;
    std::wstring path;
    std::wstring commandLine;
    SIZE_T memoryUsage;
    SIZE_T virtualMemory;
    DWORD threads;
    DWORD handles;
    std::chrono::system_clock::time_point startTime;
    bool isSigned;
    bool isSystem;
    bool isSuspicious;
    std::vector<std::string> loadedModules;
    std::vector<std::string> networkConnections;
    float riskScore;
};

// ==================== هيكل السلوك المشبوه ====================

struct SuspiciousBehavior {
    enum class Type {
        PROCESS_INJECTION,      // حقن العمليات
        MEMORY_MANIPULATION,    // التلاعب بالذاكرة
        PERSISTENCE_MECHANISM,  // آليات البقاء
        PRIVILEGE_ESCALATION,   // رفع الصلاحيات
        NETWORK_SUSPICIOUS,     // شبكة مشبوهة
        CODE_INJECTION,         // حقن كود
        ANTI_DEBUGGING,         // مكافحة التصحيح
        RANSOMWARE_PATTERN,     // نمط فدية
        KEYLOGGER_PATTERN,      // نمط التجسس
        ROOTKIT_BEHAVIOR        // سلوك روتكيت
    };

    Type type;
    DWORD pid;
    std::string description;
    std::chrono::system_clock::time_point timestamp;
    int severity; // 1-10
};

// ==================== محلل العمليات الرئيسي ====================

class ProcessAnalyzer {
private:
    std::map<DWORD, ProcessInfo> processCache;
    std::vector<SuspiciousBehavior> detectedBehaviors;
    std::mutex cacheMutex;
    std::mutex behaviorMutex;
    std::atomic<bool> isMonitoring{ false };
    std::thread monitorThread;

    // قواعد الكشف عن السلوك الضار
    struct DetectionRule {
        std::string name;
        std::function<bool(const ProcessInfo&)> check;
        int severity;
        SuspiciousBehavior::Type type;
    };
    std::vector<DetectionRule> rules;

public:
    ProcessAnalyzer() {
        std::cout << "[INIT] ProcessAnalyzer Engine Loading...\n";
        initializeDetectionRules();
        refreshProcessList();
    }

    ~ProcessAnalyzer() {
        stopMonitoring();
        std::cout << "[SHUTDOWN] ProcessAnalyzer Engine Stopped\n";
    }

    // ==================== جمع المعلومات ====================

    void refreshProcessList() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            std::cerr << "[ERROR] Failed to create process snapshot\n";
            return;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe32)) {
            std::lock_guard<std::mutex> lock(cacheMutex);
            processCache.clear();

            do {
                ProcessInfo info;
                info.pid = pe32.th32ProcessID;
                info.parentPid = pe32.th32ParentProcessID;
                info.name = pe32.szExeFile;
                info.riskScore = 0.0f;
                info.isSuspicious = false;
                info.isSystem = false;

                // تجاهل System Idle Process
                if (info.pid == 0) continue;

                // الحصول على معلومات إضافية
                getDetailedProcessInfo(info);

                // تحليل السلوك
                analyzeProcessBehavior(info);

                processCache[info.pid] = info;

            } while (Process32NextW(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
    }

    void getDetailedProcessInfo(ProcessInfo& info) {
        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, info.pid
        );

        if (hProcess == NULL) {
            // لا يمكن الوصول (نظام أو محمي)
            info.isSystem = true;
            return;
        }

        // المسار الكامل
        WCHAR path[MAX_PATH];
        if (GetModuleFileNameExW(hProcess, NULL, path, MAX_PATH)) {
            info.path = path;
        }

        // استخدام الذاكرة
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
            info.memoryUsage = pmc.WorkingSetSize;
            info.virtualMemory = pmc.PagefileUsage;
        }

        // عدد المقابض والخيوط
        info.handles = GetProcessHandleCount(hProcess, &info.handles) ? info.handles : 0;

        // معلومات الأداء
        FILETIME createTime, exitTime, kernelTime, userTime;
        if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
            ULARGE_INTEGER ull;
            ull.LowPart = createTime.dwLowDateTime;
            ull.HighPart = createTime.dwHighDateTime;

            // تحويل Windows FILETIME إلى time_point
            auto epoch = std::chrono::system_clock::from_time_t(0);
            auto fileTime = std::chrono::system_clock::time_point(
                std::chrono::duration_cast<std::chrono::system_clock::duration>(
                    std::chrono::nanoseconds((ull.QuadPart - 116444736000000000ULL) * 100)
                )
            );
            info.startTime = fileTime;
        }

        // التحقق من التوقيع الرقمي
        info.isSigned = verifyDigitalSignature(info.path);

        // سطر الأوامر
        info.commandLine = getProcessCommandLine(info.pid);

        // الوحدات المحملة
        enumerateModules(hProcess, info);

        CloseHandle(hProcess);

        // الاتصالات الشبكية
        getNetworkConnections(info);
    }

    // ==================== تحليل السلوك ====================

    void analyzeProcessBehavior(ProcessInfo& info) {
        // تطبيق قواعد الكشف
        for (const auto& rule : rules) {
            if (rule.check(info)) {
                info.isSuspicious = true;
                info.riskScore += rule.severity * 1.5f;

                SuspiciousBehavior behavior;
                behavior.type = rule.type;
                behavior.pid = info.pid;
                behavior.description = rule.name + " detected in: " +
                    std::string(info.name.begin(), info.name.end());
                behavior.timestamp = std::chrono::system_clock::now();
                behavior.severity = rule.severity;

                {
                    std::lock_guard<std::mutex> lock(behaviorMutex);
                    detectedBehaviors.push_back(behavior);
                }

                logThreat(behavior, info);
            }
        }

        // تقييد النتيجة بين 0 و 100
        info.riskScore = std::min(100.0f, info.riskScore);
    }

    void initializeDetectionRules() {
        // 1. حقن العمليات: فتح عمليات أخرى للكتابة
        rules.push_back({
            "Process Injection Attempt",
            [](const ProcessInfo& info) {
                // التحقق من وجود أدوات حقن معروفة في الوحدات
                std::vector<std::wstring> injectionTools = {
                    L"CreateRemoteThread", L"WriteProcessMemory",
                    L"SetWindowsHookEx", L"NtMapViewOfSection"
                };
                for (const auto& mod : info.loadedModules) {
                    std::wstring wmod(mod.begin(), mod.end());
                    for (const auto& tool : injectionTools) {
                        if (wmod.find(tool) != std::wstring::npos) return true;
                    }
                }
                return false;
            },
            9,
            SuspiciousBehavior::Type::PROCESS_INJECTION
            });

        // 2. رفع الصلاحيات
        rules.push_back({
            "Privilege Escalation",
            [](const ProcessInfo& info) {
                // عمليات نظامية مع مسار غير نظامي
                if (info.isSystem && !info.path.empty()) {
                    std::wstring wpath = info.path;
                    std::transform(wpath.begin(), wpath.end(), wpath.begin(), ::tolower);
                    return wpath.find(L"\\windows\\") == std::wstring::npos &&
                           wpath.find(L"\\program files") == std::wstring::npos;
                }
                return false;
            },
            10,
            SuspiciousBehavior::Type::PRIVILEGE_ESCALATION
            });

        // 3. البقاء في النظام
        rules.push_back({
            "Persistence Mechanism",
            [](const ProcessInfo& info) {
                std::wstring cmd = info.commandLine;
                std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);
                return cmd.find(L"run") != std::wstring::npos ||
                       cmd.find(L"startuo") != std::wstring::npos ||
                       cmd.find(L"reg add") != std::wstring::npos ||
                       cmd.find(L"schtasks") != std::wstring::npos;
            },
            7,
            SuspiciousBehavior::Type::PERSISTENCE_MECHANISM
            });

        // 4. نمط الفدية
        rules.push_back({
            "Ransomware Pattern",
            [](const ProcessInfo& info) {
                // كتابة مكثفة على الملفات مع تغيير الامتدادات
                if (info.memoryUsage > 100 * 1024 * 1024) { // > 100MB
                    std::wstring name = info.name;
                    std::transform(name.begin(), name.end(), name.begin(), ::tolower);
                    return name.find(L"encrypt") != std::wstring::npos ||
                           name.find(L"crypt") != std::wstring::npos ||
                           name.find(L"lock") != std::wstring::npos;
                }
                return false;
            },
            10,
            SuspiciousBehavior::Type::RANSOMWARE_PATTERN
            });

        // 5. اتصالات شبكية مشبوهة
        rules.push_back({
            "Suspicious Network Activity",
            [](const ProcessInfo& info) {
                // عمليات غير معروفة مع اتصالات خارجية
                if (!info.networkConnections.empty()) {
                    bool isKnownBrowser = info.name.find(L"chrome") != std::wstring::npos ||
                                        info.name.find(L"firefox") != std::wstring::npos ||
                                        info.name.find(L"edge") != std::wstring::npos ||
                                        info.name.find(L"svchost") != std::wstring::npos;
                    return !isKnownBrowser && !info.isSigned;
                }
                return false;
            },
            8,
            SuspiciousBehavior::Type::NETWORK_SUSPICIOUS
            });

        // 6. مكافحة التصحيح
        rules.push_back({
            "Anti-Debugging",
            [](const ProcessInfo& info) {
                std::vector<std::wstring> antiDebug = {
                    L"IsDebuggerPresent", L"CheckRemoteDebuggerPresent",
                    L"NtQueryInformationProcess", L"OutputDebugString"
                };
                for (const auto& mod : info.loadedModules) {
                    std::wstring wmod(mod.begin(), mod.end());
                    for (const auto& api : antiDebug) {
                        if (wmod.find(api) != std::wstring::npos) return true;
                    }
                }
                return false;
            },
            6,
            SuspiciousBehavior::Type::ANTI_DEBUGGING
            });

        // 7. عمليات مشفرة أو مشبوهة
        rules.push_back({
            "Obfuscated Process",
            [](const ProcessInfo& info) {
                std::wstring name = info.name;
                // أسماء عشوائية مثل svch0st.exe بدل svchost.exe
                if (name.length() > 4) {
                    int digits = 0;
                    for (wchar_t c : name) {
                        if (iswdigit(c)) digits++;
                    }
                    return digits > 2; // أكثر من رقمين في الاسم
                }
                return false;
            },
            5,
            SuspiciousBehavior::Type::CODE_INJECTION
            });
    }

    // ==================== أدوات التحليل ====================

    bool verifyDigitalSignature(const std::wstring& filePath) {
        if (filePath.empty()) return false;

        WINTRUST_FILE_INFO fileInfo = {};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = filePath.c_str();
        fileInfo.hFile = NULL;
        fileInfo.pgKnownSubject = NULL;

        GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA trustData = {};
        trustData.cbStruct = sizeof(trustData);
        trustData.pPolicyCallbackData = NULL;
        trustData.pSIPClientData = NULL;
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.hWVTStateData = NULL;
        trustData.pwszURLReference = NULL;
        trustData.dwProvFlags = WTD_SAFER_FLAG;
        trustData.dwUIContext = 0;

        LONG result = WinVerifyTrust(NULL, &actionGuid, &trustData);

        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &actionGuid, &trustData);

        return result == ERROR_SUCCESS;
    }

    std::wstring getProcessCommandLine(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return L"";

        // الحصول على PEB (Process Environment Block)
        PROCESS_BASIC_INFORMATION pbi;
        ULONG returnLength;

        typedef NTSTATUS(WINAPI* NtQueryInfoPtr)(
            HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG
            );

        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        auto NtQueryInformationProcess = (NtQueryInfoPtr)GetProcAddress(ntdll, "NtQueryInformationProcess");

        if (!NtQueryInformationProcess) {
            CloseHandle(hProcess);
            return L"";
        }

        NTSTATUS status = NtQueryInformationProcess(
            hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength
        );

        if (status != 0) {
            CloseHandle(hProcess);
            return L"";
        }

        // قراءة كتلة البيئة من PEB
        // (معقد جداً، نستخدم طريقة أبسط هنا)

        // طريقة بديلة: WMI أو سطر الأوامر من GetCommandLine() للعملية نفسها
        // للتبسيط نعيد فارغ
        CloseHandle(hProcess);
        return L"";
    }

    void enumerateModules(HANDLE hProcess, ProcessInfo& info) {
        HMODULE hMods[1024];
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char modName[MAX_PATH];
                if (GetModuleFileNameExA(hProcess, hMods[i], modName, sizeof(modName))) {
                    info.loadedModules.push_back(modName);
                }
            }
        }
    }

    void getNetworkConnections(ProcessInfo& info) {
        // الحصول على اتصالات TCP
        MIB_TCPTABLE_OWNER_PID* pTcpTable = NULL;
        DWORD dwSize = 0;
        DWORD dwRetVal = 0;

        // الحصول على الحجم المطلوب
        GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(dwSize);

        if (pTcpTable != NULL) {
            dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE,
                AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

            if (dwRetVal == NO_ERROR) {
                for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                    if (pTcpTable->table[i].dwOwningPid == info.pid) {
                        char localAddr[16], remoteAddr[16];

                        inet_ntop(AF_INET, &pTcpTable->table[i].dwLocalAddr,
                            localAddr, 16);
                        inet_ntop(AF_INET, &pTcpTable->table[i].dwRemoteAddr,
                            remoteAddr, 16);

                        std::string conn = std::string(localAddr) + ":" +
                            std::to_string(ntohs((u_short)pTcpTable->table[i].dwLocalPort)) +
                            " -> " + remoteAddr + ":" +
                            std::to_string(ntohs((u_short)pTcpTable->table[i].dwRemotePort));

                        info.networkConnections.push_back(conn);
                    }
                }
            }
            free(pTcpTable);
        }
    }

    // ==================== المراقبة المستمرة ====================

    void startMonitoring(int intervalSeconds = 5) {
        if (isMonitoring) return;

        isMonitoring = true;
        monitorThread = std::thread([this, intervalSeconds]() {
            while (isMonitoring) {
                refreshProcessList();
                detectNewProcesses();
                checkProcessAnomalies();
                std::this_thread::sleep_for(std::chrono::seconds(intervalSeconds));
            }
            });

        std::cout << "[ACTIVE] Process monitoring started ("
            << intervalSeconds << "s interval)\n";
    }

    void stopMonitoring() {
        isMonitoring = false;
        if (monitorThread.joinable()) {
            monitorThread.join();
        }
    }

    void detectNewProcesses() {
        static std::set<DWORD> knownProcesses;
        std::set<DWORD> currentProcesses;

        {
            std::lock_guard<std::mutex> lock(cacheMutex);
            for (const auto& [pid, info] : processCache) {
                currentProcesses.insert(pid);

                if (knownProcesses.find(pid) == knownProcesses.end()) {
                    // عملية جديدة
                    std::wcout << L"[NEW PROCESS] PID: " << pid
                        << L" | " << info.name;

                    if (info.isSuspicious) {
                        std::wcout << L" [SUSPICIOUS]";
                    }
                    std::wcout << L"\n";
                }
            }
        }

        // التحقق من العمليات المنتهية
        for (const auto& pid : knownProcesses) {
            if (currentProcesses.find(pid) == currentProcesses.end()) {
                std::cout << "[TERMINATED] PID: " << pid << "\n";
            }
        }

        knownProcesses = currentProcesses;
    }

    void checkProcessAnomalies() {
        // التحقق من استهلاك الموارد غير الطبيعي
        std::lock_guard<std::mutex> lock(cacheMutex);

        for (auto& [pid, info] : processCache) {
            // استهلاك عالي للذاكرة
            if (info.memoryUsage > 1024 * 1024 * 1024) { // > 1GB
                std::wcout << L"[WARNING] High memory usage: " << info.name
                    << L" (" << (info.memoryUsage / 1024 / 1024) << L" MB)\n";
            }

            // عمليات بدون توقيع رقمي
            if (!info.isSigned && !info.isSystem && !info.path.empty()) {
                bool isKnownGood = false;
                std::vector<std::wstring> knownGood = {
                    L"chrome.exe", L"firefox.exe", L"code.exe", L"notepad++.exe"
                };
                for (const auto& good : knownGood) {
                    if (info.name == good) {
                        isKnownGood = true;
                        break;
                    }
                }

                if (!isKnownGood) {
                    std::wcout << L"[WARNING] Unsigned process: " << info.name
                        << L" | Path: " << info.path << L"\n";
                }
            }
        }
    }

    // ==================== التحكم والتقارير ====================

public:
    bool terminateProcess(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess == NULL) {
            std::cerr << "[ERROR] Cannot open process for termination\n";
            return false;
        }

        BOOL result = TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);

        if (result) {
            std::cout << "[ACTION] Terminated process PID: " << pid << "\n";
        }

        return result;
    }

    bool suspendProcess(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
        if (!hProcess) return false;

        typedef LONG(NTAPI* NtSuspendProcess)(HANDLE);
        HMODULE ntdll = GetModuleHandleA("ntdll");
        auto pfnSuspend = (NtSuspendProcess)GetProcAddress(ntdll, "NtSuspendProcess");

        LONG result = pfnSuspend(hProcess);
        CloseHandle(hProcess);

        return result == 0;
    }

    void showProcessTree() {
        std::lock_guard<std::mutex> lock(cacheMutex);

        std::cout << "\n=== PROCESS TREE ===\n";
        std::cout << std::left << std::setw(8) << "PID"
            << std::setw(8) << "PPID"
            << std::setw(25) << "Name"
            << std::setw(10) << "Memory"
            << std::setw(8) << "Risk"
            << "Status\n";
        std::cout << std::string(80, '-') << "\n";

        for (const auto& [pid, info] : processCache) {
            if (info.isSystem) continue; // تجاهل عمليات النظام

            std::string name(info.name.begin(), info.name.end());
            if (name.length() > 24) name = name.substr(0, 21) + "...";

            std::cout << std::left << std::setw(8) << pid
                << std::setw(8) << info.parentPid
                << std::setw(25) << name
                << std::setw(10) << (info.memoryUsage / 1024 / 1024)
                << std::setw(8) << (int)info.riskScore
                << (info.isSuspicious ? "THREAT" :
                    (info.isSigned ? "Signed" : "Unknown")) << "\n";
        }
        std::cout << "====================\n";
    }

    std::vector<SuspiciousBehavior> getThreats(int minSeverity = 5) {
        std::lock_guard<std::mutex> lock(behaviorMutex);
        std::vector<SuspiciousBehavior> threats;

        for (const auto& behavior : detectedBehaviors) {
            if (behavior.severity >= minSeverity) {
                threats.push_back(behavior);
            }
        }

        return threats;
    }

    void exportReport(const std::string& filename) {
        std::ofstream report(filename);
        report << "=== PROCESS ANALYSIS REPORT ===\n\n";

        {
            std::lock_guard<std::mutex> lock(cacheMutex);
            report << "Total Processes: " << processCache.size() << "\n";
            report << "Suspicious Processes: " <<
                std::count_if(processCache.begin(), processCache.end(),
                    [](const auto& p) { return p.second.isSuspicious; }) << "\n\n";
        }

        {
            std::lock_guard<std::mutex> lock(behaviorMutex);
            report << "=== Detected Behaviors ===\n";
            for (const auto& behavior : detectedBehaviors) {
                report << "[" << behavior.severity << "/10] "
                    << behavior.description << "\n";
            }
        }

        report.close();
        std::cout << "[INFO] Process report saved: " << filename << "\n";
    }

private:
    void logThreat(const SuspiciousBehavior& behavior, const ProcessInfo& info) {
        const char* typeStr;
        switch (behavior.type) {
        case SuspiciousBehavior::Type::PROCESS_INJECTION: typeStr = "INJECTION"; break;
        case SuspiciousBehavior::Type::RANSOMWARE_PATTERN: typeStr = "RANSOMWARE"; break;
        case SuspiciousBehavior::Type::PRIVILEGE_ESCALATION: typeStr = "PRIVESC"; break;
        case SuspiciousBehavior::Type::NETWORK_SUSPICIOUS: typeStr = "NETWORK"; break;
        default: typeStr = "SUSPICIOUS";
        }

        std::cerr << "\n!!! " << typeStr << " DETECTED !!!\n";
        std::cerr << "Process: " << std::string(info.name.begin(), info.name.end())
            << " (PID: " << info.pid << ")\n";
        std::cerr << "Risk Score: " << info.riskScore << "/100\n";
        std::cerr << "Description: " << behavior.description << "\n";
        std::cerr << "Recommendation: " << (behavior.severity > 7 ?
            "TERMINATE IMMEDIATELY" : "INVESTIGATE") << "\n\n";
    }
};

// ==================== نقطة الاختبار ====================

#ifdef TEST_PROCESS
int main() {
    ProcessAnalyzer analyzer;

    std::cout << "AI Antivirus - Process Analyzer\n";
    std::cout << "Scanning current processes...\n\n";

    analyzer.showProcessTree();

    std::cout << "\nStarting real-time monitoring...\n";
    analyzer.startMonitoring(3); // كل 3 ثواني

    std::cout << "Monitoring for 30 seconds...\n";
    Sleep(30000);

    analyzer.stopMonitoring();

    auto threats = analyzer.getThreats(5);
    std::cout << "\nTotal threats detected: " << threats.size() << "\n";

    analyzer.exportReport("process_report.txt");

    return 0;
}
#endif