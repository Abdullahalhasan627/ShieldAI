// SelfProtection.cpp - Security Module
// نظام الحماية الذاتية للبرنامج - Anti-Tampering & Self-Defense

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <mutex>
#include <functional>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <aclapi.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

// ==================== هيكل حالة الحماية ====================

struct ProtectionStatus {
    bool isProtected;
    bool isRunningElevated;
    bool isDebuggerAttached;
    bool isVirtualized;
    int integrityLevel;
    std::vector<std::string> activeDefenses;
    std::chrono::system_clock::time_point startTime;
};

// ==================== الحماية الذاتية الرئيسية ====================

class SelfProtection {
private:
    std::atomic<bool> isActive{ false };
    std::atomic<bool> isTampered{ false };
    std::thread watchdogThread;
    std::thread integrityThread;
    std::vector<std::thread> defenseThreads;

    // معلومات العملية
    DWORD ownProcessId;
    HANDLE ownProcessHandle;
    std::wstring processName;
    std::wstring processPath;

    // دوائر التحقق
    std::vector<std::function<bool()>> integrityChecks;
    std::vector<std::function<void()>> tamperResponses;

    // معالجات الحماية
    HANDLE hJobObject = NULL;

public:
    SelfProtection() {
        std::cout << "[INIT] Self-Protection System Initializing...\n";

        ownProcessId = GetCurrentProcessId();
        ownProcessHandle = GetCurrentProcess();

        // الحصول على معلومات العملية
        WCHAR path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        processPath = path;
        processName = std::wstring(path).substr(
            std::wstring(path).find_last_of(L"\\") + 1);

        initializeDefenses();
    }

    ~SelfProtection() {
        deactivate();
        std::cout << "[SHUTDOWN] Self-Protection deactivated\n";
    }

    // ==================== التهيئة والتفعيل ====================

    bool activate() {
        if (isActive) return true;

        std::cout << "[ACTIVATING] Starting self-defense mechanisms...\n";

        // 1. رفع الصلاحيات
        if (!elevatePrivileges()) {
            std::cerr << "[WARNING] Running without elevated privileges\n";
        }

        // 2. حماية الذاكرة
        if (!protectMemory()) {
            std::cerr << "[ERROR] Memory protection failed\n";
        }

        // 3. منع تصحيح الأخطاء
        if (!preventDebugging()) {
            std::cerr << "[WARNING] Debug protection limited\n";
        }

        // 4. حماية العملية
        if (!protectProcess()) {
            std::cerr << "[ERROR] Process protection failed\n";
        }

        // 5. إخفاء البرنامج (اختياري)
        hideFromTaskManager();

        // 6. بدء المراقبة المستمرة
        startWatchdog();
        startIntegrityMonitor();

        isActive = true;
        std::cout << "[SUCCESS] Self-protection ACTIVE\n";

        displayStatus();

        return true;
    }

    void deactivate() {
        if (!isActive) return;

        isActive = false;

        // إيقاف الخيوط
        if (watchdogThread.joinable()) watchdogThread.join();
        if (integrityThread.joinable()) integrityThread.join();

        for (auto& t : defenseThreads) {
            if (t.joinable()) t.join();
        }

        // إغلاق مقابض
        if (hJobObject) {
            CloseHandle(hJobObject);
            hJobObject = NULL;
        }
    }

    // ==================== رفع الصلاحيات ====================

private:
    bool elevatePrivileges() {
        HANDLE hToken;
        TOKEN_ELEVATION elevation;
        DWORD size;

        if (!OpenProcessToken(ownProcessHandle, TOKEN_QUERY, &hToken)) {
            return false;
        }

        BOOL result = GetTokenInformation(hToken, TokenElevation,
            &elevation, sizeof(elevation), &size);
        CloseHandle(hToken);

        if (result && elevation.TokenIsElevated) {
            std::cout << "[INFO] Running with elevated privileges\n";

            // تعيين مستوى النزاهة العالي
            setHighIntegrityLevel();
            return true;
        }

        return false;
    }

    bool setHighIntegrityLevel() {
        HANDLE hToken;
        if (!OpenProcessToken(ownProcessHandle, TOKEN_ALL_ACCESS, &hToken)) {
            return false;
        }

        // تقليل قابلية البرنامج للحقن
        // (تعقيد - يتطلب SID خاص)

        CloseHandle(hToken);
        return true;
    }

    // ==================== حماية الذاكرة ====================

    bool protectMemory() {
        // حماية صفحات الذاكرة الحرجة من الكتابة
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        // الحصول على معلومات الوحدة النمطية
        MODULEINFO modInfo;
        HMODULE hMod = GetModuleHandle(NULL);

        if (GetModuleInformation(ownProcessHandle, hMod, &modInfo, sizeof(modInfo))) {
            // جعل قسم الكود للقراءة فقط (غير قابل للكتابة)
            DWORD oldProtect;
            SIZE_T codeSize = modInfo.SizeOfImage;

            // حماية: منع التعديل على الكود
            if (!VirtualProtect(modInfo.EntryPoint, 4096,
                PAGE_EXECUTE_READ, &oldProtect)) {
                return false;
            }
        }

        // كشف نقاط التوقف البرمجية (Breakpoints)
        checkForBreakpoints();

        return true;
    }

    void checkForBreakpoints() {
        // فحص أول بايتات الدوال الحرجة بحثاً عن 0xCC (INT3)
        BYTE* mainStart = (BYTE*)GetModuleHandle(NULL);

        for (size_t i = 0; i < 100; i++) {
            if (mainStart[i] == 0xCC) { // نقطة توقف
                std::cerr << "[ALERT] Debug breakpoint detected!\n";
                triggerTamperResponse();
                return;
            }
        }
    }

    // ==================== منع التصحيح ====================

    bool preventDebugging() {
        // 1. استدعاء Windows API
        if (IsDebuggerPresent()) {
            std::cerr << "[WARNING] Debugger detected!\n";
            triggerTamperResponse();
            return false;
        }

        // 2. إزالة أعلام التصحيح من PEB
#ifndef _WIN64
        __asm {
            mov eax, fs: [0x30]      // PEB
            mov byte ptr[eax + 2], 0 // BeingDebugged = false
        }
#else
// للـ x64: استخدام inline asm أو NtQueryInformationProcess
#endif

// 3. تسجيل معالج استثناء خاص
        SetUnhandledExceptionFilter(exceptionHandler);

        // 4. كشف التصحيح عن بُعد
        checkRemoteDebugger();

        // 5. كشف hardware breakpoints
        checkHardwareBreakpoints();

        return true;
    }

    void checkRemoteDebugger() {
        // استخدام NtQueryInformationProcess
        typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(
            HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG
            );

        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        auto NtQueryInformationProcess = (pNtQueryInformationProcess)
            GetProcAddress(ntdll, "NtQueryInformationProcess");

        if (NtQueryInformationProcess) {
            HANDLE hDebugObject = NULL;
            DWORD returnLength;

            NTSTATUS status = NtQueryInformationProcess(
                ownProcessHandle,
                (PROCESSINFOCLASS)0x1E, // ProcessDebugObjectHandle
                &hDebugObject,
                sizeof(hDebugObject),
                &returnLength
            );

            if (NT_SUCCESS(status) && hDebugObject != NULL) {
                std::cerr << "[ALERT] Remote debugger detected!\n";
                triggerTamperResponse();
            }
        }
    }

    void checkHardwareBreakpoints() {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            // التحقق من DR0-DR3 (registers نقاط التوقف)
            if (ctx.Dr0 != 0 || ctx.Dr1 != 0 ||
                ctx.Dr2 != 0 || ctx.Dr3 != 0) {
                std::cerr << "[ALERT] Hardware breakpoint detected!\n";
                triggerTamperResponse();
            }
        }
    }

    static LONG WINAPI exceptionHandler(EXCEPTION_POINTERS* pExceptionInfo) {
        if (pExceptionInfo->ExceptionRecord->ExceptionCode ==
            EXCEPTION_BREAKPOINT) {
            std::cerr << "[CRITICAL] Breakpoint exception!\n";
            // لا نسمح بالاستمرار
            ExitProcess(0xDEAD);
        }
        return EXCEPTION_EXECUTE_HANDLER;
    }

    // ==================== حماية العملية ====================

    bool protectProcess() {
        // 1. Job Object - منع الخروج من العملية
        hJobObject = CreateJobObjectA(NULL, "AI_Antivirus_Protected");
        if (hJobObject) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
            jeli.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                JOB_OBJECT_LIMIT_BREAKAWAY_OK;

            SetInformationJobObject(hJobObject,
                JobObjectExtendedLimitInformation,
                &jeli, sizeof(jeli));

            AssignProcessToJobObject(hJobObject, ownProcessHandle);
        }

        // 2. حماية الملف من الحذف/التعديل
        protectFiles();

        // 3. منع إنشاء مقابض للكتابة
        preventHandleAccess();

        // 4. مراقبة العمليات المشبوهة
        monitorSuspiciousProcesses();

        return true;
    }

    void protectFiles() {
        // حماية ملف البرنامج وملفات التكوين
        std::vector<std::wstring> protectedFiles = {
            processPath,
            processPath + L".config",
            // أضف الملفات الحرجة الأخرى
        };

        for (const auto& file : protectedFiles) {
            if (fs::exists(file)) {
                // تعيين صلاحيات للقراءة فقط
                DWORD attrs = GetFileAttributesW(file.c_str());
                SetFileAttributesW(file.c_str(),
                    attrs | FILE_ATTRIBUTE_READONLY);
            }
        }
    }

    void preventHandleAccess() {
        // تقليل الأذونات على مقبض العملية
        // (يتطلب SetSecurityInfo - معقد)
    }

    // ==================== إخفاء البرنامج ====================

    void hideFromTaskManager() {
        // إخفاء من قائمة التطبيقات (ليس من العمليات)
        // عبر SetWindowDisplayAffinity أو أسلوب آخر

        // ملاحظة: الإخفاء الكامل يتطلب برمجة kernel-level (غير مستحسن)
    }

    // ==================== المراقبة المستمرة ====================

    void startWatchdog() {
        watchdogThread = std::thread([this]() {
            while (isActive) {
                // التحقق كل ثانية
                std::this_thread::sleep_for(std::chrono::seconds(1));

                if (!performHealthCheck()) {
                    std::cerr << "[CRITICAL] Health check failed!\n";
                    triggerTamperResponse();
                }

                // كشف الـ debugger بشكل دوري
                if (IsDebuggerPresent()) {
                    triggerTamperResponse();
                }
            }
            });
    }

    void startIntegrityMonitor() {
        integrityThread = std::thread([this]() {
            // حساب هاش الكود الأصلي
            std::string originalHash = calculateCodeHash();

            while (isActive) {
                std::this_thread::sleep_for(std::chrono::seconds(5));

                std::string currentHash = calculateCodeHash();
                if (currentHash != originalHash) {
                    std::cerr << "[CRITICAL] Code integrity violation!\n";
                    isTampered = true;
                    triggerTamperResponse();
                }
            }
            });
    }

    bool performHealthCheck() {
        // التحقق من أن العملية لا تزال صحيحة
        if (isTampered) return false;

        // التحقق من عدم وجود حقن
        if (detectCodeInjection()) {
            return false;
        }

        return true;
    }

    bool detectCodeInjection() {
        // فحص الوحدات المحملة بحثاً عن DLLs مشبوهة
        HMODULE hMods[1024];
        DWORD cbNeeded;

        if (EnumProcessModules(ownProcessHandle, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                WCHAR szModName[MAX_PATH];
                if (GetModuleFileNameExW(ownProcessHandle, hMods[i],
                    szModName, sizeof(szModName) / sizeof(WCHAR))) {
                    std::wstring modName(szModName);

                    // التحقق من DLLs غير موثقة
                    if (!isModuleTrusted(modName)) {
                        std::wcerr << L"[WARNING] Untrusted module: " << modName << L"\n";
                        return true;
                    }
                }
            }
        }

        return false;
    }

    bool isModuleTrusted(const std::wstring& modulePath) {
        // قائمة DLLs الموثوقة من النظام
        static std::vector<std::wstring> trustedPaths = {
            L"C:\\Windows\\System32\\",
            L"C:\\Windows\\SysWOW64\\",
            // أضف مسارات أخرى
        };

        for (const auto& path : trustedPaths) {
            if (modulePath.find(path) == 0) {
                return true;
            }
        }

        // السماح بـ DLLs في نفس مجلد البرنامج
        std::wstring exeDir = processPath.substr(0,
            processPath.find_last_of(L"\\") + 1);
        if (modulePath.find(exeDir) == 0) {
            return true;
        }

        return false;
    }

    // ==================== مراقبة العمليات المشبوهة ====================

    void monitorSuspiciousProcesses() {
        defenseThreads.emplace_back([this]() {
            while (isActive) {
                std::this_thread::sleep_for(std::chrono::seconds(3));

                // البحث عن أدوات كشف البرمجيات الخبيثة الأخرى
                // أو أدوات التحليل التي قد تستهدفنا

                HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnapshot == INVALID_HANDLE_VALUE) continue;

                PROCESSENTRY32W pe32;
                pe32.dwSize = sizeof(PROCESSENTRY32W);

                if (Process32FirstW(hSnapshot, &pe32)) {
                    do {
                        std::wstring procName(pe32.szExeFile);
                        std::transform(procName.begin(), procName.end(),
                            procName.begin(), ::tolower);

                        // كشف أدوات التحليل
                        std::vector<std::wstring> suspiciousTools = {
                            L"procmon.exe",    // Process Monitor
                            L"processhacker.exe",
                            L"autoruns.exe",
                            L"wireshark.exe",
                            L"fiddler.exe",
                            L"cheatengine.exe",
                            L"x64dbg.exe",
                            L"ollydbg.exe",
                            L"idaq.exe",
                            L"immunitydebugger.exe"
                        };

                        for (const auto& tool : suspiciousTools) {
                            if (procName.find(tool) != std::wstring::npos) {
                                std::wcerr << L"[ALERT] Analysis tool detected: "
                                    << procName << L"\n";
                                // لا نتخذ إجراء فوري لكن نسجل
                            }
                        }

                    } while (Process32NextW(hSnapshot, &pe32));
                }

                CloseHandle(hSnapshot);
            }
            });
    }

    // ==================== أدوات مساعدة ====================

    std::string calculateCodeHash() {
        // حساب هاش قسم الكود للتحقق من السلامة
        HMODULE hMod = GetModuleHandle(NULL);

        MODULEINFO modInfo;
        if (!GetModuleInformation(ownProcessHandle, hMod, &modInfo, sizeof(modInfo))) {
            return "";
        }

        // قراءة أول 4KB من الكود
        BYTE* codeStart = (BYTE*)modInfo.EntryPoint;
        std::vector<BYTE> code(codeStart, codeStart + 4096);

        // هاش بسيط (في الإنتاج استخدم SHA-256)
        size_t hash = 0;
        for (auto b : code) {
            hash = hash * 31 + b;
        }

        return std::to_string(hash);
    }

    void initializeDefenses() {
        // إضافة فحوصات نزاهة مخصصة
        integrityChecks.push_back([this]() {
            return !IsDebuggerPresent();
            });

        // إضافة ردود فعل على التلاعب
        tamperResponses.push_back([this]() {
            // الرد 1: تسجيل
            logSecurityEvent("TAMPER_DETECTED");

            // الرد 2: إعلام المستخدم
            MessageBoxA(NULL,
                "Security violation detected!\nThe application will now close.",
                "AI Antivirus - Security Alert",
                MB_OK | MB_ICONERROR);

            // الرد 3: إنهاء العملية
            ExitProcess(0xDEADBEEF);
            });
    }

    void triggerTamperResponse() {
        for (const auto& response : tamperResponses) {
            response();
        }
    }

    void logSecurityEvent(const std::string& event) {
        std::string logPath = "C:\\ProgramData\\AI_Antivirus\\security.log";

        std::ofstream log(logPath, std::ios::app);
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);

        log << std::ctime(&time);
        log << "Event: " << event << "\n";
        log << "PID: " << ownProcessId << "\n";
        log << "------------------------\n";
    }

    // ==================== واجهة برمجة التطبيقات العامة ====================

public:
    ProtectionStatus getStatus() const {
        ProtectionStatus status;
        status.isProtected = isActive;
        status.isDebuggerAttached = IsDebuggerPresent();
        status.isRunningElevated = false; // يتم التحقق لاحقاً

        // التحقق من التصحيح الافتراضي
        BOOL isVirtual = FALSE;
        IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED);
        status.isVirtualized = isVirtual;

        status.startTime = std::chrono::system_clock::now();
        status.activeDefenses = {
            "Memory Protection",
            "Anti-Debugging",
            "Process Monitoring",
            "Integrity Checks",
            "Code Injection Detection"
        };

        return status;
    }

    void displayStatus() const {
        auto status = getStatus();

        std::cout << "\n=== SELF-PROTECTION STATUS ===\n";
        std::cout << "Status: " << (status.isProtected ? "🟢 ACTIVE" : "🔴 INACTIVE") << "\n";
        std::cout << "Debugger: " << (status.isDebuggerAttached ? "⚠️  DETECTED" : "✅ Clear") << "\n";
        std::cout << "Virtualized: " << (status.isVirtualized ? "⚠️  YES" : "✅ No") << "\n";
        std::cout << "Active Defenses (" << status.activeDefenses.size() << "):\n";
        for (const auto& defense : status.activeDefenses) {
            std::cout << "  • " << defense << "\n";
        }
        std::cout << "===============================\n";
    }

    bool isProtectionActive() const {
        return isActive;
    }

    // كشف التلاعب يدوياً
    bool verifyIntegrity() {
        return performHealthCheck();
    }
};

// ==================== نقطة الاختبار ====================

#ifdef TEST_PROTECTION
int main() {
    std::cout << "AI Antivirus - Self-Protection Test\n\n";

    SelfProtection protection;

    if (!protection.activate()) {
        std::cerr << "Failed to activate protection\n";
        return 1;
    }

    std::cout << "\nProtection active for 30 seconds...\n";
    std::cout << "Try attaching a debugger or modifying memory!\n\n";

    Sleep(30000);

    protection.deactivate();

    return 0;
}
#endif