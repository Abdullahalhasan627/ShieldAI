// main.cpp - AI Antivirus
// نقطة البداية الرئيسية - النظام المتكامل

#include <iostream>
#include <memory>
#include <thread>
#include <chrono>
#include <string>
#include <vector>
#include <map>
#include <windows.h>
#include <filesystem>

// تضمين الوحدات (في المشروع الحقيقي استخدم header files)
#include "Core/FileScanner.cpp"
#include "Core/RealTimeMonitor.cpp"
#include "Core/ProcessAnalyzer.cpp"
#include "Core/FeatureExtractor.cpp"
#include "AI/AIDetector.cpp"
#include "Security/Quarantine.cpp"
#include "Security/SelfProtection.cpp"

namespace fs = std::filesystem;

// ==================== إعدادات النظام ====================

struct SystemConfig {
    bool enableRealTimeProtection = true;
    bool enableAI = true;
    bool enableSelfProtection = true;
    bool enableProcessMonitor = true;
    int scanDepth = 2;  // 1=Quick, 2=Normal, 3=Deep
    std::vector<std::string> protectedPaths;
    std::string modelPath = "AI/model.onnx";
};

// ==================== مدير النظام الرئيسي ====================

class AIAntivirus {
private:
    // الوحدات الأساسية
    std::unique_ptr<FileScanner> fileScanner;
    std::unique_ptr<RealTimeMonitor> realTimeMonitor;
    std::unique_ptr<ProcessAnalyzer> processAnalyzer;
    std::unique_ptr<FeatureExtractor> featureExtractor;
    std::unique_ptr<AIDetector> aiDetector;
    std::unique_ptr<QuarantineManager> quarantine;
    std::unique_ptr<SelfProtection> selfProtection;

    // التكوين
    SystemConfig config;
    bool isRunning = false;
    bool isInitialized = false;

public:
    AIAntivirus() {
        std::cout << R"(
    █████╗ ██╗      █████╗ ███╗   ██╗████████╗██╗██╗   ██╗██████╗ ██╗   ██╗███████╗
   ██╔══██╗██║     ██╔══██╗████╗  ██║╚══██╔══╝██║██║   ██║██╔══██╗██║   ██║██╔════╝
   ███████║██║     ███████║██╔██╗ ██║   ██║   ██║██║   ██║██████╔╝██║   ██║███████╗
   ██╔══██║██║     ██╔══██║██║╚██╗██║   ██║   ██║╚██╗ ██╔╝██╔══██╗██║   ██║╚════██║
   ██║  ██║███████╗██║  ██║██║ ╚████║   ██║   ██║ ╚████╔╝ ██║  ██║╚██████╔╝███████║
   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
        )" << "\n\n";

        std::cout << "Initializing AI Antivirus System...\n";
        std::cout << "Version: 2.0.0-BETA\n";
        std::cout << "Build Date: " << __DATE__ << " " << __TIME__ << "\n\n";
    }

    ~AIAntivirus() {
        shutdown();
    }

    // ==================== التهيئة ====================

    bool initialize(const SystemConfig& cfg = SystemConfig()) {
        config = cfg;

        try {
            // 1. الحماية الذاتية أولاً (الأهم)
            if (config.enableSelfProtection) {
                std::cout << "[1/7] Initializing Self-Protection...\n";
                selfProtection = std::make_unique<SelfProtection>();
                if (!selfProtection->activate()) {
                    std::cerr << "[WARNING] Self-protection limited\n";
                }
            }

            // 2. الماسح الضوئي
            std::cout << "[2/7] Loading File Scanner...\n";
            fileScanner = std::make_unique<FileScanner>();

            // 3. مستخرج الميزات
            std::cout << "[3/7] Loading Feature Extractor...\n";
            featureExtractor = std::make_unique<FeatureExtractor>();

            // 4. الذكاء الاصطناعي
            if (config.enableAI) {
                std::cout << "[4/7] Loading AI Engine...\n";
                aiDetector = std::make_unique<AIDetector>(config.modelPath);
                if (!aiDetector->isReady()) {
                    std::cerr << "[WARNING] AI Engine not available\n";
                }
            }

            // 5. نظام الحجر الصحي
            std::cout << "[5/7] Initializing Quarantine...\n";
            quarantine = std::make_unique<QuarantineManager>();

            // 6. محلل العمليات
            if (config.enableProcessMonitor) {
                std::cout << "[6/7] Loading Process Analyzer...\n";
                processAnalyzer = std::make_unique<ProcessAnalyzer>();
                processAnalyzer->startMonitoring(5);
            }

            // 7. المراقبة في الوقت الفعلي
            if (config.enableRealTimeProtection) {
                std::cout << "[7/7] Starting Real-Time Protection...\n";
                realTimeMonitor = std::make_unique<RealTimeMonitor>();
                setupRealTimeCallbacks();

                // إضافة المسارات المحمية
                setupProtectedPaths();

                if (!realTimeMonitor->start()) {
                    std::cerr << "[ERROR] Real-time protection failed to start\n";
                }
            }

            isInitialized = true;
            std::cout << "\n✅ System initialized successfully!\n\n";

            showSystemStatus();

            return true;

        }
        catch (const std::exception& e) {
            std::cerr << "\n❌ Initialization failed: " << e.what() << "\n";
            return false;
        }
    }

    void shutdown() {
        if (!isRunning) return;

        std::cout << "\nShutting down AI Antivirus...\n";

        if (realTimeMonitor) realTimeMonitor->stop();
        if (processAnalyzer) processAnalyzer->stopMonitoring();
        if (selfProtection) selfProtection->deactivate();

        isRunning = false;
        std::cout << "Goodbye!\n";
    }

    // ==================== الإعدادات والتكوين ====================

private:
    void setupRealTimeCallbacks() {
        if (!realTimeMonitor) return;

        // رد الاتصال عند اكتشاف ملف جديد
        realTimeMonitor->setThreatCallback(
            [this](const std::string& filePath) -> bool {
                return handleNewFile(filePath);
            }
        );

        // رد الاتصال لتسجيل الأحداث
        realTimeMonitor->setEventCallback(
            [this](const FileEvent& event) {
                logEvent(event);
            }
        );
    }

    void setupProtectedPaths() {
        if (!realTimeMonitor) return;

        // إضافة المسارات الحرجة
        char userProfile[MAX_PATH];
        GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH);

        realTimeMonitor->addWatchPath(std::string(userProfile) + "\\Downloads");
        realTimeMonitor->addWatchPath(std::string(userProfile) + "\\Desktop");
        realTimeMonitor->addWatchPath(std::string(userProfile) + "\\Documents");

        // Temp folders
        char tempPath[MAX_PATH];
        GetTempPathA(MAX_PATH, tempPath);
        realTimeMonitor->addWatchPath(tempPath);

        // إضافة المسارات المخصصة
        for (const auto& path : config.protectedPaths) {
            realTimeMonitor->addWatchPath(path);
        }
    }

    // ==================== معالجة التهديدات ====================

public:
    bool handleNewFile(const std::string& filePath) {
        std::cout << "\n🔍 New file detected: " << filePath << "\n";

        // 1. فحص سريع بالماسح الضوئي
        bool scannerThreat = fileScanner->scanSingleFile(filePath);

        if (scannerThreat) {
            std::cout << "⚠️  Traditional scanner detected threat!\n";
            handleConfirmedThreat(filePath, "Heuristic Detection", 7);
            return true;
        }

        // 2. تحليل AI (إذا كان متاحاً)
        if (aiDetector && aiDetector->isReady()) {
            auto features = featureExtractor->getFeatureVector(filePath);
            auto result = aiDetector->predict(features);

            if (!result.isError) {
                aiDetector->displayResult(result);

                // اتخاذ قرار بناءً على الثقة
                if (result.confidence > 0.85f && result.threatClass != "Benign") {
                    std::cout << "🤖 AI detected: " << result.threatClass << "\n";
                    handleConfirmedThreat(filePath, result.threatClass,
                        static_cast<int>(result.confidence * 10));
                    return true;
                }
                else if (result.confidence > 0.6f && result.threatClass != "Benign") {
                    std::cout << "⚡ Suspicious file (AI uncertain): "
                        << result.threatClass << "\n";
                    // مراقبة إضافية بدون عزل فوري
                    monitorFile(filePath);
                }
            }
        }

        // 3. فحص العمليات إذا كان ملف تنفيذي
        if (filePath.find(".exe") != std::string::npos ||
            filePath.find(".dll") != std::string::npos) {

            // سيتم فحصه عند التشغيل عبر ProcessAnalyzer
        }

        std::cout << "✅ File appears clean\n";
        return false;
    }

    void handleConfirmedThreat(const std::string& filePath,
        const std::string& threatName,
        int threatLevel) {
        // عرض تنبيه
        std::cerr << "\n╔══════════════════════════════════════════╗\n";
        std::cerr << "║     🚨 THREAT DETECTED - ACTION TAKEN    ║\n";
        std::cerr << "╠══════════════════════════════════════════╣\n";
        std::cerr << "║ File: " << fs::path(filePath).filename().string() << "\n";
        std::cerr << "║ Threat: " << threatName << "\n";
        std::cerr << "║ Level: " << threatLevel << "/10\n";
        std::cerr << "║ Action: QUARANTINE\n";
        std::cerr << "╚══════════════════════════════════════════╝\n";

        // عزل الملف
        if (quarantine) {
            if (quarantine->quarantineFile(filePath, threatName, threatLevel)) {
                // نجاح العزل
                showNotification("Threat Neutralized",
                    "File has been quarantined: " + threatName);
            }
            else {
                // فشل العزل - المحاولة البديلة
                std::cerr << "⚠️  Quarantine failed! Attempting secure delete...\n";
                secureDeleteFallback(filePath);
            }
        }

        // تسجيل الحدث
        logThreat(filePath, threatName, threatLevel);
    }

    void monitorFile(const std::string& filePath) {
        // إضافة للمراقبة المشددة
        std::cout << "[MONITOR] Added to watch list: " << filePath << "\n";

        // يمكن إضافة منطق إضافي هنا
    }

    bool secureDeleteFallback(const std::string& filePath) {
        // حذف آمن كحل أخير
        try {
            // الكتابة فوق الملف
            std::ofstream file(filePath, std::ios::binary | std::ios::trunc);
            std::vector<char> zeros(4096, 0);
            for (int i = 0; i < 10; i++) {
                file.write(zeros.data(), zeros.size());
            }
            file.close();

            // إعادة تسمية ثم حذف
            std::string tempName = filePath + ".tmp";
            fs::rename(filePath, tempName);
            fs::remove(tempName);

            return true;
        }
        catch (...) {
            return false;
        }
    }

    // ==================== أوامر المستخدم ====================

public:
    void runInteractive() {
        if (!isInitialized) {
            std::cerr << "System not initialized!\n";
            return;
        }

        isRunning = true;

        std::cout << "\n╔══════════════════════════════════════════╗\n";
        std::cout << "║     AI Antivirus Command Interface       ║\n";
        std::cout << "╚══════════════════════════════════════════╝\n\n";

        std::string command;

        while (isRunning) {
            std::cout << "\n[AI-AV] > ";
            std::getline(std::cin, command);

            processCommand(command);
        }
    }

    void processCommand(const std::string& command) {
        std::vector<std::string> args;
        std::stringstream ss(command);
        std::string arg;

        while (ss >> arg) {
            args.push_back(arg);
        }

        if (args.empty()) return;

        std::string cmd = args[0];
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

        if (cmd == "scan" || cmd == "s") {
            if (args.size() < 2) {
                std::cout << "Usage: scan <path>\n";
                return;
            }
            performScan(args[1]);

        }
        else if (cmd == "quick") {
            performQuickScan();

        }
        else if (cmd == "full") {
            performFullScan();

        }
        else if (cmd == "status" || cmd == "st") {
            showSystemStatus();

        }
        else if (cmd == "quarantine" || cmd == "q") {
            showQuarantine();

        }
        else if (cmd == "restore" && args.size() > 1) {
            restoreFile(args[1]);

        }
        else if (cmd == "delete" && args.size() > 1) {
            deleteQuarantined(args[1]);

        }
        else if (cmd == "processes" || cmd == "ps") {
            showProcesses();

        }
        else if (cmd == "realtime" || cmd == "rt") {
            toggleRealTime();

        }
        else if (cmd == "update") {
            checkUpdates();

        }
        else if (cmd == "help" || cmd == "?") {
            showHelp();

        }
        else if (cmd == "exit" || cmd == "quit") {
            shutdown();

        }
        else {
            std::cout << "Unknown command. Type 'help' for available commands.\n";
        }
    }

    // ==================== وظائف الفحص ====================

    void performScan(const std::string& path) {
        std::cout << "\n📂 Starting scan: " << path << "\n";
        std::cout << "Mode: " << (config.scanDepth == 3 ? "Deep" :
            config.scanDepth == 2 ? "Normal" : "Quick") << "\n";
        std::cout << "AI Engine: " << (aiDetector && aiDetector->isReady() ?
            "Enabled" : "Disabled") << "\n\n";

        if (!fs::exists(path)) {
            std::cerr << "Path not found: " << path << "\n";
            return;
        }

        if (fs::is_directory(path)) {
            fileScanner->scanDirectory(path);
        }
        else {
            fileScanner->scanSingleFile(path);
        }

        // عرض النتائج
        auto infected = fileScanner->getInfectedFiles();
        if (!infected.empty()) {
            std::cout << "\n⚠️  Scan complete. " << infected.size()
                << " threats found.\n";

            for (const auto& file : infected) {
                // AI analysis للملفات المكتشفة
                if (aiDetector && aiDetector->isReady()) {
                    auto features = featureExtractor->getFeatureVector(file);
                    auto result = aiDetector->predict(features);

                    handleConfirmedThreat(file, result.threatClass,
                        static_cast<int>(result.confidence * 10));
                }
            }
        }
        else {
            std::cout << "\n✅ Scan complete. No threats found.\n";
        }

        fileScanner->exportReport("scan_report.txt");
    }

    void performQuickScan() {
        char userProfile[MAX_PATH];
        GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH);

        std::cout << "\n⚡ Quick Scan started...\n";
        performScan(std::string(userProfile) + "\\Downloads");
    }

    void performFullScan() {
        std::cout << "\n🔍 Full System Scan started...\n";
        std::cout << "This may take a while...\n";

        // فحص جميع محركات الأقراص
        DWORD drives = GetLogicalDrives();
        for (int i = 0; i < 26; i++) {
            if (drives & (1 << i)) {
                char drive[4] = { 'A' + i, ':', '\\', '\0' };
                UINT type = GetDriveTypeA(drive);

                if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE) {
                    std::cout << "\nScanning drive: " << drive << "\n";
                    performScan(drive);
                }
            }
        }
    }

    // ==================== عرض المعلومات ====================

    void showSystemStatus() {
        std::cout << "\n╔══════════════════════════════════════════╗\n";
        std::cout << "║         SYSTEM STATUS                    ║\n";
        std::cout << "╠══════════════════════════════════════════╣\n";

        std::cout << "║ Self-Protection:  "
            << (selfProtection && selfProtection->isProtectionActive() ?
                "🟢 ACTIVE" : "🔴 INACTIVE") << "\n";

        std::cout << "║ Real-Time Monitor: "
            << (realTimeMonitor && realTimeMonitor->isActive() ?
                "🟢 ACTIVE" : "🔴 INACTIVE") << "\n";

        std::cout << "║ AI Engine:         "
            << (aiDetector && aiDetector->isReady() ?
                "🟢 READY" : "🟡 UNAVAILABLE") << "\n";

        std::cout << "║ Process Monitor:   "
            << (processAnalyzer ? "🟢 ACTIVE" : "🔴 INACTIVE") << "\n";

        std::cout << "║ Quarantine:        "
            << (quarantine ? "🟢 READY" : "🔴 ERROR") << "\n";

        if (realTimeMonitor) {
            auto paths = realTimeMonitor->getWatchedPaths();
            std::cout << "║ Watched Paths:     " << paths.size() << "\n";
        }

        std::cout << "╚══════════════════════════════════════════╝\n";
    }

    void showQuarantine() {
        if (quarantine) {
            quarantine->showQuarantineList();
        }
    }

    void showProcesses() {
        if (processAnalyzer) {
            processAnalyzer->showProcessTree();

            auto threats = processAnalyzer->getThreats(5);
            if (!threats.empty()) {
                std::cout << "\n⚠️  Active process threats detected: "
                    << threats.size() << "\n";
            }
        }
    }

    void showHelp() {
        std::cout << "\n╔══════════════════════════════════════════╗\n";
        std::cout << "║           AVAILABLE COMMANDS             ║\n";
        std::cout << "╠══════════════════════════════════════════╣\n";
        std::cout << "║ scan <path>    - Scan specific path      ║\n";
        std::cout << "║ quick          - Quick scan Downloads    ║\n";
        std::cout << "║ full           - Full system scan        ║\n";
        std::cout << "║ status         - Show system status      ║\n";
        std::cout << "║ quarantine     - List quarantined files  ║\n";
        std::cout << "║ restore <id>   - Restore quarantined file║\n";
        std::cout << "║ delete <id>    - Delete quarantined file ║\n";
        std::cout << "║ processes      - Show process tree       ║\n";
        std::cout << "║ realtime       - Toggle real-time protection║\n";
        std::cout << "║ update         - Check for updates       ║\n";
        std::cout << "║ help           - Show this help          ║\n";
        std::cout << "║ exit           - Shutdown system         ║\n";
        std::cout << "╚══════════════════════════════════════════╝\n";
    }

    // ==================== أوامر الحجر الصحي ====================

    void restoreFile(const std::string& itemId) {
        if (!quarantine) return;

        if (quarantine->restoreFile(itemId)) {
            std::cout << "✅ File restored successfully\n";
        }
        else {
            std::cerr << "❌ Failed to restore file\n";
        }
    }

    void deleteQuarantined(const std::string& itemId) {
        if (!quarantine) return;

        std::cout << "Are you sure? This cannot be undone. (yes/no): ";
        std::string confirm;
        std::getline(std::cin, confirm);

        if (confirm == "yes") {
            if (quarantine->deletePermanently(itemId)) {
                std::cout << "✅ File permanently deleted\n";
            }
        }
    }

    void toggleRealTime() {
        if (!realTimeMonitor) return;

        if (realTimeMonitor->isActive()) {
            realTimeMonitor->pause();
            std::cout << "⏸️  Real-time protection paused\n";
        }
        else {
            realTimeMonitor->resume();
            std::cout << "▶️  Real-time protection resumed\n";
        }
    }

    // ==================== التحديثات ====================

    void checkUpdates() {
        std::cout << "\n🔄 Checking for updates...\n";
        std::cout << "Current version: 2.0.0-BETA\n";
        std::cout << "Update server: https://ai-antivirus.example.com\n";
        std::cout << "Status: Up to date (simulated)\n";
    }

    // ==================== التسجيل والإشعارات ====================

private:
    void logEvent(const FileEvent& event) {
        // تسجيل في ملف السجل
        std::ofstream log("ai_antivirus.log", std::ios::app);
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);

        log << "[" << std::ctime(&time) << "] ";
        log << "Event: " << static_cast<int>(event.type) << " | ";
        log << "Path: " << event.filePath << "\n";
    }

    void logThreat(const std::string& filePath,
        const std::string& threatName,
        int level) {
        std::ofstream log("threats.log", std::ios::app);
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);

        log << "[" << std::ctime(&time) << "] ";
        log << "THREAT: " << threatName << " | ";
        log << "Level: " << level << " | ";
        log << "File: " << filePath << "\n";
    }

    void showNotification(const std::string& title,
        const std::string& message) {
        // Windows notification (يمكن استخدام Toast API)
        MessageBoxA(NULL, message.c_str(), title.c_str(),
            MB_OK | MB_ICONWARNING | MB_TOPMOST);
    }
};

// ==================== نقطة البداية ====================

int main(int argc, char* argv[]) {
    // إعداد وحدة التحكم
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitleA("AI Antivirus - Advanced Threat Protection");

    // تكوين النظام
    SystemConfig config;
    config.enableRealTimeProtection = true;
    config.enableAI = true;
    config.enableSelfProtection = true;
    config.enableProcessMonitor = true;

    // قراءة المعاملات من سطر الأوامر
    if (argc > 1) {
        std::string arg = argv[1];

        if (arg == "--service" || arg == "-s") {
            // وضع الخدمة (بدون واجهة)
            config.enableSelfProtection = true;
            // تشغيل في الخلفية...
        }
        else if (arg == "--scan" && argc > 2) {
            // فحص سريع من سطر الأوامر
            AIAntivirus av;
            if (av.initialize(config)) {
                // av.performScan(argv[2]);
            }
            return 0;
        }
    }

    // التشغيل التفاعلي العادي
    AIAntivirus antivirus;

    if (!antivirus.initialize(config)) {
        std::cerr << "\n❌ Failed to initialize system. Exiting.\n";
        return 1;
    }

    // تشغيل الواجهة التفاعلية
    antivirus.runInteractive();

    return 0;
}