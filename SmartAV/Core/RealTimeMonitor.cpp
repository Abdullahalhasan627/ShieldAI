// RealTimeMonitor.cpp - Core Module
// مراقب النظام في الوقت الفعلي - Real-Time Protection

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <functional>
#include <windows.h>
#include <filesystem>

namespace fs = std::filesystem;

// ==================== هيكل حدث الملف ====================

struct FileEvent {
    enum class Type {
        CREATED,
        MODIFIED,
        DELETED,
        RENAMED
    };

    Type type;
    std::string filePath;
    std::string oldPath;  // للإعادة تسمية
    std::chrono::system_clock::time_point timestamp;
    DWORD processId;      // العملية المسؤولة
    std::string processName;
};

// ==================== مراقب النظام الرئيسي ====================

class RealTimeMonitor {
private:
    // قائمة المسارات المراقبة
    std::vector<std::string> watchedPaths;

    // مؤشرات التحكم
    std::atomic<bool> isRunning{ false };
    std::atomic<bool> isPaused{ false };

    // الخيوط (Threads)
    std::vector<std::thread> monitorThreads;
    std::thread processingThread;

    // قائمة انتظار الأحداث (Thread-Safe)
    std::queue<FileEvent> eventQueue;
    std::mutex queueMutex;
    std::condition_variable queueCV;

    // رد الاتصال للكشف عن التهديدات
    std::function<bool(const std::string&)> onThreatDetected;
    std::function<void(const FileEvent&)> onEventLogged;

    // مقبض IOCP لكفاءة عالية
    HANDLE iocpHandle = INVALID_HANDLE_VALUE;

public:
    RealTimeMonitor() {
        std::cout << "[INIT] RealTimeMonitor Engine Starting...\n";
        initializeCriticalPaths();
    }

    ~RealTimeMonitor() {
        stop();
        std::cout << "[SHUTDOWN] RealTimeMonitor Engine Stopped\n";
    }

    // ==================== إدارة المسارات ====================

    void addWatchPath(const std::string& path) {
        if (!fs::exists(path)) {
            std::cerr << "[ERROR] Path does not exist: " << path << "\n";
            return;
        }

        // التحقق من عدم التكرار
        for (const auto& existing : watchedPaths) {
            if (existing == path) {
                std::cout << "[INFO] Path already watched: " << path << "\n";
                return;
            }
        }

        watchedPaths.push_back(path);
        std::cout << "[ADDED] Watch path: " << path << "\n";

        // إذا كان المحرك يعمل، ابدأ مراقبة هذا المسار فوراً
        if (isRunning) {
            startMonitoringPath(path);
        }
    }

    void removeWatchPath(const std::string& path) {
        auto it = std::find(watchedPaths.begin(), watchedPaths.end(), path);
        if (it != watchedPaths.end()) {
            watchedPaths.erase(it);
            std::cout << "[REMOVED] Watch path: " << path << "\n";
        }
    }

    // ==================== التحكم الرئيسي ====================

    bool start() {
        if (isRunning) {
            std::cout << "[WARNING] Monitor already running\n";
            return false;
        }

        if (watchedPaths.empty()) {
            std::cerr << "[ERROR] No paths configured for monitoring\n";
            return false;
        }

        isRunning = true;
        isPaused = false;

        // إنشاء IOCP (I/O Completion Port) للكفاءة العالية
        iocpHandle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
        if (iocpHandle == NULL) {
            std::cerr << "[ERROR] Failed to create IOCP\n";
            isRunning = false;
            return false;
        }

        // بدء خيوط المراقبة لكل مسار
        for (const auto& path : watchedPaths) {
            startMonitoringPath(path);
        }

        // بدء خيط معالجة الأحداث
        processingThread = std::thread(&RealTimeMonitor::processEventsLoop, this);

        std::cout << "[SUCCESS] Real-time protection ACTIVE\n";
        std::cout << "          Monitoring " << watchedPaths.size() << " path(s)\n";

        return true;
    }

    void stop() {
        if (!isRunning) return;

        isRunning = false;
        queueCV.notify_all();  // إيقاظ خيط المعالجة

        // إغلاق جميع مقابض المراقبة
        for (auto& handle : directoryHandles) {
            CancelIoEx(handle, NULL);
            CloseHandle(handle);
        }
        directoryHandles.clear();

        // انتظار انتهاء الخيوط
        for (auto& thread : monitorThreads) {
            if (thread.joinable()) thread.join();
        }

        if (processingThread.joinable()) processingThread.join();

        // إغلاق IOCP
        if (iocpHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(iocpHandle);
            iocpHandle = INVALID_HANDLE_VALUE;
        }

        monitorThreads.clear();
        std::cout << "[STOPPED] Real-time protection disabled\n";
    }

    void pause() {
        isPaused = true;
        std::cout << "[PAUSED] Monitoring suspended\n";
    }

    void resume() {
        isPaused = false;
        std::cout << "[RESUMED] Monitoring active\n";
    }

    bool isActive() const { return isRunning && !isPaused; }

    // ==================== إعدادات الاستدعاء ====================

    void setThreatCallback(std::function<bool(const std::string&)> callback) {
        onThreatDetected = callback;
    }

    void setEventCallback(std::function<void(const FileEvent&)> callback) {
        onEventLogged = callback;
    }

    // ==================== المراقبة الداخلية ====================

private:
    std::vector<HANDLE> directoryHandles;
    std::vector<std::unique_ptr<char[]>> buffers;

    void startMonitoringPath(const std::string& path) {
        // فتح المجلد للمراقبة
        HANDLE dirHandle = CreateFileA(
            path.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            NULL
        );

        if (dirHandle == INVALID_HANDLE_VALUE) {
            std::cerr << "[ERROR] Cannot open directory: " << path
                << " (Error: " << GetLastError() << ")\n";
            return;
        }

        directoryHandles.push_back(dirHandle);

        // ربط بالـ IOCP
        CreateIoCompletionPort(dirHandle, iocpHandle, (ULONG_PTR)dirHandle, 0);

        // بدء خيط المراقبة لهذا المسار
        monitorThreads.emplace_back(&RealTimeMonitor::monitorDirectory,
            this, dirHandle, path);
    }

    void monitorDirectory(HANDLE dirHandle, const std::string& rootPath) {
        const DWORD bufferSize = 4096;
        auto buffer = std::make_unique<char[]>(bufferSize);
        OVERLAPPED overlapped = {};
        DWORD bytesReturned;

        while (isRunning) {
            // طلب إشعارات التغيير
            BOOL success = ReadDirectoryChangesW(
                dirHandle,
                buffer.get(),
                bufferSize,
                TRUE,  // مراقبة متكررة (Subdirectories)
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

            if (!success) {
                std::cerr << "[ERROR] ReadDirectoryChanges failed: "
                    << GetLastError() << "\n";
                break;
            }

            // انتظار الإشعار عبر IOCP
            DWORD completionKey;
            LPOVERLAPPED lpOverlapped;

            BOOL iocpSuccess = GetQueuedCompletionStatus(
                iocpHandle,
                &bytesReturned,
                &completionKey,
                &lpOverlapped,
                INFINITE
            );

            if (!isRunning) break;

            if (iocpSuccess && bytesReturned > 0) {
                processDirectoryChanges(buffer.get(), bytesReturned, rootPath);
            }
        }
    }

    void processDirectoryChanges(char* buffer, DWORD length,
        const std::string& rootPath) {
        FILE_NOTIFY_INFORMATION* info =
            reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);

        do {
            // تحويل الاسم من Unicode
            std::wstring wFileName(info->FileName,
                info->FileNameLength / sizeof(WCHAR));

            int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wFileName.c_str(),
                (int)wFileName.length(),
                NULL, 0, NULL, NULL);
            std::string fileName(sizeNeeded, 0);
            WideCharToMultiByte(CP_UTF8, 0, wFileName.c_str(),
                (int)wFileName.length(),
                &fileName[0], sizeNeeded, NULL, NULL);

            std::string fullPath = rootPath + "\\" + fileName;

            // تحديد نوع الحدث
            FileEvent::Type eventType;
            switch (info->Action) {
            case FILE_ACTION_ADDED:
                eventType = FileEvent::Type::CREATED;
                break;
            case FILE_ACTION_REMOVED:
                eventType = FileEvent::Type::DELETED;
                break;
            case FILE_ACTION_MODIFIED:
                eventType = FileEvent::Type::MODIFIED;
                break;
            case FILE_ACTION_RENAMED_OLD_NAME:
                eventType = FileEvent::Type::RENAMED;
                break;
            case FILE_ACTION_RENAMED_NEW_NAME:
                eventType = FileEvent::Type::CREATED;
                break;
            default:
                eventType = FileEvent::Type::MODIFIED;
            }

            // إنشاء الحدث
            FileEvent event;
            event.type = eventType;
            event.filePath = fullPath;
            event.timestamp = std::chrono::system_clock::now();
            event.processId = getProcessIdForFile(fullPath);

            // إضافة للقائمة
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                eventQueue.push(event);
            }
            queueCV.notify_one();

            // الانتقال للسجل التالي
            if (info->NextEntryOffset == 0) break;
            info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                reinterpret_cast<char*>(info) + info->NextEntryOffset
                );

        } while (true);
    }

    // ==================== معالجة الأحداث ====================

    void processEventsLoop() {
        while (isRunning) {
            std::unique_lock<std::mutex> lock(queueMutex);

            // انتظار حتى يتوفر حدث
            queueCV.wait(lock, [this] {
                return !eventQueue.empty() || !isRunning;
                });

            if (!isRunning) break;

            // معالجة جميع الأحداث المتوفرة
            while (!eventQueue.empty()) {
                FileEvent event = eventQueue.front();
                eventQueue.pop();
                lock.unlock();

                // التحقق من الإيقاف المؤقت
                if (!isPaused) {
                    handleEvent(event);
                }

                lock.lock();
            }
        }
    }

    void handleEvent(const FileEvent& event) {
        // تسجيل الحدث
        if (onEventLogged) {
            onEventLogged(event);
        }

        // عرض في وحدة التحكم (للتصحيح)
        logEvent(event);

        // فحص الملفات الجديدة والمعدلة
        if (event.type == FileEvent::Type::CREATED ||
            event.type == FileEvent::Type::MODIFIED) {

            // فحص التهديدات
            if (fs::exists(event.filePath) &&
                fs::is_regular_file(event.filePath)) {

                bool isThreat = false;
                if (onThreatDetected) {
                    isThreat = onThreatDetected(event.filePath);
                }

                if (isThreat) {
                    handleThreat(event);
                }
            }
        }
    }

    void handleThreat(const FileEvent& event) {
        std::cerr << "\n!!! THREAT DETECTED !!!\n";
        std::cerr << "File: " << event.filePath << "\n";
        std::cerr << "Action: Blocking access\n";

        // هنا يمكن استدعاء وحدة الحجر الصحي
        // Quarantine::isolate(event.filePath);
    }

    void logEvent(const FileEvent& event) {
        const char* typeStr;
        switch (event.type) {
        case FileEvent::Type::CREATED:  typeStr = "[CREATE]"; break;
        case FileEvent::Type::MODIFIED: typeStr = "[MODIFY] "; break;
        case FileEvent::Type::DELETED:  typeStr = "[DELETE] "; break;
        case FileEvent::Type::RENAMED:  typeStr = "[RENAME] "; break;
        default: typeStr = "[UNKNOWN]";
        }

        std::cout << typeStr << " " << event.filePath << "\n";
    }

    // ==================== أدوات مساعدة ====================

    DWORD getProcessIdForFile(const std::string& filePath) {
        // الحصول على الـ Process ID الذي يصل للملف
        // هذا يتطلب NtQuerySystemInformation أو WMI (معقد)
        // للتبسيط هنا نعيد 0
        return 0;
    }

    void initializeCriticalPaths() {
        // إضافة المسارات الحرجة افتراضياً
        char userProfile[MAX_PATH];
        GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH);

        std::string downloads = std::string(userProfile) + "\\Downloads";
        std::string desktop = std::string(userProfile) + "\\Desktop";
        std::string temp = std::string(userProfile) + "\\AppData\\Local\\Temp";

        // إضافة تلقائية (يمكن تعديلها لاحقاً)
        // addWatchPath(downloads);
        // addWatchPath(desktop);
    }

public:
    // ==================== واجهة برمجة التطبيقات ====================

    std::vector<std::string> getWatchedPaths() const {
        return watchedPaths;
    }

    size_t getPendingEventsCount() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(queueMutex));
        return eventQueue.size();
    }

    void showStatus() const {
        std::cout << "\n=== REAL-TIME MONITOR STATUS ===\n";
        std::cout << "Status: " << (isActive() ? "ACTIVE 🟢" : "INACTIVE 🔴") << "\n";
        std::cout << "Watched Paths: " << watchedPaths.size() << "\n";
        for (const auto& path : watchedPaths) {
            std::cout << "  📁 " << path << "\n";
        }
        std::cout << "================================\n";
    }
};

// ==================== نقطة الاختبار ====================

#ifdef TEST_MONITOR
int main() {
    RealTimeMonitor monitor;

    // إضافة مسارات للاختبار
    char userProfile[MAX_PATH];
    GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH);

    std::string testPath = std::string(userProfile) + "\\Downloads";

    monitor.addWatchPath(testPath);

    // تعيين رد الاتصال للكشف عن التهديدات
    monitor.setThreatCallback([](const std::string& path) -> bool {
        // محاكاة: اعتبر أي ملف .exe مشبوه
        if (path.find(".exe") != std::string::npos ||
            path.find(".tmp") != std::string::npos) {
            return true;
        }
        return false;
        });

    // بدء المراقبة
    if (monitor.start()) {
        std::cout << "\nMonitoring for 60 seconds... Create/modify files to test.\n";
        std::cout << "Press Ctrl+C to stop early.\n\n";

        Sleep(60000);  // مراقبة لمدة دقيقة

        monitor.stop();
    }

    return 0;
}
#endif