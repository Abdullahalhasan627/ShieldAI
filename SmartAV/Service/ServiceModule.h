#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <memory>

namespace AIAntivirus {

    class FileScanner;
    class RealTimeMonitor;
    class ProcessAnalyzer;
    class AIDetector;
    class QuarantineManager;
    class SelfProtection;

    enum class ScanType { NONE, QUICK, FULL, CUSTOM, REALTIME };

    struct ServiceConfig {
        std::wstring serviceName = L"SmartAVService";
        std::wstring displayName = L"AI Antivirus Service";
        DWORD startType = SERVICE_AUTO_START;
        std::wstring pipeName = L"\\\\.\\pipe\\SmartAV_Service";
    };

    class ServiceModule {
    public:
        static ServiceModule& GetInstance();

        static void WINAPI ServiceMain(DWORD argc, LPWSTR* argv);
        static void WINAPI ControlHandler(DWORD control);
        static bool Install(const ServiceConfig& config = ServiceConfig{});
        static bool Uninstall(const std::wstring& serviceName);

        bool RunAsConsole();
        bool Initialize();
        void Shutdown();

        bool StartScan(ScanType type, const std::wstring& path = L"");
        bool StopScan();

    private:
        ServiceModule() = default;
        ~ServiceModule() = default;

        std::unique_ptr<FileScanner> m_fileScanner;
        std::unique_ptr<RealTimeMonitor> m_realTimeMonitor;
        std::unique_ptr<ProcessAnalyzer> m_processAnalyzer;
        std::unique_ptr<AIDetector> m_aiDetector;
        std::unique_ptr<QuarantineManager> m_quarantineManager;
        std::unique_ptr<SelfProtection> m_selfProtection;

        SERVICE_STATUS_HANDLE m_statusHandle = NULL;
        std::atomic<bool> m_scanRunning{ false };
    };

} // namespace AIAntivirus