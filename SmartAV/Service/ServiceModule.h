#pragma once

#include <windows.h>

#include <string>

#include <vector>

#include <memory>

#include <atomic>



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

        // Singleton classes - accessed via GetInstance(), not owned
        // FileScanner, RealTimeMonitor, ProcessAnalyzer, AIDetector,
        // QuarantineManager, SelfProtection are all singletons

        SERVICE_STATUS_HANDLE m_statusHandle = NULL;

        std::atomic<bool> m_scanRunning{ false };

    };



} // namespace AIAntivirus