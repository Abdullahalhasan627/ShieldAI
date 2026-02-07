/**
 * ServiceModule_impl.cpp - Windows Service Implementation
 */

#include "ServiceModule.h"
#include "../Core/FileScanner.h"
#include "../Core/RealTimeMonitor.h"
#include "../Core/ProcessAnalyzer.h"
#include "../AI/AIDetector.h"
#include "../Security/Quarantine.h"
#include "../Security/SelfProtection.h"

namespace AIAntivirus {

    static SERVICE_STATUS g_serviceStatus = { 0 };
    static SERVICE_STATUS_HANDLE g_statusHandle = NULL;

    ServiceModule& ServiceModule::GetInstance() {
        static ServiceModule instance;
        return instance;
    }

    void WINAPI ServiceModule::ServiceMain(DWORD argc, LPWSTR* argv) {
        g_statusHandle = RegisterServiceCtrlHandlerW(L"SmartAVService", ControlHandler);
        if (!g_statusHandle) return;

        g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        g_serviceStatus.dwCurrentState = SERVICE_START_PENDING;
        g_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        SetServiceStatus(g_statusHandle, &g_serviceStatus);

        if (GetInstance().Initialize()) {
            g_serviceStatus.dwCurrentState = SERVICE_RUNNING;
            SetServiceStatus(g_statusHandle, &g_serviceStatus);

            // Main service loop
            while (g_serviceStatus.dwCurrentState == SERVICE_RUNNING) {
                Sleep(1000);
            }
        }

        GetInstance().Shutdown();
        g_serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_statusHandle, &g_serviceStatus);
    }

    void WINAPI ServiceModule::ControlHandler(DWORD control) {
        switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            g_serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_statusHandle, &g_serviceStatus);
            GetInstance().Shutdown();
            g_serviceStatus.dwCurrentState = SERVICE_STOPPED;
            SetServiceStatus(g_statusHandle, &g_serviceStatus);
            break;
        default:
            break;
        }
    }

    bool ServiceModule::Install(const ServiceConfig& config) {
        SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
        if (!schSCManager) return false;

        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);

        SC_HANDLE schService = CreateServiceW(
            schSCManager,
            config.serviceName.c_str(),
            config.displayName.c_str(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            config.startType,
            SERVICE_ERROR_NORMAL,
            path,
            NULL, NULL, NULL, NULL, NULL
        );

        bool success = (schService != NULL);
        if (schService) CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return success;
    }

    bool ServiceModule::Uninstall(const std::wstring& serviceName) {
        SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (!schSCManager) return false;

        SC_HANDLE schService = OpenServiceW(schSCManager, serviceName.c_str(), DELETE);
        bool success = false;
        if (schService) {
            success = DeleteService(schService) == TRUE;
            CloseServiceHandle(schService);
        }
        CloseServiceHandle(schSCManager);
        return success;
    }

    bool ServiceModule::RunAsConsole() {
        if (!Initialize()) return false;
        
        // Simple console mode - wait for input
        while (true) {
            Sleep(1000);
        }
        
        Shutdown();
        return true;
    }

    bool ServiceModule::Initialize() {
        // Initialize all components using singletons
        AIDetector::GetInstance().Initialize();
        QuarantineManager::GetInstance().Initialize();
        SelfProtection::Instance().Initialize();
        RealTimeMonitor::GetInstance().Initialize();
        RealTimeMonitor::GetInstance().Start();
        
        return true;
    }

    void ServiceModule::Shutdown() {
        RealTimeMonitor::GetInstance().Stop();
        RealTimeMonitor::GetInstance().Shutdown();
        SelfProtection::Instance().Shutdown();
        QuarantineManager::GetInstance().Shutdown();
        AIDetector::GetInstance().Shutdown();
    }

    bool ServiceModule::StartScan(ScanType type, const std::wstring& path) {
        if (m_scanRunning) return false;
        m_scanRunning = true;

        // Use FileScanner as local instance
        FileScanner scanner;
        
        switch (type) {
        case ScanType::QUICK:
            scanner.QuickScan(nullptr);
            break;
        case ScanType::FULL:
            scanner.FullScan(nullptr);
            break;
        case ScanType::CUSTOM:
            if (!path.empty()) {
                ScanReport report;
                scanner.ScanSingleFile(path, report);
            }
            break;
        default:
            break;
        }

        m_scanRunning = false;
        return true;
    }

    bool ServiceModule::StopScan() {
        // Signal scan to stop
        m_scanRunning = false;
        return true;
    }

} // namespace AIAntivirus
