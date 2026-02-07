/**
 * RealTimeMonitor_impl.cpp - Real-Time Monitor Implementation
 */

#include "RealTimeMonitor.h"
#include <filesystem>

namespace fs = std::filesystem;

namespace AIAntivirus {

    RealTimeMonitor& RealTimeMonitor::GetInstance() {
        static RealTimeMonitor instance;
        return instance;
    }

    bool RealTimeMonitor::Initialize(const MonitorConfig& config) {
        m_config = config;
        m_isInitialized = true;
        return true;
    }

    void RealTimeMonitor::Shutdown() {
        Stop();
        m_isInitialized = false;
    }

    bool RealTimeMonitor::Start() {
        if (!m_isInitialized || m_isRunning) return false;
        
        m_isRunning = true;
        m_stopRequested = false;
        m_startTime = std::chrono::steady_clock::now();
        
        // Start monitoring thread
        m_monitorThread = std::thread([this]() {
            while (!m_stopRequested) {
                // Check for events (simplified)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        });
        
        return true;
    }

    void RealTimeMonitor::Stop() {
        if (!m_isRunning) return;
        
        m_stopRequested = true;
        if (m_monitorThread.joinable()) {
            m_monitorThread.join();
        }
        m_isRunning = false;
    }

    bool RealTimeMonitor::AddWatchPath(const std::wstring& path) {
        std::lock_guard<std::mutex> lock(m_pathsMutex);
        m_watchedPaths.insert(path);
        return true;
    }

    bool RealTimeMonitor::RemoveWatchPath(const std::wstring& path) {
        std::lock_guard<std::mutex> lock(m_pathsMutex);
        m_watchedPaths.erase(path);
        return true;
    }

    void RealTimeMonitor::SetEventCallback(EventCallback callback) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_eventCallback = callback;
    }

    void RealTimeMonitor::AddException(const std::wstring& path) {
        std::lock_guard<std::shared_mutex> lock(m_exceptionsMutex);
        m_exceptions.insert(path);
    }

    void RealTimeMonitor::RemoveException(const std::wstring& path) {
        std::lock_guard<std::shared_mutex> lock(m_exceptionsMutex);
        m_exceptions.erase(path);
    }

    MonitorStats RealTimeMonitor::GetStatistics() const {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        MonitorStats stats = m_stats;
        if (m_isRunning) {
            auto now = std::chrono::steady_clock::now();
            stats.uptimeSeconds = std::chrono::duration<double>(now - m_startTime).count();
        }
        return stats;
    }

} // namespace AIAntivirus
