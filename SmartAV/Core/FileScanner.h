#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <mutex>
#include <queue>

namespace AIAntivirus {

    enum class ScanResult { CLEAN, MALICIOUS, SUSPICIOUS, SCAN_ERROR, WHITELISTED };

    struct FileInfo {
        std::wstring filePath;
        std::wstring fileName;
        uint64_t fileSize = 0;
        std::string sha256Hash;
        bool isPEFile = false;
        bool isSigned = false;
        std::string signerName;
        uint32_t entryPoint = 0;
        uint32_t imageBase = 0;
        uint16_t numberOfSections = 0;
        std::vector<std::string> imports;
        std::vector<std::string> sectionNames;
        std::vector<float> featureVector;
    };

    struct ScanReport {
        ScanResult result = ScanResult::CLEAN;
        float confidenceScore = 0.0f;
        std::wstring threatName;
        std::string detectionMethod;
        std::string details;
    };

    using ProgressCallback = std::function<void(const std::wstring&, size_t, size_t, const ScanReport&)>;

    class FileScanner {
    public:
        struct ScanStatistics {
            size_t totalFiles = 0;
            size_t threatsFound = 0;
            size_t errors = 0;
            double durationSeconds = 0.0;
        };

        FileScanner();
        ~FileScanner();

        FileScanner(const FileScanner&) = delete;
        FileScanner& operator=(const FileScanner&) = delete;

        bool ScanSingleFile(const std::wstring& filePath, ScanReport& report);
        size_t ScanDirectory(const std::wstring& directoryPath, ProgressCallback callback, bool recursive = true);
        size_t QuickScan(ProgressCallback callback);
        size_t FullScan(ProgressCallback callback);
        void StopScan();
        bool IsScanning() const { return m_isScanning.load(); }
        ScanStatistics GetLastStatistics() const;

    private:
        std::atomic<bool> m_isScanning{ false };
        std::atomic<bool> m_stopRequested{ false };
        std::mutex m_scanMutex;
        mutable std::mutex m_statsMutex;
        ScanStatistics m_statistics;

        bool ExtractFileInfo(const std::wstring& filePath, FileInfo& info);
        bool CalculateSHA256(const std::wstring& filePath, std::string& hashOut);
        bool AnalyzePEFile(const std::wstring& filePath, FileInfo& info);
        bool VerifyDigitalSignature(const std::wstring& filePath, bool& isSigned, std::string& signerName);
        bool IsWhitelisted(const std::wstring& filePath);
        void CollectFiles(const std::wstring& directoryPath, std::vector<std::wstring>& files, bool recursive);
        void ProcessSingleFile(const std::wstring& filePath, ProgressCallback callback, size_t current, size_t total);
    };

} // namespace AIAntivirus