#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <functional>

namespace AIAntivirus {

    enum class ScanResult { CLEAN, MALICIOUS, SUSPICIOUS, ERROR, WHITELISTED };

    struct FileInfo {
        std::wstring filePath;
        std::wstring fileName;
        uint64_t fileSize;
        std::string sha256Hash;
        bool isPEFile;
        bool isSigned;
        std::string signerName;
        uint32_t entryPoint;
        uint32_t imageBase;
        uint16_t numberOfSections;
        std::vector<std::string> imports;
        std::vector<std::string> sectionNames;
        std::vector<float> featureVector;
    };

    struct ScanReport {
        ScanResult result;
        float confidenceScore;
        std::wstring threatName;
        std::string detectionMethod;
        std::string details;
    };

    using ProgressCallback = std::function<void(const std::wstring&, size_t, size_t, const ScanReport&)>;

    class FileScanner {
    public:
        FileScanner();
        ~FileScanner();

        bool ScanSingleFile(const std::wstring& filePath, ScanReport& report);
        size_t ScanDirectory(const std::wstring& directoryPath, ProgressCallback callback, bool recursive = true);
        size_t QuickScan(ProgressCallback callback);
        size_t FullScan(ProgressCallback callback);
        void StopScan();
        bool IsScanning() const;

        struct ScanStatistics {
            size_t totalFiles;
            size_t threatsFound;
            size_t errors;
            double durationSeconds;
        };
        ScanStatistics GetLastStatistics() const;

    private:
        // ... (Implementation details from .cpp)
        std::atomic<bool> m_isScanning{ false };
    };

} // namespace AIAntivirus