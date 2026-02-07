#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <mutex>
#include <atomic>
#include <thread>
#include <fstream>
#include <sstream>

namespace AIAntivirus {

    enum class ThreatLevel { SAFE, LOW, MEDIUM, HIGH, CRITICAL };
    enum class DetectionMethod { SIGNATURE, HEURISTIC, AI, BEHAVIORAL };

    struct ThreatInfo {
        std::wstring filePath;
        std::string sha256Hash;
        std::wstring threatName;
        ThreatLevel level = ThreatLevel::SAFE;
        DetectionMethod method = DetectionMethod::SIGNATURE;
        float confidence = 0.0f;
        std::string details;
        bool quarantined = false;
    };

    struct ScanProgress {
        size_t totalFiles = 0;
        size_t scannedFiles = 0;
        size_t threatsFound = 0;
        size_t errors = 0;
        std::wstring currentFile;
        bool isComplete = false;
    };

    using ScanCallback = std::function<void(const ScanProgress& progress, const ThreatInfo* threat)>;

    class ScanEngine {
    public:
        static ScanEngine& GetInstance();

        bool Initialize(const std::wstring& dataPath);
        void Shutdown();

        // Scanning
        void StartQuickScan(ScanCallback callback);
        void StartFullScan(ScanCallback callback);
        void StartCustomScan(const std::wstring& path, ScanCallback callback);
        void StopScan();
        bool IsScanning() const { return m_isScanning.load(); }

        // Single file scan
        ThreatInfo ScanFile(const std::wstring& filePath);

        // Results
        std::vector<ThreatInfo> GetThreats() const;
        ScanProgress GetProgress() const;

        // Signatures
        bool LoadSignatures(const std::wstring& sigFile);
        bool LoadWhitelist(const std::wstring& whitelistFile);
        size_t GetSignatureCount() const { return m_signatures.size(); }

    private:
        ScanEngine() = default;
        ~ScanEngine() = default;

        // Signature database: hash -> {threatName, severity}
        std::unordered_map<std::string, std::pair<std::wstring, int>> m_signatures;
        std::unordered_set<std::string> m_whitelist;
        mutable std::mutex m_sigMutex;

        // Scan state
        std::atomic<bool> m_isScanning{false};
        std::atomic<bool> m_stopRequested{false};
        std::thread m_scanThread;
        mutable std::mutex m_progressMutex;
        ScanProgress m_progress;
        std::vector<ThreatInfo> m_threats;
        mutable std::mutex m_threatsMutex;

        // Internal methods
        void ScanDirectory(const std::wstring& path, bool recursive, ScanCallback callback);
        ThreatInfo AnalyzeFile(const std::wstring& filePath);
        bool CheckSignature(const std::string& hash, std::wstring& threatName, int& severity);
        bool IsWhitelisted(const std::string& hash);
        float RunHeuristicAnalysis(const std::wstring& filePath, std::vector<std::string>& indicators);
        float RunAIAnalysis(const std::vector<float>& features);
        std::string CalculateSHA256(const std::wstring& filePath);
        std::vector<float> ExtractFeatures(const std::wstring& filePath);
        void CollectFiles(const std::wstring& path, bool recursive, std::vector<std::wstring>& files);
    };

} // namespace AIAntivirus
