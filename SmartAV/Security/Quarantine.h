#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <mutex>

namespace AIAntivirus {

    enum class QuarantineResult {
        SUCCESS, ALREADY_QUARANTINED, ACCESS_DENIED, FILE_NOT_FOUND,
        ENCRYPTION_FAILED, INSUFFICIENT_SPACE, DATABASE_ERROR, UNKNOWN_ERROR
    };

    struct QuarantineEntry {
        std::wstring quarantineId;
        std::wstring originalPath;
        std::wstring fileName;
        std::wstring quarantinePath;
        std::string threatName;
        float threatScore;
        std::chrono::system_clock::time_point quarantineTime;
    };

    struct QuarantineConfig {
        std::wstring quarantineRoot = L"C:\\ProgramData\\AIAntivirus\\Quarantine\\";
        bool encryptFiles = true;
        int retentionDays = 30;
    };

    class QuarantineManager {
    public:
        static QuarantineManager& GetInstance();

        bool Initialize(const QuarantineConfig& config = QuarantineConfig{});
        void Shutdown();

        QuarantineResult QuarantineFile(const std::wstring& filePath, const std::wstring& threatName);
        QuarantineResult RestoreFile(const std::wstring& quarantinePath);
        QuarantineResult DeletePermanently(const std::wstring& quarantinePath);

        std::vector<QuarantineEntry> GetQuarantinedFiles() const;
        size_t GetQuarantineCount() const;

    private:
        QuarantineManager() = default;
        ~QuarantineManager() = default;
        
        QuarantineConfig m_config;
        bool m_isInitialized = false;
        std::vector<QuarantineEntry> m_entries;
        mutable std::mutex m_entriesMutex;
    };

} // namespace AIAntivirus