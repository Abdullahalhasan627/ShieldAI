#pragma once
#include <string>
#include <vector>
#include <chrono>

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

        QuarantineResult QuarantineFile(const std::wstring& filePath,
            const std::string& threatName,
            const std::string& detectionMethod,
            float threatScore,
            QuarantineEntry* outEntry = nullptr);

        QuarantineResult RestoreFile(const std::wstring& quarantineId,
            const std::wstring& destinationPath = L"");
        QuarantineResult DeletePermanently(const std::wstring& quarantineId, bool secureDelete = true);

        std::vector<QuarantineEntry> GetQuarantinedFiles();
        bool FindEntry(const std::wstring& quarantineId, QuarantineEntry& entry);

    private:
        QuarantineManager() = default;
        ~QuarantineManager() = default;
    };

} // namespace AIAntivirus