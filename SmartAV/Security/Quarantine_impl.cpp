/**
 * Quarantine_impl.cpp - Quarantine Implementation with Encryption
 */

#include "Quarantine.h"
#include <filesystem>
#include <fstream>
#include <random>

namespace fs = std::filesystem;

namespace AIAntivirus {

    // XOR encryption key (256 bytes)
    static const uint8_t ENCRYPTION_KEY[256] = {
        0x5A, 0x3C, 0x9F, 0x2B, 0x7E, 0x1D, 0x4A, 0x8C, 0xF3, 0x6B, 0xD2, 0x0E, 0x95, 0x47, 0xA1, 0xC8,
        0x2D, 0x8E, 0x5F, 0x1A, 0x6C, 0xB4, 0x39, 0xE7, 0x0B, 0x72, 0xD5, 0x4E, 0x91, 0xA3, 0xC6, 0x28,
        0x7D, 0x1F, 0x5B, 0x9A, 0x3E, 0x6D, 0xB2, 0x48, 0xE1, 0x0C, 0x74, 0xD9, 0x45, 0x92, 0xA7, 0xC3,
        0x2A, 0x8F, 0x5C, 0x19, 0x6E, 0xB1, 0x3A, 0xE4, 0x09, 0x76, 0xD3, 0x4C, 0x98, 0xA5, 0xC1, 0x2E,
        0x7B, 0x1E, 0x5D, 0x9C, 0x3F, 0x6A, 0xB8, 0x49, 0xE2, 0x0D, 0x73, 0xD7, 0x46, 0x93, 0xA4, 0xC9,
        0x2C, 0x8D, 0x5E, 0x1B, 0x6F, 0xB3, 0x38, 0xE6, 0x0A, 0x75, 0xD4, 0x4D, 0x99, 0xA6, 0xC2, 0x29,
        0x7A, 0x1C, 0x5A, 0x9B, 0x3D, 0x6C, 0xB7, 0x4A, 0xE3, 0x0F, 0x71, 0xD6, 0x47, 0x94, 0xA2, 0xC5,
        0x2B, 0x8C, 0x5F, 0x18, 0x6D, 0xB5, 0x3B, 0xE5, 0x08, 0x77, 0xD1, 0x4F, 0x9A, 0xA8, 0xC4, 0x2F,
        0x79, 0x1D, 0x5C, 0x9E, 0x3C, 0x6B, 0xB6, 0x4B, 0xE0, 0x0E, 0x72, 0xD8, 0x44, 0x95, 0xA1, 0xC7,
        0x2A, 0x8B, 0x5D, 0x1A, 0x6E, 0xB4, 0x39, 0xE7, 0x0B, 0x74, 0xD2, 0x4E, 0x9B, 0xA9, 0xC3, 0x28,
        0x7E, 0x1F, 0x5B, 0x9D, 0x3E, 0x6A, 0xB2, 0x48, 0xE1, 0x0C, 0x73, 0xD9, 0x45, 0x92, 0xA0, 0xC6,
        0x2D, 0x8E, 0x5E, 0x19, 0x6F, 0xB1, 0x3A, 0xE4, 0x09, 0x76, 0xD3, 0x4C, 0x98, 0xA5, 0xC1, 0x2E,
        0x7D, 0x1E, 0x5A, 0x9C, 0x3F, 0x6C, 0xB8, 0x49, 0xE2, 0x0D, 0x71, 0xD7, 0x46, 0x93, 0xA4, 0xC9,
        0x2C, 0x8D, 0x5F, 0x1B, 0x6D, 0xB3, 0x38, 0xE6, 0x0A, 0x75, 0xD4, 0x4D, 0x99, 0xA6, 0xC2, 0x29,
        0x7A, 0x1C, 0x5C, 0x9B, 0x3D, 0x6B, 0xB7, 0x4A, 0xE3, 0x0F, 0x72, 0xD6, 0x47, 0x94, 0xA2, 0xC5,
        0x2B, 0x8C, 0x5E, 0x18, 0x6E, 0xB5, 0x3B, 0xE5, 0x08, 0x77, 0xD1, 0x4F, 0x9A, 0xA8, 0xC4, 0x2F
    };

    // Encrypt/Decrypt using XOR with rolling key
    static void EncryptDecrypt(std::vector<uint8_t>& data, uint32_t seed) {
        for (size_t i = 0; i < data.size(); i++) {
            data[i] ^= ENCRYPTION_KEY[(i + seed) % 256];
            data[i] ^= static_cast<uint8_t>((seed >> ((i % 4) * 8)) & 0xFF);
        }
    }

    // Generate random seed
    static uint32_t GenerateSeed() {
        std::random_device rd;
        return rd();
    }

    QuarantineManager& QuarantineManager::GetInstance() {
        static QuarantineManager instance;
        return instance;
    }

    bool QuarantineManager::Initialize(const QuarantineConfig& config) {
        m_config = config;
        
        // Create quarantine directory
        try {
            fs::create_directories(m_config.quarantineRoot);
            m_isInitialized = true;
            return true;
        } catch (...) {
            return false;
        }
    }

    void QuarantineManager::Shutdown() {
        m_isInitialized = false;
    }

    QuarantineResult QuarantineManager::QuarantineFile(const std::wstring& filePath, const std::wstring& threatName) {
        if (!m_isInitialized) return QuarantineResult::UNKNOWN_ERROR;
        if (!fs::exists(filePath)) return QuarantineResult::FILE_NOT_FOUND;

        try {
            // Read original file
            std::ifstream inFile(filePath, std::ios::binary);
            if (!inFile) return QuarantineResult::ACCESS_DENIED;
            
            std::vector<uint8_t> fileData((std::istreambuf_iterator<char>(inFile)),
                                           std::istreambuf_iterator<char>());
            inFile.close();

            // Generate encryption seed
            uint32_t seed = GenerateSeed();

            // Encrypt the data
            if (m_config.encryptFiles) {
                EncryptDecrypt(fileData, seed);
            }

            // Create quarantine file path
            std::wstring fileName = fs::path(filePath).filename().wstring();
            std::wstring quarantinePath = m_config.quarantineRoot + L"\\" + fileName + L".qvault";

            // Write encrypted file with header
            std::ofstream outFile(quarantinePath, std::ios::binary);
            if (!outFile) return QuarantineResult::ACCESS_DENIED;

            // Write header: "QVLT" magic + seed + original size
            const char magic[] = "QVLT";
            uint64_t originalSize = fileData.size();
            outFile.write(magic, 4);
            outFile.write(reinterpret_cast<const char*>(&seed), sizeof(seed));
            outFile.write(reinterpret_cast<const char*>(&originalSize), sizeof(originalSize));
            outFile.write(reinterpret_cast<const char*>(fileData.data()), fileData.size());
            outFile.close();

            // Delete original file
            fs::remove(filePath);

            // Record entry
            QuarantineEntry entry;
            entry.originalPath = filePath;
            entry.quarantinePath = quarantinePath;
            entry.fileName = fileName;
            entry.threatScore = 1.0f;
            entry.quarantineTime = std::chrono::system_clock::now();

            std::lock_guard<std::mutex> lock(m_entriesMutex);
            m_entries.push_back(entry);

            return QuarantineResult::SUCCESS;
        } catch (...) {
            return QuarantineResult::UNKNOWN_ERROR;
        }
    }

    QuarantineResult QuarantineManager::RestoreFile(const std::wstring& quarantinePath) {
        std::lock_guard<std::mutex> lock(m_entriesMutex);
        
        for (auto& entry : m_entries) {
            if (entry.quarantinePath == quarantinePath) {
                try {
                    fs::rename(entry.quarantinePath, entry.originalPath);
                    return QuarantineResult::SUCCESS;
                } catch (...) {
                    return QuarantineResult::UNKNOWN_ERROR;
                }
            }
        }
        return QuarantineResult::FILE_NOT_FOUND;
    }

    QuarantineResult QuarantineManager::DeletePermanently(const std::wstring& quarantinePath) {
        std::lock_guard<std::mutex> lock(m_entriesMutex);
        
        for (auto it = m_entries.begin(); it != m_entries.end(); ++it) {
            if (it->quarantinePath == quarantinePath) {
                try {
                    fs::remove(it->quarantinePath);
                    m_entries.erase(it);
                    return QuarantineResult::SUCCESS;
                } catch (...) {
                    return QuarantineResult::UNKNOWN_ERROR;
                }
            }
        }
        return QuarantineResult::FILE_NOT_FOUND;
    }

    std::vector<QuarantineEntry> QuarantineManager::GetQuarantinedFiles() const {
        std::lock_guard<std::mutex> lock(m_entriesMutex);
        return m_entries;
    }

    size_t QuarantineManager::GetQuarantineCount() const {
        std::lock_guard<std::mutex> lock(m_entriesMutex);
        return m_entries.size();
    }

} // namespace AIAntivirus
