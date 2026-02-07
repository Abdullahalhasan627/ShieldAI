/**
 * FileScanner_impl.cpp - Clean Implementation
 */

#include "FileScanner.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <thread>
#include <chrono>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

namespace fs = std::filesystem;

namespace AIAntivirus {

    FileScanner::FileScanner() : m_statistics{0, 0, 0, 0.0} {}

    FileScanner::~FileScanner() {
        StopScan();
    }

    bool FileScanner::ScanSingleFile(const std::wstring& filePath, ScanReport& report) {
        if (!fs::exists(filePath)) {
            report.result = ScanResult::SCAN_ERROR;
            report.details = "File does not exist";
            return false;
        }

        if (IsWhitelisted(filePath)) {
            report.result = ScanResult::WHITELISTED;
            report.confidenceScore = 0.0f;
            report.details = "File is whitelisted";
            return true;
        }

        FileInfo fileInfo;
        if (!ExtractFileInfo(filePath, fileInfo)) {
            report.result = ScanResult::SCAN_ERROR;
            report.details = "Failed to extract file information";
            return false;
        }

        // Basic heuristic analysis
        float threatScore = 0.0f;

        if (fileInfo.isPEFile && !fileInfo.isSigned) {
            threatScore += 0.3f;
        }

        for (const auto& imp : fileInfo.imports) {
            if (imp.find("CreateRemoteThread") != std::string::npos ||
                imp.find("WriteProcessMemory") != std::string::npos) {
                threatScore += 0.4f;
            }
        }

        if (threatScore >= 0.8f) {
            report.result = ScanResult::MALICIOUS;
            report.threatName = L"HEUR:Trojan.Win32.Generic";
        } else if (threatScore >= 0.4f) {
            report.result = ScanResult::SUSPICIOUS;
            report.threatName = L"HEUR:Suspicious.Win32.Generic";
        } else {
            report.result = ScanResult::CLEAN;
            report.threatName = L"";
        }

        report.confidenceScore = threatScore;
        report.detectionMethod = "Heuristic Analysis";

        {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_statistics.totalFiles++;
            if (report.result == ScanResult::MALICIOUS || report.result == ScanResult::SUSPICIOUS) {
                m_statistics.threatsFound++;
            }
        }

        return true;
    }

    size_t FileScanner::ScanDirectory(const std::wstring& directoryPath, ProgressCallback callback, bool recursive) {
        if (!fs::exists(directoryPath) || !fs::is_directory(directoryPath)) {
            return 0;
        }

        m_isScanning = true;
        m_stopRequested = false;

        std::vector<std::wstring> files;
        CollectFiles(directoryPath, files, recursive);

        size_t scannedCount = 0;
        auto startTime = std::chrono::steady_clock::now();

        for (const auto& filePath : files) {
            if (m_stopRequested.load()) break;
            ProcessSingleFile(filePath, callback, scannedCount, files.size());
            scannedCount++;
        }

        auto endTime = std::chrono::steady_clock::now();
        {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_statistics.durationSeconds = std::chrono::duration<double>(endTime - startTime).count();
        }

        m_isScanning = false;
        return scannedCount;
    }

    size_t FileScanner::QuickScan(ProgressCallback callback) {
        std::vector<std::wstring> paths = {
            L"C:\\Windows\\System32",
            L"C:\\Program Files"
        };
        
        size_t total = 0;
        for (const auto& path : paths) {
            if (fs::exists(path)) {
                total += ScanDirectory(path, callback, false);
            }
        }
        return total;
    }

    size_t FileScanner::FullScan(ProgressCallback callback) {
        DWORD drives = GetLogicalDrives();
        size_t total = 0;

        for (int i = 0; i < 26; i++) {
            if (drives & (1 << i)) {
                std::wstring drivePath = std::wstring(1, L'A' + i) + L":\\";
                if (GetDriveTypeW(drivePath.c_str()) == DRIVE_FIXED) {
                    total += ScanDirectory(drivePath, callback, true);
                }
            }
        }
        return total;
    }

    void FileScanner::StopScan() {
        m_stopRequested = true;
        int timeout = 0;
        while (m_isScanning.load() && timeout < 50) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            timeout++;
        }
    }

    FileScanner::ScanStatistics FileScanner::GetLastStatistics() const {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        return m_statistics;
    }

    bool FileScanner::ExtractFileInfo(const std::wstring& filePath, FileInfo& info) {
        info.filePath = filePath;
        info.fileName = fs::path(filePath).filename().wstring();
        
        try {
            info.fileSize = fs::file_size(filePath);
        } catch (...) {
            info.fileSize = 0;
        }

        CalculateSHA256(filePath, info.sha256Hash);

        std::wstring ext = fs::path(filePath).extension().wstring();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        info.isPEFile = (ext == L".exe" || ext == L".dll" || ext == L".sys");

        if (info.isPEFile) {
            AnalyzePEFile(filePath, info);
        }

        return true;
    }

    bool FileScanner::CalculateSHA256(const std::wstring& filePath, std::string& hashOut) {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            CloseHandle(hFile);
            return false;
        }

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return false;
        }

        BYTE buffer[4096];
        DWORD bytesRead;
        while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
            CryptHashData(hHash, buffer, bytesRead, 0);
        }

        BYTE hash[32];
        DWORD hashLen = 32;
        if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
            std::stringstream ss;
            for (DWORD i = 0; i < hashLen; i++) {
                ss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
            }
            hashOut = ss.str();
        }

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return true;
    }

    bool FileScanner::AnalyzePEFile(const std::wstring& filePath, FileInfo& info) {
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        IMAGE_DOS_HEADER dosHeader;
        DWORD bytesRead;
        if (!ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, NULL) ||
            dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            CloseHandle(hFile);
            return false;
        }

        SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN);
        IMAGE_NT_HEADERS ntHeaders;
        if (!ReadFile(hFile, &ntHeaders, sizeof(ntHeaders), &bytesRead, NULL) ||
            ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
            CloseHandle(hFile);
            return false;
        }

        info.entryPoint = ntHeaders.OptionalHeader.AddressOfEntryPoint;
        info.imageBase = (uint32_t)ntHeaders.OptionalHeader.ImageBase;
        info.numberOfSections = ntHeaders.FileHeader.NumberOfSections;

        CloseHandle(hFile);
        return true;
    }

    bool FileScanner::VerifyDigitalSignature(const std::wstring& filePath, bool& isSigned, std::string& signerName) {
        isSigned = false;
        signerName = "";
        // Simplified - just check if file exists
        return fs::exists(filePath);
    }

    bool FileScanner::IsWhitelisted(const std::wstring& filePath) {
        // System files are whitelisted
        std::wstring lower = filePath;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        return lower.find(L"\\windows\\system32\\") != std::wstring::npos &&
               lower.find(L".exe") == std::wstring::npos;
    }

    void FileScanner::CollectFiles(const std::wstring& directoryPath, std::vector<std::wstring>& files, bool recursive) {
        try {
            if (recursive) {
                for (const auto& entry : fs::recursive_directory_iterator(directoryPath, fs::directory_options::skip_permission_denied)) {
                    if (entry.is_regular_file()) {
                        files.push_back(entry.path().wstring());
                    }
                }
            } else {
                for (const auto& entry : fs::directory_iterator(directoryPath, fs::directory_options::skip_permission_denied)) {
                    if (entry.is_regular_file()) {
                        files.push_back(entry.path().wstring());
                    }
                }
            }
        } catch (...) {}
    }

    void FileScanner::ProcessSingleFile(const std::wstring& filePath, ProgressCallback callback, size_t current, size_t total) {
        ScanReport report;
        bool success = ScanSingleFile(filePath, report);

        if (!success) {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_statistics.errors++;
        }

        if (callback) {
            callback(filePath, current + 1, total, report);
        }
    }

} // namespace AIAntivirus
