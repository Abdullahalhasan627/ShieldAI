/**
 * ScanEngine.cpp - Complete Scanning Engine Implementation
 */

#define NOMINMAX
#include "ScanEngine.h"
#include "../AI/AIDetector.h"
#include "../Security/Quarantine.h"
#include <filesystem>
#include <wincrypt.h>
#include <algorithm>
#include <chrono>

#pragma comment(lib, "crypt32.lib")

namespace fs = std::filesystem;

namespace AIAntivirus {

    // Suspicious API calls for heuristic analysis
    static const std::vector<std::string> SUSPICIOUS_IMPORTS = {
        "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
        "NtUnmapViewOfSection", "SetWindowsHookEx", "GetAsyncKeyState",
        "InternetOpen", "URLDownloadToFile", "WinExec", "ShellExecute",
        "RegSetValueEx", "CreateService", "OpenProcess", "ReadProcessMemory",
        "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC"
    };

    // Suspicious strings in files
    static const std::vector<std::string> SUSPICIOUS_STRINGS = {
        "mimikatz", "metasploit", "cobalt", "beacon", "payload",
        "keylog", "ransom", "encrypt", "bitcoin", "wallet",
        "password", "credential", "dump", "inject", "hook"
    };

    ScanEngine& ScanEngine::GetInstance() {
        static ScanEngine instance;
        return instance;
    }

    bool ScanEngine::Initialize(const std::wstring& dataPath) {
        std::wstring sigPath = dataPath + L"\\signatures.txt";
        std::wstring whitePath = dataPath + L"\\whitelist.txt";
        
        LoadSignatures(sigPath);
        LoadWhitelist(whitePath);
        
        // Initialize AI Detector
        DetectorConfig aiConfig;
        aiConfig.modelPath = "models/model.onnx";
        aiConfig.detectionThreshold = 0.7f;
        AIDetector::GetInstance().Initialize(aiConfig);
        
        return true;
    }

    void ScanEngine::Shutdown() {
        StopScan();
        AIDetector::GetInstance().Shutdown();
    }

    bool ScanEngine::LoadSignatures(const std::wstring& sigFile) {
        std::ifstream file(sigFile);
        if (!file.is_open()) return false;

        std::lock_guard<std::mutex> lock(m_sigMutex);
        m_signatures.clear();

        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;
            
            // Parse: HASH|THREAT_NAME|SEVERITY
            size_t pos1 = line.find('|');
            size_t pos2 = line.rfind('|');
            if (pos1 != std::string::npos && pos2 != pos1) {
                std::string hash = line.substr(0, pos1);
                std::string name = line.substr(pos1 + 1, pos2 - pos1 - 1);
                int severity = std::stoi(line.substr(pos2 + 1));
                
                std::wstring wname(name.begin(), name.end());
                m_signatures[hash] = {wname, severity};
            }
        }
        return true;
    }

    bool ScanEngine::LoadWhitelist(const std::wstring& whitelistFile) {
        std::ifstream file(whitelistFile);
        if (!file.is_open()) return false;

        std::lock_guard<std::mutex> lock(m_sigMutex);
        m_whitelist.clear();

        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;
            size_t pos = line.find('|');
            std::string hash = (pos != std::string::npos) ? line.substr(0, pos) : line;
            m_whitelist.insert(hash);
        }
        return true;
    }

    void ScanEngine::StartQuickScan(ScanCallback callback) {
        if (m_isScanning.load()) return;

        m_scanThread = std::thread([this, callback]() {
            m_isScanning = true;
            m_stopRequested = false;
            m_threats.clear();
            m_progress = ScanProgress{};

            std::vector<std::wstring> quickPaths = {
                L"C:\\Windows\\System32",
                L"C:\\Windows\\SysWOW64",
                L"C:\\Program Files",
                L"C:\\Program Files (x86)"
            };

            // Add user folders
            wchar_t* userProfile = nullptr;
            size_t len = 0;
            if (_wdupenv_s(&userProfile, &len, L"USERPROFILE") == 0 && userProfile) {
                quickPaths.push_back(std::wstring(userProfile) + L"\\Downloads");
                quickPaths.push_back(std::wstring(userProfile) + L"\\Desktop");
                quickPaths.push_back(std::wstring(userProfile) + L"\\AppData\\Roaming");
                free(userProfile);
            }

            for (const auto& path : quickPaths) {
                if (m_stopRequested.load()) break;
                if (fs::exists(path)) {
                    ScanDirectory(path, false, callback); // Non-recursive for quick scan
                }
            }

            m_progress.isComplete = true;
            if (callback) callback(m_progress, nullptr);
            m_isScanning = false;
        });
        m_scanThread.detach();
    }

    void ScanEngine::StartFullScan(ScanCallback callback) {
        if (m_isScanning.load()) return;

        m_scanThread = std::thread([this, callback]() {
            m_isScanning = true;
            m_stopRequested = false;
            m_threats.clear();
            m_progress = ScanProgress{};

            DWORD drives = GetLogicalDrives();
            for (int i = 0; i < 26; i++) {
                if (m_stopRequested.load()) break;
                if (drives & (1 << i)) {
                    std::wstring drivePath = std::wstring(1, L'A' + i) + L":\\";
                    if (GetDriveTypeW(drivePath.c_str()) == DRIVE_FIXED) {
                        ScanDirectory(drivePath, true, callback);
                    }
                }
            }

            m_progress.isComplete = true;
            if (callback) callback(m_progress, nullptr);
            m_isScanning = false;
        });
        m_scanThread.detach();
    }

    void ScanEngine::StartCustomScan(const std::wstring& path, ScanCallback callback) {
        if (m_isScanning.load()) return;

        m_scanThread = std::thread([this, path, callback]() {
            m_isScanning = true;
            m_stopRequested = false;
            m_threats.clear();
            m_progress = ScanProgress{};

            if (fs::exists(path)) {
                if (fs::is_directory(path)) {
                    ScanDirectory(path, true, callback);
                } else {
                    auto threat = ScanFile(path);
                    if (threat.level != ThreatLevel::SAFE) {
                        std::lock_guard<std::mutex> lock(m_threatsMutex);
                        m_threats.push_back(threat);
                        if (callback) callback(m_progress, &threat);
                    }
                }
            }

            m_progress.isComplete = true;
            if (callback) callback(m_progress, nullptr);
            m_isScanning = false;
        });
        m_scanThread.detach();
    }

    void ScanEngine::StopScan() {
        m_stopRequested = true;
    }

    void ScanEngine::ScanDirectory(const std::wstring& path, bool recursive, ScanCallback callback) {
        std::vector<std::wstring> files;
        CollectFiles(path, recursive, files);

        {
            std::lock_guard<std::mutex> lock(m_progressMutex);
            m_progress.totalFiles += files.size();
        }

        for (const auto& file : files) {
            if (m_stopRequested.load()) break;

            {
                std::lock_guard<std::mutex> lock(m_progressMutex);
                m_progress.currentFile = file;
            }

            try {
                auto threat = ScanFile(file);
                
                {
                    std::lock_guard<std::mutex> lock(m_progressMutex);
                    m_progress.scannedFiles++;
                }

                if (threat.level != ThreatLevel::SAFE) {
                    {
                        std::lock_guard<std::mutex> lock(m_threatsMutex);
                        m_threats.push_back(threat);
                        m_progress.threatsFound++;
                    }
                    if (callback) callback(m_progress, &threat);
                } else {
                    if (callback) callback(m_progress, nullptr);
                }
            } catch (...) {
                std::lock_guard<std::mutex> lock(m_progressMutex);
                m_progress.errors++;
            }
        }
    }

    ThreatInfo ScanEngine::ScanFile(const std::wstring& filePath) {
        ThreatInfo result;
        result.filePath = filePath;
        result.level = ThreatLevel::SAFE;

        // 1. Calculate hash
        result.sha256Hash = CalculateSHA256(filePath);
        if (result.sha256Hash.empty()) {
            return result;
        }

        // 2. Check whitelist
        if (IsWhitelisted(result.sha256Hash)) {
            return result;
        }

        // 3. Check signature database
        std::wstring threatName;
        int severity = 0;
        if (CheckSignature(result.sha256Hash, threatName, severity)) {
            result.threatName = threatName;
            result.method = DetectionMethod::SIGNATURE;
            result.confidence = 1.0f;
            result.level = static_cast<ThreatLevel>(severity);
            result.details = "Matched known malware signature";
            return result;
        }

        // 4. Heuristic analysis
        std::vector<std::string> indicators;
        float heuristicScore = RunHeuristicAnalysis(filePath, indicators);
        
        // 5. AI analysis
        auto features = ExtractFeatures(filePath);
        float aiScore = 0.0f;
        if (!features.empty()) {
            aiScore = RunAIAnalysis(features);
        }

        // 6. Combine scores
        float finalScore = (heuristicScore * 0.4f) + (aiScore * 0.6f);

        if (finalScore >= 0.85f) {
            result.level = ThreatLevel::CRITICAL;
            result.threatName = L"HEUR:Malware.AI.Detected";
            result.method = DetectionMethod::AI;
        } else if (finalScore >= 0.7f) {
            result.level = ThreatLevel::HIGH;
            result.threatName = L"HEUR:Suspicious.High";
            result.method = DetectionMethod::AI;
        } else if (finalScore >= 0.5f) {
            result.level = ThreatLevel::MEDIUM;
            result.threatName = L"HEUR:Suspicious.Medium";
            result.method = DetectionMethod::HEURISTIC;
        } else if (finalScore >= 0.3f) {
            result.level = ThreatLevel::LOW;
            result.threatName = L"HEUR:Suspicious.Low";
            result.method = DetectionMethod::HEURISTIC;
        }

        result.confidence = finalScore;
        
        // Build details
        if (!indicators.empty()) {
            std::stringstream ss;
            ss << "Indicators: ";
            for (size_t i = 0; i < indicators.size() && i < 5; i++) {
                if (i > 0) ss << ", ";
                ss << indicators[i];
            }
            result.details = ss.str();
        }

        return result;
    }

    bool ScanEngine::CheckSignature(const std::string& hash, std::wstring& threatName, int& severity) {
        std::lock_guard<std::mutex> lock(m_sigMutex);
        auto it = m_signatures.find(hash);
        if (it != m_signatures.end()) {
            threatName = it->second.first;
            severity = it->second.second;
            return true;
        }
        return false;
    }

    bool ScanEngine::IsWhitelisted(const std::string& hash) {
        std::lock_guard<std::mutex> lock(m_sigMutex);
        return m_whitelist.find(hash) != m_whitelist.end();
    }

    float ScanEngine::RunHeuristicAnalysis(const std::wstring& filePath, std::vector<std::string>& indicators) {
        float score = 0.0f;
        
        try {
            // Check file extension
            std::wstring ext = fs::path(filePath).extension().wstring();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
            
            if (ext == L".exe" || ext == L".dll" || ext == L".scr" || ext == L".sys") {
                // Read file for analysis
                std::ifstream file(filePath, std::ios::binary);
                if (!file.is_open()) return 0.0f;

                std::vector<char> buffer(1024 * 1024); // 1MB max
                file.read(buffer.data(), buffer.size());
                size_t bytesRead = file.gcount();
                file.close();

                std::string content(buffer.data(), bytesRead);

                // Check for suspicious imports
                for (const auto& api : SUSPICIOUS_IMPORTS) {
                    if (content.find(api) != std::string::npos) {
                        score += 0.1f;
                        indicators.push_back("Suspicious API: " + api);
                    }
                }

                // Check for suspicious strings
                for (const auto& str : SUSPICIOUS_STRINGS) {
                    if (content.find(str) != std::string::npos) {
                        score += 0.15f;
                        indicators.push_back("Suspicious string: " + str);
                    }
                }

                // Check PE header for anomalies
                if (bytesRead > 64 && buffer[0] == 'M' && buffer[1] == 'Z') {
                    // Check for packed/encrypted sections
                    if (content.find("UPX") != std::string::npos) {
                        score += 0.2f;
                        indicators.push_back("Packed with UPX");
                    }
                    if (content.find("Themida") != std::string::npos ||
                        content.find("VMProtect") != std::string::npos) {
                        score += 0.25f;
                        indicators.push_back("Protected/Virtualized code");
                    }

                    // Calculate section entropy
                    int highEntropyBytes = 0;
                    for (size_t i = 0; i < bytesRead; i++) {
                        if ((unsigned char)buffer[i] > 200) highEntropyBytes++;
                    }
                    float entropyRatio = (float)highEntropyBytes / bytesRead;
                    if (entropyRatio > 0.6f) {
                        score += 0.2f;
                        indicators.push_back("High entropy (possible encryption)");
                    }

                    // Check if unsigned
                    // (simplified - just check for no certificate data)
                    if (content.find("-----BEGIN CERTIFICATE-----") == std::string::npos) {
                        score += 0.1f;
                        indicators.push_back("Unsigned executable");
                    }
                }
            }
        } catch (...) {
            // Ignore errors
        }

        return std::min(score, 1.0f);
    }

    float ScanEngine::RunAIAnalysis(const std::vector<float>& features) {
        if (features.empty()) return 0.0f;
        
        auto& detector = AIDetector::GetInstance();
        auto result = detector.Detect(features);
        
        if (result.isValid) {
            return result.maliciousScore;
        }
        return 0.0f;
    }

    std::string ScanEngine::CalculateSHA256(const std::wstring& filePath) {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        std::string result;

        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return "";

        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            CloseHandle(hFile);
            return "";
        }

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return "";
        }

        BYTE buffer[65536];
        DWORD bytesRead;
        while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
            CryptHashData(hHash, buffer, bytesRead, 0);
        }

        BYTE hash[32];
        DWORD hashLen = 32;
        if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
            char hex[65];
            for (DWORD i = 0; i < hashLen; i++) {
                sprintf_s(hex + i * 2, 3, "%02x", hash[i]);
            }
            result = hex;
        }

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return result;
    }

    std::vector<float> ScanEngine::ExtractFeatures(const std::wstring& filePath) {
        std::vector<float> features;
        
        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open()) return features;

            std::vector<uint8_t> content((std::istreambuf_iterator<char>(file)),
                                          std::istreambuf_iterator<char>());
            file.close();

            if (content.empty() || content.size() > 50 * 1024 * 1024) return features; // Skip files > 50MB

            // Byte histogram (256 values)
            std::vector<float> histogram(256, 0.0f);
            for (uint8_t byte : content) {
                histogram[byte]++;
            }
            for (float& h : histogram) {
                h /= content.size();
            }
            features.insert(features.end(), histogram.begin(), histogram.end());

            // Entropy
            float entropy = 0.0f;
            for (float h : histogram) {
                if (h > 0) entropy -= h * std::log2(h);
            }
            features.push_back(entropy / 8.0f);

            // File size (normalized)
            features.push_back(std::min(1.0f, (float)content.size() / (10.0f * 1024 * 1024)));

            // PE detection
            bool isPE = content.size() > 64 && content[0] == 'M' && content[1] == 'Z';
            features.push_back(isPE ? 1.0f : 0.0f);

            // Pad to expected size (512 features typical for malware models)
            while (features.size() < 512) {
                features.push_back(0.0f);
            }

        } catch (...) {
            features.clear();
        }

        return features;
    }

    void ScanEngine::CollectFiles(const std::wstring& path, bool recursive, std::vector<std::wstring>& files) {
        try {
            auto options = fs::directory_options::skip_permission_denied;
            
            if (recursive) {
                for (const auto& entry : fs::recursive_directory_iterator(path, options)) {
                    if (m_stopRequested.load()) break;
                    if (entry.is_regular_file()) {
                        std::wstring ext = entry.path().extension().wstring();
                        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
                        // Focus on executable files
                        if (ext == L".exe" || ext == L".dll" || ext == L".scr" || 
                            ext == L".sys" || ext == L".bat" || ext == L".cmd" ||
                            ext == L".ps1" || ext == L".vbs" || ext == L".js") {
                            files.push_back(entry.path().wstring());
                        }
                    }
                }
            } else {
                for (const auto& entry : fs::directory_iterator(path, options)) {
                    if (m_stopRequested.load()) break;
                    if (entry.is_regular_file()) {
                        std::wstring ext = entry.path().extension().wstring();
                        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
                        if (ext == L".exe" || ext == L".dll" || ext == L".scr" || 
                            ext == L".sys" || ext == L".bat" || ext == L".cmd" ||
                            ext == L".ps1" || ext == L".vbs" || ext == L".js") {
                            files.push_back(entry.path().wstring());
                        }
                    }
                }
            }
        } catch (...) {
            // Ignore access errors
        }
    }

    std::vector<ThreatInfo> ScanEngine::GetThreats() const {
        std::lock_guard<std::mutex> lock(m_threatsMutex);
        return m_threats;
    }

    ScanProgress ScanEngine::GetProgress() const {
        std::lock_guard<std::mutex> lock(m_progressMutex);
        return m_progress;
    }

} // namespace AIAntivirus
