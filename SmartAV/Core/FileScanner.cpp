// FileScanner.cpp - Core Module
// الماسح الضوئي للملفات

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <windows.h>
#include <chrono>
#include <iomanip>

namespace fs = std::filesystem;

// ==================== المكتبة الرئيسية ====================

class FileScanner {
private:
    std::vector<std::string> infectedFiles;
    std::vector<std::string> scanLog;
    bool isScanning = false;
    long totalFiles = 0;
    long scannedFiles = 0;

public:
    FileScanner() {
        std::cout << "[INFO] FileScanner Initialized\n";
    }

    ~FileScanner() {
        std::cout << "[INFO] FileScanner Destroyed\n";
    }

    // ==================== دوال الفحص الأساسية ====================

    // فحص ملف واحد
    bool scanSingleFile(const std::string& filePath) {
        scannedFiles++;
        
        if (!fs::exists(filePath)) {
            log("ERROR", "File not found: " + filePath);
            return false;
        }

        // التحقق من التوقيعات المشبوهة
        if (checkSignatures(filePath)) {
            infectedFiles.push_back(filePath);
            quarantineFile(filePath);
            return true;
        }

        // تحليل السلوك
        if (analyzeBehavior(filePath)) {
            infectedFiles.push_back(filePath);
            return true;
        }

        return false;
    }

    // فحص مجلد بالكامل
    void scanDirectory(const std::string& dirPath) {
        isScanning = true;
        auto start = std::chrono::high_resolution_clock::now();

        std::cout << "\n========================================\n";
        std::cout << "  AI ANTIVIRUS - SYSTEM SCAN\n";
        std::cout << "========================================\n";
        std::cout << "Target: " << dirPath << "\n\n";

        try {
            for (const auto& entry : fs::recursive_directory_iterator(dirPath)) {
                if (entry.is_regular_file()) {
                    totalFiles++;
                    std::string path = entry.path().string();
                    
                    // عرض التقدم
                    showProgress(path);
                    
                    // فحص الملف
                    scanSingleFile(path);
                }
            }
        } catch (const std::exception& e) {
            log("ERROR", std::string("Scan error: ") + e.what());
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - start);

        showResults(duration.count());
        isScanning = false;
    }

    // ==================== التوقيعات والكشف ====================

private:
    bool checkSignatures(const std::string& filePath) {
        // فتح الملف والتحقق من التوقيعات المشبوهة
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return false;

        // قراءة أول 1024 بايت (Header)
        std::vector<unsigned char> buffer(1024);
        file.read(reinterpret_cast<char*>(buffer.data()), 1024);
        size_t bytesRead = file.gcount();

        // قائمة التوقيعات المشبوهة (Hex Signatures)
        std::vector<std::vector<unsigned char>> suspiciousSignatures = {
            {0x4D, 0x5A},                    // DOS Executable (EXE)
            {0x7F, 0x45, 0x4C, 0x46},        // ELF (Linux)
            {0xCA, 0xFE, 0xBA, 0xBE},        // Java Class
            {0x50, 0x4B, 0x03, 0x04},        // ZIP (JAR, DOCX)
        };

        // التحقق من كل توقيع
        for (const auto& sig : suspiciousSignatures) {
            if (bytesRead >= sig.size()) {
                bool match = true;
                for (size_t i = 0; i < sig.size(); i++) {
                    if (buffer[i] != sig[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    log("THREAT", "Suspicious signature detected: " + filePath);
                    return true;
                }
            }
        }

        // فحص النصوص المشبوهة داخل الملف
        return scanForMaliciousStrings(filePath, buffer);
    }

    bool scanForMaliciousStrings(const std::string& filePath, 
                                  const std::vector<unsigned char>& buffer) {
        // تحويل البايتات لنص
        std::string content(buffer.begin(), buffer.end());
        
        // قائمة السلاسل المشبوهة
        std::vector<std::string> maliciousStrings = {
            "CreateRemoteThread",
            "WriteProcessMemory",
            "VirtualAllocEx",
            "RegDeleteKey",
            "cmd.exe /c",
            "powershell -enc",
            "rundll32.exe",
            "regsvr32 /s",
            "certutil -decode",
        };

        for (const auto& str : maliciousStrings) {
            if (content.find(str) != std::string::npos) {
                log("ALERT", "Malicious string found '" + str + "' in: " + filePath);
                return true;
            }
        }
        return false;
    }

    // ==================== تحليل السلوك ====================

    bool analyzeBehavior(const std::string& filePath) {
        // التحقق من امتدادات الملفات المشبوهة
        std::vector<std::string> suspiciousExts = {
            ".exe", ".dll", ".scr", ".bat", ".cmd", 
            ".vbs", ".js", ".ps1", ".wsf"
        };

        std::string ext = fs::path(filePath).extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

        for (const auto& sExt : suspiciousExts) {
            if (ext == sExt) {
                // ملف تنفيذي - تحقق عميق
                return deepAnalysis(filePath);
            }
        }
        return false;
    }

    bool deepAnalysis(const std::string& filePath) {
        // تحليل عميق للملفات التنفيذية
        WIN32_FILE_ATTRIBUTE_DATA fileInfo;
        
        if (GetFileAttributesExA(filePath.c_str(), GetFileExInfoStandard, &fileInfo)) {
            // التحقق من حجم الملف المشبوه (صغير جداً أو كبير جداً)
            LARGE_INTEGER size;
            size.HighPart = fileInfo.nFileSizeHigh;
            size.LowPart = fileInfo.nFileSizeLow;

            if (size.QuadPart == 0) {
                log("SUSPICIOUS", "Zero-byte executable: " + filePath);
                return true;
            }
            
            if (size.QuadPart > 100 * 1024 * 1024) { // > 100MB
                log("SUSPICIOUS", "Oversized executable: " + filePath);
            }
        }

        // التحقق من موارد PE (لملفات Windows)
        return checkPEResources(filePath);
    }

    bool checkPEResources(const std::string& filePath) {
        // فحص موارد PE للكشف عن الستغانوغرافي
        HANDLE hFile = CreateFileA(
            filePath.c_str(), 
            GENERIC_READ, 
            FILE_SHARE_READ, 
            NULL, 
            OPEN_EXISTING, 
            FILE_ATTRIBUTE_NORMAL, 
            NULL
        );

        if (hFile == INVALID_HANDLE_VALUE) return false;

        // قراءة DOS Header
        IMAGE_DOS_HEADER dosHeader;
        DWORD bytesRead;
        ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, NULL);

        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            CloseHandle(hFile);
            return false;
        }

        // الانتقال إلى NT Headers
        SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN);
        
        IMAGE_NT_HEADERS ntHeaders;
        ReadFile(hFile, &ntHeaders, sizeof(ntHeaders), &bytesRead, NULL);

        CloseHandle(hFile);

        // التحقق من التوقيع
        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
            log("CORRUPTED", "Invalid PE signature: " + filePath);
            return true;
        }

        // التحقق من خصائص مشبوهة
        if (ntHeaders.FileHeader.Characteristics & IMAGE_FILE_DLL) {
            // DLL - تحقق إضافي
        }

        if (ntHeaders.OptionalHeader.CheckSum == 0) {
            log("SUSPICIOUS", "No checksum in PE: " + filePath);
        }

        return false;
    }

    // ==================== الحجر الصحي ====================

    void quarantineFile(const std::string& filePath) {
        std::string quarantineDir = "C:\\AI_Antivirus\\Quarantine\\";
        
        // إنشاء مجلد الحجر إذا لم يكن موجوداً
        CreateDirectoryA(quarantineDir.c_str(), NULL);
        
        // توليد اسم فريد
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();

        std::string newName = quarantineDir + 
                             std::to_string(timestamp) + "_" + 
                             fs::path(filePath).filename().string() + 
                             ".quarantined";

        // نقل الملف (في الواقع: نسخ ثم حذف الأصلي)
        if (MoveFileExA(filePath.c_str(), newName.c_str(), 
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            log("QUARANTINE", "File moved to: " + newName);
        } else {
            log("ERROR", "Failed to quarantine: " + filePath);
        }
    }

    // ==================== التقارير والسجلات ====================

    void showProgress(const std::string& currentFile) {
        // عرض شريط التقدم البسيط
        int progress = (totalFiles > 0) ? (scannedFiles * 100 / totalFiles) : 0;
        
        std::cout << "\r[" << std::string(progress / 2, '=') 
                  << std::string(50 - progress / 2, ' ') << "] " 
                  << progress << "% | Scanning: " 
                  << fs::path(currentFile).filename().string().substr(0, 30);
        std::cout.flush();
    }

    void showResults(long duration) {
        std::cout << "\n\n========================================\n";
        std::cout << "  SCAN COMPLETE\n";
        std::cout << "========================================\n";
        std::cout << "Total Files Scanned: " << scannedFiles << "\n";
        std::cout << "Threats Found:       " << infectedFiles.size() << "\n";
        std::cout << "Duration:            " << duration << " seconds\n";
        std::cout << "========================================\n";

        if (!infectedFiles.empty()) {
            std::cout << "\nINFECTED FILES:\n";
            for (const auto& file : infectedFiles) {
                std::cout << "  [!] " << file << "\n";
            }
        }
    }

    void log(const std::string& level, const std::string& message) {
        auto now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);
        
        char timestamp[26];
        ctime_s(timestamp, sizeof(timestamp), &time);
        timestamp[24] = '\0'; // إزالة newline

        std::string entry = "[" + std::string(timestamp) + "] [" + level + "] " + message;
        scanLog.push_back(entry);
        
        // عرض في الوقت الفعلي للأخطاء الخطيرة
        if (level == "THREAT" || level == "ALERT" || level == "ERROR") {
            std::cout << "\n" << entry << "\n";
        }
    }

public:
    // ==================== واجهة برمجة التطبيقات العامة ====================

    std::vector<std::string> getInfectedFiles() const {
        return infectedFiles;
    }

    void exportReport(const std::string& filename) {
        std::ofstream report(filename);
        report << "=== AI ANTIVIRUS SCAN REPORT ===\n\n";
        
        for (const auto& entry : scanLog) {
            report << entry << "\n";
        }
        
        report << "\n=== SUMMARY ===\n";
        report << "Scanned: " << scannedFiles << "\n";
        report << "Threats: " << infectedFiles.size() << "\n";
        
        report.close();
        std::cout << "[INFO] Report saved to: " << filename << "\n";
    }

    bool isCurrentlyScanning() const {
        return isScanning;
    }
};

// ==================== نقطة الاختبار ====================

#ifdef TEST_FILESCANNER
int main() {
    FileScanner scanner;
    
    std::cout << "AI Antivirus - File Scanner Module\n";
    std::cout << "==================================\n";
    
    // اختبار فحص مجلد
    std::string testPath = "C:\\Users\\%USERNAME%\\Downloads";
    char expandedPath[MAX_PATH];
    ExpandEnvironmentStringsA(testPath.c_str(), expandedPath, MAX_PATH);
    
    scanner.scanDirectory(expandedPath);
    scanner.exportReport("scan_report.txt");
    
    return 0;
}
#endif