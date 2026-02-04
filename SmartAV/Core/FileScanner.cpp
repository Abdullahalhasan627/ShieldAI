/**
 * FileScanner.cpp
 *
 * وحدة فحص الملفات - Core Component
 *
 * المسؤوليات:
 * - فحص ملف واحد أو مجلد كامل (Recursive)
 * - استخراج خصائص الملفات (PE Analysis, Hashes, Imports)
 * - التواصل مع FeatureExtractor للتحضير لنموذج AI
 * - إدارة حالة الفحص والتقدم
 *
 * متطلبات: C++17, Windows API, Cryptography API
 */

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <queue>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>

 // ربط مكتبات Windows اللازمة
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

namespace fs = std::filesystem;

namespace AIAntivirus {

    // ==================== تعريفات الأنواع ====================

    /**
     * نتيجة فحص الملف
     */
    enum class ScanResult {
        CLEAN,          // نظيف
        MALICIOUS,      // خبيث (مكتشف بالذكاء الاصطناعي)
        SUSPICIOUS,     // مشبوه (درجة خطورة متوسطة)
        ERROR,          // خطأ في الفحص
        WHITELISTED     // في القائمة البيضاء
    };

    /**
     * معلومات مفصلة عن الملف المفحوص
     */
    struct FileInfo {
        std::wstring filePath;          // المسار الكامل
        std::wstring fileName;          // اسم الملف
        uint64_t fileSize;              // الحجم بالبايت
        std::string sha256Hash;         // الهاش
        bool isPEFile;                  // هل ملف PE تنفيذي؟
        bool isSigned;                  // هل موقع رقمياً؟
        std::string signerName;         // اسم جهة التوقيع

        // خصائص PE
        uint32_t entryPoint;            // نقطة الدخول
        uint32_t imageBase;             // قاعدة الصورة
        uint16_t numberOfSections;      // عدد الأقسام
        std::vector<std::string> imports; // قائمة الـ Imports
        std::vector<std::string> sectionNames; // أسماء الأقسام

        // بيانات للذكاء الاصطناعي
        std::vector<float> featureVector; // متجه الخصائص
    };

    /**
     * نتيجة الفحص النهائية
     */
    struct ScanReport {
        ScanResult result;              // النتيجة
        float confidenceScore;          // درجة الثقة (0.0 - 1.0)
        std::wstring threatName;        // اسم التهديد (إن وجد)
        std::string detectionMethod;    // طريقة الاكتشاف
        std::string details;            // تفاصيل إضافية
    };

    /**
     * حدث تقدم الفحص (Callback)
     */
    using ProgressCallback = std::function<void(const std::wstring& currentFile,
        size_t scannedCount,
        size_t totalCount,
        const ScanReport& report)>;

    // ==================== الفئة الرئيسية: FileScanner ====================

    class FileScanner {
    public:
        FileScanner();
        ~FileScanner();

        // منع النسخ والنقل
        FileScanner(const FileScanner&) = delete;
        FileScanner& operator=(const FileScanner&) = delete;
        FileScanner(FileScanner&&) = delete;
        FileScanner& operator=(FileScanner&&) = delete;

        // ==================== واجهة الفحص العامة ====================

        /**
         * فحص ملف واحد
         * @param filePath: مسار الملف
         * @param report: نتيجة الفحص (إخراج)
         * @return: true إذا نجح الفحص، false إذا فشل
         */
        bool ScanSingleFile(const std::wstring& filePath, ScanReport& report);

        /**
         * فحص مجلد كامل (Recursive)
         * @param directoryPath: مسار المجلد
         * @param callback: دالة رد الاتصال للتقدم
         * @param recursive: هل يشمل المجلدات الفرعية؟
         * @return: عدد الملفات المفحوصة
         */
        size_t ScanDirectory(const std::wstring& directoryPath,
            ProgressCallback callback,
            bool recursive = true);

        /**
         * فحص سريع (Quick Scan) - المسارات الحساسة
         */
        size_t QuickScan(ProgressCallback callback);

        /**
         * فحص كامل (Full Scan) - جميع الأقراص
         */
        size_t FullScan(ProgressCallback callback);

        /**
         * إيقاف الفحص الجاري
         */
        void StopScan();

        /**
         * التحقق من حالة الفحص
         */
        bool IsScanning() const { return m_isScanning.load(); }

        /**
         * الحصول على إحصائيات آخر فحص
         */
        struct ScanStatistics {
            size_t totalFiles;
            size_t threatsFound;
            size_t errors;
            double durationSeconds;
        };
        ScanStatistics GetLastStatistics() const;

    private:
        // ==================== الأعضاء الخاصة ====================

        std::atomic<bool> m_isScanning{ false };
        std::atomic<bool> m_stopRequested{ false };
        std::mutex m_scanMutex;
        std::queue<std::wstring> m_scanQueue;

        // الإحصائيات
        ScanStatistics m_statistics{ 0, 0, 0, 0.0 };
        mutable std::mutex m_statsMutex;

        // ==================== وظائف استخراج المعلومات ====================

        /**
         * استخراج معلومات أساسية عن الملف
         */
        bool ExtractFileInfo(const std::wstring& filePath, FileInfo& info);

        /**
         * حساب SHA-256 للملف
         */
        bool CalculateSHA256(const std::wstring& filePath, std::string& hashOut);

        /**
         * تحليل هيكل PE (Portable Executable)
         */
        bool AnalyzePEFile(const std::wstring& filePath, FileInfo& info);

        /**
         * التحقق من التوقيع الرقمي
         */
        bool VerifyDigitalSignature(const std::wstring& filePath,
            bool& isSigned,
            std::string& signerName);

        /**
         * استخراج قائمة Imports من ملف PE
         */
        bool ExtractImports(const std::wstring& filePath,
            std::vector<std::string>& imports);

        /**
         * إعداد متجه الخصائص للذكاء الاصطناعي
         * TODO: ربط هذا مع FeatureExtractor.cpp لاحقاً
         */
        bool PrepareFeatureVector(const FileInfo& info,
            std::vector<float>& featureVector);

        // ==================== وظائف مساعدة ====================

        /**
         * التحقق من القائمة البيضاء
         */
        bool IsWhitelisted(const std::wstring& filePath);

        /**
         * جمع جميع الملفات في مجلد
         */
        void CollectFiles(const std::wstring& directoryPath,
            std::vector<std::wstring>& files,
            bool recursive);

        /**
         * إضافة ملف إلى قائمة الانتظار
         */
        void EnqueueFile(const std::wstring& filePath);

        /**
         * معالجة ملف واحد من قائمة الانتظار
         */
        void ProcessSingleFile(const std::wstring& filePath,
            ProgressCallback callback,
            size_t current,
            size_t total);
    };

    // ==================== التنفيذ (Implementation) ====================

    FileScanner::FileScanner() {
        // تهيئة مكونات التشفير
        // لا حاجة لتهيئة خاصة لـ SHA-256 باستخدام Windows Crypto API
    }

    FileScanner::~FileScanner() {
        // التأكد من إيقاف أي فحص جاري
        StopScan();
    }

    bool FileScanner::ScanSingleFile(const std::wstring& filePath, ScanReport& report) {
        // التحقق المبدئي من الملف
        if (!fs::exists(filePath)) {
            report.result = ScanResult::ERROR;
            report.details = "File does not exist";
            return false;
        }

        // التحقق من القائمة البيضاء
        if (IsWhitelisted(filePath)) {
            report.result = ScanResult::WHITELISTED;
            report.confidenceScore = 0.0f;
            report.details = "File is whitelisted";
            return true;
        }

        // استخراج معلومات الملف
        FileInfo fileInfo;
        if (!ExtractFileInfo(filePath, fileInfo)) {
            report.result = ScanResult::ERROR;
            report.details = "Failed to extract file information";
            return false;
        }

        // تحليل التوقيع الرقمي
        bool isSigned = false;
        std::string signer;
        if (VerifyDigitalSignature(filePath, isSigned, signer)) {
            fileInfo.isSigned = isSigned;
            fileInfo.signerName = signer;

            // الملفات الموقعة من Microsoft أو شركات موثوقة تعتبر أقل خطورة
            if (isSigned && (signer.find("Microsoft") != std::string::npos ||
                signer.find("Windows") != std::string::npos)) {
                // يمكن خفض درجة الخطورة هنا، لكن لا نتجاهلها تماماً
            }
        }

        // TODO: إرسال البيانات إلى AIDetector للتحليل
        // هذا الجزء سيتم ربطه مع AI/AIDetector.cpp
        // حالياً نستخدم تحليل سلوكي بسيط

        // تحليل ابتدائي (Placeholder للذكاء الاصطناعي)
        bool isSuspicious = false;
        float threatScore = 0.0f;

        // مؤشرات مشبوهة:
        // 1. ملف PE غير موقع
        if (fileInfo.isPEFile && !fileInfo.isSigned) {
            threatScore += 0.3f;
        }

        // 2. Imports مشبوهة (مثل WinExec, CreateRemoteThread)
        for (const auto& imp : fileInfo.imports) {
            if (imp.find("CreateRemoteThread") != std::string::npos ||
                imp.find("WriteProcessMemory") != std::string::npos ||
                imp.find("WinExec") != std::string::npos ||
                imp.find("ShellExecute") != std::string::npos) {
                threatScore += 0.4f;
                isSuspicious = true;
            }
        }

        // 3. أقسام PE غير عادية
        for (const auto& section : fileInfo.sectionNames) {
            if (section.find("UPX") != std::string::npos ||
                section.find("packed") != std::string::npos) {
                threatScore += 0.3f;
            }
        }

        // تحديد النتيجة
        if (threatScore >= 0.8f) {
            report.result = ScanResult::MALICIOUS;
            report.threatName = L"HEUR:Trojan.Win32.Generic";
        }
        else if (threatScore >= 0.4f) {
            report.result = ScanResult::SUSPICIOUS;
            report.threatName = L"HEUR:Suspicious.Win32.Generic";
        }
        else {
            report.result = ScanResult::CLEAN;
            report.threatName = L"";
        }

        report.confidenceScore = threatScore;
        report.detectionMethod = isSuspicious ? "Heuristic Analysis" : "Static Analysis";
        report.details = "File analyzed successfully. PE: " +
            std::string(fileInfo.isPEFile ? "Yes" : "No") +
            ", Signed: " + std::string(fileInfo.isSigned ? "Yes" : "No");

        // تحديث الإحصائيات
        {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_statistics.totalFiles++;
            if (report.result == ScanResult::MALICIOUS || report.result == ScanResult::SUSPICIOUS) {
                m_statistics.threatFound++;
            }
        }

        return true;
    }

    size_t FileScanner::ScanDirectory(const std::wstring& directoryPath,
        ProgressCallback callback,
        bool recursive) {
        if (!fs::exists(directoryPath) || !fs::is_directory(directoryPath)) {
            return 0;
        }

        m_isScanning = true;
        m_stopRequested = false;

        // جمع جميع الملفات أولاً
        std::vector<std::wstring> files;
        CollectFiles(directoryPath, files, recursive);

        size_t totalFiles = files.size();
        size_t scannedCount = 0;

        auto startTime = std::chrono::steady_clock::now();

        // فحص الملفات واحداً تلو الآخر
        for (const auto& filePath : files) {
            if (m_stopRequested.load()) {
                break;
            }

            ProcessSingleFile(filePath, callback, scannedCount, totalFiles);
            scannedCount++;
        }

        auto endTime = std::chrono::steady_clock::now();
        double duration = std::chrono::duration<double>(endTime - startTime).count();

        {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_statistics.durationSeconds = duration;
        }

        m_isScanning = false;
        return scannedCount;
    }

    void FileScanner::ProcessSingleFile(const std::wstring& filePath,
        ProgressCallback callback,
        size_t current,
        size_t total) {
        ScanReport report;
        bool success = ScanSingleFile(filePath, report);

        if (!success) {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_statistics.errors++;
        }

        // استدعاء callback للتقدم
        if (callback) {
            callback(filePath, current + 1, total, report);
        }
    }

    size_t FileScanner::QuickScan(ProgressCallback callback) {
        // المسارات الحساسة في Windows
        std::vector<std::wstring> criticalPaths = {
            LR"(C:\Windows\System32)",
            LR"(C:\Windows\SysWOW64)",
            LR"(C:\Program Files)",
            LR"(C:\Program Files (x86))",
            // مجلدات المستخدم الحساسة
            fs::path(getenv("USERPROFILE")) / "Downloads",
            fs::path(getenv("USERPROFILE")) / "AppData" / "Roaming",
            fs::path(getenv("USERPROFILE")) / "AppData" / "Local" / "Temp"
        };

        size_t totalScanned = 0;

        for (const auto& path : criticalPaths) {
            if (fs::exists(path)) {
                totalScanned += ScanDirectory(path, callback, true);
            }
        }

        return totalScanned;
    }

    size_t FileScanner::FullScan(ProgressCallback callback) {
        // فحص جميع الأقراص الثابتة
        DWORD drives = GetLogicalDrives();
        size_t totalScanned = 0;

        for (int i = 0; i < 26; i++) {
            if (drives & (1 << i)) {
                std::wstring drivePath = std::wstring(1, L'A' + i) + L":\\";

                // التحقق من نوع القرص (نريد الأقراص الثابتة فقط)
                UINT driveType = GetDriveTypeW(drivePath.c_str());
                if (driveType == DRIVE_FIXED) {
                    totalScanned += ScanDirectory(drivePath, callback, true);
                }
            }
        }

        return totalScanned;
    }

    void FileScanner::StopScan() {
        m_stopRequested = true;
        // انتظار انتهاء الفحص الحالي (timeout قصير)
        int timeout = 0;
        while (m_isScanning.load() && timeout < 50) { // 5 ثواني كحد أقصى
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            timeout++;
        }
    }

    FileScanner::ScanStatistics FileScanner::GetLastStatistics() const {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        return m_statistics;
    }

    // ==================== وظائف استخراج المعلومات التفصيلية ====================

    bool FileScanner::ExtractFileInfo(const std::wstring& filePath, FileInfo& info) {
        info.filePath = filePath;
        info.fileName = fs::path(filePath).filename().wstring();

        try {
            info.fileSize = fs::file_size(filePath);
        }
        catch (...) {
            info.fileSize = 0;
        }

        // حساب الهاش
        if (!CalculateSHA256(filePath, info.sha256Hash)) {
            info.sha256Hash = "ERROR";
        }

        // تحليل PE إذا كان ملف تنفيذي
        info.isPEFile = false;
        std::wstring ext = fs::path(filePath).extension().wstring();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

        if (ext == L".exe" || ext == L".dll" || ext == L".sys" ||
            ext == L".scr" || ext == L".ocx") {
            info.isPEFile = AnalyzePEFile(filePath, info);
        }

        return true;
    }

    bool FileScanner::CalculateSHA256(const std::wstring& filePath, std::string& hashOut) {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        HANDLE hFile = INVALID_HANDLE_VALUE;
        BOOL result = FALSE;
        BYTE rgbFile[1024];
        DWORD cbRead = 0;
        BYTE rgbHash[32]; // SHA-256 = 32 bytes
        DWORD cbHash = 32;
        CHAR rgbDigits[] = "0123456789abcdef";

        // فتح الملف
        hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }

        // الحصول على مقبض CSP
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            CloseHandle(hFile);
            return false;
        }

        // إنشاء كائن Hash
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return false;
        }

        // قراءة الملف وتحديث الهاش
        while (ReadFile(hFile, rgbFile, 1024, &cbRead, NULL) && cbRead > 0) {
            if (!CryptHashData(hHash, rgbFile, cbRead, 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                CloseHandle(hFile);
                return false;
            }
        }

        // الحصول على قيمة الهاش
        if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
            std::stringstream ss;
            for (DWORD i = 0; i < cbHash; i++) {
                ss << rgbDigits[rgbHash[i] >> 4];
                ss << rgbDigits[rgbHash[i] & 0xf];
            }
            hashOut = ss.str();
            result = TRUE;
        }

        // تنظيف
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);

        return result == TRUE;
    }

    bool FileScanner::AnalyzePEFile(const std::wstring& filePath, FileInfo& info) {
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }

        HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!hMapping) {
            CloseHandle(hFile);
            return false;
        }

        LPVOID lpBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        if (!lpBase) {
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }

        // التحقق من رأس DOS
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            UnmapViewOfFile(lpBase);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }

        // التحقق من رأس NT
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            UnmapViewOfFile(lpBase);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }

        // استخراج معلومات PE
        info.entryPoint = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
        info.imageBase = pNtHeaders->OptionalHeader.ImageBase;
        info.numberOfSections = pNtHeaders->FileHeader.NumberOfSections;

        // استخراج أسماء الأقسام
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            char name[9] = { 0 };
            memcpy(name, pSection[i].Name, 8);
            info.sectionNames.push_back(std::string(name));
        }

        // استخراج Imports
        ExtractImports(filePath, info.imports);

        UnmapViewOfFile(lpBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);

        return true;
    }

    bool FileScanner::ExtractImports(const std::wstring& filePath,
        std::vector<std::string>& imports) {
        // هذا تنفيذ مبسط - يمكن تحسينه باستخدام مكتبة متخصصة
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!hMapping) {
            CloseHandle(hFile);
            return false;
        }

        LPVOID lpBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        if (!lpBase) {
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }

        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + pDosHeader->e_lfanew);

        // العثور على دليل Import
        DWORD importDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importDirRVA == 0) {
            UnmapViewOfFile(lpBase);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return true; // لا يوجد imports لكن هذا ليس خطأ
        }

        // تحويل RVA إلى مؤشر (مبسط - يفترض أن الملف mapped مباشرة)
        // في الواقع يجب استخدام ImageRvaToVa أو حساب manual
        // هذا Stub مبسط للتوضيح

        // TODO: تنفيذ كامل لاستخراج Imports يتطلب معالجة أكثر تعقيداً للـ RVA
        // يمكن استخدام مكتبة like "pe-parse" أو "pe-bear" للتبسيط

        UnmapViewOfFile(lpBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);

        return true;
    }

    bool FileScanner::VerifyDigitalSignature(const std::wstring& filePath,
        bool& isSigned,
        std::string& signerName) {
        WINTRUST_FILE_INFO fileInfo = { 0 };
        WINTRUST_DATA trustData = { 0 };
        GUID actionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();
        fileInfo.hFile = NULL;
        fileInfo.pgKnownSubject = NULL;

        trustData.cbStruct = sizeof(WINTRUST_DATA);
        trustData.pPolicyCallbackData = NULL;
        trustData.pSIPClientData = NULL;
        trustData.dwUIChoice = WTD_UI_NONE; // لا واجهة مستخدم
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.hWVTStateData = NULL;
        trustData.pwszURLReference = NULL;
        trustData.dwProvFlags = WTD_SAFER_FLAG;
        trustData.dwUIContext = WTD_UICONTEXT_EXECUTE;

        LONG result = WinVerifyTrust(NULL, &actionGUID, &trustData);

        isSigned = (result == ERROR_SUCCESS);

        if (isSigned) {
            // استخراج اسم الموقع يتطلب استخدام Cert APIs
            // هذا Stub للتوضيح
            signerName = "Verified Publisher";
        }
        else {
            signerName = "";
        }

        // تنظيف
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &actionGUID, &trustData);

        return true;
    }

    bool FileScanner::PrepareFeatureVector(const FileInfo& info,
        std::vector<float>& featureVector) {
        // TODO: ربط مع FeatureExtractor.cpp
        // هذا Stub يوضح الشكل المتوقع

        featureVector.clear();

        // مثال على Features:
        // 1. حجم الملف (مُطَبَّع)
        featureVector.push_back(static_cast<float>(info.fileSize) / (1024.0f * 1024.0f)); // MB

        // 2. هل هو PE؟
        featureVector.push_back(info.isPEFile ? 1.0f : 0.0f);

        // 3. هل موقع؟
        featureVector.push_back(info.isSigned ? 1.0f : 0.0f);

        // 4. عدد الـ Imports (مُطَبَّع)
        featureVector.push_back(static_cast<float>(info.imports.size()) / 1000.0f);

        // 5. عدد الأقسام
        featureVector.push_back(static_cast<float>(info.numberOfSections) / 10.0f);

        // 6. Entropy (يحتاج حساب منفصل)
        featureVector.push_back(0.0f); // Placeholder

        // TODO: إضافة المزيد من الخصائص الرياضية والإحصائية

        return true;
    }

    bool FileScanner::IsWhitelisted(const std::wstring& filePath) {
        // TODO: التحقق من قاعدة بيانات القائمة البيضاء
        // يمكن أن تكون في ملف أو Registry أو قاعدة بيانات SQLite

        // مؤقتاً: القائمة البيضاء الأساسية
        static const std::vector<std::wstring> whitelistPaths = {
            LR"(C:\Windows\System32\)",
            LR"(C:\Windows\SysWOW64\)"
        };

        for (const auto& whitePath : whitelistPaths) {
            if (filePath.find(whitePath) == 0) {
                // يمكن التحقق من التوقيع الرقمي هنا للتأكد
                return false; // مؤقتاً نعيد false للفحص الكامل
            }
        }

        return false;
    }

    void FileScanner::CollectFiles(const std::wstring& directoryPath,
        std::vector<std::wstring>& files,
        bool recursive) {
        try {
            if (recursive) {
                for (const auto& entry : fs::recursive_directory_iterator(directoryPath,
                    fs::directory_options::skip_permission_denied)) {
                    if (fs::is_regular_file(entry)) {
                        files.push_back(entry.path().wstring());
                    }
                }
            }
            else {
                for (const auto& entry : fs::directory_iterator(directoryPath,
                    fs::directory_options::skip_permission_denied)) {
                    if (fs::is_regular_file(entry)) {
                        files.push_back(entry.path().wstring());
                    }
                }
            }
        }
        catch (const fs::filesystem_error& e) {
            // تجاهل الأخطاء (مثل عدم وجود صلاحيات)
            // يمكن تسجيل الخطأ هنا
        }
    }

} // namespace AIAntivirus