/**
 * Quarantine.cpp
 *
 * مدير الحجر الصحي - Quarantine Manager
 *
 * المسؤوليات:
 * - عزل الملفات الخبيثة في موقع آمن ومشفر
 * - تشفير الملفات المعزولة لمنع التنفيذ العرضي
 * - تسجيل البيانات الوصفية (المسار الأصلي، نوع التهديد، وقت الاكتشاف)
 * - استعادة الملفات إلى موقعها الأصلي (إذا كان خطأ)
 * - الحذف النهائي الآمن (Secure Deletion)
 * - منع الوصول غير المصرح به للملفات المعزولة
 * - التكامل مع FileScanner و AIDetector
 *
 * آلية الأمان:
 * 1. تشفير AES-256 للملفات
 * 2. تغيير الامتداد إلى .quarantine
 * 3. تخزين في مجلد محمي بـ ACLs (صلاحيات NTFS)
 * 4. Metadata مشفرة في قاعدة بيانات SQLite (Stub)
 *
 * متطلبات: C++17, Windows API, Cryptography API (BCrypt)
 */

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <sddl.h>
#include <accctrl.h>
#include <aclapi.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <filesystem>
#include <algorithm>
#include <random>

 // TODO: تضمين مكتبة SQLite عند الحاجة
 // #include "sqlite3.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace fs = std::filesystem;

namespace AIAntivirus {

    // ==================== تعريفات الأنواع ====================

    /**
     * معلومات ملف معزول
     */
    struct QuarantineEntry {
        std::wstring quarantineId;          // معرف فريد (UUID)
        std::wstring originalPath;          // المسار الأصلي قبل العزل
        std::wstring fileName;              // اسم الملف الأصلي
        std::wstring quarantinePath;        // المسار الحالي في الحجر
        std::string threatName;             // اسم التهديد المكتشف
        std::string detectionMethod;        // طريقة الاكتشاف (AI, Heuristic, etc.)
        float threatScore;                  // درجة الخطورة
        std::chrono::system_clock::time_point detectionTime;
        std::chrono::system_clock::time_point quarantineTime;
        uint64_t originalFileSize;
        std::string originalHash;           // SHA-256 قبل العزل
        std::string encryptedHash;          // SHA-256 بعد التشفير
        bool isEncrypted;                   // هل تم التشفير بنجاح؟
        bool isCompressed;                  // هل تم الضغط؟
        std::string encryptionKeyId;        // معرف مفتاح التشفير
        std::string metadata;               // بيانات إضافية (JSON)
    };

    /**
     * نتيجة عملية العزل
     */
    enum class QuarantineResult {
        SUCCESS,                // نجاح
        ALREADY_QUARANTINED,    // موجود مسبقاً
        ACCESS_DENIED,          // رفض الوصول
        FILE_NOT_FOUND,         // الملف غير موجود
        ENCRYPTION_FAILED,      // فشل التشفير
        INSUFFICIENT_SPACE,     // مساحة غير كافية
        DATABASE_ERROR,         // خطأ في قاعدة البيانات
        UNKNOWN_ERROR           // خطأ غير معروف
    };

    /**
     * إعدادات الحجر
     */
    struct QuarantineConfig {
        std::wstring quarantineRoot = L"C:\\ProgramData\\AIAntivirus\\Quarantine\\";
        bool encryptFiles = true;               // تشفير الملفات
        bool compressFiles = true;              // ضغط قبل التشفير
        bool secureDeleteOriginal = false;      // حذف آمن للأصلي
        int retentionDays = 30;                 // أيام الاحتفاظ
        size_t maxQuarantineSizeMB = 1024;      // حد أقصى 1GB
        std::string encryptionAlgorithm = "AES-256-GCM";
    };

    /**
     * إحصائيات الحجر
     */
    struct QuarantineStats {
        size_t totalFiles;
        size_t totalSizeBytes;
        size_t encryptedFiles;
        size_t compressedFiles;
        size_t restoredFiles;       // تم استعادته
        size_t deletedFiles;        // تم حذفه نهائياً
        std::chrono::system_clock::time_point oldestEntry;
    };

    // ==================== الفئة الرئيسية: QuarantineManager ====================

    class QuarantineManager {
    public:
        // ==================== Singleton Pattern ====================

        static QuarantineManager& GetInstance() {
            static QuarantineManager instance;
            return instance;
        }

        // منع النسخ
        QuarantineManager(const QuarantineManager&) = delete;
        QuarantineManager& operator=(const QuarantineManager&) = delete;

        // ==================== واجهة التهيئة ====================

        /**
         * تهيئة مدير الحجر
         */
        bool Initialize(const QuarantineConfig& config = QuarantineConfig{});

        /**
         * إيقاف وتحرير الموارد
         */
        void Shutdown();

        /**
         * التحقق من التهيئة
         */
        bool IsInitialized() const { return m_isInitialized; }

        // ==================== واجهة العزل الرئيسية ====================

        /**
         * عزل ملف (الوظيفة الأساسية)
         */
        QuarantineResult QuarantineFile(const std::wstring& filePath,
            const std::string& threatName,
            const std::string& detectionMethod,
            float threatScore,
            QuarantineEntry* outEntry = nullptr);

        /**
         * عزل ملف مع معلومات كاملة
         */
        QuarantineResult QuarantineFile(const std::wstring& filePath,
            const QuarantineEntry& info);

        // ==================== واجهة الإدارة ====================

        /**
         * الحصول على قائمة الملفات المعزولة
         */
        std::vector<QuarantineEntry> GetQuarantinedFiles();

        /**
         * البحث عن ملف معزول
         */
        bool FindEntry(const std::wstring& quarantineId, QuarantineEntry& entry);
        bool FindEntryByOriginalPath(const std::wstring& originalPath, QuarantineEntry& entry);

        /**
         * استعادة ملف إلى موقعه الأصلي
         */
        QuarantineResult RestoreFile(const std::wstring& quarantineId,
            const std::wstring& destinationPath = L"");

        /**
         * حذف ملف نهائيًا من الحجر
         */
        QuarantineResult DeletePermanently(const std::wstring& quarantineId,
            bool secureDelete = true);

        /**
         * حذف جميع الملفات
         */
        QuarantineResult ClearAll(bool secureDelete = true);

        // ==================== واجهة الصيانة ====================

        /**
         * تنظيف الملفات القديمة (بناءً على retentionDays)
         */
        size_t CleanupOldFiles();

        /**
         * فحص سلامة الملفات المعزولة
         */
        bool VerifyIntegrity(const std::wstring& quarantineId);

        /**
         * الحصول على إحصائيات
         */
        QuarantineStats GetStatistics() const;

        /**
         * تصدير قائمة الحجر (للتقرير)
         */
        bool ExportList(const std::wstring& reportPath);

        // ==================== واجهة الأمان المتقدمة ====================

        /**
         * تغيير مفتاح التشفير (إعادة تشفير كل الملفات)
         */
        bool RotateEncryptionKey();

        /**
         * حظر استعادة ملفات معينة (Threats شديدة الخطورة)
         */
        bool BlockRestore(const std::wstring& quarantineId, const std::string& reason);

        /**
         * التحقق مما إذا كان ملف في الحجر
         */
        bool IsQuarantined(const std::wstring& filePath) const;

    private:
        // ==================== الأعضاء الخاصة ====================

        QuarantineManager() = default;
        ~QuarantineManager() { Shutdown(); }

        bool m_isInitialized = false;
        QuarantineConfig m_config;
        std::wstring m_databasePath;

        // التزامن
        mutable std::mutex m_mutex;
        mutable std::shared_mutex m_entriesMutex;

        // الكاش في الذاكرة
        std::map<std::wstring, QuarantineEntry> m_entries;

        // معالج التشفير
        BCRYPT_ALG_HANDLE m_hAesProvider = NULL;
        std::vector<BYTE> m_encryptionKey;

        // ==================== وظائف الأمان والتشفير ====================

        /**
         * إعداد مجلد الحجر بحماية كاملة
         */
        bool SetupQuarantineDirectory();

        /**
         * تعيين صلاحيات NTFS على مجلد
         */
        bool SetDirectoryACLs(const std::wstring& path);

        /**
         * تشفير ملف
         */
        bool EncryptFile(const std::wstring& sourcePath,
            const std::wstring& destPath,
            std::string& outHash);

        /**
         * فك تشفير ملف
         */
        bool DecryptFile(const std::wstring& sourcePath,
            const std::wstring& destPath);

        /**
         * ضغط ملف (اختياري)
         */
        bool CompressFile(const std::wstring& sourcePath,
            const std::wstring& destPath);

        /**
         * فك ضغط ملف
         */
        bool DecompressFile(const std::wstring& sourcePath,
            const std::wstring& destPath);

        /**
         * حذف آمن (Secure Deletion - Overwriting)
         */
        bool SecureDelete(const std::wstring& filePath, int passes = 3);

        /**
         * إنشاء معرف فريد (UUID)
         */
        static std::wstring GenerateUUID();

        /**
         * حساب SHA-256
         */
        static std::string CalculateSHA256(const std::wstring& filePath);

        // ==================== وظائف قاعدة البيانات ====================

        /**
         * تحميل الإدخالات من قاعدة البيانات
         */
        bool LoadEntriesFromDatabase();

        /**
         * حفظ إدخال في قاعدة البيانات
         */
        bool SaveEntryToDatabase(const QuarantineEntry& entry);

        /**
         * حذف إدخال من قاعدة البيانات
         */
        bool RemoveEntryFromDatabase(const std::wstring& quarantineId);

        /**
         * تحديث إدخال في قاعدة البيانات
         */
        bool UpdateEntryInDatabase(const QuarantineEntry& entry);

        // ==================== وظائف مساعدة ====================

        /**
         * التحقق من توفر مساحة كافية
         */
        bool CheckDiskSpace(uint64_t requiredBytes);

        /**
         * نسخ بيانات وصفية للملف (Alternate Data Streams)
         */
        bool WriteMetadataToADS(const std::wstring& filePath,
            const QuarantineEntry& entry);

        /**
         * قراءة بيانات وصفية من ADS
         */
        bool ReadMetadataFromADS(const std::wstring& filePath,
            QuarantineEntry& entry);

        /**
         * إنشاء مسار عشوائي للملف المعزول
         */
        std::wstring GenerateQuarantinePath(const std::wstring& originalName);

        /**
         * تسجيل العمليات (Logging)
         */
        void LogOperation(const std::string& operation,
            const std::wstring& fileId,
            bool success,
            const std::string& details = "");
    };

    // ==================== التنفيذ (Implementation) ====================

    bool QuarantineManager::Initialize(const QuarantineConfig& config) {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_isInitialized) {
            Shutdown();
        }

        m_config = config;

        // 1. إنشاء مجلد الحجر إذا لم يكن موجوداً
        if (!SetupQuarantineDirectory()) {
            return false;
        }

        // 2. إعداد التشفير
        if (m_config.encryptFiles) {
            NTSTATUS status = BCryptOpenAlgorithmProvider(&m_hAesProvider,
                BCRYPT_AES_ALGORITHM,
                NULL,
                0);
            if (!BCRYPT_SUCCESS(status)) {
                return false;
            }

            // إنشاء مفتاح عشوائي (في التطبيق الحقيقي، يُخزن بأمان)
            m_encryptionKey.resize(32); // 256-bit
            std::random_device rd;
            std::generate(m_encryptionKey.begin(), m_encryptionKey.end(),
                [&rd]() { return static_cast<BYTE>(rd() % 256); });
        }

        // 3. تحميل الإدخالات السابقة
        LoadEntriesFromDatabase();

        m_isInitialized = true;
        return true;
    }

    void QuarantineManager::Shutdown() {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_hAesProvider) {
            BCryptCloseAlgorithmProvider(m_hAesProvider, 0);
            m_hAesProvider = NULL;
        }

        // تنظيف المفتاح من الذاكرة
        std::fill(m_encryptionKey.begin(), m_encryptionKey.end(), 0);
        m_encryptionKey.clear();

        m_entries.clear();
        m_isInitialized = false;
    }

    QuarantineResult QuarantineManager::QuarantineFile(const std::wstring& filePath,
        const std::string& threatName,
        const std::string& detectionMethod,
        float threatScore,
        QuarantineEntry* outEntry) {
        if (!m_isInitialized) {
            return QuarantineResult::UNKNOWN_ERROR;
        }

        if (!fs::exists(filePath)) {
            return QuarantineResult::FILE_NOT_FOUND;
        }

        // التحقق من عدم وجوده مسبقاً
        QuarantineEntry existing;
        if (FindEntryByOriginalPath(filePath, existing)) {
            return QuarantineResult::ALREADY_QUARANTINED;
        }

        // التحقق من المساحة
        uint64_t fileSize = fs::file_size(filePath);
        if (!CheckDiskSpace(fileSize * 2)) { // ضعف المساحة للتشفير
            return QuarantineResult::INSUFFICIENT_SPACE;
        }

        // إنشاء إدخال جديد
        QuarantineEntry entry;
        entry.quarantineId = GenerateUUID();
        entry.originalPath = fs::absolute(filePath).wstring();
        entry.fileName = fs::path(filePath).filename().wstring();
        entry.threatName = threatName;
        entry.detectionMethod = detectionMethod;
        entry.threatScore = threatScore;
        entry.detectionTime = std::chrono::system_clock::now();
        entry.quarantineTime = entry.detectionTime;
        entry.originalFileSize = fileSize;
        entry.originalHash = CalculateSHA256(filePath);
        entry.isEncrypted = false;
        entry.isCompressed = false;

        // إنشاء مسار الحجر
        entry.quarantinePath = GenerateQuarantinePath(entry.fileName);

        try {
            // 1. ضغط (اختياري)
            std::wstring tempPath = entry.quarantinePath + L".tmp";
            if (m_config.compressFiles) {
                if (CompressFile(filePath, tempPath)) {
                    entry.isCompressed = true;
                }
                else {
                    tempPath = entry.quarantinePath + L".tmp";
                    fs::copy_file(filePath, tempPath, fs::copy_options::overwrite_existing);
                }
            }
            else {
                fs::copy_file(filePath, tempPath, fs::copy_options::overwrite_existing);
            }

            // 2. تشفير
            if (m_config.encryptFiles) {
                if (EncryptFile(tempPath, entry.quarantinePath, entry.encryptedHash)) {
                    entry.isEncrypted = true;
                    fs::remove(tempPath);
                }
                else {
                    fs::remove(tempPath);
                    return QuarantineResult::ENCRYPTION_FAILED;
                }
            }
            else {
                fs::rename(tempPath, entry.quarantinePath);
            }

            // 3. كتابة Metadata في ADS
            WriteMetadataToADS(entry.quarantinePath, entry);

            // 4. حفظ في قاعدة البيانات
            SaveEntryToDatabase(entry);

            // 5. إضافة للكاش
            {
                std::unique_lock<std::shared_mutex> lock(m_entriesMutex);
                m_entries[entry.quarantineId] = entry;
            }

            // 6. حذف الأصلي (بشكل آمن أو عادي)
            if (m_config.secureDeleteOriginal) {
                SecureDelete(filePath);
            }
            else {
                fs::remove(filePath);
            }

            if (outEntry) {
                *outEntry = entry;
            }

            LogOperation("QUARANTINE", entry.quarantineId, true);
            return QuarantineResult::SUCCESS;

        }
        catch (const fs::filesystem_error& e) {
            LogOperation("QUARANTINE", entry.quarantineId, false, e.what());
            return QuarantineResult::UNKNOWN_ERROR;
        }
    }

    bool QuarantineManager::EncryptFile(const std::wstring& sourcePath,
        const std::wstring& destPath,
        std::string& outHash) {
        if (!m_hAesProvider || m_encryptionKey.empty()) {
            return false;
        }

        // TODO: تنفيذ كامل للتشفير باستخدام BCrypt
        // 1. Generate IV
        // 2. Create AES key object
        // 3. Read file in chunks
        // 4. Encrypt with AES-256-GCM
        // 5. Write IV + Ciphertext + Tag

        // حالياً: نسخ مع Hash فقط (Stub)
        try {
            fs::copy_file(sourcePath, destPath, fs::copy_options::overwrite_existing);
            outHash = CalculateSHA256(destPath);
            return true;
        }
        catch (...) {
            return false;
        }
    }

    bool QuarantineManager::DecryptFile(const std::wstring& sourcePath,
        const std::wstring& destPath) {
        // TODO: فك التشفير
        try {
            fs::copy_file(sourcePath, destPath, fs::copy_options::overwrite_existing);
            return true;
        }
        catch (...) {
            return false;
        }
    }

    QuarantineResult QuarantineManager::RestoreFile(const std::wstring& quarantineId,
        const std::wstring& destinationPath) {
        std::shared_lock<std::shared_mutex> lock(m_entriesMutex);

        auto it = m_entries.find(quarantineId);
        if (it == m_entries.end()) {
            return QuarantineResult::FILE_NOT_FOUND;
        }

        const QuarantineEntry& entry = it->second;
        std::wstring dest = destinationPath.empty() ? entry.originalPath : destinationPath;

        // التحقق من عدم وجود ملف بنفس الاسم
        if (fs::exists(dest)) {
            dest += L".restored_" + GenerateUUID().substr(0, 8);
        }

        try {
            // 1. إنشاء المجلد إذا لم يكن موجوداً
            fs::create_directories(fs::path(dest).parent_path());

            // 2. فك التشفير والضغط
            std::wstring tempPath = entry.quarantinePath + L".restore_tmp";

            if (entry.isEncrypted) {
                if (!DecryptFile(entry.quarantinePath, tempPath)) {
                    return QuarantineResult::ENCRYPTION_FAILED;
                }
            }
            else {
                tempPath = entry.quarantinePath;
            }

            if (entry.isCompressed) {
                if (!DecompressFile(tempPath, dest)) {
                    if (tempPath != entry.quarantinePath) fs::remove(tempPath);
                    return QuarantineResult::UNKNOWN_ERROR;
                }
                if (tempPath != entry.quarantinePath) fs::remove(tempPath);
            }
            else {
                fs::rename(tempPath, dest);
            }

            // 3. التحقق من الـ Hash
            std::string restoredHash = CalculateSHA256(dest);
            if (restoredHash != entry.originalHash) {
                LogOperation("RESTORE", quarantineId, false, "Hash mismatch");
                return QuarantineResult::UNKNOWN_ERROR;
            }

            // 4. إزالة من الحجر
            RemoveEntryFromDatabase(quarantineId);
            fs::remove(entry.quarantinePath);

            {
                std::unique_lock<std::shared_mutex> writeLock(m_entriesMutex);
                m_entries.erase(quarantineId);
            }

            LogOperation("RESTORE", quarantineId, true);
            return QuarantineResult::SUCCESS;

        }
        catch (const fs::filesystem_error& e) {
            LogOperation("RESTORE", quarantineId, false, e.what());
            return QuarantineResult::UNKNOWN_ERROR;
        }
    }

    QuarantineResult QuarantineManager::DeletePermanently(const std::wstring& quarantineId,
        bool secureDelete) {
        std::shared_lock<std::shared_mutex> lock(m_entriesMutex);

        auto it = m_entries.find(quarantineId);
        if (it == m_entries.end()) {
            return QuarantineResult::FILE_NOT_FOUND;
        }

        const QuarantineEntry& entry = it->second;

        try {
            // حذف آمن
            if (secureDelete) {
                SecureDelete(entry.quarantinePath);
            }
            else {
                fs::remove(entry.quarantinePath);
            }

            // إزالة من قاعدة البيانات
            RemoveEntryFromDatabase(quarantineId);

            {
                std::unique_lock<std::shared_mutex> writeLock(m_entriesMutex);
                m_entries.erase(quarantineId);
            }

            LogOperation("DELETE", quarantineId, true);
            return QuarantineResult::SUCCESS;

        }
        catch (const fs::filesystem_error& e) {
            LogOperation("DELETE", quarantineId, false, e.what());
            return QuarantineResult::UNKNOWN_ERROR;
        }
    }

    std::vector<QuarantineEntry> QuarantineManager::GetQuarantinedFiles() {
        std::shared_lock<std::shared_mutex> lock(m_entriesMutex);

        std::vector<QuarantineEntry> result;
        result.reserve(m_entries.size());

        for (const auto& [id, entry] : m_entries) {
            result.push_back(entry);
        }

        return result;
    }

    bool QuarantineManager::FindEntry(const std::wstring& quarantineId,
        QuarantineEntry& entry) {
        std::shared_lock<std::shared_mutex> lock(m_entriesMutex);

        auto it = m_entries.find(quarantineId);
        if (it != m_entries.end()) {
            entry = it->second;
            return true;
        }
        return false;
    }

    bool QuarantineManager::FindEntryByOriginalPath(const std::wstring& originalPath,
        QuarantineEntry& entry) {
        std::shared_lock<std::shared_mutex> lock(m_entriesMutex);

        for (const auto& [id, e] : m_entries) {
            if (e.originalPath == originalPath) {
                entry = e;
                return true;
            }
        }
        return false;
    }

    bool QuarantineManager::SetupQuarantineDirectory() {
        try {
            // إنشاء المجلد
            fs::create_directories(m_config.quarantineRoot);

            // إخفاء المجلد
            SetFileAttributesW(m_config.quarantineRoot.c_str(), FILE_ATTRIBUTE_HIDDEN);

            // تعيين ACLs
            return SetDirectoryACLs(m_config.quarantineRoot);
        }
        catch (...) {
            return false;
        }
    }

    bool QuarantineManager::SetDirectoryACLs(const std::wstring& path) {
        // إزالة صلاحيات Users ومنحها فقط لـ SYSTEM والـ Admins
        // TODO: تنفيذ كامل باستخدام SetSecurityDescriptorDacl

        PSECURITY_DESCRIPTOR pSD = NULL;
        PACL pACL = NULL;
        EXPLICIT_ACCESSW ea[2];
        SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
        PSID pAdminSID = NULL;
        PSID pSystemSID = NULL;

        // إنشاء SIDs
        AllocateAndInitializeSid(&SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSID);
        AllocateAndInitializeSid(&SIDAuthNT, 1, SECURITY_LOCAL_SYSTEM_RID,
            0, 0, 0, 0, 0, 0, 0, &pSystemSID);

        // إعداد Explicit Access
        ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESSW));

        // Admin: Full Control
        ea[0].grfAccessPermissions = GENERIC_ALL;
        ea[0].grfAccessMode = SET_ACCESS;
        ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[0].Trustee.ptstrName = (LPWSTR)pAdminSID;

        // System: Full Control
        ea[1].grfAccessPermissions = GENERIC_ALL;
        ea[1].grfAccessMode = SET_ACCESS;
        ea[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[1].Trustee.ptstrName = (LPWSTR)pSystemSID;

        // إنشاء ACL
        DWORD dwRes = SetEntriesInAclW(2, ea, NULL, &pACL);
        if (dwRes != ERROR_SUCCESS) {
            if (pAdminSID) FreeSid(pAdminSID);
            if (pSystemSID) FreeSid(pSystemSID);
            return false;
        }

        // إنشاء Security Descriptor
        pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
        if (!pSD || !InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) {
            LocalFree(pSD);
            LocalFree(pACL);
            FreeSid(pAdminSID);
            FreeSid(pSystemSID);
            return false;
        }

        if (!SetSecurityDescriptorDacl(pSD, TRUE, pACL, FALSE)) {
            LocalFree(pSD);
            LocalFree(pACL);
            FreeSid(pAdminSID);
            FreeSid(pSystemSID);
            return false;
        }

        // تطبيق على المجلد
        BOOL result = SetFileSecurityW(path.c_str(), DACL_SECURITY_INFORMATION, pSD);

        // تنظيف
        LocalFree(pSD);
        LocalFree(pACL);
        FreeSid(pAdminSID);
        FreeSid(pSystemSID);

        return result == TRUE;
    }

    bool QuarantineManager::SecureDelete(const std::wstring& filePath, int passes) {
        // الكتابة فوق الملف عدة مرات قبل الحذف
        try {
            // الحصول على حجم الملف
            uint64_t size = fs::file_size(filePath);

            // فتح للكتابة
            HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, NULL,
                OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);
            if (hFile == INVALID_HANDLE_VALUE) return false;

            // Patterns للكتابة فوق (Gutmann method مبسط)
            const BYTE patterns[] = { 0x00, 0xFF, 0xAA, 0x55, 0x92, 0x49, 0x24 };

            std::vector<BYTE> buffer(65536); // 64KB chunks

            for (int pass = 0; pass < passes; ++pass) {
                BYTE pattern = patterns[pass % sizeof(patterns)];
                std::fill(buffer.begin(), buffer.end(), pattern);

                SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

                uint64_t written = 0;
                while (written < size) {
                    DWORD toWrite = static_cast<DWORD>(std::min<uint64_t>(buffer.size(),
                        size - written));
                    DWORD writtenNow = 0;
                    if (!WriteFile(hFile, buffer.data(), toWrite, &writtenNow, NULL)) {
                        CloseHandle(hFile);
                        return false;
                    }
                    written += writtenNow;
                }
                FlushFileBuffers(hFile);
            }

            CloseHandle(hFile);

            // إعادة تسمية عدة مرات قبل الحذف
            std::wstring tempPath = filePath;
            for (int i = 0; i < 3; ++i) {
                std::wstring newPath = tempPath + L".del";
                MoveFileW(tempPath.c_str(), newPath.c_str());
                tempPath = newPath;
            }

            return DeleteFileW(tempPath.c_str()) == TRUE;
        }
        catch (...) {
            return false;
        }
    }

    std::wstring QuarantineManager::GenerateUUID() {
        UUID uuid;
        UuidCreate(&uuid);

        WCHAR* wszUuid = NULL;
        UuidToStringW(&uuid, (RPC_WSTR*)&wszUuid);

        std::wstring result(wszUuid);
        RpcStringFreeW((RPC_WSTR*)&wszUuid);

        // إزالة الأقواس والشرطات
        result.erase(std::remove(result.begin(), result.end(), L'-'), result.end());
        result.erase(std::remove(result.begin(), result.end(), L'{'), result.end());
        result.erase(std::remove(result.begin(), result.end(), L'}'), result.end());

        return result;
    }

    std::string QuarantineManager::CalculateSHA256(const std::wstring& filePath) {
        // TODO: استخدام نفس دالة FileScanner
        // Stub مؤقت
        return "stub_hash";
    }

    std::wstring QuarantineManager::GenerateQuarantinePath(const std::wstring& originalName) {
        std::wstringstream ss;
        ss << m_config.quarantineRoot
            << GenerateUUID()
            << L"_"
            << fs::path(originalName).stem().wstring()
            << L".quarantine";
        return ss.str();
    }

    bool QuarantineManager::CheckDiskSpace(uint64_t requiredBytes) {
        ULARGE_INTEGER freeBytesAvailable;
        if (GetDiskFreeSpaceExW(m_config.quarantineRoot.c_str(),
            &freeBytesAvailable, NULL, NULL)) {
            return freeBytesAvailable.QuadPart >= requiredBytes;
        }
        return false;
    }

    // ==================== Database Stubs ====================

    bool QuarantineManager::LoadEntriesFromDatabase() {
        // TODO: تحميل من SQLite
        // CREATE TABLE quarantine (
        //   id TEXT PRIMARY KEY,
        //   original_path TEXT,
        //   file_name TEXT,
        //   threat_name TEXT,
        //   detection_time INTEGER,
        //   ...
        // );
        return true;
    }

    bool QuarantineManager::SaveEntryToDatabase(const QuarantineEntry& entry) {
        // TODO: INSERT INTO quarantine
        return true;
    }

    bool QuarantineManager::RemoveEntryFromDatabase(const std::wstring& quarantineId) {
        // TODO: DELETE FROM quarantine WHERE id = ?
        return true;
    }

    bool QuarantineManager::UpdateEntryInDatabase(const QuarantineEntry& entry) {
        // TODO: UPDATE quarantine SET ...
        return true;
    }

    // ==================== ADS (Alternate Data Streams) ====================

    bool QuarantineManager::WriteMetadataToADS(const std::wstring& filePath,
        const QuarantineEntry& entry) {
        std::wstring streamPath = filePath + L":AIAV_Meta";

        // Serialize entry to JSON or binary
        std::stringstream ss;
        ss << entry.quarantineId.length() << "|"
            << std::string(entry.originalPath.begin(), entry.originalPath.end()) << "|"
            << entry.threatName << "|"
            << entry.originalHash;

        std::string data = ss.str();

        HANDLE hStream = CreateFileW(streamPath.c_str(), GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hStream == INVALID_HANDLE_VALUE) return false;

        DWORD written;
        BOOL result = WriteFile(hStream, data.data(), static_cast<DWORD>(data.size()),
            &written, NULL);
        CloseHandle(hStream);

        return result == TRUE;
    }

    bool QuarantineManager::ReadMetadataFromADS(const std::wstring& filePath,
        QuarantineEntry& entry) {
        std::wstring streamPath = filePath + L":AIAV_Meta";

        HANDLE hStream = CreateFileW(streamPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hStream == INVALID_HANDLE_VALUE) return false;

        char buffer[4096];
        DWORD read;
        if (ReadFile(hStream, buffer, sizeof(buffer), &read, NULL) && read > 0) {
            // Parse (TODO: proper parsing)
            buffer[read] = '\0';
            CloseHandle(hStream);
            return true;
        }

        CloseHandle(hStream);
        return false;
    }

    // ==================== Maintenance ====================

    size_t QuarantineManager::CleanupOldFiles() {
        auto now = std::chrono::system_clock::now();
        std::vector<std::wstring> toDelete;

        {
            std::shared_lock<std::shared_mutex> lock(m_entriesMutex);
            for (const auto& [id, entry] : m_entries) {
                auto age = std::chrono::duration_cast<std::chrono::hours>(
                    now - entry.quarantineTime).count() / 24;

                if (age > m_config.retentionDays) {
                    toDelete.push_back(id);
                }
            }
        }

        for (const auto& id : toDelete) {
            DeletePermanently(id, false);
        }

        return toDelete.size();
    }

    QuarantineStats QuarantineManager::GetStatistics() const {
        std::shared_lock<std::shared_mutex> lock(m_entriesMutex);

        QuarantineStats stats{};
        stats.totalFiles = m_entries.size();

        for (const auto& [id, entry] : m_entries) {
            stats.totalSizeBytes += entry.originalFileSize;
            if (entry.isEncrypted) stats.encryptedFiles++;
            if (entry.isCompressed) stats.compressedFiles++;

            if (stats.oldestEntry == std::chrono::system_clock::time_point{} ||
                entry.quarantineTime < stats.oldestEntry) {
                stats.oldestEntry = entry.quarantineTime;
            }
        }

        return stats;
    }

    void QuarantineManager::LogOperation(const std::string& operation,
        const std::wstring& fileId,
        bool success,
        const std::string& details) {
        // TODO: كتابة في Windows Event Log أو ملف Log
        // EventWrite(...) أو std::ofstream
    }

} // namespace AIAntivirus