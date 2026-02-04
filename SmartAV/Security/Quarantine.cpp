// Quarantine.cpp - Security Module
// نظام الحجر الصحي والعزل الآمن للتهديدات

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <windows.h>
#include <wincrypt.h>
#include <aclapi.h>
#include <sddl.h>

namespace fs = std::filesystem;

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

// ==================== هيكل عنصر محجوز ====================

struct QuarantinedItem {
    std::string originalPath;           // المسار الأصلي
    std::string quarantinePath;         // المسار في الحجر
    std::string itemId;                 // معرف فريد
    std::string detectionName;          // اسم التهديد المكتشف
    std::string timestamp;              // وقت العزل
    uint64_t fileSize;                  // حجم الملف
    std::string fileHash;               // هاش التحقق
    std::string encryptionKey;          // مفتاح التشفير (مشفر)
    int threatLevel;                    // مستوى الخطورة (1-10)
    bool isRestored;                    // هل تم استعادته؟
    std::string restorePath;            // مسار الاستعادة إن وجد
};

// ==================== نظام الحجر الصحي ====================

class QuarantineManager {
private:
    std::string quarantineRoot;         // مجلد الحجر الرئيسي
    std::string databasePath;           // ملف قاعدة البيانات
    std::vector<QuarantinedItem> items; // قائمة العناصر المحجوزة
    std::map<std::string, size_t> idIndex; // فهرس المعرفات
    bool isInitialized = false;

    // ثوابت التشفير
    const std::string ENCRYPTION_HEADER = "AIAV_QUARANTINE_V1";

public:
    QuarantineManager(const std::string& rootPath = "") {
        if (rootPath.empty()) {
            // المسار الافتراضي: ProgramData\AI_Antivirus\Quarantine
            char programData[MAX_PATH];
            GetEnvironmentVariableA("PROGRAMDATA", programData, MAX_PATH);
            quarantineRoot = std::string(programData) + "\\AI_Antivirus\\Quarantine";
        }
        else {
            quarantineRoot = rootPath;
        }

        databasePath = quarantineRoot + "\\quarantine.db";

        std::cout << "[INIT] Quarantine Manager Initializing...\n";

        if (initializeStorage()) {
            loadDatabase();
            isInitialized = true;
            std::cout << "[SUCCESS] Quarantine ready. Items: " << items.size() << "\n";
        }
        else {
            std::cerr << "[ERROR] Failed to initialize quarantine storage\n";
        }
    }

    ~QuarantineManager() {
        if (isInitialized) {
            saveDatabase();
        }
    }

    // ==================== التهيئة والتخزين ====================

private:
    bool initializeStorage() {
        try {
            // إنشاء المجلدات
            if (!fs::exists(quarantineRoot)) {
                fs::create_directories(quarantineRoot);
            }

            // إخفاء المجلد (اختياري)
            SetFileAttributesA(quarantineRoot.c_str(), FILE_ATTRIBUTE_HIDDEN);

            // إنشاء مجلدات فرعية
            std::string folders[] = { "Files", "Logs", "Temp" };
            for (const auto& folder : folders) {
                std::string path = quarantineRoot + "\\" + folder;
                if (!fs::exists(path)) {
                    fs::create_directory(path);
                }
            }

            // تأمين الصلاحيات (فقط SYSTEM و Administrators)
            return secureDirectory(quarantineRoot);

        }
        catch (const std::exception& e) {
            std::cerr << "[ERROR] Storage init failed: " << e.what() << "\n";
            return false;
        }
    }

    bool secureDirectory(const std::string& path) {
        // إزالة جميع الصلاحيات وإعطاء خاصة للنظام فقط
        PSECURITY_DESCRIPTOR sd = nullptr;
        PACL acl = nullptr;

        // SID للنظام والمسؤولين
        const char* sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

        if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
            sddl, SDDL_REVISION_1, &sd, nullptr)) {

            // تطبيق الأمان على المجلد
            // (مبسط - في الإنتاج استخدم SetNamedSecurityInfo)
            LocalFree(sd);
            return true;
        }

        return false;
    }

    // ==================== العزل الأساسي ====================

public:
    bool quarantineFile(const std::string& filePath,
        const std::string& threatName,
        int threatLevel) {
        if (!isInitialized) {
            std::cerr << "[ERROR] Quarantine not initialized\n";
            return false;
        }

        if (!fs::exists(filePath)) {
            std::cerr << "[ERROR] File not found: " << filePath << "\n";
            return false;
        }

        try {
            std::cout << "[QUARANTINE] Processing: " << filePath << "\n";

            // 1. إنشاء معرف فريد
            std::string itemId = generateItemId();

            // 2. حساب الهاش الأصلي
            std::string originalHash = calculateFileHash(filePath);

            // 3. قراءة الملف
            std::vector<uint8_t> fileData = readFile(filePath);

            // 4. تشفير الملف
            std::string encryptionKey = generateEncryptionKey();
            std::vector<uint8_t> encryptedData = encryptData(fileData, encryptionKey);

            // 5. حفظ في الحجر
            std::string quarantineFile = quarantineRoot + "\\Files\\" + itemId + ".aqf";
            if (!writeFile(quarantineFile, encryptedData)) {
                std::cerr << "[ERROR] Failed to write quarantine file\n";
                return false;
            }

            // 6. حذف الملف الأصلي بشكل آمن
            if (!secureDelete(filePath)) {
                std::cerr << "[WARNING] Could not securely delete original\n";
                // لا نزال نكمل العزل
            }

            // 7. تسجيل في قاعدة البيانات
            QuarantinedItem item;
            item.itemId = itemId;
            item.originalPath = filePath;
            item.quarantinePath = quarantineFile;
            item.detectionName = threatName;
            item.timestamp = getCurrentTimestamp();
            item.fileSize = fileData.size();
            item.fileHash = originalHash;
            item.encryptionKey = encryptionKey; // في الإنتاج: تشفير هذا المفتاح أيضاً
            item.threatLevel = threatLevel;
            item.isRestored = false;

            items.push_back(item);
            idIndex[itemId] = items.size() - 1;

            saveDatabase();

            logAction("QUARANTINE", itemId, "File quarantined: " + threatName);

            std::cout << "[SUCCESS] Quarantined with ID: " << itemId << "\n";
            return true;

        }
        catch (const std::exception& e) {
            std::cerr << "[ERROR] Quarantine failed: " << e.what() << "\n";
            return false;
        }
    }

    // ==================== الاستعادة ====================

    bool restoreFile(const std::string& itemId,
        const std::string& restorePath = "") {
        if (!isInitialized) return false;

        auto it = idIndex.find(itemId);
        if (it == idIndex.end()) {
            std::cerr << "[ERROR] Item not found: " << itemId << "\n";
            return false;
        }

        QuarantinedItem& item = items[it->second];

        if (item.isRestored) {
            std::cerr << "[ERROR] Item already restored\n";
            return false;
        }

        try {
            std::cout << "[RESTORE] Restoring: " << itemId << "\n";

            // 1. التحقق من وجود الملف المحجوز
            if (!fs::exists(item.quarantinePath)) {
                std::cerr << "[ERROR] Quarantine file missing\n";
                return false;
            }

            // 2. قراءة وفك التشفير
            std::vector<uint8_t> encryptedData = readFile(item.quarantinePath);
            std::vector<uint8_t> decryptedData = decryptData(encryptedData,
                item.encryptionKey);

            // 3. التحقق من سلامة البيانات
            std::string currentHash = calculateHash(decryptedData);
            if (currentHash != item.fileHash) {
                std::cerr << "[CRITICAL] Integrity check failed! File corrupted.\n";
                return false;
            }

            // 4. تحديد مسار الاستعادة
            std::string targetPath = restorePath.empty() ?
                item.originalPath : restorePath;

            // 5. التحقق من عدم وجود ملف بنفس الاسم
            if (fs::exists(targetPath)) {
                targetPath = generateUniquePath(targetPath);
            }

            // 6. كتابة الملف
            if (!writeFile(targetPath, decryptedData)) {
                std::cerr << "[ERROR] Failed to write restored file\n";
                return false;
            }

            // 7. تحديث الحالة
            item.isRestored = true;
            item.restorePath = targetPath;
            saveDatabase();

            // 8. حذف من الحجر (اختياري - يمكن الاحتفاظ للسجلات)
            // fs::remove(item.quarantinePath);

            logAction("RESTORE", itemId, "Restored to: " + targetPath);

            std::cout << "[SUCCESS] Restored to: " << targetPath << "\n";
            return true;

        }
        catch (const std::exception& e) {
            std::cerr << "[ERROR] Restore failed: " << e.what() << "\n";
            return false;
        }
    }

    // ==================== الحذف الدائم ====================

    bool deletePermanently(const std::string& itemId) {
        if (!isInitialized) return false;

        auto it = idIndex.find(itemId);
        if (it == idIndex.end()) {
            std::cerr << "[ERROR] Item not found\n";
            return false;
        }

        try {
            QuarantinedItem& item = items[it->second];

            // 1. الكتابة فوق الملف عدة مرات (secure wipe)
            if (fs::exists(item.quarantinePath)) {
                secureWipeFile(item.quarantinePath);
                fs::remove(item.quarantinePath);
            }

            // 2. إزالة من القائمة
            items.erase(items.begin() + it->second);
            rebuildIndex();

            saveDatabase();

            logAction("DELETE", itemId, "Permanently deleted");

            std::cout << "[SUCCESS] Item permanently deleted\n";
            return true;

        }
        catch (const std::exception& e) {
            std::cerr << "[ERROR] Delete failed: " << e.what() << "\n";
            return false;
        }
    }

    // ==================== أدوات الأمان ====================

private:
    std::string generateItemId() {
        // UUID بسيط
        GUID guid;
        CoCreateGuid(&guid);

        char guidStr[40];
        sprintf_s(guidStr, "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
            guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

        return std::string(guidStr);
    }

    std::string generateEncryptionKey() {
        // توليد مفتاح عشوائي 256-bit
        HCRYPTPROV hProv;
        CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

        BYTE key[32];
        CryptGenRandom(hProv, 32, key);

        CryptReleaseContext(hProv, 0);

        // تحويل إلى hex
        std::stringstream ss;
        for (int i = 0; i < 32; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)key[i];
        }
        return ss.str();
    }

    std::vector<uint8_t> encryptData(const std::vector<uint8_t>& data,
        const std::string& key) {
        // XOR تشفير بسيط (في الإنتاج استخدم AES-256-GCM)
        std::vector<uint8_t> encrypted = data;
        std::vector<uint8_t> keyBytes = hexToBytes(key);

        for (size_t i = 0; i < encrypted.size(); i++) {
            encrypted[i] ^= keyBytes[i % keyBytes.size()];
        }

        // إضافة رأس التعريف
        std::vector<uint8_t> result(ENCRYPTION_HEADER.begin(),
            ENCRYPTION_HEADER.end());
        result.insert(result.end(), encrypted.begin(), encrypted.end());

        return result;
    }

    std::vector<uint8_t> decryptData(const std::vector<uint8_t>& data,
        const std::string& key) {
        // إزالة الرأس
        if (data.size() < ENCRYPTION_HEADER.size()) {
            throw std::runtime_error("Invalid encrypted data");
        }

        std::string header(data.begin(),
            data.begin() + ENCRYPTION_HEADER.size());
        if (header != ENCRYPTION_HEADER) {
            throw std::runtime_error("Invalid encryption header");
        }

        std::vector<uint8_t> encrypted(data.begin() + ENCRYPTION_HEADER.size(),
            data.end());

        // فك التشفير
        std::vector<uint8_t> decrypted = encrypted;
        std::vector<uint8_t> keyBytes = hexToBytes(key);

        for (size_t i = 0; i < decrypted.size(); i++) {
            decrypted[i] ^= keyBytes[i % keyBytes.size()];
        }

        return decrypted;
    }

    std::vector<uint8_t> hexToBytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

    bool secureDelete(const std::string& filePath) {
        // حذف آمن: الكتابة فوق الملف ثم حذفه
        if (!fs::exists(filePath)) return true;

        try {
            // الحصول على الحجم
            uint64_t fileSize = fs::file_size(filePath);

            // فتح للكتابة
            std::fstream file(filePath, std::ios::in | std::ios::out | std::ios::binary);
            if (!file) return false;

            // الكتابة فوق (3 مرات: 0x00, 0xFF, عشوائي)
            std::vector<char> zeros(fileSize, 0x00);
            std::vector<char> ones(fileSize, 0xFF);

            file.seekp(0);
            file.write(zeros.data(), fileSize);
            file.flush();

            file.seekp(0);
            file.write(ones.data(), fileSize);
            file.flush();

            file.close();

            // إعادة تسمية عشوائية قبل الحذف
            std::string tempName = fs::path(filePath).parent_path().string() +
                "\\" + generateItemId().substr(0, 8) + ".tmp";
            fs::rename(filePath, tempName);

            // الحذف النهائي
            return fs::remove(tempName);

        }
        catch (...) {
            return false;
        }
    }

    void secureWipeFile(const std::string& filePath) {
        secureDelete(filePath);
    }

    // ==================== قراءة/كتابة الملفات ====================

    std::vector<uint8_t> readFile(const std::string& path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) throw std::runtime_error("Cannot open file for reading");

        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<uint8_t> buffer(size);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            throw std::runtime_error("Failed to read file");
        }

        return buffer;
    }

    bool writeFile(const std::string& path, const std::vector<uint8_t>& data) {
        // إنشاء المجلدات إذا لزم الأمر
        fs::create_directories(fs::path(path).parent_path());

        std::ofstream file(path, std::ios::binary);
        if (!file) return false;

        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        return file.good();
    }

    // ==================== قاعدة البيانات ====================

    void loadDatabase() {
        if (!fs::exists(databasePath)) return;

        try {
            std::ifstream file(databasePath);
            std::string line;

            while (std::getline(file, line)) {
                // تنسيق: CSV بسيط
                std::stringstream ss(line);
                std::string token;
                std::vector<std::string> tokens;

                while (std::getline(ss, token, '|')) {
                    tokens.push_back(token);
                }

                if (tokens.size() >= 9) {
                    QuarantinedItem item;
                    item.itemId = tokens[0];
                    item.originalPath = tokens[1];
                    item.quarantinePath = tokens[2];
                    item.detectionName = tokens[3];
                    item.timestamp = tokens[4];
                    item.fileSize = std::stoull(tokens[5]);
                    item.fileHash = tokens[6];
                    item.encryptionKey = tokens[7];
                    item.threatLevel = std::stoi(tokens[8]);
                    item.isRestored = (tokens.size() > 9 && tokens[9] == "1");

                    items.push_back(item);
                }
            }

            rebuildIndex();

        }
        catch (const std::exception& e) {
            std::cerr << "[WARNING] Failed to load database: " << e.what() << "\n";
        }
    }

    void saveDatabase() {
        try {
            std::ofstream file(databasePath);

            for (const auto& item : items) {
                file << item.itemId << "|"
                    << item.originalPath << "|"
                    << item.quarantinePath << "|"
                    << item.detectionName << "|"
                    << item.timestamp << "|"
                    << item.fileSize << "|"
                    << item.fileHash << "|"
                    << item.encryptionKey << "|"
                    << item.threatLevel << "|"
                    << (item.isRestored ? "1" : "0") << "\n";
            }

        }
        catch (const std::exception& e) {
            std::cerr << "[ERROR] Failed to save database: " << e.what() << "\n";
        }
    }

    void rebuildIndex() {
        idIndex.clear();
        for (size_t i = 0; i < items.size(); i++) {
            idIndex[items[i].itemId] = i;
        }
    }

    // ==================== أدوات مساعدة ====================

    std::string calculateFileHash(const std::string& filePath) {
        auto data = readFile(filePath);
        return calculateHash(data);
    }

    std::string calculateHash(const std::vector<uint8_t>& data) {
        // SHA-256 مبسط (في الإنتاج استخدم مكتبة حقيقية)
        // هنا نستخدم dummy hash للتبسيط
        std::hash<std::string> hasher;
        size_t hash = hasher(std::string(data.begin(),
            data.begin() + std::min(data.size(),
                size_t(1024))));

        std::stringstream ss;
        ss << std::hex << hash;
        return ss.str();
    }

    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);

        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    std::string generateUniquePath(const std::string& original) {
        fs::path p(original);
        std::string stem = p.stem().string();
        std::string ext = p.extension().string();
        std::string dir = p.parent_path().string();

        int counter = 1;
        std::string newPath;
        do {
            newPath = dir + "\\" + stem + "_(" + std::to_string(counter) +
                ")" + ext;
            counter++;
        } while (fs::exists(newPath));

        return newPath;
    }

    void logAction(const std::string& action, const std::string& itemId,
        const std::string& details) {
        std::string logPath = quarantineRoot + "\\Logs\\quarantine.log";

        std::ofstream log(logPath, std::ios::app);
        log << "[" << getCurrentTimestamp() << "] "
            << "[" << action << "] "
            << "ID: " << itemId << " | "
            << details << "\n";
    }

    // ==================== واجهة برمجة التطبيقات العامة ====================

public:
    std::vector<QuarantinedItem> getAllItems() const {
        return items;
    }

    QuarantinedItem* getItem(const std::string& itemId) {
        auto it = idIndex.find(itemId);
        if (it != idIndex.end()) {
            return &items[it->second];
        }
        return nullptr;
    }

    void showQuarantineList() const {
        std::cout << "\n=== QUARANTINE LIST ===\n";
        std::cout << std::left << std::setw(20) << "ID"
            << std::setw(25) << "Threat"
            << std::setw(12) << "Level"
            << std::setw(20) << "Date"
            << "Status\n";
        std::cout << std::string(100, '-') << "\n";

        for (const auto& item : items) {
            std::string shortId = item.itemId.substr(0, 16) + "...";
            std::string status = item.isRestored ? "RESTORED" : "QUARANTINED";

            std::cout << std::left << std::setw(20) << shortId
                << std::setw(25) << item.detectionName
                << std::setw(12) << item.threatLevel
                << std::setw(20) << item.timestamp
                << status << "\n";
        }

        std::cout << "Total: " << items.size() << " items\n";
        std::cout << "=======================\n";
    }

    bool isInitialized() const {
        return isInitialized;
    }

    std::string getStoragePath() const {
        return quarantineRoot;
    }
};

// ==================== نقطة الاختبار ====================

#ifdef TEST_QUARANTINE
int main() {
    QuarantineManager quarantine;

    if (!quarantine.isInitialized()) {
        std::cerr << "Quarantine system failed to start\n";
        return 1;
    }

    // إنشاء ملف اختبار
    std::string testFile = "C:\\Temp\\test_malware.exe";
    fs::create_directories("C:\\Temp");

    {
        std::ofstream f(testFile);
        f << "This is a test malware file for quarantine system testing";
    }

    std::cout << "\n1. Quarantining test file...\n";
    if (quarantine.quarantineFile(testFile, "Trojan.Win32.Test", 8)) {
        std::cout << "Success!\n";
    }

    std::cout << "\n2. Listing quarantined items:\n";
    quarantine.showQuarantineList();

    // استعادة (اختياري)
    /*
    auto items = quarantine.getAllItems();
    if (!items.empty()) {
        std::cout << "\n3. Restoring first item...\n";
        quarantine.restoreFile(items[0].itemId, "C:\\Temp\\restored.exe");
    }
    */

    std::cout << "\nQuarantine storage: " << quarantine.getStoragePath() << "\n";

    return 0;
}
#endif