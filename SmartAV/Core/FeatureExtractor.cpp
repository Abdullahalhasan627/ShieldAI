// FeatureExtractor.cpp - Core Module
// مستخرج الميزات للذكاء الاصطناعي - AI Feature Extraction

#include <iostream>
#include <fstream>
#include <vector>
#include <array>
#include <string>
#include <map>
#include <set>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <windows.h>
#include <winnt.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

// ==================== هيكل الميزات المستخرجة ====================

struct FileFeatures {
    // معرفات الملف
    std::string md5Hash;
    std::string sha256Hash;
    uint64_t fileSize;

    // ميزات PE Header (للملفات التنفيذية)
    bool isPE;
    uint16_t machineType;        // x86, x64, ARM
    uint32_t timeStamp;
    uint16_t numberOfSections;
    uint32_t entryPoint;
    uint32_t imageBase;
    uint32_t subsystem;          // GUI, Console, Driver
    bool hasHighEntropySections;
    double entropy;              // قياس العشوائية

    // ميزات الاستيراد/التصدير
    int importCount;
    int exportCount;
    std::vector<std::string> importedDLLs;
    std::vector<std::string> suspiciousImports;

    // ميزات الموارد
    bool hasEmbeddedResources;
    bool hasExecutableResources; // موارد قابلة للتنفيذ
    int resourceCount;

    // ميزات السلاسل
    int stringCount;
    int suspiciousStringCount;
    int urlCount;
    int ipCount;
    int registryKeyCount;
    int fileOperationCount;

    // ميزات السلوك المحتمل
    bool hasAntiVM;
    bool hasAntiDebug;
    bool hasPackedCode;
    bool hasEncryptedSections;

    // إحصائيات البايت
    std::array<double, 256> byteHistogram{};  // توزيع البايتات
    double meanByteValue;
    double stdDevBytes;

    // النتيجة النهائية للـ AI
    std::vector<float> featureVector;  // مصفوفة للنموذج
};

// ==================== مستخرج الميزات الرئيسي ====================

class FeatureExtractor {
private:
    // قوائم الكلمات المفتاحية
    std::vector<std::string> suspiciousAPIs = {
        "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
        "NtUnmapViewOfSection", "SetWindowsHookEx", "RegisterHotKey",
        "GetAsyncKeyState", "GetForegroundWindow", "GetClipboardData",
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",
        "InternetOpen", "InternetConnect", "HttpSendRequest",
        "URLDownloadToFile", "WinExec", "ShellExecute",
        "RegCreateKeyEx", "RegSetValueEx", "RegDeleteKey",
        "CreateService", "StartService", "OpenSCManager",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugString",
        "FindWindow", "ShowWindow", "BlockInput",
        "CreateToolhelp32Snapshot", "Process32First", "Process32Next"
    };

    std::vector<std::string> antiVMStrings = {
        "vmware", "virtualbox", "vbox", "qemu", "xen", "hyper-v",
        "sandboxie", "cuckoo", "wireshark", "process explorer"
    };

    std::vector<std::string> antiDebugStrings = {
        "debugger", "debug", "ida", "ollydbg", "x64dbg", "immunity",
        "windbg", "cheat engine"
    };

    // أقسام حزم شائعة
    std::vector<std::string> packerSignatures = {
        "UPX", "ASPack", "PECompact", "Themida", "VMProtect",
        "Enigma", "MPRESS", "FSG", "MEW", "Petite"
    };

public:
    FeatureExtractor() {
        std::cout << "[INIT] FeatureExtractor Engine Loading...\n";
        std::cout << "[INFO] Loaded " << suspiciousAPIs.size()
            << " suspicious API signatures\n";
    }

    // ==================== الاستخراج الرئيسي ====================

    FileFeatures extract(const std::string& filePath) {
        FileFeatures features;

        std::cout << "[EXTRACT] Processing: " << filePath << "\n";

        // 1. المعلومات الأساسية
        extractBasicInfo(filePath, features);

        // 2. حساب الـ Hashes
        computeHashes(filePath, features);

        // 3. تحليل PE (إذا كان ملف تنفيذي)
        if (isPEFile(filePath)) {
            extractPEFeatures(filePath, features);
        }

        // 4. تحليل السلاسل
        extractStringFeatures(filePath, features);

        // 5. تحليل الإنتروبيا والإحصائيات
        extractStatisticalFeatures(filePath, features);

        // 6. بناء متجه الميزات للـ AI
        buildFeatureVector(features);

        std::cout << "[SUCCESS] Extraction complete. Features: "
            << features.featureVector.size() << "\n";

        return features;
    }

    // ==================== الاستخراج الأساسي ====================

private:
    void extractBasicInfo(const std::string& filePath, FileFeatures& features) {
        // حجم الملف
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (file.is_open()) {
            features.fileSize = file.tellg();
            file.close();
        }

        // التحقق من نوع الملف
        features.isPE = isPEFile(filePath);
    }

    bool isPEFile(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return false;

        char dosMagic[2];
        file.read(dosMagic, 2);

        if (dosMagic[0] != 'M' || dosMagic[1] != 'Z') {
            return false;
        }

        // الانتقال إلى PE Header
        file.seekg(0x3C);
        uint32_t peOffset;
        file.read(reinterpret_cast<char*>(&peOffset), 4);

        file.seekg(peOffset);
        char peMagic[4];
        file.read(peMagic, 4);

        file.close();

        return (peMagic[0] == 'P' && peMagic[1] == 'E' &&
            peMagic[2] == 0 && peMagic[3] == 0);
    }

    // ==================== حساب الهاش ====================

    void computeHashes(const std::string& filePath, FileFeatures& features) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return;

        // قراءة الملف كاملاً (للملفات الصغيرة فقط)
        std::vector<uint8_t> buffer(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>()
        );
        file.close();

        // MD5
        unsigned char md5Digest[MD5_DIGEST_LENGTH];
        MD5(buffer.data(), buffer.size(), md5Digest);
        features.md5Hash = bytesToHex(md5Digest, MD5_DIGEST_LENGTH);

        // SHA256
        unsigned char sha256Digest[SHA256_DIGEST_LENGTH];
        SHA256(buffer.data(), buffer.size(), sha256Digest);
        features.sha256Hash = bytesToHex(sha256Digest, SHA256_DIGEST_LENGTH);
    }

    std::string bytesToHex(const unsigned char* data, size_t len) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < len; ++i) {
            ss << std::setw(2) << static_cast<int>(data[i]);
        }
        return ss.str();
    }

    // ==================== استخراج ميزات PE ====================

    void extractPEFeatures(const std::string& filePath, FileFeatures& features) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return;

        // DOS Header
        IMAGE_DOS_HEADER dosHeader;
        file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));

        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return;

        // الانتقال إلى NT Headers
        file.seekg(dosHeader.e_lfanew);

        IMAGE_NT_HEADERS ntHeaders;
        file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));

        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) return;

        // استخراج المعلومات
        features.machineType = ntHeaders.FileHeader.Machine;
        features.timeStamp = ntHeaders.FileHeader.TimeDateStamp;
        features.numberOfSections = ntHeaders.FileHeader.NumberOfSections;
        features.entryPoint = ntHeaders.OptionalHeader.AddressOfEntryPoint;
        features.imageBase = ntHeaders.OptionalHeader.ImageBase;
        features.subsystem = ntHeaders.OptionalHeader.Subsystem;

        // قراءة أقسام الملف
        std::vector<IMAGE_SECTION_HEADER> sections;
        for (int i = 0; i < features.numberOfSections; i++) {
            IMAGE_SECTION_HEADER section;
            file.read(reinterpret_cast<char*>(&section), sizeof(section));
            sections.push_back(section);

            // التحقق من أسماء الأقسام المشبوهة
            char secName[9] = { 0 };
            memcpy(secName, section.Name, 8);
            std::string sectionName(secName);

            // التحقق من الحزم
            for (const auto& packer : packerSignatures) {
                if (sectionName.find(packer) != std::string::npos) {
                    features.hasPackedCode = true;
                }
            }

            // حساب إنتروبيا القسم
            double sectionEntropy = calculateSectionEntropy(file, section);
            if (sectionEntropy > 7.0) { // إنتروبيا عالية جداً = مشفور/مضغوط
                features.hasHighEntropySections = true;
                features.hasEncryptedSections = true;
            }
        }

        // استخراج جدول الاستيراد
        extractImportTable(file, ntHeaders, features);

        // استخراج جدول التصدير
        extractExportTable(file, ntHeaders, features);

        file.close();
    }

    double calculateSectionEntropy(std::ifstream& file,
        const IMAGE_SECTION_HEADER& section) {
        // الانتقال إلى بداية القسم
        std::streampos currentPos = file.tellg();
        file.seekg(section.PointerToRawData);

        std::vector<uint8_t> data(std::min((DWORD)4096, section.SizeOfRawData));
        file.read(reinterpret_cast<char*>(data.data()), data.size());
        file.seekg(currentPos);

        // حساب الإنتروبيا
        std::array<int, 256> freq{};
        for (auto byte : data) {
            freq[byte]++;
        }

        double entropy = 0.0;
        double len = data.size();
        for (int i = 0; i < 256; i++) {
            if (freq[i] > 0) {
                double p = freq[i] / len;
                entropy -= p * std::log2(p);
            }
        }

        return entropy;
    }

    void extractImportTable(std::ifstream& file,
        const IMAGE_NT_HEADERS& ntHeaders,
        FileFeatures& features) {
        DWORD importDirRVA = ntHeaders.OptionalHeader.
            DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].
            VirtualAddress;

        if (importDirRVA == 0) return;

        // قراءة وحدات الاستيراد
        // (مبسط - في الواقع يتطلب تحويل RVA إلى Offset)
        IMAGE_IMPORT_DESCRIPTOR importDesc;
        // ... قراءة الجدول

        features.importCount = 0; // يحسب من العدد الفعلي
    }

    void extractExportTable(std::ifstream& file,
        const IMAGE_NT_HEADERS& ntHeaders,
        FileFeatures& features) {
        DWORD exportDirRVA = ntHeaders.OptionalHeader.
            DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].
            VirtualAddress;

        if (exportDirRVA == 0) {
            features.exportCount = 0;
            return;
        }

        features.exportCount = 1; // يحسب من العدد الفعلي
    }

    // ==================== استخراج السلاسل ====================

    void extractStringFeatures(const std::string& filePath,
        FileFeatures& features) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return;

        const size_t chunkSize = 8192;
        std::vector<char> buffer(chunkSize);

        std::string currentString;
        features.stringCount = 0;
        features.suspiciousStringCount = 0;
        features.urlCount = 0;
        features.ipCount = 0;
        features.registryKeyCount = 0;
        features.fileOperationCount = 0;

        while (file.read(buffer.data(), chunkSize) || file.gcount() > 0) {
            size_t bytesRead = file.gcount();

            for (size_t i = 0; i < bytesRead; i++) {
                char c = buffer[i];

                // السلاسل القابلة للطباعة (طول >= 4)
                if (isprint(c) && c != '\0') {
                    currentString += c;
                }
                else {
                    if (currentString.length() >= 4) {
                        processString(currentString, features);
                        features.stringCount++;
                    }
                    currentString.clear();
                }
            }
        }

        file.close();
    }

    void processString(const std::string& str, FileFeatures& features) {
        std::string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        // التحقق من Anti-VM
        for (const auto& vmStr : antiVMStrings) {
            if (lower.find(vmStr) != std::string::npos) {
                features.hasAntiVM = true;
                features.suspiciousStringCount++;
            }
        }

        // التحقق من Anti-Debug
        for (const auto& dbgStr : antiDebugStrings) {
            if (lower.find(dbgStr) != std::string::npos) {
                features.hasAntiDebug = true;
                features.suspiciousStringCount++;
            }
        }

        // التحقق من URLs
        if (str.find("http://") != std::string::npos ||
            str.find("https://") != std::string::npos ||
            str.find("www.") != std::string::npos) {
            features.urlCount++;
        }

        // التحقق من IPs (نمط بسيط)
        if (std::count(str.begin(), str.end(), '.') == 3) {
            // تحقق إضافي من أنها IP
            features.ipCount++;
        }

        // التحقق من مفاتيح الريجستري
        if (str.find("HKEY_") != std::string::npos ||
            str.find("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
            != std::string::npos) {
            features.registryKeyCount++;
        }

        // عمليات الملفات
        if (str.find(".exe") != std::string::npos ||
            str.find(".dll") != std::string::npos ||
            str.find("CreateFile") != std::string::npos) {
            features.fileOperationCount++;
        }

        // APIs مشبوهة
        for (const auto& api : suspiciousAPIs) {
            if (str.find(api) != std::string::npos) {
                features.suspiciousStringCount++;
                features.suspiciousImports.push_back(api);
            }
        }
    }

    // ==================== الإحصائيات والإنتروبيا ====================

    void extractStatisticalFeatures(const std::string& filePath,
        FileFeatures& features) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return;

        // قراءة أول 1MB أو حجم الملف كاملاً
        const size_t sampleSize = 1024 * 1024;
        std::vector<uint8_t> buffer;
        buffer.reserve(sampleSize);

        char byte;
        while (buffer.size() < sampleSize && file.get(byte)) {
            buffer.push_back(static_cast<uint8_t>(byte));
        }

        file.close();

        if (buffer.empty()) return;

        // بناء الهيستوغرام
        for (auto b : buffer) {
            features.byteHistogram[b]++;
        }

        // تحويل إلى نسب مئوية
        double total = buffer.size();
        for (auto& count : features.byteHistogram) {
            count /= total;
        }

        // حساب المتوسط
        double sum = 0.0;
        for (size_t i = 0; i < 256; i++) {
            sum += i * features.byteHistogram[i];
        }
        features.meanByteValue = sum;

        // حساب الانحراف المعياري
        double variance = 0.0;
        for (size_t i = 0; i < 256; i++) {
            variance += features.byteHistogram[i] *
                std::pow(i - features.meanByteValue, 2);
        }
        features.stdDevBytes = std::sqrt(variance);

        // حساب إنتروبيا الملف
        features.entropy = 0.0;
        for (const auto& p : features.byteHistogram) {
            if (p > 0) {
                features.entropy -= p * std::log2(p);
            }
        }
    }

    // ==================== بناء متجه الميزات ====================

    void buildFeatureVector(FileFeatures& features) {
        std::vector<float>& vec = features.featureVector;
        vec.clear();

        // 1. الميزات الرقمية (تطبيع)
        vec.push_back(normalize(features.fileSize, 0, 100 * 1024 * 1024)); // حجم

        // 2. ميزات PE (ثنائية/رقمية)
        vec.push_back(features.isPE ? 1.0f : 0.0f);
        vec.push_back(features.machineType == IMAGE_FILE_MACHINE_I386 ? 1.0f : 0.0f);
        vec.push_back(features.machineType == IMAGE_FILE_MACHINE_AMD64 ? 1.0f : 0.0f);
        vec.push_back(normalize(features.numberOfSections, 1, 20));
        vec.push_back(normalize(features.entropy, 0, 8));
        vec.push_back(features.hasHighEntropySections ? 1.0f : 0.0f);

        // 3. ميزات السلوك (ثنائية)
        vec.push_back(features.hasPackedCode ? 1.0f : 0.0f);
        vec.push_back(features.hasEncryptedSections ? 1.0f : 0.0f);
        vec.push_back(features.hasAntiVM ? 1.0f : 0.0f);
        vec.push_back(features.hasAntiDebug ? 1.0f : 0.0f);

        // 4. ميزات الاستيراد (تطبيع)
        vec.push_back(normalize(features.importCount, 0, 1000));
        vec.push_back(normalize(features.exportCount, 0, 500));
        vec.push_back(normalize((int)features.suspiciousImports.size(), 0, 50));

        // 5. ميزات السلاسل (تطبيع)
        vec.push_back(normalize(features.stringCount, 0, 10000));
        vec.push_back(normalize(features.suspiciousStringCount, 0, 1000));
        vec.push_back(normalize(features.urlCount, 0, 100));
        vec.push_back(normalize(features.ipCount, 0, 50));
        vec.push_back(normalize(features.registryKeyCount, 0, 100));
        vec.push_back(normalize(features.fileOperationCount, 0, 500));

        // 6. إحصائيات البايت (الهيستوغرام - 256 قيمة)
        for (const auto& val : features.byteHistogram) {
            vec.push_back(static_cast<float>(val));
        }

        // 7. الإحصائيات المتقدمة
        vec.push_back(normalize(features.meanByteValue, 0, 255));
        vec.push_back(normalize(features.stdDevBytes, 0, 128));

        // المجموع: ~280+ ميزة للنموذج
    }

    float normalize(int64_t value, int64_t min, int64_t max) {
        if (max == min) return 0.0f;
        float normalized = static_cast<float>(value - min) / static_cast<float>(max - min);
        return std::clamp(normalized, 0.0f, 1.0f);
    }

    float normalize(double value, double min, double max) {
        if (max == min) return 0.0f;
        float normalized = static_cast<float>((value - min) / (max - min));
        return std::clamp(normalized, 0.0f, 1.0f);
    }

    // ==================== واجهة برمجة التطبيقات العامة ====================

public:
    void printFeatures(const FileFeatures& features) {
        std::cout << "\n=== EXTRACTED FEATURES ===\n";
        std::cout << "File Size: " << features.fileSize << " bytes\n";
        std::cout << "MD5: " << features.md5Hash << "\n";
        std::cout << "SHA256: " << features.sha256Hash.substr(0, 16) << "...\n";
        std::cout << "Is PE: " << (features.isPE ? "Yes" : "No") << "\n";

        if (features.isPE) {
            std::cout << "Sections: " << features.numberOfSections << "\n";
            std::cout << "Entry Point: 0x" << std::hex << features.entryPoint << std::dec << "\n";
        }

        std::cout << "Entropy: " << std::fixed << std::setprecision(2)
            << features.entropy << "/8.00\n";
        std::cout << "Strings: " << features.stringCount
            << " (Suspicious: " << features.suspiciousStringCount << ")\n";
        std::cout << "URLs: " << features.urlCount
            << " | IPs: " << features.ipCount << "\n";

        std::cout << "Behavioral Flags:\n";
        std::cout << "  [Anti-VM: " << (features.hasAntiVM ? "YES" : "NO") << "] ";
        std::cout << "[Anti-Debug: " << (features.hasAntiDebug ? "YES" : "NO") << "] ";
        std::cout << "[Packed: " << (features.hasPackedCode ? "YES" : "NO") << "]\n";

        std::cout << "Feature Vector Size: " << features.featureVector.size() << "\n";
        std::cout << "==========================\n";
    }

    std::vector<float> getFeatureVector(const std::string& filePath) {
        FileFeatures features = extract(filePath);
        return features.featureVector;
    }

    // تصدير للـ AI
    void exportForTraining(const std::string& filePath,
        bool isMalicious,
        const std::string& outputFile) {
        FileFeatures features = extract(filePath);

        std::ofstream out(outputFile, std::ios::app);

        // تنسيق CSV: feature1,feature2,...,label
        for (size_t i = 0; i < features.featureVector.size(); i++) {
            out << features.featureVector[i];
            if (i < features.featureVector.size() - 1) out << ",";
        }
        out << "," << (isMalicious ? 1 : 0) << "\n";

        out.close();
    }
};

// ==================== نقطة الاختبار ====================

#ifdef TEST_EXTRACTOR
int main() {
    FeatureExtractor extractor;

    std::cout << "AI Antivirus - Feature Extractor\n\n";

    // اختبار على ملف تنفيذي
    char systemPath[MAX_PATH];
    GetSystemDirectoryA(systemPath, MAX_PATH);
    std::string testFile = std::string(systemPath) + "\\notepad.exe";

    if (std::ifstream(testFile)) {
        auto features = extractor.extract(testFile);
        extractor.printFeatures(features);
    }
    else {
        std::cout << "Testing with dummy data...\n";
    }

    return 0;
}
#endif