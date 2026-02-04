/**
 * FeatureExtractor.cpp
 *
 * مستخرج الخصائص - Feature Extraction Engine
 *
 * المسؤوليات:
 * - استخراج Feature Vector من الملفات الثنائية (PE, ELF, Mach-O)
 * - استخراج Features من بيانات الذاكرة (Memory Dumps)
 - استخراج Features سلوكية من تقارير العمليات
 * - تحويل البيانات غير المنظمة إلى Vector<float> للـ AI Model
 * - دعم Feature Hashing وSelection للأداء الأمثل
 * - التعامل مع الأخطاء (ملفات تالفة، بيانات غير صالحة)
 *
 * أنواع الـ Features:
 * 1. Static Features: هيكل PE، Imports، Strings، Entropy
 * 2. Dynamic Features: Behavior، API Calls، Network
 * 3. Metadata Features: الحجم، التوقيع، المسار
 *
 * متطلبات: C++17، Windows API، الرياضيات (Histograms, Entropy)
 */

#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <array>
#include <map>
#include <set>
#include <cmath>
#include <numeric>
#include <algorithm>
#include <functional>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <cstring>

 // TODO: تضمين مكتبات إضافية عند الحاجة
 // #include <onnxruntime_cxx_api.h> // لاحقاً للـ AI Integration

namespace fs = std::filesystem;

namespace AIAntivirus {

    // ==================== تعريفات الأنواع ====================

    /**
     * أنواع Feature Vectors
     */
    enum class FeatureType {
        PE_STATIC,          // ملف PE (تنفيذي)
        MEMORY_DUMP,        // تفريغ ذاكرة
        BEHAVIORAL,         // بيانات سلوكية
        NETWORK_FLOW,       // تدفق شبكي
        HYBRID              // مزيج من الأنواع
    };

    /**
     * إعدادات الاستخراج
     */
    struct ExtractionConfig {
        size_t vectorSize = 512;            // حجم الـ Vector النهائي
        bool usePEHeader = true;            // استخدام رأس PE
        bool useByteHistogram = true;       // استخدام توزيع البايتات
        bool useStringFeatures = true;      // استخراج الـ Strings
        bool useEntropyFeatures = true;     // استخدام Entropy متعدد
        bool normalize = true;              // تطبيع القيم [0,1]
        size_t maxStrings = 1000;           // أقصى عدد Strings
        size_t maxImports = 500;            // أقصى عدد Imports
    };

    /**
     * نتيجة الاستخراج
     */
    struct FeatureVector {
        std::vector<float> data;            // البيانات الرقمية
        FeatureType type;                   // النوع
        size_t originalFeatureCount;        // عدد الخصائص الأصلي
        std::vector<std::string> featureNames; // أسماء الخصائص (للتصحيح)
        bool isValid;                       // هل صالح للاستخدام؟
        std::string errorMessage;           // رسالة الخطأ إن وجدت
    };

    /**
     * إحصائيات ملف (File Statistics)
     */
    struct FileStatistics {
        uint64_t fileSize;
        double entropy;                     // Entropy عام
        std::array<uint32_t, 256> byteHistogram; // توزيع البايتات (0-255)
        uint32_t printableStrings;          // عدد Strings القابلة للطباعة
        uint32_t suspiciousStrings;         // عدد Strings المشبوهة
        std::map<std::string, uint32_t> stringFrequencies; // تكرار Strings
    };

    /**
     * خصائص PE متقدمة
     */
    struct PEAdvancedFeatures {
        // DOS Header
        uint16_t e_magic;
        uint16_t e_cblp;
        uint16_t e_cp;
        uint16_t e_crlc;

        // COFF Header
        uint16_t Machine;
        uint16_t NumberOfSections;
        uint32_t TimeDateStamp;
        uint32_t PointerToSymbolTable;
        uint32_t NumberOfSymbols;
        uint16_t SizeOfOptionalHeader;
        uint16_t Characteristics;

        // Optional Header
        uint16_t Magic;
        uint8_t MajorLinkerVersion;
        uint8_t MinorLinkerVersion;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializedData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
        uint64_t ImageBase;
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        uint64_t SizeOfStackReserve;
        uint64_t SizeOfStackCommit;
        uint64_t SizeOfHeapReserve;
        uint64_t SizeOfHeapCommit;

        // Section Features
        std::vector<std::string> sectionNames;
        std::vector<uint32_t> sectionEntropies;
        std::vector<uint32_t> sectionVirtualSizes;
        std::vector<uint32_t> sectionRawSizes;

        // Import Features
        std::vector<std::string> importedDLLs;
        std::vector<std::string> importedFunctions;
        uint32_t totalImports;

        // Resource Features
        bool hasVersionInfo;
        bool hasManifest;
        uint32_t resourceEntropy;
    };

    // ==================== الفئة الرئيسية: FeatureExtractor ====================

    class FeatureExtractor {
    public:
        FeatureExtractor();
        explicit FeatureExtractor(const ExtractionConfig& config);
        ~FeatureExtractor() = default;

        // منع النسخ
        FeatureExtractor(const FeatureExtractor&) = delete;
        FeatureExtractor& operator=(const FeatureExtractor&) = delete;

        // ==================== واجهة الاستخراج الرئيسية ====================

        /**
         * استخراج Features من ملف كامل
         */
        FeatureVector ExtractFromFile(const std::wstring& filePath);

        /**
         * استخراج Features من بيانات في الذاكرة (Buffer)
         */
        FeatureVector ExtractFromMemory(const BYTE* data, size_t size,
            FeatureType type = FeatureType::MEMORY_DUMP);

        /**
         * استخراج Features سلوكية من تقرير عملية
         */
        FeatureVector ExtractFromBehavior(const class ProcessAnalysisReport& report);

        /**
         * استخراج Features مختلطة (Hybrid) - تجمع أكثر من مصدر
         */
        FeatureVector ExtractHybrid(const std::wstring& filePath,
            const ProcessAnalysisReport& behaviorReport);

        // ==================== واجهة التكوين ====================

        void SetConfig(const ExtractionConfig& config) { m_config = config; }
        ExtractionConfig GetConfig() const { return m_config; }

        /**
         * الحصول على حجم الـ Vector المتوقع
         */
        size_t GetExpectedVectorSize() const { return m_config.vectorSize; }

        /**
         * التحقق من صحة Feature Vector
         */
        static bool ValidateVector(const FeatureVector& vec);

        /**
         * مقارنة بمتجهين (للبحث عن التشابه)
         */
        static float CalculateSimilarity(const FeatureVector& a, const FeatureVector& b);

        /**
         * دمج متجهين (Ensemble)
         */
        static FeatureVector CombineVectors(const FeatureVector& a,
            const FeatureVector& b,
            float weightA = 0.5f);

        // ==================== دوال مساعدة للتصحيح ====================

        /**
         * حفظ Feature Vector إلى ملف (للتحليل)
         */
        static bool SaveToFile(const FeatureVector& vec, const std::wstring& path);

        /**
         * تحميل Feature Vector من ملف
         */
        static FeatureVector LoadFromFile(const std::wstring& path);

        /**
         * طباعة Feature Vector (للتصحيح)
         */
        static std::string ToString(const FeatureVector& vec, bool verbose = false);

    private:
        // ==================== الأعضاء الخاصة ====================

        ExtractionConfig m_config;

        // كلمات مفتاحية مشبوهة (للـ String Analysis)
        static const std::set<std::string> s_suspiciousKeywords;
        static const std::set<std::string> s_apiBlacklist;

        // ==================== وظائف الاستخراج الداخلية ====================

        /**
         * حساب إحصائيات الملف الأساسية
         */
        bool CalculateFileStatistics(const std::wstring& filePath,
            FileStatistics& stats);

        /**
         * حساب إحصائيات من Buffer
         */
        bool CalculateBufferStatistics(const BYTE* data, size_t size,
            FileStatistics& stats);

        /**
         * حساب Entropy لبيانات
         */
        static double CalculateEntropy(const BYTE* data, size_t size);

        /**
         * استخراج Strings من البيانات
         */
        void ExtractStrings(const BYTE* data, size_t size,
            std::vector<std::string>& strings,
            FileStatistics& stats);

        /**
         * تحليل هيكل PE المتقدم
         */
        bool ParsePEAdvanced(const BYTE* data, size_t size,
            PEAdvancedFeatures& peFeatures);

        /**
         * استخراج Imports من PE
         */
        bool ExtractPEImports(const BYTE* data, size_t size,
            PEAdvancedFeatures& peFeatures);

        /**
         * حساب Entropy لكل Section في PE
         */
        bool CalculateSectionEntropies(const BYTE* data, size_t size,
            PEAdvancedFeatures& peFeatures);

        /**
         * تحويل إحصائيات الملف إلى Features
         */
        void ConvertStatsToFeatures(const FileStatistics& stats,
            std::vector<float>& features);

        /**
         * تحويل خصائص PE إلى Features
         */
        void ConvertPEToFeatures(const PEAdvancedFeatures& pe,
            std::vector<float>& features);

        /**
         * تحويل بيانات سلوكية إلى Features
         */
        void ConvertBehaviorToFeatures(const class ProcessAnalysisReport& report,
            std::vector<float>& features);

        /**
         * تطبيع Feature Vector
         */
        void NormalizeFeatures(std::vector<float>& features);

        /**
         * تقليل الأبعاد (Dimensionality Reduction) - PCA Stub
         */
        void ReduceDimensions(std::vector<float>& features, size_t targetSize);

        /**
         * Feature Hashing للـ Strings
         */
        uint32_t HashFeature(const std::string& str, size_t buckets);

        /**
         * تحويل Strings إلى Features باستخدام Hashing Trick
         */
        void StringsToFeatures(const FileStatistics& stats,
            std::vector<float>& features,
            size_t startIndex,
            size_t bucketCount);

        // ==================== وظائف PE Helpers ====================

        static PIMAGE_NT_HEADERS GetNtHeaders(const BYTE* data, size_t size);
        static bool IsValidPE(const BYTE* data, size_t size);
        static std::string ReadASCIIString(const BYTE* data, size_t maxLen);

        // ==================== وظائف الرياضيات ====================

        /**
         * Normalization (Min-Max Scaling)
         */
        static void MinMaxNormalize(std::vector<float>& data);

        /**
         * Standardization (Z-Score)
         */
        static void ZScoreNormalize(std::vector<float>& data);

        /**
         * Cosine Similarity
         */
        static float CosineSimilarity(const std::vector<float>& a,
            const std::vector<float>& b);
    };

    // ==================== الثوابت (Keywords المشبوهة) ====================

    const std::set<std::string> FeatureExtractor::s_suspiciousKeywords = {
        "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
        "OpenProcess", "ReadProcessMemory", "NtUnmapViewOfSection",
        "SetWindowsHookEx", "GetAsyncKeyState", "GetForegroundWindow",
        "URLDownloadToFile", "WinExec", "ShellExecute", "CreateProcess",
        "cmd.exe", "powershell.exe", "regsvr32.exe", "mshta.exe",
        "WSASocket", "connect", "bind", "listen", "recv", "send",
        "InternetOpen", "InternetConnect", "HttpSendRequest",
        "CreateFileMapping", "MapViewOfFile", "RtlCreateUserThread",
        "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext"
    };

    const std::set<std::string> FeatureExtractor::s_apiBlacklist = {
        "ExitProcess", "GetProcAddress", "LoadLibrary", "GetModuleHandle"
    };

    // ==================== التنفيذ (Implementation) ====================

    FeatureExtractor::FeatureExtractor() {
        // إعدادات افتراضية محسنة
        m_config.vectorSize = 512;
        m_config.usePEHeader = true;
        m_config.useByteHistogram = true;
        m_config.useStringFeatures = true;
        m_config.normalize = true;
    }

    FeatureExtractor::FeatureExtractor(const ExtractionConfig& config)
        : m_config(config) {
    }

    FeatureVector FeatureExtractor::ExtractFromFile(const std::wstring& filePath) {
        FeatureVector result;
        result.type = FeatureType::PE_STATIC;
        result.isValid = false;

        // التحقق من وجود الملف
        if (!fs::exists(filePath)) {
            result.errorMessage = "File not found";
            return result;
        }

        // قراءة الملف
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            result.errorMessage = "Cannot open file";
            return result;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        if (size == 0 || size > 100 * 1024 * 1024) { // أقصى 100MB
            result.errorMessage = "Invalid file size";
            return result;
        }

        std::vector<BYTE> buffer(size);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            result.errorMessage = "Failed to read file";
            return result;
        }

        // استخراج من الذاكرة
        return ExtractFromMemory(buffer.data(), static_cast<size_t>(size),
            FeatureType::PE_STATIC);
    }

    FeatureVector FeatureExtractor::ExtractFromMemory(const BYTE* data, size_t size,
        FeatureType type) {
        FeatureVector result;
        result.type = type;
        result.isValid = false;

        if (!data || size == 0) {
            result.errorMessage = "Invalid memory buffer";
            return result;
        }

        std::vector<float> features;
        features.reserve(m_config.vectorSize * 2); // Buffer مؤقت أكبر

        // 1. إحصائيات أساسية
        FileStatistics stats;
        if (!CalculateBufferStatistics(data, size, stats)) {
            result.errorMessage = "Failed to calculate statistics";
            return result;
        }
        ConvertStatsToFeatures(stats, features);

        // 2. خصائص PE (إذا كان PE صالح)
        if (type == FeatureType::PE_STATIC && IsValidPE(data, size)) {
            PEAdvancedFeatures peFeatures;
            if (ParsePEAdvanced(data, size, peFeatures)) {
                ConvertPEToFeatures(peFeatures, features);
                result.type = FeatureType::PE_STATIC;
            }
        }

        // 3. تقليل الأبعاد إذا لزم الأمر
        if (features.size() > m_config.vectorSize) {
            ReduceDimensions(features, m_config.vectorSize);
        }
        else if (features.size() < m_config.vectorSize) {
            // Padding بالأصفار
            features.resize(m_config.vectorSize, 0.0f);
        }

        // 4. التطبيع
        if (m_config.normalize) {
            NormalizeFeatures(features);
        }

        result.data = std::move(features);
        result.originalFeatureCount = features.size();
        result.isValid = true;

        return result;
    }

    FeatureVector FeatureExtractor::ExtractFromBehavior(
        const class ProcessAnalysisReport& report) {

        FeatureVector result;
        result.type = FeatureType::BEHAVIORAL;
        result.isValid = true;

        std::vector<float> features;
        features.reserve(m_config.vectorSize);

        ConvertBehaviorToFeatures(report, features);

        // Padding أو Reduction
        if (features.size() > m_config.vectorSize) {
            ReduceDimensions(features, m_config.vectorSize);
        }
        else {
            features.resize(m_config.vectorSize, 0.0f);
        }

        if (m_config.normalize) {
            NormalizeFeatures(features);
        }

        result.data = std::move(features);
        return result;
    }

    bool FeatureExtractor::CalculateFileStatistics(const std::wstring& filePath,
        FileStatistics& stats) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) return false;

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<BYTE> buffer(size);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            return false;
        }

        return CalculateBufferStatistics(buffer.data(), static_cast<size_t>(size), stats);
    }

    bool FeatureExtractor::CalculateBufferStatistics(const BYTE* data, size_t size,
        FileStatistics& stats) {
        if (!data || size == 0) return false;

        stats.fileSize = size;
        stats.byteHistogram.fill(0);
        stats.printableStrings = 0;
        stats.suspiciousStrings = 0;

        // حساب Histogram
        for (size_t i = 0; i < size; ++i) {
            stats.byteHistogram[data[i]]++;
        }

        // حساب Entropy
        stats.entropy = CalculateEntropy(data, size);

        // استخراج Strings
        std::vector<std::string> strings;
        ExtractStrings(data, size, strings, stats);

        return true;
    }

    double FeatureExtractor::CalculateEntropy(const BYTE* data, size_t size) {
        if (size == 0) return 0.0;

        std::array<uint32_t, 256> freq = { 0 };
        for (size_t i = 0; i < size; ++i) {
            freq[data[i]]++;
        }

        double entropy = 0.0;
        double size_d = static_cast<double>(size);

        for (int i = 0; i < 256; ++i) {
            if (freq[i] > 0) {
                double p = static_cast<double>(freq[i]) / size_d;
                entropy -= p * std::log2(p);
            }
        }

        return entropy;
    }

    void FeatureExtractor::ExtractStrings(const BYTE* data, size_t size,
        std::vector<std::string>& strings,
        FileStatistics& stats) {
        const size_t minStringLength = 4;
        std::string currentString;

        for (size_t i = 0; i < size; ++i) {
            // ASCII printable (32-126) أو Extended ASCII
            if ((data[i] >= 32 && data[i] <= 126)) {
                currentString += static_cast<char>(data[i]);
            }
            else {
                if (currentString.length() >= minStringLength) {
                    if (stats.stringFrequencies.size() < m_config.maxStrings) {
                        stats.stringFrequencies[currentString]++;
                        stats.printableStrings++;

                        // التحقق من الكلمات المفتاحية
                        for (const auto& keyword : s_suspiciousKeywords) {
                            if (currentString.find(keyword) != std::string::npos) {
                                stats.suspiciousStrings++;
                                break;
                            }
                        }
                    }
                    strings.push_back(currentString);
                }
                currentString.clear();
            }
        }

        // معالجة آخر string إن وجد
        if (currentString.length() >= minStringLength) {
            if (stats.stringFrequencies.size() < m_config.maxStrings) {
                stats.stringFrequencies[currentString]++;
                stats.printableStrings++;
            }
            strings.push_back(currentString);
        }
    }

    bool FeatureExtractor::ParsePEAdvanced(const BYTE* data, size_t size,
        PEAdvancedFeatures& pe) {
        auto ntHeaders = GetNtHeaders(data, size);
        if (!ntHeaders) return false;

        // DOS Header
        auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
        pe.e_magic = dosHeader->e_magic;
        pe.e_cblp = dosHeader->e_cblp;
        pe.e_cp = dosHeader->e_cp;

        // COFF Header
        pe.Machine = ntHeaders->FileHeader.Machine;
        pe.NumberOfSections = ntHeaders->FileHeader.NumberOfSections;
        pe.TimeDateStamp = ntHeaders->FileHeader.TimeDateStamp;
        pe.SizeOfOptionalHeader = ntHeaders->FileHeader.SizeOfOptionalHeader;
        pe.Characteristics = ntHeaders->FileHeader.Characteristics;

        // Optional Header (32 أو 64 bit)
        bool is64bit = (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        pe.Magic = ntHeaders->OptionalHeader.Magic;
        pe.MajorLinkerVersion = ntHeaders->OptionalHeader.MajorLinkerVersion;
        pe.MinorLinkerVersion = ntHeaders->OptionalHeader.MinorLinkerVersion;
        pe.SizeOfCode = ntHeaders->OptionalHeader.SizeOfCode;
        pe.SizeOfInitializedData = ntHeaders->OptionalHeader.SizeOfInitializedData;
        pe.AddressOfEntryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
        pe.BaseOfCode = ntHeaders->OptionalHeader.BaseOfCode;
        pe.ImageBase = is64bit ?
            reinterpret_cast<const IMAGE_NT_HEADERS64*>(ntHeaders)->OptionalHeader.ImageBase :
            ntHeaders->OptionalHeader.ImageBase;
        pe.SectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;
        pe.FileAlignment = ntHeaders->OptionalHeader.FileAlignment;
        pe.SizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
        pe.SizeOfHeaders = ntHeaders->OptionalHeader.SizeOfHeaders;
        pe.CheckSum = ntHeaders->OptionalHeader.CheckSum;
        pe.Subsystem = ntHeaders->OptionalHeader.Subsystem;
        pe.DllCharacteristics = ntHeaders->OptionalHeader.DllCharacteristics;

        // Sections
        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
            char name[9] = { 0 };
            std::memcpy(name, sectionHeader[i].Name, 8);
            pe.sectionNames.push_back(name);
            pe.sectionVirtualSizes.push_back(sectionHeader[i].Misc.VirtualSize);
            pe.sectionRawSizes.push_back(sectionHeader[i].SizeOfRawData);
        }

        // Imports
        ExtractPEImports(data, size, pe);

        return true;
    }

    bool FeatureExtractor::ExtractPEImports(const BYTE* data, size_t size,
        PEAdvancedFeatures& pe) {
        auto ntHeaders = GetNtHeaders(data, size);
        if (!ntHeaders) return false;

        DWORD importDirRVA = ntHeaders->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

        if (importDirRVA == 0) return true; // لا يوجد imports

        // TODO: تحويل RVA إلى File Offset (يتطلب معالجة أكثر تعقيداً للـ Sections)
        // هذا Stub يفترض أن الملف mapped بشكل خطي

        pe.totalImports = 0;
        return true;
    }

    void FeatureExtractor::ConvertStatsToFeatures(const FileStatistics& stats,
        std::vector<float>& features) {
        size_t startIdx = features.size();

        // 1. حجم الملف (مُطَبَّع، لوغاريتمي)
        features.push_back(static_cast<float>(std::log1p(stats.fileSize)));

        // 2. Entropy العام (مُطَبَّع [0,8] -> [0,1])
        features.push_back(static_cast<float>(stats.entropy / 8.0));

        // 3. Byte Histogram (256 قيمة -> 16 bucket لتقليل الأبعاد)
        for (int i = 0; i < 16; ++i) {
            uint64_t bucketSum = 0;
            for (int j = 0; j < 16; ++j) {
                bucketSum += stats.byteHistogram[i * 16 + j];
            }
            float normalized = stats.fileSize > 0 ?
                static_cast<float>(bucketSum) / stats.fileSize : 0.0f;
            features.push_back(normalized);
        }

        // 4. إحصائيات Strings
        features.push_back(static_cast<float>(std::log1p(stats.printableStrings)));
        features.push_back(static_cast<float>(std::log1p(stats.suspiciousStrings)));

        float suspiciousRatio = stats.printableStrings > 0 ?
            static_cast<float>(stats.suspiciousStrings) / stats.printableStrings : 0.0f;
        features.push_back(suspiciousRatio);

        // 5. String Features (Hashing)
        if (m_config.useStringFeatures) {
            StringsToFeatures(stats, features, features.size(), 32); // 32 buckets
        }
    }

    void FeatureExtractor::ConvertPEToFeatures(const PEAdvancedFeatures& pe,
        std::vector<float>& features) {
        // 1. Header Features
        features.push_back(static_cast<float>(pe.Machine));
        features.push_back(static_cast<float>(pe.NumberOfSections));
        features.push_back(static_cast<float>(pe.Characteristics));
        features.push_back(static_cast<float>(pe.Subsystem));
        features.push_back(pe.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? 1.0f : 0.0f);
        features.push_back(static_cast<float>(pe.DllCharacteristics));

        // 2. Sizes (مُطَبَّعة)
        features.push_back(static_cast<float>(std::log1p(pe.SizeOfCode)));
        features.push_back(static_cast<float>(std::log1p(pe.SizeOfInitializedData)));
        features.push_back(static_cast<float>(std::log1p(pe.SizeOfImage)));

        // 3. Section Features
        float avgSectionEntropy = 0.0f;
        float avgVirtualSize = 0.0f;
        float avgRawSize = 0.0f;

        if (!pe.sectionVirtualSizes.empty()) {
            avgVirtualSize = std::accumulate(pe.sectionVirtualSizes.begin(),
                pe.sectionVirtualSizes.end(), 0.0f) /
                pe.sectionVirtualSizes.size();
            avgRawSize = std::accumulate(pe.sectionRawSizes.begin(),
                pe.sectionRawSizes.end(), 0.0f) /
                pe.sectionRawSizes.size();
        }

        features.push_back(static_cast<float>(pe.sectionNames.size()));
        features.push_back(static_cast<float>(std::log1p(static_cast<size_t>(avgVirtualSize))));
        features.push_back(static_cast<float>(std::log1p(static_cast<size_t>(avgRawSize))));

        // نسبة Virtual/Raw (Packed إذا كانت عالية)
        float virtualRawRatio = avgRawSize > 0 ? avgVirtualSize / avgRawSize : 0.0f;
        features.push_back(std::min(virtualRawRatio, 10.0f)); // Cap at 10

        // 4. Import Features
        features.push_back(static_cast<float>(std::log1p(pe.importedDLLs.size())));
        features.push_back(static_cast<float>(std::log1p(pe.importedFunctions.size())));
        features.push_back(static_cast<float>(std::log1p(pe.totalImports)));

        // 5. Section Names (One-hot encoded للأنواع الشائعة)
        std::map<std::string, float> sectionTypes = {
            {".text", 0.0f}, {".data", 0.0f}, {".rsrc", 0.0f},
            {".rdata", 0.0f}, {".reloc", 0.0f}, {".pdata", 0.0f},
            {"UPX", 0.0f}, {".aspack", 0.0f}, {".vmp", 0.0f}
        };

        for (const auto& name : pe.sectionNames) {
            auto it = sectionTypes.find(name);
            if (it != sectionTypes.end()) {
                it->second = 1.0f;
            }
            // Packed sections
            if (name.find("UPX") != std::string::npos ||
                name.find("aspack") != std::string::npos) {
                sectionTypes["UPX"] = 1.0f;
            }
        }

        for (const auto& [name, value] : sectionTypes) {
            features.push_back(value);
        }
    }

    void FeatureExtractor::ConvertBehaviorToFeatures(
        const class ProcessAnalysisReport& report,
        std::vector<float>& features) {

        // 1. Count Features
        features.push_back(static_cast<float>(report.loadedModules.size()));
        features.push_back(static_cast<float>(report.threadCount));
        features.push_back(static_cast<float>(std::log1p(report.memoryUsage / 1024 / 1024))); // MB

        // 2. Binary Features
        features.push_back(report.isElevated ? 1.0f : 0.0f);
        features.push_back(report.isCriticalSystemProcess ? 1.0f : 0.0f);
        features.push_back(report.behavior.injectedCode ? 1.0f : 0.0f);
        features.push_back(report.behavior.attemptedEscalation ? 1.0f : 0.0f);
        features.push_back(report.behavior.hookedAPI ? 1.0f : 0.0f);

        // 3. Attack Techniques (One-hot)
        std::vector<float> techniqueVector(10, 0.0f); // 10 techniques
        for (const auto& tech : report.detectedTechniques) {
            int idx = static_cast<int>(tech);
            if (idx < 10) techniqueVector[idx] = 1.0f;
        }
        features.insert(features.end(), techniqueVector.begin(), techniqueVector.end());

        // 4. Threat Score
        features.push_back(report.threatScore);
    }

    void FeatureExtractor::NormalizeFeatures(std::vector<float>& features) {
        // Min-Max Normalization لكل Feature على حدة (مؤقت)
        // في التطبيق الحقيقي، نستخدم معايير محسوبة من Dataset

        float minVal = *std::min_element(features.begin(), features.end());
        float maxVal = *std::max_element(features.begin(), features.end());

        if (maxVal > minVal) {
            for (auto& f : features) {
                f = (f - minVal) / (maxVal - minVal);
            }
        }
    }

    void FeatureExtractor::ReduceDimensions(std::vector<float>& features,
        size_t targetSize) {
        // TODO: PCA (Principal Component Analysis) أو Autoencoder
        // حالياً: اختيار أول N feature (غير مثالي)

        if (features.size() > targetSize) {
            features.resize(targetSize);
        }
    }

    void FeatureExtractor::StringsToFeatures(const FileStatistics& stats,
        std::vector<float>& features,
        size_t startIndex,
        size_t bucketCount) {
        // Feature Hashing: توزيع Strings على Buckets
        std::vector<float> buckets(bucketCount, 0.0f);

        for (const auto& [str, count] : stats.stringFrequencies) {
            uint32_t hash = HashFeature(str, bucketCount);
            buckets[hash] += static_cast<float>(count);
        }

        // Normalization
        float maxCount = *std::max_element(buckets.begin(), buckets.end());
        if (maxCount > 0) {
            for (auto& b : buckets) {
                b /= maxCount;
            }
        }

        features.insert(features.end(), buckets.begin(), buckets.end());
    }

    uint32_t FeatureExtractor::HashFeature(const std::string& str, size_t buckets) {
        // FNV-1a Hash
        uint32_t hash = 2166136261u;
        for (char c : str) {
            hash ^= static_cast<uint8_t>(c);
            hash *= 16777619u;
        }
        return hash % buckets;
    }

    // ==================== Static Helper Methods ====================

    PIMAGE_NT_HEADERS FeatureExtractor::GetNtHeaders(const BYTE* data, size_t size) {
        if (size < sizeof(IMAGE_DOS_HEADER)) return nullptr;

        auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        if (size < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) return nullptr;

        auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(data + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        return const_cast<PIMAGE_NT_HEADERS>(ntHeaders);
    }

    bool FeatureExtractor::IsValidPE(const BYTE* data, size_t size) {
        return GetNtHeaders(data, size) != nullptr;
    }

    std::string FeatureExtractor::ReadASCIIString(const BYTE* data, size_t maxLen) {
        std::string result;
        for (size_t i = 0; i < maxLen && data[i] != '\0'; ++i) {
            if (data[i] >= 32 && data[i] <= 126) {
                result += static_cast<char>(data[i]);
            }
        }
        return result;
    }

    float FeatureExtractor::CalculateSimilarity(const FeatureVector& a,
        const FeatureVector& b) {
        if (!a.isValid || !b.isValid || a.data.size() != b.data.size()) {
            return -1.0f;
        }
        return CosineSimilarity(a.data, b.data);
    }

    float FeatureExtractor::CosineSimilarity(const std::vector<float>& a,
        const std::vector<float>& b) {
        if (a.size() != b.size() || a.empty()) return 0.0f;

        float dot = 0.0f, normA = 0.0f, normB = 0.0f;
        for (size_t i = 0; i < a.size(); ++i) {
            dot += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }

        float denom = std::sqrt(normA) * std::sqrt(normB);
        return denom > 0 ? dot / denom : 0.0f;
    }

    FeatureVector FeatureExtractor::CombineVectors(const FeatureVector& a,
        const FeatureVector& b,
        float weightA) {
        FeatureVector result;
        result.type = FeatureType::HYBRID;
        result.isValid = a.isValid && b.isValid;

        if (!result.isValid || a.data.size() != b.data.size()) {
            result.errorMessage = "Incompatible vectors";
            return result;
        }

        float weightB = 1.0f - weightA;
        result.data.resize(a.data.size());

        for (size_t i = 0; i < a.data.size(); ++i) {
            result.data[i] = (a.data[i] * weightA) + (b.data[i] * weightB);
        }

        return result;
    }

    bool FeatureExtractor::ValidateVector(const FeatureVector& vec) {
        if (!vec.isValid) return false;
        if (vec.data.empty()) return false;

        // التحقق من NaN أو Infinity
        for (float f : vec.data) {
            if (std::isnan(f) || std::isinf(f)) return false;
        }

        return true;
    }

    bool FeatureExtractor::SaveToFile(const FeatureVector& vec,
        const std::wstring& path) {
        std::ofstream file(path, std::ios::binary);
        if (!file.is_open()) return false;

        // Header: Type (4) + Size (4) + Valid (1)
        int type = static_cast<int>(vec.type);
        file.write(reinterpret_cast<const char*>(&type), sizeof(type));

        size_t size = vec.data.size();
        file.write(reinterpret_cast<const char*>(&size), sizeof(size));

        file.write(reinterpret_cast<const char*>(&vec.isValid), sizeof(vec.isValid));

        // Data
        file.write(reinterpret_cast<const char*>(vec.data.data()),
            size * sizeof(float));

        return true;
    }

    FeatureVector FeatureExtractor::LoadFromFile(const std::wstring& path) {
        FeatureVector result;
        result.isValid = false;

        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            result.errorMessage = "Cannot open file";
            return result;
        }

        int type;
        size_t size;
        bool isValid;

        file.read(reinterpret_cast<char*>(&type), sizeof(type));
        file.read(reinterpret_cast<char*>(&size), sizeof(size));
        file.read(reinterpret_cast<char*>(&isValid), sizeof(isValid));

        result.type = static_cast<FeatureType>(type);
        result.isValid = isValid;
        result.data.resize(size);

        file.read(reinterpret_cast<char*>(result.data.data()), size * sizeof(float));

        return result;
    }

    std::string FeatureExtractor::ToString(const FeatureVector& vec, bool verbose) {
        std::stringstream ss;
        ss << "FeatureVector [Type: " << static_cast<int>(vec.type)
            << ", Size: " << vec.data.size()
            << ", Valid: " << (vec.isValid ? "Yes" : "No") << "]\n";

        if (!vec.isValid) {
            ss << "Error: " << vec.errorMessage << "\n";
            return ss.str();
        }

        if (verbose) {
            ss << "Data: [";
            for (size_t i = 0; i < std::min(vec.data.size(), size_t(20)); ++i) {
                ss << std::fixed << std::setprecision(4) << vec.data[i] << " ";
            }
            if (vec.data.size() > 20) {
                ss << "... (" << vec.data.size() - 20 << " more)";
            }
            ss << "]\n";
        }

        // إحصائيات سريعة
        float minVal = *std::min_element(vec.data.begin(), vec.data.end());
        float maxVal = *std::max_element(vec.data.begin(), vec.data.end());
        float avg = std::accumulate(vec.data.begin(), vec.data.end(), 0.0f) / vec.data.size();

        ss << "Stats: Min=" << minVal << ", Max=" << maxVal << ", Avg=" << avg << "\n";

        return ss.str();
    }

} // namespace AIAntivirus