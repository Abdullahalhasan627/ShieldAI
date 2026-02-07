/**
 * FeatureExtractor.h
 *
 * مستخرج الخصائص - Feature Extraction Engine
 *
 * المسؤوليات:
 * - استخراج Feature Vector من الملفات الثنائية (PE, ELF, Mach-O)
 * - استخراج Features من بيانات الذاكرة (Memory Dumps)
 * - استخراج Features سلوكية من تقارير العمليات
 * - تحويل البيانات غير المنظمة إلى Vector<float> للـ AI Model
 *
 * متطلبات: C++17، Windows API
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <array>
#include <map>
#include <set>

namespace AIAntivirus {

    // Forward declaration
    class ProcessAnalysisReport;

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

    /**
     * الفئة الرئيسية: FeatureExtractor
     */
    class FeatureExtractor {
    public:
        static FeatureExtractor& GetInstance();
        
        bool Initialize(const ExtractionConfig& config = ExtractionConfig{});
        void Shutdown();

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
        FeatureVector ExtractFromMemory(const std::vector<uint8_t>& data);
        FeatureVector ExtractFromProcess(DWORD processId);
        float CalculateEntropy(const std::vector<uint8_t>& data);

        /**
         * استخراج Features سلوكية من تقرير عملية
         */
        FeatureVector ExtractFromBehavior(const ProcessAnalysisReport& report);

        /**
         * استخراج Features مختلطة (Hybrid)
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
         * حفظ Feature Vector إلى ملف
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
        FeatureExtractor() = default;
        ~FeatureExtractor() = default;
        
        ExtractionConfig m_config;
        bool m_isInitialized = false;

        // كلمات مفتاحية مشبوهة
        static const std::set<std::string> s_suspiciousKeywords;
        static const std::set<std::string> s_apiBlacklist;

        // ==================== وظائف الاستخراج الداخلية ====================

        bool CalculateFileStatistics(const std::wstring& filePath, FileStatistics& stats);
        bool CalculateBufferStatistics(const BYTE* data, size_t size, FileStatistics& stats);
        static double CalculateEntropy(const BYTE* data, size_t size);
        void ExtractStrings(const BYTE* data, size_t size,
            std::vector<std::string>& strings, FileStatistics& stats);
        bool ParsePEAdvanced(const BYTE* data, size_t size, PEAdvancedFeatures& peFeatures);
        bool ExtractPEImports(const BYTE* data, size_t size, PEAdvancedFeatures& peFeatures);
        bool CalculateSectionEntropies(const BYTE* data, size_t size, PEAdvancedFeatures& peFeatures);
        void ConvertStatsToFeatures(const FileStatistics& stats, std::vector<float>& features);
        void ConvertPEToFeatures(const PEAdvancedFeatures& pe, std::vector<float>& features);
        void ConvertBehaviorToFeatures(const ProcessAnalysisReport& report, std::vector<float>& features);
        void NormalizeFeatures(std::vector<float>& features);
        void ReduceDimensions(std::vector<float>& features, size_t targetSize);
        void StringsToFeatures(const FileStatistics& stats, std::vector<float>& features,
            size_t startIndex, size_t bucketCount);
        static uint32_t HashFeature(const std::string& feature, size_t bucketCount);
    };

} // namespace AIAntivirus
