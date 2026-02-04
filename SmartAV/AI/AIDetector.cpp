// AIDetector.cpp - AI Module
// كاشف التهديدات بالذكاء الاصطناعي - ONNX Runtime Integration

#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <cmath>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <onnxruntime_cxx_api.h>

// ==================== هيكل نتيجة التحليل ====================

struct DetectionResult {
    float malwareProbability;    // احتمالية البرمجية الخبيثة (0.0 - 1.0)
    float confidence;            // ثقة النموذج في النتيجة
    std::string threatClass;     // فئة التهديد (Trojan, Ransomware, etc.)
    std::vector<std::pair<std::string, float>> topClasses; // أفضل 3 تخمينات
    int64_t inferenceTimeMs;     // وقت التحليل بالمللي ثانية
    bool isError;                // هل حدث خطأ
    std::string errorMessage;    // رسالة الخطأ إن وجدت
};

// ==================== كاشف الذكاء الاصطناعي ====================

class AIDetector {
private:
    std::unique_ptr<Ort::Session> session;
    std::unique_ptr<Ort::Env> environment;

    // معلومات النموذج
    std::string modelPath;
    std::string inputName;
    std::string outputName;
    size_t inputSize;
    size_t outputSize;

    // إعدادات الجلسة
    Ort::SessionOptions sessionOptions;
    Ort::MemoryInfo memoryInfo{ nullptr };

    // فئات التهديدات المعروفة
    std::vector<std::string> threatClasses = {
        "Benign",           // 0 - نظيف
        "Trojan",           // 1 - تروجان
        "Ransomware",       // 2 - فدية
        "Spyware",          // 3 - تجسس
        "Adware",           // 4 - إعلانات
        "Rootkit",          // 5 - روتكيت
        "Worm",             // 6 - دودة
        "Backdoor",         // 7 - باب خلفي
        "Keylogger",        // 8 - مسجل ضغطات
        "Cryptominer"       // 9 - تعدين مخفي
    };

    bool isInitialized = false;

public:
    AIDetector(const std::string& modelFile = "model.onnx")
        : modelPath(modelFile), memoryInfo(nullptr) {

        std::cout << "[INIT] AI Detector Initializing...\n";

        try {
            initializeONNX();
            loadModel();
            isInitialized = true;
            std::cout << "[SUCCESS] AI Engine Ready\n";
        }
        catch (const Ort::Exception& e) {
            std::cerr << "[ERROR] ONNX Runtime Error: " << e.what() << "\n";
            isInitialized = false;
        }
        catch (const std::exception& e) {
            std::cerr << "[ERROR] Initialization Failed: " << e.what() << "\n";
            isInitialized = false;
        }
    }

    ~AIDetector() {
        if (isInitialized) {
            std::cout << "[SHUTDOWN] AI Detector Closed\n";
        }
    }

    // ==================== تهيئة ONNX Runtime ====================

private:
    void initializeONNX() {
        // إنشاء البيئة
        OrtLoggingLevel loggingLevel = ORT_LOGGING_LEVEL_WARNING;
        environment = std::make_unique<Ort::Env>(loggingLevel, "AI_Antivirus");

        // إعدادات الجلسة للأداء الأمثل
        sessionOptions.SetIntraOpNumThreads(4);  // استخدام 4 أنوية
        sessionOptions.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);

        // تعيين موفر التنفيذ (CPU/GPU)
        // للـ GPU: OrtCUDAProviderOptions cudaOptions;

        memoryInfo = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
    }

    void loadModel() {
        // تحويل المسار إلى wstring للـ Windows
        std::wstring wModelPath(modelPath.begin(), modelPath.end());

        // إنشاء الجلسة
        session = std::make_unique<Ort::Session>(*environment,
            wModelPath.c_str(),
            sessionOptions);

        // الحصول على أسماء الإدخال والإخراج
        Ort::AllocatorWithDefaultOptions allocator;

        // معلومات الإدخال
        size_t numInputNodes = session->GetInputCount();
        if (numInputNodes > 0) {
            Ort::AllocatedStringPtr inputNamePtr =
                session->GetInputNameAllocated(0, allocator);
            inputName = inputNamePtr.get();

            Ort::TypeInfo inputTypeInfo = session->GetInputTypeInfo(0);
            auto tensorInfo = inputTypeInfo.GetTensorTypeAndShapeInfo();
            inputSize = tensorInfo.GetElementCount();

            std::cout << "[INFO] Model Input: " << inputName
                << " | Size: " << inputSize << "\n";
        }

        // معلومات الإخراج
        size_t numOutputNodes = session->GetOutputCount();
        if (numOutputNodes > 0) {
            Ort::AllocatedStringPtr outputNamePtr =
                session->GetOutputNameAllocated(0, allocator);
            outputName = outputNamePtr.get();

            Ort::TypeInfo outputTypeInfo = session->GetOutputTypeInfo(0);
            auto tensorInfo = outputTypeInfo.GetTensorTypeAndShapeInfo();
            outputSize = tensorInfo.GetElementCount();

            std::cout << "[INFO] Model Output: " << outputName
                << " | Size: " << outputSize << "\n";
        }
    }

    // ==================== التنبؤ الرئيسي ====================

public:
    DetectionResult predict(const std::vector<float>& features) {
        DetectionResult result;
        result.isError = true;

        if (!isInitialized) {
            result.errorMessage = "Detector not initialized";
            return result;
        }

        if (features.empty()) {
            result.errorMessage = "Empty feature vector";
            return result;
        }

        try {
            auto start = std::chrono::high_resolution_clock::now();

            // 1. إعداد المدخلات
            std::vector<int64_t> inputShape = { 1, static_cast<int64_t>(features.size()) };

            // التأكد من تطابق حجم المدخلات مع النموذج
            std::vector<float> inputData = features;
            if (features.size() < inputSize) {
                // padding بالأصفار إذا كان أصغر
                inputData.resize(inputSize, 0.0f);
            }
            else if (features.size() > inputSize) {
                // قطع إذا كان أكبر
                inputData.resize(inputSize);
            }

            // 2. إنشاء tensor
            Ort::Value inputTensor = Ort::Value::CreateTensor<float>(
                memoryInfo,
                inputData.data(),
                inputData.size(),
                inputShape.data(),
                inputShape.size()
            );

            // 3. تشغيل الاستنتاج
            const char* inputNames[] = { inputName.c_str() };
            const char* outputNames[] = { outputName.c_str() };

            std::vector<Ort::Value> outputTensors = session->Run(
                Ort::RunOptions{ nullptr },
                inputNames, &inputTensor, 1,
                outputNames, 1
            );

            // 4. معالجة النتائج
            processOutput(outputTensors[0], result);

            auto end = std::chrono::high_resolution_clock::now();
            result.inferenceTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>
                (end - start).count();

            result.isError = false;

        }
        catch (const Ort::Exception& e) {
            result.errorMessage = std::string("ONNX Error: ") + e.what();
        }
        catch (const std::exception& e) {
            result.errorMessage = std::string("Error: ") + e.what();
        }

        return result;
    }

    // تنبؤ سريع (للملفات)
    DetectionResult predictFile(const std::string& filePath,
        const std::vector<float>& features) {
        std::cout << "[AI] Analyzing: " << filePath << "\n";
        auto result = predict(features);

        if (!result.isError) {
            displayResult(result);
        }
        else {
            std::cerr << "[ERROR] " << result.errorMessage << "\n";
        }

        return result;
    }

    // ==================== معالجة النتائج ====================

private:
    void processOutput(Ort::Value& outputTensor, DetectionResult& result) {
        // الحصول على البيانات الخام
        float* outputData = outputTensor.GetTensorMutableData<float>();
        size_t numClasses = outputTensor.GetTensorTypeAndShapeInfo().GetElementCount();

        // تطبيق Softmax إذا كانت النتيجة logits
        std::vector<float> probabilities = applySoftmax(outputData, numClasses);

        // إيجاد الأعلى
        auto maxIt = std::max_element(probabilities.begin(), probabilities.end());
        int predictedClass = std::distance(probabilities.begin(), maxIt);

        // تعبئة النتيجة
        result.malwareProbability = (predictedClass == 0) ?
            (1.0f - *maxIt) : *maxIt;
        result.confidence = *maxIt;
        result.threatClass = (predictedClass < threatClasses.size()) ?
            threatClasses[predictedClass] : "Unknown";

        // إعداد Top 3
        std::vector<std::pair<int, float>> indexedProbs;
        for (size_t i = 0; i < probabilities.size(); i++) {
            indexedProbs.push_back({ i, probabilities[i] });
        }

        std::sort(indexedProbs.begin(), indexedProbs.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

        for (size_t i = 0; i < std::min(size_t(3), indexedProbs.size()); i++) {
            int cls = indexedProbs[i].first;
            std::string className = (cls < threatClasses.size()) ?
                threatClasses[cls] : "Unknown";
            result.topClasses.push_back({ className, indexedProbs[i].second });
        }
    }

    std::vector<float> applySoftmax(float* data, size_t size) {
        std::vector<float> result(size);

        // طرح الأقصى للاستقرار العددي
        float maxVal = *std::max_element(data, data + size);

        float sum = 0.0f;
        for (size_t i = 0; i < size; i++) {
            result[i] = std::exp(data[i] - maxVal);
            sum += result[i];
        }

        for (auto& val : result) {
            val /= sum;
        }

        return result;
    }

    // ==================== واجهة المستخدم ====================

public:
    void displayResult(const DetectionResult& result) {
        std::cout << "\n=== AI ANALYSIS RESULT ===\n";

        // شريط التقدم البصري
        int barWidth = 30;
        int pos = static_cast<int>(barWidth * result.confidence);

        std::cout << "Confidence: [";
        for (int i = 0; i < barWidth; ++i) {
            if (i < pos) std::cout << "=";
            else if (i == pos) std::cout << ">";
            else std::cout << " ";
        }
        std::cout << "] " << std::fixed << std::setprecision(1)
            << (result.confidence * 100.0f) << "%\n";

        // النتيجة الرئيسية
        std::cout << "Classification: ";
        if (result.threatClass == "Benign") {
            std::cout << "✅ CLEAN (Benign)\n";
        }
        else {
            std::cout << "⚠️  THREAT DETECTED: " << result.threatClass << "\n";
        }

        // أفضل 3 تخمينات
        std::cout << "Top Predictions:\n";
        for (size_t i = 0; i < result.topClasses.size(); i++) {
            std::cout << "  " << (i + 1) << ". "
                << std::left << std::setw(12) << result.topClasses[i].first
                << " (" << std::fixed << std::setprecision(2)
                << (result.topClasses[i].second * 100) << "%)\n";
        }

        std::cout << "Inference Time: " << result.inferenceTimeMs << " ms\n";
        std::cout << "==========================\n";
    }

    // ==================== أدوات مساعدة ====================

public:
    bool isReady() const {
        return isInitialized;
    }

    std::string getModelInfo() const {
        std::stringstream ss;
        ss << "Model: " << modelPath << "\n";
        ss << "Input Size: " << inputSize << " features\n";
        ss << "Classes: " << outputSize << "\n";
        return ss.str();
    }

    // تحديث النموذج في الوقت الفعلي
    bool reloadModel(const std::string& newModelPath) {
        try {
            std::cout << "[INFO] Reloading model: " << newModelPath << "\n";
            modelPath = newModelPath;
            loadModel();
            return true;
        }
        catch (...) {
            std::cerr << "[ERROR] Failed to reload model\n";
            return false;
        }
    }

    // ==================== التعلم التكيفي (اختياري) ====================

    void logFeedback(const std::string& fileHash,
        bool wasTruePositive,
        const std::string& correctClass) {
        // تسجيل الأخطاء لتحسين النموذج لاحقاً
        std::ofstream feedback("ai_feedback.log", std::ios::app);
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);

        feedback << std::ctime(&time);
        feedback << "Hash: " << fileHash << "\n";
        feedback << "Result: " << (wasTruePositive ? "Correct" : "False Positive") << "\n";
        if (!correctClass.empty()) {
            feedback << "Correct Class: " << correctClass << "\n";
        }
        feedback << "------------------------\n";

        feedback.close();
    }

    // ==================== وضعيات التحليل ====================

    // تحليل سريع (دقة أقل، سرعة أعلى)
    DetectionResult quickScan(const std::vector<float>& features) {
        // استخدام عينة من الميزات فقط
        std::vector<float> sampled;
        for (size_t i = 0; i < features.size(); i += 2) {
            sampled.push_back(features[i]);
        }
        return predict(sampled);
    }

    // تحليل عميق (دقة أعلى، بطيء)
    DetectionResult deepScan(const std::vector<float>& features) {
        // تشغيل تحليل متعدد الزوايا
        auto result1 = predict(features);

        // تغيير ترتيب الميزات قليلاً (data augmentation)
        std::vector<float> augmented = features;
        std::rotate(augmented.begin(), augmented.begin() + 10, augmented.end());
        auto result2 = predict(augmented);

        // دمج النتائج
        if (result1.confidence > result2.confidence) {
            return result1;
        }
        return result2;
    }
};

// ==================== نقطة الاختبار ====================

#ifdef TEST_AI
int main() {
    std::cout << "AI Antivirus - Detector Test\n\n";

    // البحث عن نموذج
    std::string modelPath = "model.onnx";
    if (!std::ifstream(modelPath)) {
        std::cerr << "[ERROR] Model not found: " << modelPath << "\n";
        std::cerr << "Please place 'model.onnx' in the application directory.\n";

        // إنشاء بيانات اختبار وهمية
        std::cout << "\nRunning in simulation mode...\n";

        // محاكاة نتيجة
        std::cout << "\n=== SIMULATED AI ANALYSIS ===\n";
        std::cout << "Classification: ⚠️  THREAT DETECTED: Trojan\n";
        std::cout << "Confidence: 87.5%\n";
        std::cout << "Inference Time: 45 ms\n";

        return 0;
    }

    AIDetector detector(modelPath);

    if (!detector.isReady()) {
        std::cerr << "Failed to initialize detector\n";
        return 1;
    }

    std::cout << detector.getModelInfo() << "\n";

    // إنشاء بيانات اختبار عشوائية
    std::vector<float> testFeatures(280);
    std::generate(testFeatures.begin(), testFeatures.end(), []() {
        return static_cast<float>(rand()) / RAND_MAX;
        });

    // اختبار التنبؤ
    auto result = detector.predict(testFeatures);

    if (!result.isError) {
        detector.displayResult(result);
    }

    return 0;
}
#endif