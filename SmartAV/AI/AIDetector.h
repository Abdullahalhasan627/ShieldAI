#pragma once
#include <vector>
#include <string>
#include <onnxruntime_cxx_api.h>

namespace AIAntivirus {

    struct AIDetectionResult {
        bool isMalicious;
        float confidence;
        float benignScore;
        float maliciousScore;
        std::string threatFamily;
        std::vector<std::string> indicators;
        std::chrono::system_clock::time_point timestamp;
        int64_t inferenceTimeMs;
        bool isValid;
        std::string errorMessage;
    };

    struct DetectorConfig {
        std::string modelPath = "model.onnx";
        float detectionThreshold = 0.75f;
        bool useGPU = false;
        bool useCaching = true;
    };

    class AIDetector {
    public:
        static AIDetector& GetInstance();

        bool Initialize(const DetectorConfig& config = DetectorConfig{});
        void Shutdown();

        AIDetectionResult Detect(const std::vector<float>& featureVector);
        bool IsMalicious(const std::vector<float>& featureVector, float* confidence = nullptr);
        float GetMalwareScore(const std::vector<float>& featureVector);

    private:
        AIDetector() = default;
        ~AIDetector() = default;
        // ... (Implementation details)
    };

} // namespace AIAntivirus