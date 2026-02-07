#pragma once
#include <vector>
#include <string>
#include <chrono>

#ifdef ONNX_RUNTIME_AVAILABLE
#include <onnxruntime_cxx_api.h>
#endif

namespace AIAntivirus {

    struct DetectorConfig {
        std::string modelPath = "models/model.onnx";
        float detectionThreshold = 0.7f;
        bool useGPU = false;
        size_t expectedInputSize = 512;
    };

    struct AIDetectionResult {
        bool isValid = false;
        float maliciousScore = 0.0f;
        float cleanScore = 0.0f;
        std::string predictedClass;
        std::string details;
    };

    class AIDetector {
    public:
        static AIDetector& GetInstance();

        bool Initialize(const DetectorConfig& config = DetectorConfig{});
        void Shutdown();
        bool IsInitialized() const { return m_isInitialized; }

        AIDetectionResult Detect(const std::vector<float>& featureVector);
        bool IsMalicious(const std::vector<float>& featureVector, float* confidence = nullptr);
        float GetMalwareScore(const std::vector<float>& featureVector);

    private:
        AIDetector() = default;
        ~AIDetector() = default;
        AIDetector(const AIDetector&) = delete;
        AIDetector& operator=(const AIDetector&) = delete;

        DetectorConfig m_config;
        bool m_isInitialized = false;
        bool m_modelLoaded = false;
        
        // ONNX Runtime members (opaque pointers)
        void* m_ortEnv = nullptr;
        void* m_ortSession = nullptr;
        void* m_ortMemoryInfo = nullptr;
        
        std::vector<std::string> m_inputNames;
        std::vector<std::string> m_outputNames;
        std::vector<int64_t> m_inputShape;
    };

} // namespace AIAntivirus