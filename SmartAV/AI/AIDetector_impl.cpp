/**
 * AIDetector_impl.cpp - AI Detection with ONNX Runtime
 */

#include "AIDetector.h"
#include <fstream>
#include <filesystem>
#include <cmath>
#include <algorithm>
#include <numeric>

// Try to load ONNX Runtime dynamically
#ifdef ONNX_RUNTIME_AVAILABLE
#include <onnxruntime_cxx_api.h>
#endif

namespace fs = std::filesystem;

namespace AIAntivirus {

    AIDetector& AIDetector::GetInstance() {
        static AIDetector instance;
        return instance;
    }

    bool AIDetector::Initialize(const DetectorConfig& config) {
        m_config = config;
        m_modelLoaded = false;

        // Check if model file exists
        if (fs::exists(config.modelPath)) {
            // TODO: Load ONNX model when ONNX Runtime is available
            // For now, use heuristic fallback
            m_modelLoaded = false; // Will use heuristic mode
        }

        m_isInitialized = true;
        return true;
    }

    void AIDetector::Shutdown() {
        // Cleanup ONNX Runtime resources
        m_ortSession = nullptr;
        m_ortEnv = nullptr;
        m_ortMemoryInfo = nullptr;
        m_modelLoaded = false;
        m_isInitialized = false;
    }

    AIDetectionResult AIDetector::Detect(const std::vector<float>& featureVector) {
        AIDetectionResult result;
        result.isValid = false;

        if (!m_isInitialized || featureVector.empty()) {
            result.details = "Detector not initialized or empty features";
            return result;
        }

        // If ONNX model is loaded, use it
        if (m_modelLoaded) {
            // TODO: Run ONNX inference
            // This requires linking with ONNX Runtime library
        }

        // Fallback: Advanced heuristic scoring
        result.isValid = true;
        
        // 1. Entropy analysis (first 256 features are byte histogram)
        float entropy = 0.0f;
        if (featureVector.size() >= 256) {
            for (size_t i = 0; i < 256; i++) {
                if (featureVector[i] > 0) {
                    entropy -= featureVector[i] * std::log2(featureVector[i]);
                }
            }
        }
        float entropyScore = entropy / 8.0f; // Normalize to 0-1
        
        // High entropy (>7.0) is suspicious (packed/encrypted)
        float entropyWeight = 0.0f;
        if (entropy > 7.5f) entropyWeight = 0.8f;
        else if (entropy > 7.0f) entropyWeight = 0.5f;
        else if (entropy > 6.5f) entropyWeight = 0.3f;
        else if (entropy < 4.0f) entropyWeight = 0.2f; // Very low entropy also suspicious
        
        // 2. Byte distribution analysis
        float uniformityScore = 0.0f;
        if (featureVector.size() >= 256) {
            float expected = 1.0f / 256.0f;
            float deviation = 0.0f;
            for (size_t i = 0; i < 256; i++) {
                deviation += std::abs(featureVector[i] - expected);
            }
            uniformityScore = deviation / 2.0f; // High uniformity = suspicious
        }

        // 3. Null byte ratio (malware often has unusual null patterns)
        float nullRatio = (featureVector.size() > 0) ? featureVector[0] : 0.0f;
        float nullWeight = (nullRatio > 0.3f || nullRatio < 0.01f) ? 0.3f : 0.0f;

        // 4. Non-printable character ratio
        float nonPrintableRatio = 0.0f;
        if (featureVector.size() >= 256) {
            for (size_t i = 0; i < 32; i++) nonPrintableRatio += featureVector[i];
            for (size_t i = 127; i < 256; i++) nonPrintableRatio += featureVector[i];
        }
        float nonPrintableWeight = nonPrintableRatio > 0.5f ? 0.4f : nonPrintableRatio * 0.5f;

        // 5. Feature vector statistics
        float mean = 0.0f, variance = 0.0f;
        for (float f : featureVector) mean += f;
        mean /= featureVector.size();
        for (float f : featureVector) variance += (f - mean) * (f - mean);
        variance /= featureVector.size();
        
        // Combine scores with weights
        result.maliciousScore = std::min(1.0f,
            entropyWeight * 0.35f +
            uniformityScore * 0.25f +
            nullWeight * 0.15f +
            nonPrintableWeight * 0.25f
        );

        result.cleanScore = 1.0f - result.maliciousScore;
        
        if (result.maliciousScore >= 0.8f) {
            result.predictedClass = "Malicious";
            result.details = "High-confidence malware detection";
        } else if (result.maliciousScore >= 0.6f) {
            result.predictedClass = "Suspicious";
            result.details = "Potentially unwanted or suspicious file";
        } else if (result.maliciousScore >= 0.4f) {
            result.predictedClass = "LowRisk";
            result.details = "Low risk, monitoring recommended";
        } else {
            result.predictedClass = "Clean";
            result.details = "No threats detected";
        }

        return result;
    }

    bool AIDetector::IsMalicious(const std::vector<float>& featureVector, float* confidence) {
        auto result = Detect(featureVector);
        if (confidence) *confidence = result.maliciousScore;
        return result.maliciousScore >= m_config.detectionThreshold;
    }

    float AIDetector::GetMalwareScore(const std::vector<float>& featureVector) {
        auto result = Detect(featureVector);
        return result.maliciousScore;
    }

} // namespace AIAntivirus
