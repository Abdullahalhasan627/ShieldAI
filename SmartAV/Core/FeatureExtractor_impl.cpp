/**
 * FeatureExtractor_impl.cpp - Feature Extraction Implementation
 */

#include "FeatureExtractor.h"
#include <fstream>
#include <algorithm>
#include <cmath>
#include <numeric>
#include <iomanip>
#include <sstream>

namespace AIAntivirus {

    // Static member initialization
    const std::set<std::string> FeatureExtractor::s_suspiciousKeywords = {};
    const std::set<std::string> FeatureExtractor::s_apiBlacklist = {};

    FeatureExtractor& FeatureExtractor::GetInstance() {
        static FeatureExtractor instance;
        return instance;
    }

    bool FeatureExtractor::Initialize(const ExtractionConfig& config) {
        m_config = config;
        m_isInitialized = true;
        return true;
    }

    void FeatureExtractor::Shutdown() {
        m_isInitialized = false;
    }

    FeatureVector FeatureExtractor::ExtractFromFile(const std::wstring& filePath) {
        FeatureVector result;
        result.isValid = false;
        result.type = FeatureType::PE_STATIC;
        result.originalFeatureCount = 0;

        if (!m_isInitialized) {
            result.errorMessage = "Extractor not initialized";
            return result;
        }

        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open()) {
                result.errorMessage = "Failed to open file";
                return result;
            }

            // Read file content
            std::vector<uint8_t> content((std::istreambuf_iterator<char>(file)),
                                          std::istreambuf_iterator<char>());
            file.close();

            if (content.empty()) {
                result.errorMessage = "Empty file";
                return result;
            }

            // Extract features
            result.data.reserve(m_config.vectorSize);

            // 1. Byte histogram (256 values normalized)
            std::vector<float> histogram(256, 0.0f);
            for (uint8_t byte : content) {
                histogram[byte]++;
            }
            for (float& h : histogram) {
                h /= content.size();
            }
            result.data.insert(result.data.end(), histogram.begin(), histogram.end());

            // 2. Entropy calculation
            float entropy = 0.0f;
            for (float h : histogram) {
                if (h > 0) {
                    entropy -= h * std::log2(h);
                }
            }
            result.data.push_back(entropy / 8.0f); // Normalize to 0-1

            // 3. File size features
            result.data.push_back(static_cast<float>(content.size()) / (1024.0f * 1024.0f)); // MB

            // 4. PE header detection
            bool isPE = content.size() > 64 && content[0] == 'M' && content[1] == 'Z';
            result.data.push_back(isPE ? 1.0f : 0.0f);

            // Pad to required size
            while (result.data.size() < m_config.vectorSize) {
                result.data.push_back(0.0f);
            }
            
            result.originalFeatureCount = result.data.size();

            result.isValid = true;
        }
        catch (const std::exception& e) {
            result.errorMessage = e.what();
        }

        return result;
    }

    FeatureVector FeatureExtractor::ExtractFromMemory(const std::vector<uint8_t>& data) {
        FeatureVector result;
        result.isValid = false;
        result.type = FeatureType::MEMORY_DUMP;

        if (data.empty()) {
            result.errorMessage = "Empty data";
            return result;
        }

        // Simple entropy-based features
        std::vector<float> histogram(256, 0.0f);
        for (uint8_t byte : data) {
            histogram[byte]++;
        }
        for (float& h : histogram) {
            h /= data.size();
        }

        result.data = histogram;
        result.isValid = true;
        return result;
    }

    FeatureVector FeatureExtractor::ExtractFromProcess(DWORD processId) {
        FeatureVector result;
        result.isValid = false;
        result.type = FeatureType::BEHAVIORAL;
        result.errorMessage = "Process extraction not implemented";
        return result;
    }

    float FeatureExtractor::CalculateEntropy(const std::vector<uint8_t>& data) {
        if (data.empty()) return 0.0f;

        std::vector<int> freq(256, 0);
        for (uint8_t byte : data) {
            freq[byte]++;
        }

        float entropy = 0.0f;
        float size = static_cast<float>(data.size());
        for (int f : freq) {
            if (f > 0) {
                float p = f / size;
                entropy -= p * std::log2(p);
            }
        }
        return entropy;
    }

} // namespace AIAntivirus
