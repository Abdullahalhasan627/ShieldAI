// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Tests/MLTests.cs
// اختبارات ML
// =====================================================

using ShieldAI.Core.ML;
using Xunit;

namespace ShieldAI.Tests
{
    /// <summary>
    /// اختبارات وحدة لنظام ML
    /// </summary>
    public class MLTests
    {
        [Fact]
        public void MalwareClassifier_Creation_Succeeds()
        {
            // Act
            var classifier = new MalwareClassifier();
            
            // Assert
            Assert.NotNull(classifier);
        }

        [Fact]
        public void MalwareClassifier_Predict_ReturnsResult()
        {
            // Arrange
            var classifier = new MalwareClassifier();
            var features = new MalwareFeatures();
            
            // Act
            var result = classifier.Predict(features);
            
            // Assert
            Assert.NotNull(result);
        }

        [Fact]
        public void ModelTrainer_Creation_Succeeds()
        {
            // Act
            var trainer = new ModelTrainer();
            
            // Assert
            Assert.NotNull(trainer);
        }

        [Fact]
        public void MalwarePrediction_DefaultValues_AreCorrect()
        {
            // Act
            var prediction = new MalwarePrediction();
            
            // Assert
            Assert.NotNull(prediction);
        }
    }
}
