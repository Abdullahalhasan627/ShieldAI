// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Tests/ThreatAggregatorTests.cs
// اختبارات ThreatAggregator ومنطق التجميع
// =====================================================

using ShieldAI.Core.Detection;
using ShieldAI.Core.Detection.ThreatScoring;
using Xunit;

namespace ShieldAI.Tests
{
    public class ThreatAggregatorTests
    {
        #region Weighted Score Tests

        [Fact]
        public void CalculateWeightedScore_AllClean_ShouldReturnZero()
        {
            // Arrange
            var aggregator = ThreatAggregator.CreateDefault();
            var results = new[]
            {
                ThreatScanResult.Clean("SignatureEngine"),
                ThreatScanResult.Clean("HeuristicEngine"),
                ThreatScanResult.Clean("MlEngine"),
                ThreatScanResult.Clean("ReputationEngine")
            };

            // Act
            var score = aggregator.CalculateWeightedScore(results);

            // Assert
            Assert.Equal(0, score);
        }

        [Fact]
        public void CalculateWeightedScore_SingleHighScore_ShouldReflectWeight()
        {
            // Arrange
            var aggregator = ThreatAggregator.CreateDefault();
            var results = new[]
            {
                new ThreatScanResult { EngineName = "SignatureEngine", Score = 90, Confidence = 0.95 },
                ThreatScanResult.Clean("HeuristicEngine"),
                ThreatScanResult.Clean("MlEngine"),
                ThreatScanResult.Clean("ReputationEngine")
            };

            // Act
            var score = aggregator.CalculateWeightedScore(results);

            // Assert
            Assert.True(score > 0, "Score should be positive when one engine detects a threat");
            Assert.True(score < 90, "Score should be less than raw score due to averaging");
        }

        [Fact]
        public void CalculateWeightedScore_AllHighScores_ShouldBeHigh()
        {
            // Arrange
            var aggregator = ThreatAggregator.CreateDefault();
            var results = new[]
            {
                new ThreatScanResult { EngineName = "SignatureEngine", Score = 95, Confidence = 0.95 },
                new ThreatScanResult { EngineName = "HeuristicEngine", Score = 80, Confidence = 0.75 },
                new ThreatScanResult { EngineName = "MlEngine", Score = 85, Confidence = 0.8 },
                new ThreatScanResult { EngineName = "ReputationEngine", Score = 60, Confidence = 0.5 }
            };

            // Act
            var score = aggregator.CalculateWeightedScore(results);

            // Assert
            Assert.True(score >= 70, $"Score should be high when all engines detect threats, got {score}");
        }

        [Fact]
        public void CalculateWeightedScore_ErrorResults_ShouldBeIgnored()
        {
            // Arrange
            var aggregator = ThreatAggregator.CreateDefault();
            var results = new[]
            {
                new ThreatScanResult { EngineName = "SignatureEngine", Score = 90, Confidence = 0.95 },
                ThreatScanResult.Error("HeuristicEngine", "test error"),
                ThreatScanResult.Error("MlEngine", "test error"),
                ThreatScanResult.Clean("ReputationEngine")
            };

            // Act
            var score = aggregator.CalculateWeightedScore(results);

            // Assert - only SignatureEngine and ReputationEngine should count
            Assert.True(score > 0);
        }

        [Fact]
        public void CalculateWeightedScore_ClampedTo100()
        {
            // Arrange
            var aggregator = ThreatAggregator.CreateDefault();
            var results = new[]
            {
                new ThreatScanResult { EngineName = "SignatureEngine", Score = 100, Confidence = 1.0 },
                new ThreatScanResult { EngineName = "HeuristicEngine", Score = 100, Confidence = 1.0 },
                new ThreatScanResult { EngineName = "MlEngine", Score = 100, Confidence = 1.0 },
                new ThreatScanResult { EngineName = "ReputationEngine", Score = 100, Confidence = 1.0 }
            };

            // Act
            var score = aggregator.CalculateWeightedScore(results);

            // Assert
            Assert.True(score <= 100);
        }

        [Fact]
        public void CalculateWeightedScore_EmptyResults_ShouldReturnZero()
        {
            // Arrange
            var aggregator = ThreatAggregator.CreateDefault();
            var results = Array.Empty<ThreatScanResult>();

            // Act
            var score = aggregator.CalculateWeightedScore(results);

            // Assert
            Assert.Equal(0, score);
        }

        #endregion

        #region Verdict Tests

        [Fact]
        public void DetermineVerdict_HighScore_ShouldBlock()
        {
            // Arrange
            var aggregator = ThreatAggregator.CreateDefault();
            var results = new[]
            {
                new ThreatScanResult
                {
                    EngineName = "SignatureEngine",
                    Score = 95,
                    Verdict = EngineVerdict.Malicious,
                    Confidence = 0.95
                }
            };

            // Act
            var verdict = aggregator.DetermineVerdict(85, results);

            // Assert
            Assert.Equal(AggregatedVerdict.Block, verdict);
        }

        [Fact]
        public void DetermineVerdict_MediumScore_ShouldQuarantine()
        {
            // Arrange
            var aggregator = ThreatAggregator.CreateDefault();
            var results = new[]
            {
                new ThreatScanResult
                {
                    EngineName = "HeuristicEngine",
                    Score = 60,
                    Verdict = EngineVerdict.Suspicious,
                    Confidence = 0.7
                }
            };

            // Act
            var verdict = aggregator.DetermineVerdict(60, results);

            // Assert
            Assert.Equal(AggregatedVerdict.Quarantine, verdict);
        }

        [Fact]
        public void DetermineVerdict_LowScore_ShouldAllow()
        {
            // Arrange
            var aggregator = ThreatAggregator.CreateDefault();
            var results = new[]
            {
                ThreatScanResult.Clean("SignatureEngine"),
                ThreatScanResult.Clean("HeuristicEngine")
            };

            // Act
            var verdict = aggregator.DetermineVerdict(5, results);

            // Assert
            Assert.Equal(AggregatedVerdict.Allow, verdict);
        }

        [Fact]
        public void DetermineVerdict_MultipleMalicious_ShouldQuarantine()
        {
            // Arrange
            var aggregator = ThreatAggregator.CreateDefault();
            var results = new[]
            {
                new ThreatScanResult { EngineName = "SignatureEngine", Verdict = EngineVerdict.Malicious, Confidence = 0.6 },
                new ThreatScanResult { EngineName = "HeuristicEngine", Verdict = EngineVerdict.Malicious, Confidence = 0.6 }
            };

            // Act
            var verdict = aggregator.DetermineVerdict(45, results);

            // Assert
            Assert.Equal(AggregatedVerdict.Quarantine, verdict);
        }

        [Fact]
        public void DetermineVerdict_HighConfidenceMalicious_ShouldBlock()
        {
            // Arrange
            var aggregator = ThreatAggregator.CreateDefault();
            var results = new[]
            {
                new ThreatScanResult
                {
                    EngineName = "SignatureEngine",
                    Verdict = EngineVerdict.Malicious,
                    Confidence = 0.95
                }
            };

            // Act - even with low score, high confidence malicious should block
            var verdict = aggregator.DetermineVerdict(30, results);

            // Assert
            Assert.Equal(AggregatedVerdict.Block, verdict);
        }

        [Fact]
        public void DetermineVerdict_Suspicious_ShouldNeedReview()
        {
            // Arrange
            var aggregator = ThreatAggregator.CreateDefault();
            var results = new[]
            {
                new ThreatScanResult { EngineName = "HeuristicEngine", Verdict = EngineVerdict.Suspicious, Confidence = 0.5 }
            };

            // Act
            var verdict = aggregator.DetermineVerdict(25, results);

            // Assert
            Assert.Equal(AggregatedVerdict.NeedsReview, verdict);
        }

        #endregion

        #region Custom Weights Tests

        [Fact]
        public void CustomWeights_ShouldAffectScore()
        {
            // Arrange - give signature engine very high weight, others zero
            var highSigWeights = new EngineWeights
            {
                SignatureEngine = 1.0,
                HeuristicEngine = 0.0,
                MlEngine = 0.0,
                ReputationEngine = 0.0
            };

            var lowSigWeights = new EngineWeights
            {
                SignatureEngine = 0.1,
                HeuristicEngine = 1.0,
                MlEngine = 1.0,
                ReputationEngine = 1.0
            };

            var aggHigh = ThreatAggregator.CreateDefault(weights: highSigWeights);
            var aggLow = ThreatAggregator.CreateDefault(weights: lowSigWeights);

            var results = new[]
            {
                new ThreatScanResult { EngineName = "SignatureEngine", Score = 90, Confidence = 1.0 },
                new ThreatScanResult { EngineName = "HeuristicEngine", Score = 10, Confidence = 1.0 },
                new ThreatScanResult { EngineName = "MlEngine", Score = 10, Confidence = 1.0 },
                new ThreatScanResult { EngineName = "ReputationEngine", Score = 10, Confidence = 1.0 }
            };

            // Act
            var scoreHigh = aggHigh.CalculateWeightedScore(results);
            var scoreLow = aggLow.CalculateWeightedScore(results);

            // Assert - high signature weight should produce higher score
            Assert.True(scoreHigh > scoreLow,
                $"High sig weight score ({scoreHigh}) should be > low sig weight score ({scoreLow})");
        }

        #endregion

        #region Custom Thresholds Tests

        [Fact]
        public void CustomThresholds_ShouldAffectVerdict()
        {
            // Arrange
            var aggregator = ThreatAggregator.CreateDefault();
            aggregator.BlockThreshold = 90;
            aggregator.QuarantineThreshold = 70;
            aggregator.ReviewThreshold = 50;

            var results = new[]
            {
                new ThreatScanResult { EngineName = "HeuristicEngine", Verdict = EngineVerdict.Suspicious, Confidence = 0.5 }
            };

            // Act - score 60 is below quarantine (70) but above review (50)
            var verdict = aggregator.DetermineVerdict(60, results);

            // Assert
            Assert.Equal(AggregatedVerdict.NeedsReview, verdict);
        }

        #endregion

        #region Integration Tests

        [Fact]
        public async Task ScanAsync_NonExistentFile_ShouldReturnResult()
        {
            // Arrange
            var aggregator = ThreatAggregator.CreateDefault();
            var fakePath = Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.exe");

            // Act
            var result = await aggregator.ScanAsync(fakePath);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(fakePath, result.FilePath);
        }

        [Fact]
        public async Task ScanAsync_CleanTextFile_ShouldAllow()
        {
            // Arrange
            var aggregator = ThreatAggregator.CreateDefault();
            var tempFile = Path.GetTempFileName();
            File.WriteAllText(tempFile, "This is a clean text file with normal content.");

            try
            {
                // Act
                var result = await aggregator.ScanAsync(tempFile);

                // Assert
                Assert.NotNull(result);
                Assert.True(result.RiskScore < 50, $"Clean text file should have low risk, got {result.RiskScore}");
                Assert.True(result.EngineResults.Count > 0, "Should have engine results");
            }
            finally
            {
                File.Delete(tempFile);
            }
        }

        [Fact]
        public async Task ScanAsync_ShouldCollectReasons()
        {
            // Arrange
            var aggregator = ThreatAggregator.CreateDefault();
            var tempFile = Path.GetTempFileName();
            File.WriteAllText(tempFile, "test content");

            try
            {
                // Act
                var result = await aggregator.ScanAsync(tempFile);

                // Assert
                Assert.NotNull(result);
                Assert.NotNull(result.Reasons);
                Assert.True(result.Duration.TotalMilliseconds >= 0);
            }
            finally
            {
                File.Delete(tempFile);
            }
        }

        #endregion
    }
}
