// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Tests/EicarDetectionTests.cs
// اختبارات كشف EICAR عبر SignatureEngine و ThreatAggregator
// =====================================================

using ShieldAI.Core.Detection;
using ShieldAI.Core.Detection.ThreatScoring;
using Xunit;

namespace ShieldAI.Tests
{
    public class EicarDetectionTests : IDisposable
    {
        // EICAR standard test string (safe, not a real virus)
        private const string EicarString =
            @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        // Known correct hashes
        private const string EicarSha256 =
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        private const string EicarMd5 =
            "44d88612fea8a8f36de82e1278abb02f";

        private readonly string _testDir;
        private readonly SignatureDatabase _sigDb;

        public EicarDetectionTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), $"ShieldAI_Eicar_{Guid.NewGuid():N}");
            Directory.CreateDirectory(_testDir);
            // Use in-memory DB (non-existent path triggers InitializeDefaultSignatures)
            _sigDb = new SignatureDatabase(databasePath: Path.Combine(_testDir, "sig.json"));
        }

        public void Dispose()
        {
            try { if (Directory.Exists(_testDir)) Directory.Delete(_testDir, true); } catch { }
        }

        private string CreateEicarFile(string name = "eicar.com")
        {
            var path = Path.Combine(_testDir, name);
            File.WriteAllText(path, EicarString);
            return path;
        }

        // -------------------------------------------------------
        // 1) SignatureEngine detects EICAR by SHA256 hash
        // -------------------------------------------------------
        [Fact]
        public async Task Eicar_Should_Be_Detected_By_SignatureEngine()
        {
            // Arrange
            var engine = new SignatureEngine(_sigDb);
            var eicarPath = CreateEicarFile();

            var context = new ThreatScanContext
            {
                FilePath = eicarPath,
                Sha256Hash = EicarSha256,
                Md5Hash = EicarMd5,
                FileSize = new FileInfo(eicarPath).Length
            };

            // Act
            var result = await engine.ScanAsync(context);

            // Assert
            Assert.Equal("SignatureEngine", result.EngineName);
            Assert.Equal(100, result.Score);
            Assert.Equal(1.0, result.Confidence);
            Assert.Equal(EngineVerdict.Malicious, result.Verdict);
            Assert.Contains(result.Reasons, r => r.Contains("EICAR"));
        }

        // -------------------------------------------------------
        // 2) SignatureEngine detects EICAR by MD5 hash
        // -------------------------------------------------------
        [Fact]
        public async Task Eicar_Should_Be_Detected_By_Md5()
        {
            var engine = new SignatureEngine(_sigDb);
            var eicarPath = CreateEicarFile();

            var context = new ThreatScanContext
            {
                FilePath = eicarPath,
                Sha256Hash = null,
                Md5Hash = EicarMd5,
                FileSize = new FileInfo(eicarPath).Length
            };

            var result = await engine.ScanAsync(context);

            Assert.Equal(100, result.Score);
            Assert.Equal(EngineVerdict.Malicious, result.Verdict);
        }

        // -------------------------------------------------------
        // 3) SignatureEngine detects EICAR by file content (no hash pre-computed)
        // -------------------------------------------------------
        [Fact]
        public async Task Eicar_Should_Be_Detected_By_FileContent()
        {
            var engine = new SignatureEngine(_sigDb);
            var eicarPath = CreateEicarFile();

            var context = new ThreatScanContext
            {
                FilePath = eicarPath,
                FileSize = new FileInfo(eicarPath).Length
            };

            var result = await engine.ScanAsync(context);

            Assert.Equal(100, result.Score);
            Assert.Equal(EngineVerdict.Malicious, result.Verdict);
        }

        // -------------------------------------------------------
        // 4) ThreatAggregator returns Block or Quarantine for EICAR
        // -------------------------------------------------------
        [Fact]
        public async Task Eicar_Should_Result_In_Block_Or_Quarantine_By_Aggregator()
        {
            var aggregator = ThreatAggregator.CreateDefault(_sigDb);
            var eicarPath = CreateEicarFile();

            var result = await aggregator.ScanAsync(eicarPath);

            // SignatureEngine Score=100 Confidence=1.0 → anyHighConfidenceMalicious → Block
            Assert.True(
                result.Verdict == AggregatedVerdict.Block ||
                result.Verdict == AggregatedVerdict.Quarantine,
                $"Expected Block or Quarantine but got {result.Verdict} (RiskScore={result.RiskScore})");

            Assert.True(result.RiskScore >= 80,
                $"EICAR RiskScore should be >= 80, got {result.RiskScore}");

            Assert.Contains(result.Reasons, r => r.Contains("EICAR"));
            Assert.Contains(result.EngineResults, r =>
                r.EngineName == "SignatureEngine" && r.Score == 100);
        }

        // -------------------------------------------------------
        // 5) Clean file should NOT match EICAR signature
        // -------------------------------------------------------
        [Fact]
        public async Task CleanFile_Should_Not_Match_Eicar()
        {
            var engine = new SignatureEngine(_sigDb);
            var cleanPath = Path.Combine(_testDir, "clean.txt");
            File.WriteAllText(cleanPath, "This is a perfectly clean file.");

            var context = new ThreatScanContext
            {
                FilePath = cleanPath,
                FileSize = new FileInfo(cleanPath).Length
            };

            var result = await engine.ScanAsync(context);

            Assert.Equal(0, result.Score);
            Assert.Equal(EngineVerdict.Clean, result.Verdict);
        }
    }
}
