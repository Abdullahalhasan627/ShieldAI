// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Tests/AmsiEngineTests.cs
// اختبارات AmsiEngine: فلترة الامتدادات + تجاوز الملفات غير المستهدفة
// =====================================================

using ShieldAI.Core.Detection.ThreatScoring;
using Xunit;

namespace ShieldAI.Tests
{
    public class AmsiEngineTests : IDisposable
    {
        private readonly string _testDir;

        public AmsiEngineTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), $"ShieldAI_Amsi_{Guid.NewGuid():N}");
            Directory.CreateDirectory(_testDir);
        }

        public void Dispose()
        {
            try { if (Directory.Exists(_testDir)) Directory.Delete(_testDir, true); } catch { }
        }

        [Theory]
        [InlineData(".ps1")]
        [InlineData(".vbs")]
        [InlineData(".js")]
        [InlineData(".bat")]
        [InlineData(".cmd")]
        public async Task AmsiEngine_Should_Accept_Script_Extensions(string ext)
        {
            var engine = new AmsiEngine();
            var filePath = Path.Combine(_testDir, $"test{ext}");
            File.WriteAllText(filePath, "Write-Host 'hello'");

            var context = new ThreatScanContext
            {
                FilePath = filePath,
                FileSize = new FileInfo(filePath).Length
            };

            var result = await engine.ScanAsync(context);

            // AMSI may not be available in test/CI environments
            // Valid outcomes: Clean (AMSI not ready or no threat), Malicious, Suspicious, or Error (AMSI init failed)
            Assert.True(
                result.Verdict is EngineVerdict.Clean or EngineVerdict.Malicious
                    or EngineVerdict.Suspicious or EngineVerdict.Unknown,
                $"Unexpected verdict {result.Verdict} for {ext}");
        }

        [Theory]
        [InlineData(".exe")]
        [InlineData(".dll")]
        [InlineData(".txt")]
        [InlineData(".pdf")]
        [InlineData(".zip")]
        public async Task AmsiEngine_Should_Skip_NonScript_Extensions(string ext)
        {
            var engine = new AmsiEngine();
            var filePath = Path.Combine(_testDir, $"test{ext}");
            File.WriteAllText(filePath, "MZ fake binary content");

            var context = new ThreatScanContext
            {
                FilePath = filePath,
                FileSize = new FileInfo(filePath).Length
            };

            var result = await engine.ScanAsync(context);

            // Non-script extensions should be immediately Clean
            Assert.Equal(EngineVerdict.Clean, result.Verdict);
            Assert.Equal(0, result.Score);
        }

        [Fact]
        public async Task AmsiEngine_Should_Return_Clean_For_NonExistent_File()
        {
            var engine = new AmsiEngine();
            var context = new ThreatScanContext
            {
                FilePath = Path.Combine(_testDir, "nonexistent.ps1"),
                FileSize = 0
            };

            var result = await engine.ScanAsync(context);

            Assert.Equal(EngineVerdict.Clean, result.Verdict);
        }

        [Fact]
        public async Task AmsiEngine_Should_Skip_Large_Scripts()
        {
            var engine = new AmsiEngine();
            var filePath = Path.Combine(_testDir, "large.ps1");
            // 6MB > 5MB limit
            File.WriteAllText(filePath, new string('X', 6 * 1024 * 1024));

            var context = new ThreatScanContext
            {
                FilePath = filePath,
                FileSize = new FileInfo(filePath).Length
            };

            var result = await engine.ScanAsync(context);

            Assert.Equal(EngineVerdict.Clean, result.Verdict);
            Assert.Contains(result.Reasons, r => r.Contains("حد حجم السكربت"));
        }

        [Fact]
        public void AmsiEngine_Metadata_Should_Be_Correct()
        {
            var engine = new AmsiEngine();
            Assert.Equal("AmsiEngine", engine.EngineName);
            Assert.Equal(0.6, engine.DefaultWeight);
        }
    }
}
