// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Tests/ThreatActionExecutorTests.cs
// اختبارات منفّذ إجراءات التهديد
// =====================================================

using ShieldAI.Core.Configuration;
using ShieldAI.Core.Contracts;
using ShieldAI.Core.Detection;
using ShieldAI.Core.Detection.ThreatScoring;
using ShieldAI.Core.Monitoring.Quarantine;
using Xunit;

namespace ShieldAI.Tests
{
    public class ThreatActionExecutorTests : IDisposable
    {
        private readonly string _testDir;
        private readonly string _quarantineDir;
        private readonly QuarantineStore _store;
        private readonly AppSettings _settings;

        public ThreatActionExecutorTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), $"ShieldAI_Exec_{Guid.NewGuid():N}");
            _quarantineDir = Path.Combine(_testDir, "Quarantine");
            Directory.CreateDirectory(_testDir);
            _store = new QuarantineStore(_quarantineDir);
            _settings = new AppSettings
            {
                AutoQuarantine = true,
                RealTimeActionMode = "AutoQuarantine",
                AskUserMinScore = 55,
                AutoQuarantineMinScore = 80,
                AtomicMoveMaxRetries = 2,
                AtomicMoveInitialDelayMs = 10,
                AtomicMoveMaxDelayMs = 50
            };
        }

        public void Dispose()
        {
            _store.Dispose();
            try { if (Directory.Exists(_testDir)) Directory.Delete(_testDir, true); } catch { }
        }

        private (AggregatedThreatResult result, ThreatScanContext context) CreateThreat(
            string fileName, int score, AggregatedVerdict verdict)
        {
            var filePath = Path.Combine(_testDir, fileName);
            File.WriteAllText(filePath, "malicious content");

            var context = new ThreatScanContext
            {
                FilePath = filePath,
                FileSize = new FileInfo(filePath).Length,
                Sha256Hash = $"fakehash_{fileName}"
            };

            var result = new AggregatedThreatResult
            {
                FilePath = filePath,
                RiskScore = score,
                Verdict = verdict,
                Reasons = new List<string> { "Test threat" },
                EngineResults = new List<ThreatScanResult>
                {
                    new()
                    {
                        EngineName = "TestEngine",
                        Score = score,
                        Verdict = score >= 80 ? EngineVerdict.Malicious : EngineVerdict.Suspicious,
                        Confidence = score >= 95 ? 1.0 : 0.7
                    }
                }
            };

            return (result, context);
        }

        [Fact]
        public async Task AutoQuarantine_ShouldQuarantineBlockVerdict()
        {
            _settings.RealTimeActionMode = "AutoQuarantine";
            var executor = new ThreatActionExecutor(_store, _settings);
            var (result, context) = CreateThreat("block_me.exe", 90, AggregatedVerdict.Block);

            var dto = await executor.ApplyActionAsync(result, context);

            Assert.True(dto.ActionTaken);
            Assert.Equal("Quarantined", dto.ActionResult);
            Assert.False(File.Exists(context.FilePath));
        }

        [Fact]
        public async Task AutoQuarantine_ShouldNotActOnAllowVerdict()
        {
            _settings.RealTimeActionMode = "AutoQuarantine";
            var executor = new ThreatActionExecutor(_store, _settings);
            var (result, context) = CreateThreat("clean.txt", 10, AggregatedVerdict.Allow);

            var dto = await executor.ApplyActionAsync(result, context);

            Assert.False(dto.ActionTaken);
            Assert.Equal("None", dto.RecommendedAction);
            Assert.True(File.Exists(context.FilePath));
        }

        [Fact]
        public async Task AskUser_HighScore_ShouldAutoQuarantine()
        {
            _settings.RealTimeActionMode = "AskUser";
            var executor = new ThreatActionExecutor(_store, _settings);
            var (result, context) = CreateThreat("definite_malware.exe", 95, AggregatedVerdict.Block);
            // Set high confidence to trigger auto-quarantine even in AskUser mode
            result.EngineResults[0].Confidence = 1.0;
            result.EngineResults[0].Score = 100;

            var dto = await executor.ApplyActionAsync(result, context);

            Assert.True(dto.ActionTaken);
            Assert.Equal("Quarantined", dto.ActionResult);
        }

        [Fact]
        public async Task AskUser_MediumScore_ShouldFireThreatActionRequired()
        {
            _settings.RealTimeActionMode = "AskUser";
            var executor = new ThreatActionExecutor(_store, _settings);
            var (result, context) = CreateThreat("suspicious.exe", 60, AggregatedVerdict.Quarantine);

            ThreatEventDto? receivedDto = null;
            executor.ThreatActionRequired += (_, dto) => receivedDto = dto;

            var dto = await executor.ApplyActionAsync(result, context);

            Assert.False(dto.ActionTaken);
            Assert.Equal("NeedsReview", dto.RecommendedAction);
            Assert.NotNull(receivedDto);
            Assert.Equal(context.FilePath, receivedDto!.FilePath);
            Assert.True(File.Exists(context.FilePath)); // File should NOT be deleted yet
        }

        [Fact]
        public async Task ResolveThreat_Delete_ShouldDeleteFile()
        {
            _settings.RealTimeActionMode = "AskUser";
            var executor = new ThreatActionExecutor(_store, _settings);
            var (result, context) = CreateThreat("to_delete.exe", 60, AggregatedVerdict.Quarantine);

            var dto = await executor.ApplyActionAsync(result, context);
            Assert.False(dto.ActionTaken);

            ThreatEventDto? appliedDto = null;
            executor.ThreatActionApplied += (_, d) => appliedDto = d;

            var response = await executor.ResolveThreatAsync(new ResolveThreatRequest
            {
                EventId = dto.EventId,
                Action = ThreatAction.Delete
            });

            Assert.True(response.Success);
            Assert.Equal("Delete", response.ActionApplied);
            Assert.NotNull(appliedDto);
            Assert.False(File.Exists(context.FilePath));
        }

        [Fact]
        public async Task ResolveThreat_Allow_ShouldAddToAllowlist()
        {
            _settings.RealTimeActionMode = "AskUser";
            _settings.Sha256Allowlist = new List<string>();
            var executor = new ThreatActionExecutor(_store, _settings);
            var (result, context) = CreateThreat("allow_me.exe", 60, AggregatedVerdict.Quarantine);

            var dto = await executor.ApplyActionAsync(result, context);

            var response = await executor.ResolveThreatAsync(new ResolveThreatRequest
            {
                EventId = dto.EventId,
                Action = ThreatAction.Allow,
                AddToExclusions = true
            });

            Assert.True(response.Success);
            Assert.Contains(context.Sha256Hash!, _settings.Sha256Allowlist);
        }

        [Fact]
        public async Task Allowlist_ShouldSkipEnforcement()
        {
            _settings.RealTimeActionMode = "AutoQuarantine";
            _settings.Sha256Allowlist = new List<string> { "allowed_hash" };
            var executor = new ThreatActionExecutor(_store, _settings);

            var filePath = Path.Combine(_testDir, "allowed.exe");
            File.WriteAllText(filePath, "allowed content");

            var context = new ThreatScanContext
            {
                FilePath = filePath,
                FileSize = new FileInfo(filePath).Length,
                Sha256Hash = "allowed_hash"
            };

            var result = new AggregatedThreatResult
            {
                FilePath = filePath,
                RiskScore = 90,
                Verdict = AggregatedVerdict.Block,
                Reasons = new List<string> { "Test" },
                EngineResults = new List<ThreatScanResult>()
            };

            var dto = await executor.ApplyActionAsync(result, context);

            Assert.True(dto.ActionTaken);
            Assert.Contains("Allowlist", dto.ActionResult!);
            Assert.True(File.Exists(filePath)); // Should NOT be quarantined
        }

        [Fact]
        public async Task ResolveThreat_InvalidEventId_ShouldFail()
        {
            var executor = new ThreatActionExecutor(_store, _settings);

            var response = await executor.ResolveThreatAsync(new ResolveThreatRequest
            {
                EventId = "nonexistent",
                Action = ThreatAction.Delete
            });

            Assert.False(response.Success);
            Assert.Contains("not found", response.Error!);
        }

        [Fact]
        public async Task GetPendingThreats_ShouldReturnPending()
        {
            _settings.RealTimeActionMode = "AskUser";
            var executor = new ThreatActionExecutor(_store, _settings);
            var (result, context) = CreateThreat("pending.exe", 60, AggregatedVerdict.Quarantine);

            await executor.ApplyActionAsync(result, context);

            var pending = executor.GetPendingThreats();
            Assert.Single(pending);
            Assert.Equal(context.FilePath, pending[0].FilePath);
        }

        [Fact]
        public async Task AutoBlock_ShouldDeleteFile()
        {
            _settings.RealTimeActionMode = "AutoBlock";
            var executor = new ThreatActionExecutor(_store, _settings);
            var (result, context) = CreateThreat("autoblock.exe", 90, AggregatedVerdict.Block);

            var dto = await executor.ApplyActionAsync(result, context);

            Assert.True(dto.ActionTaken);
            Assert.Equal("Deleted", dto.ActionResult);
            Assert.False(File.Exists(context.FilePath));
        }
    }
}
