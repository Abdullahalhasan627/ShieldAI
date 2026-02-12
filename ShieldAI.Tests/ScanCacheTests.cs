// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Tests/ScanCacheTests.cs
// اختبارات كاش الفحص: cache hit, invalidation, TTL, bounded size
// =====================================================

using ShieldAI.Core.Detection.ThreatScoring;
using ShieldAI.Core.Scanning;
using Xunit;

namespace ShieldAI.Tests
{
    public class ScanCacheTests
    {
        private static AggregatedThreatResult MakeResult(int score, AggregatedVerdict verdict)
        {
            return new AggregatedThreatResult
            {
                FilePath = "test.exe",
                RiskScore = score,
                Verdict = verdict,
                Reasons = new List<string> { "test reason" },
                EngineResults = new List<ThreatScanResult>
                {
                    new() { EngineName = "TestEngine", Score = score, Verdict = EngineVerdict.Malicious }
                }
            };
        }

        [Fact]
        public void CachedResult_Should_Be_Returned()
        {
            var cache = new ScanCache(TimeSpan.FromMinutes(30));
            var sha = "abc123";
            long size = 1024;
            var lwt = DateTime.UtcNow;

            var original = MakeResult(85, AggregatedVerdict.Block);
            cache.Store(sha, size, lwt, original);

            var found = cache.TryGet(sha, size, lwt, out var cached);

            Assert.True(found);
            Assert.NotNull(cached);
            Assert.Equal(85, cached!.RiskScore);
            Assert.Equal(AggregatedVerdict.Block, cached.Verdict);
        }

        [Fact]
        public void Different_LastWriteTime_Should_Miss_Cache()
        {
            var cache = new ScanCache(TimeSpan.FromMinutes(30));
            var sha = "abc123";
            long size = 1024;
            var lwt = DateTime.UtcNow;

            cache.Store(sha, size, lwt, MakeResult(85, AggregatedVerdict.Block));

            var found = cache.TryGet(sha, size, lwt.AddSeconds(1), out var cached);

            Assert.False(found);
            Assert.Null(cached);
        }

        [Fact]
        public void Different_FileSize_Should_Miss_Cache()
        {
            var cache = new ScanCache(TimeSpan.FromMinutes(30));
            var sha = "abc123";
            var lwt = DateTime.UtcNow;

            cache.Store(sha, 1024, lwt, MakeResult(85, AggregatedVerdict.Block));

            var found = cache.TryGet(sha, 2048, lwt, out _);

            Assert.False(found);
        }

        [Fact]
        public void Expired_Entry_Should_Miss_Cache()
        {
            var cache = new ScanCache(TimeSpan.FromMilliseconds(1));
            var sha = "abc123";
            long size = 1024;
            var lwt = DateTime.UtcNow;

            cache.Store(sha, size, lwt, MakeResult(85, AggregatedVerdict.Block));

            Thread.Sleep(50);

            var found = cache.TryGet(sha, size, lwt, out _);
            Assert.False(found);
        }

        [Fact]
        public void Bounded_Cache_Should_Trim_Oldest()
        {
            var cache = new ScanCache(TimeSpan.FromMinutes(30), maxEntries: 3);
            var lwt = DateTime.UtcNow;

            cache.Store("sha1", 100, lwt, MakeResult(10, AggregatedVerdict.Allow));
            cache.Store("sha2", 200, lwt, MakeResult(20, AggregatedVerdict.Allow));
            cache.Store("sha3", 300, lwt, MakeResult(30, AggregatedVerdict.Allow));
            cache.Store("sha4", 400, lwt, MakeResult(40, AggregatedVerdict.Allow));

            // sha1 should have been trimmed
            Assert.False(cache.TryGet("sha1", 100, lwt, out _));
            // sha4 should still be present
            Assert.True(cache.TryGet("sha4", 400, lwt, out _));
        }

        [Fact]
        public void CachedResult_Should_Be_Clone_Not_Reference()
        {
            var cache = new ScanCache(TimeSpan.FromMinutes(30));
            var sha = "abc123";
            long size = 1024;
            var lwt = DateTime.UtcNow;

            var original = MakeResult(85, AggregatedVerdict.Block);
            cache.Store(sha, size, lwt, original);

            cache.TryGet(sha, size, lwt, out var cached);

            // Mutate the cached copy
            cached!.RiskScore = 0;
            cached.Reasons.Clear();

            // Re-fetch: original stored value should be unaffected
            cache.TryGet(sha, size, lwt, out var cached2);
            Assert.Equal(85, cached2!.RiskScore);
            Assert.NotEmpty(cached2.Reasons);
        }
    }
}
