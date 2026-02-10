// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Core/Scanning/ScanCache.cs
// كاش نتائج الفحص لتقليل إعادة الفحص
// =====================================================

using System.Collections.Concurrent;
using ShieldAI.Core.Detection.ThreatScoring;

namespace ShieldAI.Core.Scanning
{
    /// <summary>
    /// كاش نتائج الفحص - يعتمد على (SHA256, FileSize, LastWriteTimeUtc)
    /// </summary>
    public class ScanCache
    {
        private readonly ConcurrentDictionary<string, CacheEntry> _entries = new();
        private readonly TimeSpan _ttl;

        public ScanCache(TimeSpan? ttl = null)
        {
            _ttl = ttl ?? TimeSpan.FromMinutes(30);
        }

        public bool TryGet(string sha256, long fileSize, DateTime lastWriteUtc, out AggregatedThreatResult? result)
        {
            result = null;
            var key = BuildKey(sha256, fileSize, lastWriteUtc);
            if (!_entries.TryGetValue(key, out var entry))
                return false;

            if (DateTime.UtcNow - entry.TimestampUtc > _ttl)
            {
                _entries.TryRemove(key, out _);
                return false;
            }

            result = entry.CloneResult();
            return true;
        }

        public void Store(string sha256, long fileSize, DateTime lastWriteUtc, AggregatedThreatResult result)
        {
            var key = BuildKey(sha256, fileSize, lastWriteUtc);
            _entries[key] = new CacheEntry(result);
        }

        public void ClearExpired()
        {
            foreach (var kvp in _entries)
            {
                if (DateTime.UtcNow - kvp.Value.TimestampUtc > _ttl)
                    _entries.TryRemove(kvp.Key, out _);
            }
        }

        private static string BuildKey(string sha256, long fileSize, DateTime lastWriteUtc)
        {
            return $"{sha256}:{fileSize}:{lastWriteUtc.Ticks}";
        }

        private sealed class CacheEntry
        {
            public CacheEntry(AggregatedThreatResult result)
            {
                Result = result;
                TimestampUtc = DateTime.UtcNow;
            }

            public AggregatedThreatResult Result { get; }
            public DateTime TimestampUtc { get; }

            public AggregatedThreatResult CloneResult()
            {
                return new AggregatedThreatResult
                {
                    FilePath = Result.FilePath,
                    RiskScore = Result.RiskScore,
                    Verdict = Result.Verdict,
                    Reasons = new List<string>(Result.Reasons),
                    EngineResults = Result.EngineResults
                        .Select(r => new ThreatScanResult
                        {
                            EngineName = r.EngineName,
                            Score = r.Score,
                            Verdict = r.Verdict,
                            Reasons = new List<string>(r.Reasons),
                            Confidence = r.Confidence,
                            Metadata = new Dictionary<string, object>(r.Metadata),
                            HasError = r.HasError,
                            ErrorMessage = r.ErrorMessage
                        }).ToList(),
                    ScannedAt = DateTime.Now,
                    Duration = TimeSpan.Zero
                };
            }
        }
    }
}
