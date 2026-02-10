// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Detection/ThreatScoring/ReputationCache.cs
// كاش السمعة لتقليل التكرار
// =====================================================

using System.Collections.Concurrent;

namespace ShieldAI.Core.Detection.ThreatScoring
{
    public class ReputationCache
    {
        private readonly ConcurrentDictionary<string, CacheEntry> _entries = new();
        private readonly TimeSpan _ttl;

        public ReputationCache(TimeSpan? ttl = null)
        {
            _ttl = ttl ?? TimeSpan.FromMinutes(30);
        }

        public bool TryGet(string key, out ReputationResult? result)
        {
            result = null;
            if (!_entries.TryGetValue(key, out var entry))
                return false;

            if (DateTime.UtcNow - entry.TimestampUtc > _ttl)
            {
                _entries.TryRemove(key, out _);
                return false;
            }

            result = entry.Result;
            return true;
        }

        public void Store(string key, ReputationResult result)
        {
            _entries[key] = new CacheEntry(result);
        }

        private sealed class CacheEntry
        {
            public CacheEntry(ReputationResult result)
            {
                Result = result;
                TimestampUtc = DateTime.UtcNow;
            }

            public ReputationResult Result { get; }
            public DateTime TimestampUtc { get; }
        }
    }

    public class ReputationResult
    {
        public int Score { get; set; }
        public List<string> Reasons { get; set; } = new();
        public bool IsTrustedSigner { get; set; }
        public bool IsSigned { get; set; }
        public string? SignerName { get; set; }
    }
}
