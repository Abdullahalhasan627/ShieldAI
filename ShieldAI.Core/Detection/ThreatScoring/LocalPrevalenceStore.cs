// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Detection/ThreatScoring/LocalPrevalenceStore.cs
// تتبع مدى انتشار الملفات محلياً
// =====================================================

using System.Collections.Concurrent;
using System.Text.Json;

namespace ShieldAI.Core.Detection.ThreatScoring
{
    public class LocalPrevalenceStore
    {
        private readonly string _storePath;
        private readonly ConcurrentDictionary<string, PrevalenceEntry> _entries = new();
        private readonly object _lock = new();

        public LocalPrevalenceStore(string? storePath = null)
        {
            _storePath = storePath ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "ShieldAI", "reputation_store.json");
            Load();
        }

        public PrevalenceEntry Record(string sha256)
        {
            var now = DateTime.UtcNow;
            var entry = _entries.AddOrUpdate(sha256,
                _ => new PrevalenceEntry { FirstSeenUtc = now, LastSeenUtc = now, SeenCount = 1 },
                (_, existing) =>
                {
                    existing.LastSeenUtc = now;
                    existing.SeenCount++;
                    return existing;
                });

            Save();
            return entry;
        }

        public bool TryGet(string sha256, out PrevalenceEntry entry)
        {
            return _entries.TryGetValue(sha256, out entry!);
        }

        private void Load()
        {
            try
            {
                if (!File.Exists(_storePath))
                    return;

                var json = File.ReadAllText(_storePath);
                var data = JsonSerializer.Deserialize<Dictionary<string, PrevalenceEntry>>(json);
                if (data == null) return;

                foreach (var kvp in data)
                    _entries[kvp.Key] = kvp.Value;
            }
            catch
            {
                // ignore
            }
        }

        private void Save()
        {
            lock (_lock)
            {
                try
                {
                    var dir = Path.GetDirectoryName(_storePath);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                        Directory.CreateDirectory(dir);

                    var json = JsonSerializer.Serialize(_entries, new JsonSerializerOptions
                    {
                        WriteIndented = true
                    });
                    File.WriteAllText(_storePath, json);
                }
                catch
                {
                    // ignore
                }
            }
        }
    }

    public class PrevalenceEntry
    {
        public DateTime FirstSeenUtc { get; set; }
        public DateTime LastSeenUtc { get; set; }
        public int SeenCount { get; set; }
    }
}
