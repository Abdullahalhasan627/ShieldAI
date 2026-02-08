// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Core/Monitoring/FileEventDebouncer.cs
// Debouncer للأحداث المتكررة
// =====================================================

using System.Collections.Concurrent;
using System.Timers;
using Timer = System.Timers.Timer;

namespace ShieldAI.Core.Monitoring
{
    /// <summary>
    /// Debouncer للأحداث المتكررة على نفس الملف
    /// </summary>
    public class FileEventDebouncer : IDisposable
    {
        private readonly ConcurrentDictionary<string, FileEventInfo> _pendingEvents = new();
        private readonly Timer _flushTimer;
        private readonly int _debounceMs;
        private readonly Action<string, WatcherChangeTypes> _onFileReady;
        private bool _disposed;

        public FileEventDebouncer(Action<string, WatcherChangeTypes> onFileReady, int debounceMs = 1000)
        {
            _onFileReady = onFileReady;
            _debounceMs = debounceMs;
            
            _flushTimer = new Timer(debounceMs / 2.0);
            _flushTimer.Elapsed += FlushTimer_Elapsed;
            _flushTimer.AutoReset = true;
            _flushTimer.Start();
        }

        /// <summary>
        /// إضافة حدث
        /// </summary>
        public void Add(string filePath, WatcherChangeTypes changeType)
        {
            var normalizedPath = Path.GetFullPath(filePath).ToLowerInvariant();
            
            _pendingEvents.AddOrUpdate(
                normalizedPath,
                _ => new FileEventInfo(filePath, changeType, DateTime.UtcNow),
                (_, existing) =>
                {
                    existing.LastEventTime = DateTime.UtcNow;
                    existing.ChangeType = changeType;
                    return existing;
                });
        }

        /// <summary>
        /// فحص الأحداث المنتهية
        /// </summary>
        private void FlushTimer_Elapsed(object? sender, ElapsedEventArgs e)
        {
            var now = DateTime.UtcNow;
            var cutoff = now.AddMilliseconds(-_debounceMs);

            foreach (var kvp in _pendingEvents.ToArray())
            {
                if (kvp.Value.LastEventTime <= cutoff)
                {
                    if (_pendingEvents.TryRemove(kvp.Key, out var eventInfo))
                    {
                        // التحقق من أن الملف موجود ومستقر
                        if (IsFileReady(eventInfo.FilePath))
                        {
                            try
                            {
                                _onFileReady(eventInfo.FilePath, eventInfo.ChangeType);
                            }
                            catch { }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// التحقق من أن الملف جاهز للقراءة
        /// </summary>
        private static bool IsFileReady(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return false;

                // محاولة فتح الملف للتأكد من أنه ليس مقفلاً
                using var stream = new FileStream(
                    filePath, 
                    FileMode.Open, 
                    FileAccess.Read, 
                    FileShare.ReadWrite);
                
                return stream.Length > 0;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// إلغاء جميع الأحداث المعلقة
        /// </summary>
        public void Clear()
        {
            _pendingEvents.Clear();
        }

        public void Dispose()
        {
            if (_disposed) return;
            
            _flushTimer.Stop();
            _flushTimer.Dispose();
            _pendingEvents.Clear();
            
            _disposed = true;
        }

        private class FileEventInfo
        {
            public string FilePath { get; }
            public WatcherChangeTypes ChangeType { get; set; }
            public DateTime LastEventTime { get; set; }

            public FileEventInfo(string filePath, WatcherChangeTypes changeType, DateTime lastEventTime)
            {
                FilePath = filePath;
                ChangeType = changeType;
                LastEventTime = lastEventTime;
            }
        }
    }
}
