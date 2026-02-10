// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Monitoring/Pipeline/EventCoalescer.cs
// تجميع أحداث نفس الملف خلال فترة زمنية محددة
// =====================================================

using System.Collections.Concurrent;

namespace ShieldAI.Core.Monitoring.Pipeline
{
    /// <summary>
    /// يجمّع أحداث نفس الملف خلال فترة زمنية (300-800ms)
    /// لمنع الفحص المتكرر عند الكتابة المتعددة
    /// </summary>
    public class EventCoalescer : IDisposable
    {
        private readonly ConcurrentDictionary<string, CoalescedEvent> _pending = new(StringComparer.OrdinalIgnoreCase);
        private readonly FileEventQueue _outputQueue;
        private readonly int _coalesceMs;
        private readonly Timer _flushTimer;
        private bool _disposed;

        public EventCoalescer(FileEventQueue outputQueue, int coalesceMs = 500)
        {
            _outputQueue = outputQueue;
            _coalesceMs = Math.Clamp(coalesceMs, 100, 2000);

            // فحص كل نصف فترة التجميع
            _flushTimer = new Timer(FlushReady, null, _coalesceMs / 2, _coalesceMs / 2);
        }

        /// <summary>
        /// إضافة حدث (سيتم تجميعه مع أحداث نفس الملف)
        /// </summary>
        public void Add(string filePath, WatcherChangeTypes changeType)
        {
            var key = NormalizePath(filePath);

            _pending.AddOrUpdate(
                key,
                _ => new CoalescedEvent(filePath, changeType),
                (_, existing) =>
                {
                    existing.LastEventTime = DateTime.UtcNow;
                    existing.ChangeType = changeType;
                    existing.EventCount++;
                    return existing;
                });
        }

        /// <summary>
        /// فحص وإرسال الأحداث المستقرة
        /// </summary>
        private void FlushReady(object? state)
        {
            if (_disposed) return;

            var cutoff = DateTime.UtcNow.AddMilliseconds(-_coalesceMs);

            foreach (var kvp in _pending.ToArray())
            {
                if (kvp.Value.LastEventTime <= cutoff)
                {
                    if (_pending.TryRemove(kvp.Key, out var coalescedEvent))
                    {
                        // التحقق من أن الملف موجود ومستقر
                        if (IsFileReady(coalescedEvent.FilePath))
                        {
                            _outputQueue.TryEnqueue(new FileEvent
                            {
                                FilePath = coalescedEvent.FilePath,
                                ChangeType = coalescedEvent.ChangeType,
                                Timestamp = coalescedEvent.LastEventTime
                            });
                        }
                    }
                }
            }
        }

        /// <summary>
        /// التحقق من أن الملف جاهز للقراءة (غير مقفل)
        /// </summary>
        private static bool IsFileReady(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return false;

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
        /// عدد الأحداث المعلقة
        /// </summary>
        public int PendingCount => _pending.Count;

        /// <summary>
        /// مسح جميع الأحداث المعلقة
        /// </summary>
        public void Clear()
        {
            _pending.Clear();
        }

        private static string NormalizePath(string path)
        {
            return Path.GetFullPath(path).ToLowerInvariant();
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _flushTimer.Dispose();
            _pending.Clear();
        }

        private class CoalescedEvent
        {
            public string FilePath { get; }
            public WatcherChangeTypes ChangeType { get; set; }
            public DateTime LastEventTime { get; set; }
            public int EventCount { get; set; }

            public CoalescedEvent(string filePath, WatcherChangeTypes changeType)
            {
                FilePath = filePath;
                ChangeType = changeType;
                LastEventTime = DateTime.UtcNow;
                EventCount = 1;
            }
        }
    }
}
