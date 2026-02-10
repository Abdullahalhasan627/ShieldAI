// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Monitoring/Pipeline/FileEventQueue.cs
// قائمة انتظار الأحداث باستخدام System.Threading.Channels
// =====================================================

using System.Threading.Channels;

namespace ShieldAI.Core.Monitoring.Pipeline
{
    /// <summary>
    /// حدث ملف في القائمة
    /// </summary>
    public class FileEvent
    {
        public string FilePath { get; set; } = "";
        public WatcherChangeTypes ChangeType { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// قائمة انتظار الأحداث المبنية على System.Threading.Channels
    /// أسرع وأكثر كفاءة من ConcurrentQueue + Timer
    /// </summary>
    public class FileEventQueue : IDisposable
    {
        private readonly Channel<FileEvent> _channel;
        private readonly int _capacity;
        private bool _disposed;

        /// <summary>
        /// عدد العناصر المنتظرة (تقريبي)
        /// </summary>
        public int PendingCount => _channel.Reader.Count;

        public FileEventQueue(int capacity = 10_000)
        {
            _capacity = capacity;
            _channel = Channel.CreateBounded<FileEvent>(new BoundedChannelOptions(capacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = false,
                SingleWriter = false
            });
        }

        /// <summary>
        /// إضافة حدث للقائمة
        /// </summary>
        public bool TryEnqueue(FileEvent fileEvent)
        {
            if (PendingCount > _capacity * 0.8 && IsTemporaryPath(fileEvent.FilePath))
            {
                return false;
            }

            return _channel.Writer.TryWrite(fileEvent);
        }

        private static bool IsTemporaryPath(string path)
        {
            var ext = Path.GetExtension(path).ToLowerInvariant();
            return ext is ".tmp" or ".log" or ".etl" or ".lock" or ".partial" or ".crdownload";
        }

        /// <summary>
        /// قراءة الأحداث (async enumerable)
        /// </summary>
        public IAsyncEnumerable<FileEvent> ReadAllAsync(CancellationToken ct = default)
        {
            return _channel.Reader.ReadAllAsync(ct);
        }

        /// <summary>
        /// قراءة حدث واحد
        /// </summary>
        public async ValueTask<FileEvent> DequeueAsync(CancellationToken ct = default)
        {
            return await _channel.Reader.ReadAsync(ct);
        }

        /// <summary>
        /// محاولة قراءة حدث بدون انتظار
        /// </summary>
        public bool TryDequeue(out FileEvent? fileEvent)
        {
            return _channel.Reader.TryRead(out fileEvent);
        }

        /// <summary>
        /// إغلاق القائمة (لا مزيد من الكتابة)
        /// </summary>
        public void Complete()
        {
            _channel.Writer.TryComplete();
        }

        public void Dispose()
        {
            if (_disposed) return;
            Complete();
            _disposed = true;
        }
    }
}
