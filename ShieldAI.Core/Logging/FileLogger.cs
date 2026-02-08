// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Logging/FileLogger.cs
// تنفيذ تسجيل للملفات
// =====================================================

using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using ShieldAI.Core.Configuration;

namespace ShieldAI.Core.Logging
{
    /// <summary>
    /// مسجل الملفات - يسجل الأحداث في ملفات نصية و JSON
    /// </summary>
    public class FileLogger : ILogger, IDisposable
    {
        private readonly string _logDirectory;
        private readonly LogLevel _minimumLevel;
        private readonly int _maxFileSizeMB;
        private readonly ConcurrentQueue<LogEvent> _recentEvents;
        private readonly int _maxRecentEvents = 1000;
        private readonly object _writeLock = new();
        private readonly Timer _flushTimer;
        private readonly ConcurrentQueue<LogEvent> _writeQueue;
        private bool _disposed;

        private string CurrentLogFile => Path.Combine(_logDirectory, $"shieldai_{DateTime.Now:yyyyMMdd}.log");
        private string CurrentJsonFile => Path.Combine(_logDirectory, $"shieldai_{DateTime.Now:yyyyMMdd}.json");

        /// <summary>
        /// إنشاء مسجل ملفات جديد
        /// </summary>
        public FileLogger(string? logDirectory = null, LogLevel minimumLevel = LogLevel.Information, int maxFileSizeMB = 50)
        {
            _logDirectory = logDirectory ?? @"C:\ProgramData\ShieldAI\Logs";
            _minimumLevel = minimumLevel;
            _maxFileSizeMB = maxFileSizeMB;
            _recentEvents = new ConcurrentQueue<LogEvent>();
            _writeQueue = new ConcurrentQueue<LogEvent>();

            EnsureDirectoryExists();

            // Timer لكتابة الأحداث كل 5 ثواني
            _flushTimer = new Timer(FlushQueue, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        }

        #region ILogger Implementation
        public void Trace(string message, params object[] args)
        {
            Log(LogLevel.Trace, FormatMessage(message, args));
        }

        public void Debug(string message, params object[] args)
        {
            Log(LogLevel.Debug, FormatMessage(message, args));
        }

        public void Information(string message, params object[] args)
        {
            Log(LogLevel.Information, FormatMessage(message, args));
        }

        public void Warning(string message, params object[] args)
        {
            Log(LogLevel.Warning, FormatMessage(message, args));
        }

        public void Error(string message, params object[] args)
        {
            Log(LogLevel.Error, FormatMessage(message, args));
        }

        public void Error(Exception exception, string message, params object[] args)
        {
            var logEvent = new LogEvent
            {
                Level = LogLevel.Error,
                Message = FormatMessage(message, args),
                ExceptionInfo = exception.ToString()
            };
            EnqueueEvent(logEvent);
        }

        public void Critical(string message, params object[] args)
        {
            Log(LogLevel.Critical, FormatMessage(message, args));
        }

        public void Critical(Exception exception, string message, params object[] args)
        {
            var logEvent = new LogEvent
            {
                Level = LogLevel.Critical,
                Message = FormatMessage(message, args),
                ExceptionInfo = exception.ToString()
            };
            EnqueueEvent(logEvent);
            // كتابة الأحداث الحرجة فوراً
            FlushQueue(null);
        }

        public void SecurityEvent(string eventType, string details, ThreatSeverity? severity = null)
        {
            var logEvent = new LogEvent
            {
                Level = severity >= ThreatSeverity.High ? LogLevel.Warning : LogLevel.Information,
                Category = LogCategory.Security,
                Message = $"[SECURITY] {eventType}",
                Details = details,
                Severity = severity
            };
            EnqueueEvent(logEvent);
        }

        public void ScanEvent(string filePath, bool isThreat, string? threatName = null)
        {
            var logEvent = LogEvent.Scan(filePath, isThreat, threatName);
            EnqueueEvent(logEvent);
        }

        public IEnumerable<LogEvent> GetRecentEvents(int count = 100)
        {
            return _recentEvents.TakeLast(count).Reverse();
        }

        public IEnumerable<LogEvent> GetEvents(DateTime? from = null, DateTime? to = null, LogLevel? minLevel = null)
        {
            var events = _recentEvents.AsEnumerable();

            if (from.HasValue)
                events = events.Where(e => e.Timestamp >= from.Value);
            if (to.HasValue)
                events = events.Where(e => e.Timestamp <= to.Value);
            if (minLevel.HasValue)
                events = events.Where(e => e.Level >= minLevel.Value);

            return events.OrderByDescending(e => e.Timestamp);
        }

        public void CleanupOldLogs(int retentionDays)
        {
            try
            {
                var cutoffDate = DateTime.Now.AddDays(-retentionDays);
                var logFiles = Directory.GetFiles(_logDirectory, "shieldai_*.log");

                foreach (var file in logFiles)
                {
                    var fileInfo = new FileInfo(file);
                    if (fileInfo.LastWriteTime < cutoffDate)
                    {
                        File.Delete(file);
                        Information("تم حذف ملف سجل قديم: {0}", file);
                    }
                }

                var jsonFiles = Directory.GetFiles(_logDirectory, "shieldai_*.json");
                foreach (var file in jsonFiles)
                {
                    var fileInfo = new FileInfo(file);
                    if (fileInfo.LastWriteTime < cutoffDate)
                    {
                        File.Delete(file);
                    }
                }
            }
            catch (Exception ex)
            {
                Error(ex, "خطأ أثناء تنظيف السجلات القديمة");
            }
        }
        #endregion

        #region Private Methods
        private void Log(LogLevel level, string message)
        {
            if (level < _minimumLevel)
                return;

            var logEvent = new LogEvent
            {
                Level = level,
                Message = message
            };
            EnqueueEvent(logEvent);
        }

        private void EnqueueEvent(LogEvent logEvent)
        {
            // إضافة للأحداث الأخيرة
            _recentEvents.Enqueue(logEvent);
            while (_recentEvents.Count > _maxRecentEvents)
            {
                _recentEvents.TryDequeue(out _);
            }

            // إضافة لقائمة الكتابة
            _writeQueue.Enqueue(logEvent);
        }

        private void FlushQueue(object? state)
        {
            if (_writeQueue.IsEmpty)
                return;

            var events = new List<LogEvent>();
            while (_writeQueue.TryDequeue(out var logEvent))
            {
                events.Add(logEvent);
            }

            if (events.Count == 0)
                return;

            lock (_writeLock)
            {
                try
                {
                    WriteToTextFile(events);
                    WriteToJsonFile(events);
                    RotateLogsIfNeeded();
                }
                catch
                {
                    // تجاهل أخطاء الكتابة لتجنب حلقات لا نهائية
                }
            }
        }

        private void WriteToTextFile(List<LogEvent> events)
        {
            var sb = new StringBuilder();
            foreach (var e in events)
            {
                sb.AppendLine(e.ToString());
            }
            File.AppendAllText(CurrentLogFile, sb.ToString());
        }

        private void WriteToJsonFile(List<LogEvent> events)
        {
            var options = new JsonSerializerOptions { WriteIndented = false };
            var lines = events.Select(e => JsonSerializer.Serialize(e, options));
            File.AppendAllLines(CurrentJsonFile, lines);
        }

        private void RotateLogsIfNeeded()
        {
            var fileInfo = new FileInfo(CurrentLogFile);
            if (fileInfo.Exists && fileInfo.Length > _maxFileSizeMB * 1024 * 1024)
            {
                var newName = Path.Combine(_logDirectory, 
                    $"shieldai_{DateTime.Now:yyyyMMdd_HHmmss}.log");
                File.Move(CurrentLogFile, newName);
            }
        }

        private void EnsureDirectoryExists()
        {
            if (!Directory.Exists(_logDirectory))
            {
                Directory.CreateDirectory(_logDirectory);
            }
        }

        private static string FormatMessage(string message, params object[] args)
        {
            if (args == null || args.Length == 0)
                return message;

            try
            {
                return string.Format(message, args);
            }
            catch
            {
                return message;
            }
        }
        #endregion

        #region IDisposable
        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;
            _flushTimer.Dispose();
            FlushQueue(null); // كتابة الأحداث المتبقية
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}
