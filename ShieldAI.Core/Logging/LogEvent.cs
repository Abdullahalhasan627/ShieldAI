// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Logging/LogEvent.cs
// نموذج حدث التسجيل
// =====================================================

using ShieldAI.Core.Configuration;

namespace ShieldAI.Core.Logging
{
    /// <summary>
    /// نموذج حدث التسجيل - يمثل سجل واحد في النظام
    /// </summary>
    public class LogEvent
    {
        /// <summary>
        /// معرف الحدث الفريد
        /// </summary>
        public Guid Id { get; set; } = Guid.NewGuid();

        /// <summary>
        /// وقت الحدث
        /// </summary>
        public DateTime Timestamp { get; set; } = DateTime.Now;

        /// <summary>
        /// مستوى التسجيل
        /// </summary>
        public LogLevel Level { get; set; }

        /// <summary>
        /// فئة الحدث
        /// </summary>
        public LogCategory Category { get; set; } = LogCategory.General;

        /// <summary>
        /// الرسالة
        /// </summary>
        public string Message { get; set; } = string.Empty;

        /// <summary>
        /// تفاصيل إضافية
        /// </summary>
        public string? Details { get; set; }

        /// <summary>
        /// مسار الملف (إن وجد)
        /// </summary>
        public string? FilePath { get; set; }

        /// <summary>
        /// اسم التهديد (إن وجد)
        /// </summary>
        public string? ThreatName { get; set; }

        /// <summary>
        /// شدة التهديد (إن وجد)
        /// </summary>
        public ThreatSeverity? Severity { get; set; }

        /// <summary>
        /// معلومات الاستثناء (إن وجد)
        /// </summary>
        public string? ExceptionInfo { get; set; }

        /// <summary>
        /// اسم المصدر (الكلاس أو الموديول)
        /// </summary>
        public string? Source { get; set; }

        /// <summary>
        /// معرف العملية
        /// </summary>
        public int ProcessId { get; set; } = Environment.ProcessId;

        /// <summary>
        /// معرف الخيط
        /// </summary>
        public int ThreadId { get; set; } = Environment.CurrentManagedThreadId;

        #region Factory Methods
        /// <summary>
        /// إنشاء حدث معلومات
        /// </summary>
        public static LogEvent Info(string message, string? source = null)
        {
            return new LogEvent
            {
                Level = LogLevel.Information,
                Message = message,
                Source = source
            };
        }

        /// <summary>
        /// إنشاء حدث تحذير
        /// </summary>
        public static LogEvent Warn(string message, string? source = null)
        {
            return new LogEvent
            {
                Level = LogLevel.Warning,
                Message = message,
                Source = source
            };
        }

        /// <summary>
        /// إنشاء حدث خطأ
        /// </summary>
        public static LogEvent Error(string message, Exception? ex = null, string? source = null)
        {
            return new LogEvent
            {
                Level = LogLevel.Error,
                Message = message,
                ExceptionInfo = ex?.ToString(),
                Source = source
            };
        }

        /// <summary>
        /// إنشاء حدث تهديد
        /// </summary>
        public static LogEvent Threat(string filePath, string threatName, ThreatSeverity severity)
        {
            return new LogEvent
            {
                Level = LogLevel.Warning,
                Category = LogCategory.Threat,
                Message = $"تم اكتشاف تهديد: {threatName}",
                FilePath = filePath,
                ThreatName = threatName,
                Severity = severity
            };
        }

        /// <summary>
        /// إنشاء حدث فحص
        /// </summary>
        public static LogEvent Scan(string filePath, bool isThreat, string? threatName = null)
        {
            return new LogEvent
            {
                Level = isThreat ? LogLevel.Warning : LogLevel.Information,
                Category = LogCategory.Scan,
                Message = isThreat ? $"تم اكتشاف تهديد في: {filePath}" : $"تم فحص: {filePath}",
                FilePath = filePath,
                ThreatName = threatName,
                Severity = isThreat ? ThreatSeverity.Medium : null
            };
        }
        #endregion

        /// <summary>
        /// تحويل الحدث لنص
        /// </summary>
        public override string ToString()
        {
            var severity = Severity.HasValue ? $" [{Severity}]" : "";
            return $"[{Timestamp:yyyy-MM-dd HH:mm:ss}] [{Level}]{severity} {Message}";
        }

        /// <summary>
        /// تحويل الحدث لنص مفصل
        /// </summary>
        public string ToDetailedString()
        {
            var lines = new List<string>
            {
                $"ID: {Id}",
                $"Time: {Timestamp:yyyy-MM-dd HH:mm:ss.fff}",
                $"Level: {Level}",
                $"Category: {Category}",
                $"Message: {Message}"
            };

            if (!string.IsNullOrEmpty(FilePath))
                lines.Add($"File: {FilePath}");
            if (!string.IsNullOrEmpty(ThreatName))
                lines.Add($"Threat: {ThreatName}");
            if (Severity.HasValue)
                lines.Add($"Severity: {Severity}");
            if (!string.IsNullOrEmpty(Details))
                lines.Add($"Details: {Details}");
            if (!string.IsNullOrEmpty(ExceptionInfo))
                lines.Add($"Exception: {ExceptionInfo}");
            if (!string.IsNullOrEmpty(Source))
                lines.Add($"Source: {Source}");

            return string.Join(Environment.NewLine, lines);
        }
    }

    /// <summary>
    /// فئات الأحداث
    /// </summary>
    public enum LogCategory
    {
        /// <summary>
        /// عام
        /// </summary>
        General,

        /// <summary>
        /// فحص
        /// </summary>
        Scan,

        /// <summary>
        /// تهديد
        /// </summary>
        Threat,

        /// <summary>
        /// حجر صحي
        /// </summary>
        Quarantine,

        /// <summary>
        /// تحديث
        /// </summary>
        Update,

        /// <summary>
        /// إعدادات
        /// </summary>
        Configuration,

        /// <summary>
        /// أمان
        /// </summary>
        Security,

        /// <summary>
        /// خدمة
        /// </summary>
        Service,

        /// <summary>
        /// ذكاء اصطناعي
        /// </summary>
        AI
    }
}
