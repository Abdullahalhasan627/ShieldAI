// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Logging/ILogger.cs
// واجهة التسجيل
// =====================================================

using ShieldAI.Core.Configuration;

namespace ShieldAI.Core.Logging
{
    /// <summary>
    /// واجهة التسجيل - تحدد عقد التسجيل للتطبيق
    /// </summary>
    public interface ILogger
    {
        /// <summary>
        /// تسجيل رسالة Trace
        /// </summary>
        void Trace(string message, params object[] args);

        /// <summary>
        /// تسجيل رسالة Debug
        /// </summary>
        void Debug(string message, params object[] args);

        /// <summary>
        /// تسجيل رسالة معلومات
        /// </summary>
        void Information(string message, params object[] args);

        /// <summary>
        /// تسجيل تحذير
        /// </summary>
        void Warning(string message, params object[] args);

        /// <summary>
        /// تسجيل خطأ
        /// </summary>
        void Error(string message, params object[] args);

        /// <summary>
        /// تسجيل خطأ مع Exception
        /// </summary>
        void Error(Exception exception, string message, params object[] args);

        /// <summary>
        /// تسجيل خطأ حرج
        /// </summary>
        void Critical(string message, params object[] args);

        /// <summary>
        /// تسجيل خطأ حرج مع Exception
        /// </summary>
        void Critical(Exception exception, string message, params object[] args);

        /// <summary>
        /// تسجيل حدث أمني
        /// </summary>
        void SecurityEvent(string eventType, string details, ThreatSeverity? severity = null);

        /// <summary>
        /// تسجيل نتيجة فحص
        /// </summary>
        void ScanEvent(string filePath, bool isThreat, string? threatName = null);

        /// <summary>
        /// الحصول على الأحداث الأخيرة
        /// </summary>
        IEnumerable<LogEvent> GetRecentEvents(int count = 100);

        /// <summary>
        /// الحصول على أحداث بفلتر
        /// </summary>
        IEnumerable<LogEvent> GetEvents(DateTime? from = null, DateTime? to = null, LogLevel? minLevel = null);

        /// <summary>
        /// مسح السجلات القديمة
        /// </summary>
        void CleanupOldLogs(int retentionDays);
    }

    /// <summary>
    /// مستوى شدة التهديد
    /// </summary>
    public enum ThreatSeverity
    {
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }
}
