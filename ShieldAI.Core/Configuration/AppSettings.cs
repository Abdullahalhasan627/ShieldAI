// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Configuration/AppSettings.cs
// إعدادات التطبيق الأساسية
// =====================================================

namespace ShieldAI.Core.Configuration
{
    /// <summary>
    /// إعدادات التطبيق الأساسية - يتم تحميلها من ملف JSON
    /// </summary>
    public class AppSettings
    {
        #region Paths
        /// <summary>
        /// مسار مجلد الحجر الصحي
        /// </summary>
        public string QuarantinePath { get; set; } = @"C:\ProgramData\ShieldAI\Quarantine";

        /// <summary>
        /// مسار ملفات السجل
        /// </summary>
        public string LogPath { get; set; } = @"C:\ProgramData\ShieldAI\Logs";

        /// <summary>
        /// مسار قاعدة بيانات التوقيعات
        /// </summary>
        public string SignatureDatabasePath { get; set; } = @"C:\ProgramData\ShieldAI\Signatures";

        /// <summary>
        /// مسار نموذج ML.NET
        /// </summary>
        public string MLModelPath { get; set; } = @"C:\ProgramData\ShieldAI\Models\malware_model.zip";
        #endregion

        #region Scanning Options
        /// <summary>
        /// تفعيل الفحص الفوري
        /// </summary>
        public bool EnableRealTimeProtection { get; set; } = true;

        /// <summary>
        /// تفعيل فحص الذاكرة
        /// </summary>
        public bool EnableMemoryScan { get; set; } = true;

        /// <summary>
        /// تفعيل فحص العمليات
        /// </summary>
        public bool EnableProcessScan { get; set; } = true;

        /// <summary>
        /// الحد الأقصى لحجم الملف للفحص (بالميجابايت)
        /// </summary>
        public int MaxFileSizeMB { get; set; } = 100;

        /// <summary>
        /// الامتدادات المستبعدة من الفحص
        /// </summary>
        public List<string> ExcludedExtensions { get; set; } = new();

        /// <summary>
        /// المجلدات المستبعدة من الفحص
        /// </summary>
        public List<string> ExcludedFolders { get; set; } = new();
        #endregion

        #region ML Settings
        /// <summary>
        /// عتبة تصنيف البرمجيات الخبيثة (0.0 - 1.0)
        /// </summary>
        public float MalwareThreshold { get; set; } = 0.7f;

        /// <summary>
        /// استخدام ML.NET للفحص
        /// </summary>
        public bool UseMLDetection { get; set; } = true;
        #endregion

        #region Update Settings
        /// <summary>
        /// تفعيل التحديث التلقائي
        /// </summary>
        public bool AutoUpdate { get; set; } = true;

        /// <summary>
        /// فترة التحقق من التحديثات (بالساعات)
        /// </summary>
        public int UpdateCheckIntervalHours { get; set; } = 24;

        /// <summary>
        /// عنوان خادم التحديثات
        /// </summary>
        public string UpdateServerUrl { get; set; } = "https://updates.shieldai.local";
        #endregion

        #region VirusTotal Integration
        /// <summary>
        /// مفتاح API لـ VirusTotal
        /// </summary>
        public string VirusTotalApiKey { get; set; } = "";

        /// <summary>
        /// تفعيل فحص VirusTotal في AI Scan
        /// </summary>
        public bool UseVirusTotalInAIScan { get; set; } = true;

        /// <summary>
        /// تفعيل رفع الملفات إلى VirusTotal
        /// </summary>
        public bool AllowVirusTotalUpload { get; set; } = false;
        #endregion

        #region AI Scan Settings
        /// <summary>
        /// تفعيل التحليل العميق
        /// </summary>
        public bool EnableDeepAnalysis { get; set; } = true;

        /// <summary>
        /// وقت انتظار التحليل (بالثواني)
        /// </summary>
        public int AnalysisTimeoutSeconds { get; set; } = 300;

        /// <summary>
        /// العزل التلقائي للتهديدات المكتشفة
        /// </summary>
        public bool AutoQuarantine { get; set; } = true;

        /// <summary>
        /// تفعيل فحص Windows Defender كرأي ثانٍ
        /// </summary>
        public bool UseDefenderSecondOpinion { get; set; } = true;

        /// <summary>
        /// مهلة فحص Defender (بالثواني)
        /// </summary>
        public int DefenderTimeoutSeconds { get; set; } = 60;
        #endregion

        #region Logging
        /// <summary>
        /// مستوى التسجيل
        /// </summary>
        public LogLevel MinimumLogLevel { get; set; } = LogLevel.Information;

        /// <summary>
        /// الحد الأقصى لحجم ملف السجل (بالميجابايت)
        /// </summary>
        public int MaxLogFileSizeMB { get; set; } = 50;

        /// <summary>
        /// عدد أيام الاحتفاظ بالسجلات
        /// </summary>
        public int LogRetentionDays { get; set; } = 30;
        #endregion
    }

    /// <summary>
    /// مستويات التسجيل
    /// </summary>
    public enum LogLevel
    {
        Trace = 0,
        Debug = 1,
        Information = 2,
        Warning = 3,
        Error = 4,
        Critical = 5
    }
}
