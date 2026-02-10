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

        #region Engine Weights
        /// <summary>
        /// وزن محرك التوقيعات (0.0 - 1.0)
        /// </summary>
        public double SignatureEngineWeight { get; set; } = 1.0;

        /// <summary>
        /// وزن محرك التحليل السلوكي (0.0 - 1.0)
        /// </summary>
        public double HeuristicEngineWeight { get; set; } = 0.8;

        /// <summary>
        /// وزن محرك التعلم الآلي (0.0 - 1.0)
        /// </summary>
        public double MlEngineWeight { get; set; } = 0.7;

        /// <summary>
        /// وزن محرك السمعة (0.0 - 1.0)
        /// </summary>
        public double ReputationEngineWeight { get; set; } = 0.5;

        /// <summary>
        /// وزن محرك AMSI (0.0 - 1.0)
        /// </summary>
        public double AmsiEngineWeight { get; set; } = 0.6;

        /// <summary>
        /// حد الحظر (0-100)
        /// </summary>
        public int BlockThreshold { get; set; } = 80;

        /// <summary>
        /// حد الحجر (0-100)
        /// </summary>
        public int QuarantineThreshold { get; set; } = 55;

        /// <summary>
        /// حد المراجعة (0-100)
        /// </summary>
        public int ReviewThreshold { get; set; } = 30;
        #endregion

        #region Pipeline Settings
        /// <summary>
        /// فترة تجميع الأحداث بالمللي ثانية
        /// </summary>
        public int EventCoalesceMs { get; set; } = 500;

        /// <summary>
        /// عدد عمال الفحص في Pipeline
        /// </summary>
        public int PipelineScanWorkers { get; set; } = 2;

        /// <summary>
        /// سعة قناة الأحداث في Pipeline
        /// </summary>
        public int PipelineQueueCapacity { get; set; } = 10_000;

        /// <summary>
        /// حد الضغط العالي لتعطيل المحركات الثقيلة مؤقتاً
        /// </summary>
        public int PipelineHighPressureThreshold { get; set; } = 2_000;
        #endregion

        #region Scan Cache
        /// <summary>
        /// تفعيل كاش نتائج الفحص
        /// </summary>
        public bool EnableScanCache { get; set; } = true;

        /// <summary>
        /// مدة صلاحية الكاش بالدقائق
        /// </summary>
        public int ScanCacheTtlMinutes { get; set; } = 30;
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
