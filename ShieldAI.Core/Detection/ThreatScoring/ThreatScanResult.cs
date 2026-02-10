// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Detection/ThreatScoring/ThreatScanResult.cs
// نتيجة فحص محرك واحد + القرار النهائي المجمّع
// =====================================================

namespace ShieldAI.Core.Detection.ThreatScoring
{
    /// <summary>
    /// حكم المحرك
    /// </summary>
    public enum EngineVerdict
    {
        Clean,
        Suspicious,
        Malicious,
        Unknown
    }

    /// <summary>
    /// القرار النهائي المجمّع
    /// </summary>
    public enum AggregatedVerdict
    {
        Allow,
        Quarantine,
        Block,
        NeedsReview
    }

    /// <summary>
    /// نتيجة فحص من محرك واحد
    /// </summary>
    public class ThreatScanResult
    {
        /// <summary>
        /// اسم المحرك
        /// </summary>
        public string EngineName { get; set; } = "";

        /// <summary>
        /// درجة الخطورة (0-100)
        /// </summary>
        public int Score { get; set; }

        /// <summary>
        /// حكم المحرك
        /// </summary>
        public EngineVerdict Verdict { get; set; } = EngineVerdict.Clean;

        /// <summary>
        /// أسباب واضحة للمستخدم
        /// </summary>
        public List<string> Reasons { get; set; } = new();

        /// <summary>
        /// درجة الثقة (0.0 - 1.0)
        /// </summary>
        public double Confidence { get; set; } = 1.0;

        /// <summary>
        /// بيانات إضافية من المحرك
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new();

        /// <summary>
        /// هل حدث خطأ أثناء الفحص
        /// </summary>
        public bool HasError { get; set; }

        /// <summary>
        /// رسالة الخطأ
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// إنشاء نتيجة نظيفة
        /// </summary>
        public static ThreatScanResult Clean(string engineName) => new()
        {
            EngineName = engineName,
            Score = 0,
            Verdict = EngineVerdict.Clean
        };

        /// <summary>
        /// إنشاء نتيجة خطأ
        /// </summary>
        public static ThreatScanResult Error(string engineName, string error) => new()
        {
            EngineName = engineName,
            Score = 0,
            Verdict = EngineVerdict.Unknown,
            HasError = true,
            ErrorMessage = error
        };
    }

    /// <summary>
    /// النتيجة النهائية المجمّعة من جميع المحركات
    /// </summary>
    public class AggregatedThreatResult
    {
        /// <summary>
        /// درجة الخطورة النهائية (0-100)
        /// </summary>
        public int RiskScore { get; set; }

        /// <summary>
        /// القرار النهائي
        /// </summary>
        public AggregatedVerdict Verdict { get; set; } = AggregatedVerdict.Allow;

        /// <summary>
        /// جميع الأسباب المجمّعة
        /// </summary>
        public List<string> Reasons { get; set; } = new();

        /// <summary>
        /// نتائج كل محرك
        /// </summary>
        public List<ThreatScanResult> EngineResults { get; set; } = new();

        /// <summary>
        /// مسار الملف
        /// </summary>
        public string FilePath { get; set; } = "";

        /// <summary>
        /// وقت الفحص
        /// </summary>
        public DateTime ScannedAt { get; set; } = DateTime.Now;

        /// <summary>
        /// مدة الفحص
        /// </summary>
        public TimeSpan Duration { get; set; }

        /// <summary>
        /// ملخص نصي
        /// </summary>
        public string Summary =>
            $"Risk: {RiskScore}/100 | Verdict: {Verdict} | Engines: {EngineResults.Count} | Reasons: {Reasons.Count}";
    }
}
