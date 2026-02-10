// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/Models/ThreatRecord.cs
// نموذج سجل التهديدات للعرض في صفحة التاريخ
// =====================================================

namespace ShieldAI.UI.Models
{
    /// <summary>
    /// سجل تهديد مكتشف
    /// </summary>
    public class ThreatRecord
    {
        public string FilePath { get; set; } = "";
        public string FileName { get; set; } = "";
        public int RiskScore { get; set; }
        public string Verdict { get; set; } = "";
        public List<string> Reasons { get; set; } = new();
        public List<EngineResultItem> EngineResults { get; set; } = new();
        public DateTime DetectedAt { get; set; }
        public string? Action { get; set; }

        /// <summary>
        /// لون مستوى الخطورة
        /// </summary>
        public string RiskColor => RiskScore switch
        {
            >= 80 => "#E74C3C",  // أحمر - خطير
            >= 55 => "#E67E22",  // برتقالي - حجر
            >= 30 => "#F39C12",  // أصفر - مراجعة
            _ => "#27AE60"       // أخضر - آمن
        };

        /// <summary>
        /// نص مستوى الخطورة
        /// </summary>
        public string RiskText => RiskScore switch
        {
            >= 80 => "خطير",
            >= 55 => "مشبوه",
            >= 30 => "يحتاج مراجعة",
            _ => "آمن"
        };

        /// <summary>
        /// الأسباب كنص واحد
        /// </summary>
        public string ReasonsText => Reasons.Count > 0
            ? string.Join("\n• ", Reasons)
            : "لا توجد أسباب محددة";
    }

    /// <summary>
    /// نتيجة محرك واحد للعرض
    /// </summary>
    public class EngineResultItem
    {
        public string EngineName { get; set; } = "";
        public int Score { get; set; }
        public string Verdict { get; set; } = "";

        public string DisplayName => EngineName switch
        {
            "SignatureEngine" => "التوقيعات",
            "HeuristicEngine" => "التحليل السلوكي",
            "MlEngine" => "التعلم الآلي",
            "ReputationEngine" => "السمعة",
            _ => EngineName
        };
    }

    /// <summary>
    /// جلسة فحص
    /// </summary>
    public class ScanSession
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string ScanType { get; set; } = "";
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public int TotalFiles { get; set; }
        public int ScannedFiles { get; set; }
        public int ThreatsFound { get; set; }
        public string Status { get; set; } = "";
        public TimeSpan Duration => EndTime - StartTime;

        public string Summary =>
            $"{ScanType} - {ScannedFiles} ملف - {ThreatsFound} تهديد - {Duration.TotalSeconds:F1}s";
    }
}
