// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Core/Models/ScanModels.cs
// نماذج موحدة للفحص
// =====================================================

namespace ShieldAI.Core.Models
{
    /// <summary>
    /// نوع الفحص
    /// </summary>
    public enum ScanType
    {
        Quick,      // فحص سريع - مواقع شائعة فقط
        Full,       // فحص كامل - جميع الأقراص
        Custom,     // فحص مخصص - مسارات محددة
        Single,     // فحص ملف واحد
        Memory,     // فحص الذاكرة والعمليات
        Scheduled   // فحص مجدول
    }

    /// <summary>
    /// حالة الفحص
    /// </summary>
    public enum ScanStatus
    {
        Pending,    // في الانتظار
        Running,    // قيد التنفيذ
        Paused,     // متوقف مؤقتاً
        Completed,  // مكتمل
        Cancelled,  // ملغي
        Failed      // فشل
    }

    /// <summary>
    /// حكم الفحص
    /// </summary>
    public enum ScanVerdict
    {
        Clean,              // نظيف
        PotentiallyUnwanted,// قد يكون غير مرغوب
        Suspicious,         // مشبوه
        Malicious,          // خبيث
        Unknown,            // غير معروف
        Error               // خطأ في الفحص
    }

    /// <summary>
    /// مستوى التهديد
    /// </summary>
    public enum ThreatLevel
    {
        Low,        // منخفض
        Medium,     // متوسط
        High,       // عالي
        Critical    // حرج
    }

    /// <summary>
    /// مهمة فحص
    /// </summary>
    public class ScanJob
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public List<string> Paths { get; set; } = new();
        public ScanType Type { get; set; }
        public ScanStatus Status { get; set; } = ScanStatus.Pending;
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime? StartedAt { get; set; }
        public DateTime? CompletedAt { get; set; }
        
        // الإحصائيات
        public int TotalFiles { get; set; }
        public int ScannedFiles { get; set; }
        public int ThreatsFound { get; set; }
        public int ErrorCount { get; set; }
        public string? CurrentFile { get; set; }
        
        // الإعدادات
        public bool UseVirusTotal { get; set; }
        public bool DeepScan { get; set; }
        
        public double ProgressPercent => TotalFiles > 0 
            ? (double)ScannedFiles / TotalFiles * 100 
            : 0;
    }

    /// <summary>
    /// نتيجة فحص ملف واحد
    /// </summary>
    public class ScanResult
    {
        public Guid JobId { get; set; }
        public string FilePath { get; set; } = "";
        public string FileName => Path.GetFileName(FilePath);
        public long FileSize { get; set; }
        public string? SHA256 { get; set; }
        public string? MD5 { get; set; }
        
        public ScanVerdict Verdict { get; set; } = ScanVerdict.Clean;
        public double RiskScore { get; set; }
        public double Confidence { get; set; }
        
        public List<DetectionFinding> Findings { get; set; } = new();
        public string? ThreatName { get; set; }
        public string? ErrorMessage { get; set; }
        
        public DateTime ScannedAt { get; set; } = DateTime.Now;
        public TimeSpan Duration { get; set; }
        
        public bool IsThreat => Verdict == ScanVerdict.Malicious || 
                                Verdict == ScanVerdict.Suspicious;
    }

    /// <summary>
    /// اكتشاف من محرك معين
    /// </summary>
    public class DetectionFinding
    {
        public string Source { get; set; } = "";      // SignatureDB, Heuristic, ML, VirusTotal
        public string Type { get; set; } = "";        // نوع التهديد
        public string Title { get; set; } = "";       // عنوان
        public string Description { get; set; } = ""; // وصف تفصيلي
        public ThreatLevel Severity { get; set; }
        public int Confidence { get; set; }           // 0-100
        
        public Dictionary<string, string> Metadata { get; set; } = new();
    }

    /// <summary>
    /// تقرير فحص كامل
    /// </summary>
    public class ScanReport
    {
        public Guid JobId { get; set; }
        public ScanType ScanType { get; set; }
        public ScanStatus FinalStatus { get; set; }
        
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration => EndTime - StartTime;
        
        public int TotalFiles { get; set; }
        public int ScannedFiles { get; set; }
        public int ThreatsFound { get; set; }
        public int ErrorCount { get; set; }
        public long TotalBytesScanned { get; set; }
        
        public List<ScanResult> Results { get; set; } = new();
        public List<ScanResult> Threats => Results.Where(r => r.IsThreat).ToList();
        public List<string> Errors { get; set; } = new();
        
        public string Summary => $"فحص {ScannedFiles} ملف - {ThreatsFound} تهديد - {Duration.TotalSeconds:F1}s";
    }

    /// <summary>
    /// حدث تقدم الفحص
    /// </summary>
    public class ScanProgressEventArgs : EventArgs
    {
        public Guid JobId { get; set; }
        public int TotalFiles { get; set; }
        public int ScannedFiles { get; set; }
        public int ThreatsFound { get; set; }
        public string? CurrentFile { get; set; }
        public double ProgressPercent { get; set; }
        public ScanStatus Status { get; set; }
    }

    /// <summary>
    /// حدث اكتشاف تهديد
    /// </summary>
    public class ThreatDetectedEventArgs : EventArgs
    {
        public Guid JobId { get; set; }
        public ScanResult Result { get; set; } = new();
        public bool AutoQuarantined { get; set; }
    }

    /// <summary>
    /// حدث اكتمال الفحص
    /// </summary>
    public class ScanCompletedEventArgs : EventArgs
    {
        public ScanReport Report { get; set; } = new();
    }
}
