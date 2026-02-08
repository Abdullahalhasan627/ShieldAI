namespace ShieldAI.Core.Models;

/// <summary>
/// معلومات التهديد المكتشف
/// </summary>
public class ThreatInfo
{
    /// <summary>
    /// اسم التهديد
    /// </summary>
    public string Name { get; set; } = "Unknown Threat";
    
    /// <summary>
    /// نوع التهديد (Virus, Trojan, Worm, Ransomware, etc.)
    /// </summary>
    public ThreatType Type { get; set; } = ThreatType.Unknown;
    
    /// <summary>
    /// مستوى الخطورة (0-100)
    /// </summary>
    public float Severity { get; set; }
    
    /// <summary>
    /// وصف التهديد
    /// </summary>
    public string Description { get; set; } = string.Empty;
    
    /// <summary>
    /// بصمة الملف SHA256
    /// </summary>
    public string FileHash { get; set; } = string.Empty;
}

/// <summary>
/// أنواع التهديدات
/// </summary>
public enum ThreatType
{
    Unknown,
    Virus,
    Trojan,
    Worm,
    Ransomware,
    Spyware,
    Adware,
    Rootkit,
    Keylogger,
    Backdoor,
    PotentiallyUnwanted
}

/// <summary>
/// نتيجة الفحص (Legacy - للتوافق القديم)
/// </summary>
[Obsolete("Use ShieldAI.Core.Models.ScanResult instead")]
public class LegacyScanResult
{
    /// <summary>
    /// مسار الملف المفحوص
    /// </summary>
    public string FilePath { get; set; } = string.Empty;
    
    /// <summary>
    /// اسم الملف
    /// </summary>
    public string FileName => Path.GetFileName(FilePath);
    
    /// <summary>
    /// هل الملف مصاب
    /// </summary>
    public bool IsInfected { get; set; }
    
    /// <summary>
    /// هل هو ملف مشبوه (خطورة متوسطة)
    /// </summary>
    public bool IsSuspicious { get; set; }
    
    /// <summary>
    /// نسبة الخطورة من النموذج (0-1)
    /// </summary>
    public float RiskScore { get; set; }
    
    /// <summary>
    /// معلومات التهديد إن وُجد
    /// </summary>
    public ThreatInfo? Threat { get; set; }
    
    /// <summary>
    /// وقت الفحص
    /// </summary>
    public DateTime ScanTime { get; set; } = DateTime.Now;
    
    /// <summary>
    /// حجم الملف بالبايت
    /// </summary>
    public long FileSize { get; set; }
    
    /// <summary>
    /// رسالة الخطأ إن فشل الفحص
    /// </summary>
    public string? ErrorMessage { get; set; }
}

/// <summary>
/// معلومات العملية الجارية
/// </summary>
public class ProcessInfo
{
    /// <summary>
    /// معرف العملية
    /// </summary>
    public int ProcessId { get; set; }
    
    /// <summary>
    /// اسم العملية
    /// </summary>
    public string ProcessName { get; set; } = string.Empty;
    
    /// <summary>
    /// مسار الملف التنفيذي
    /// </summary>
    public string? ExecutablePath { get; set; }
    
    /// <summary>
    /// بصمة الملف SHA256
    /// </summary>
    public string? FileHash { get; set; }
    
    /// <summary>
    /// استخدام الذاكرة بالبايت
    /// </summary>
    public long MemoryUsage { get; set; }
    
    /// <summary>
    /// هل العملية موثوقة
    /// </summary>
    public bool IsTrusted { get; set; }
    
    /// <summary>
    /// هل العملية مشبوهة
    /// </summary>
    public bool IsSuspicious { get; set; }
    
    /// <summary>
    /// نتيجة الفحص
    /// </summary>
    public LegacyScanResult? ScanResult { get; set; }
}

/// <summary>
/// معلومات ملف PE
/// </summary>
public class PEFileInfo
{
    /// <summary>
    /// هل هو ملف PE صالح
    /// </summary>
    public bool IsValidPE { get; set; }
    
    /// <summary>
    /// نوع الملف (DLL, EXE, etc.)
    /// </summary>
    public string FileType { get; set; } = string.Empty;
    
    /// <summary>
    /// المعمارية (x86, x64)
    /// </summary>
    public string Architecture { get; set; } = string.Empty;
    
    /// <summary>
    /// عدد الـ Sections
    /// </summary>
    public int SectionCount { get; set; }
    
    /// <summary>
    /// أسماء الـ Sections
    /// </summary>
    public List<string> SectionNames { get; set; } = new();
    
    /// <summary>
    /// الـ DLLs المستوردة
    /// </summary>
    public List<string> ImportedDlls { get; set; } = new();
    
    /// <summary>
    /// الـ APIs المستوردة
    /// </summary>
    public List<string> ImportedApis { get; set; } = new();
    
    /// <summary>
    /// معدل الإنتروبيا (للكشف عن التشفير/الضغط)
    /// </summary>
    public double Entropy { get; set; }
    
    /// <summary>
    /// حجم الملف
    /// </summary>
    public long FileSize { get; set; }
    
    /// <summary>
    /// تاريخ البناء
    /// </summary>
    public DateTime? TimeDateStamp { get; set; }
    
    /// <summary>
    /// هل يحتوي على توقيع رقمي
    /// </summary>
    public bool HasDigitalSignature { get; set; }
    
    /// <summary>
    /// بصمة SHA256
    /// </summary>
    public string Sha256Hash { get; set; } = string.Empty;
}
