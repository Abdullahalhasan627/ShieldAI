using ShieldAI.Core.Models;
using ShieldAI.Core.Scanning;

namespace ShieldAI.Core.ML;

/// <summary>
/// مستخرج الخصائص من ملفات PE
/// يحول معلومات الملف إلى خصائص رقمية لنموذج التعلم الآلي
/// </summary>
public class FeatureExtractor
{
    private readonly PEAnalyzer _peAnalyzer;

    public FeatureExtractor()
    {
        _peAnalyzer = new PEAnalyzer();
    }

    public FeatureExtractor(PEAnalyzer peAnalyzer)
    {
        _peAnalyzer = peAnalyzer;
    }

    /// <summary>
    /// استخراج الخصائص من ملف
    /// </summary>
    public MalwareFeatures ExtractFeatures(string filePath)
    {
        var peInfo = _peAnalyzer.Analyze(filePath);
        return ExtractFeatures(peInfo);
    }

    /// <summary>
    /// استخراج الخصائص من معلومات PE
    /// </summary>
    public MalwareFeatures ExtractFeatures(PEFileInfo peInfo)
    {
        var features = new MalwareFeatures
        {
            // حجم الملف بالكيلوبايت
            FileSize = peInfo.FileSize / 1024f,
            
            // عدد الـ Sections
            SectionCount = peInfo.SectionCount,
            
            // الإنتروبيا
            Entropy = (float)peInfo.Entropy,
            
            // عدد الـ DLLs المستوردة
            ImportedDllCount = peInfo.ImportedDlls.Count,
            
            // عدد الـ DLLs المشبوهة
            SuspiciousDllCount = _peAnalyzer.CountSuspiciousDlls(peInfo),
            
            // عدد الـ APIs الخطيرة
            DangerousApiCount = _peAnalyzer.CountDangerousApis(peInfo),
            
            // التوقيع الرقمي
            HasDigitalSignature = peInfo.HasDigitalSignature ? 1f : 0f,
            
            // نوع الملف
            IsDll = peInfo.FileType.Equals("DLL", StringComparison.OrdinalIgnoreCase) ? 1f : 0f,
            
            // المعمارية
            Is64Bit = peInfo.Architecture.Contains("64") ? 1f : 0f,
            
            // نسبة الكود (تقدير مبسط)
            CodeRatio = CalculateCodeRatio(peInfo)
        };

        return features;
    }

    /// <summary>
    /// حساب نسبة الكود التقريبية
    /// </summary>
    private float CalculateCodeRatio(PEFileInfo peInfo)
    {
        // في التطبيق الحقيقي، نحسب حجم الـ .text section مقسومًا على الحجم الكلي
        // هنا نستخدم تقدير مبسط
        
        // Sections الكود عادةً: .text, CODE, .code
        var codeSections = peInfo.SectionNames.Count(s => 
            s.Equals(".text", StringComparison.OrdinalIgnoreCase) ||
            s.Equals("CODE", StringComparison.OrdinalIgnoreCase) ||
            s.Equals(".code", StringComparison.OrdinalIgnoreCase));
        
        if (peInfo.SectionCount == 0) return 0f;
        
        return (float)codeSections / peInfo.SectionCount;
    }

    /// <summary>
    /// حساب درجة الخطورة بناءً على القواعد الثابتة
    /// </summary>
    public float CalculateRiskScore(MalwareFeatures features)
    {
        float score = 0;
        
        // الإنتروبيا العالية مشبوهة (ملف مشفر/مضغوط)
        if (features.Entropy > 7.0f)
            score += 0.3f;
        else if (features.Entropy > 6.5f)
            score += 0.15f;
        
        // DLLs مشبوهة
        score += Math.Min(features.SuspiciousDllCount * 0.05f, 0.2f);
        
        // APIs خطيرة
        score += Math.Min(features.DangerousApiCount * 0.08f, 0.3f);
        
        // عدم وجود توقيع رقمي
        if (features.HasDigitalSignature == 0)
            score += 0.1f;
        
        // عدد Sections غير طبيعي
        if (features.SectionCount < 3 || features.SectionCount > 10)
            score += 0.1f;
        
        return Math.Min(score, 1f);
    }
}
