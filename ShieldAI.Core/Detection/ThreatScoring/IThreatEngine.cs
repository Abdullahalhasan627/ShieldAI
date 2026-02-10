// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Detection/ThreatScoring/IThreatEngine.cs
// واجهة عامة لكل محرك كشف
// =====================================================

namespace ShieldAI.Core.Detection.ThreatScoring
{
    /// <summary>
    /// واجهة عامة لكل محرك كشف عن التهديدات
    /// </summary>
    public interface IThreatEngine
    {
        /// <summary>
        /// اسم المحرك
        /// </summary>
        string EngineName { get; }

        /// <summary>
        /// الوزن الافتراضي للمحرك (0.0 - 1.0)
        /// </summary>
        double DefaultWeight { get; }

        /// <summary>
        /// هل المحرك جاهز للعمل
        /// </summary>
        bool IsReady { get; }

        /// <summary>
        /// فحص ملف وإرجاع النتيجة
        /// </summary>
        Task<ThreatScanResult> ScanAsync(ThreatScanContext context, CancellationToken ct = default);
    }
}
