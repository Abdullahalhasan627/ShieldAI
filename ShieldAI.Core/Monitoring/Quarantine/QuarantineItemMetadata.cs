// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Monitoring/Quarantine/QuarantineItemMetadata.cs
// بيانات وصفية لكل عنصر محجور
// =====================================================

using ShieldAI.Core.Detection.ThreatScoring;

namespace ShieldAI.Core.Monitoring.Quarantine
{
    /// <summary>
    /// بيانات وصفية شاملة لعنصر محجور
    /// </summary>
    public class QuarantineItemMetadata
    {
        /// <summary>
        /// معرف فريد
        /// </summary>
        public string Id { get; set; } = Guid.NewGuid().ToString("N");

        /// <summary>
        /// المسار الأصلي للملف
        /// </summary>
        public string OriginalPath { get; set; } = "";

        /// <summary>
        /// اسم الملف الأصلي
        /// </summary>
        public string OriginalName { get; set; } = "";

        /// <summary>
        /// حجم الملف الأصلي
        /// </summary>
        public long FileSize { get; set; }

        /// <summary>
        /// بصمة SHA256 للملف الأصلي
        /// </summary>
        public string Sha256Hash { get; set; } = "";

        /// <summary>
        /// وقت الحجر
        /// </summary>
        public DateTime QuarantinedAt { get; set; } = DateTime.Now;

        /// <summary>
        /// القرار النهائي
        /// </summary>
        public string Verdict { get; set; } = "";

        /// <summary>
        /// درجة الخطورة (0-100)
        /// </summary>
        public int RiskScore { get; set; }

        /// <summary>
        /// الأسباب
        /// </summary>
        public List<string> Reasons { get; set; } = new();

        /// <summary>
        /// ملخص المحركات
        /// </summary>
        public List<EngineSummary> EngineSummaries { get; set; } = new();

        /// <summary>
        /// اسم التهديد المكتشف
        /// </summary>
        public string? ThreatName { get; set; }

        /// <summary>
        /// اسم ملف الحجر المشفر
        /// </summary>
        public string QuarantineFileName { get; set; } = "";

        /// <summary>
        /// هل تم الاستعادة
        /// </summary>
        public bool IsRestored { get; set; }

        /// <summary>
        /// وقت الاستعادة
        /// </summary>
        public DateTime? RestoredAt { get; set; }

        /// <summary>
        /// إنشاء من نتيجة مجمّعة
        /// </summary>
        public static QuarantineItemMetadata FromAggregatedResult(
            string filePath, AggregatedThreatResult result)
        {
            var fileInfo = new FileInfo(filePath);
            var metadata = new QuarantineItemMetadata
            {
                OriginalPath = filePath,
                OriginalName = fileInfo.Name,
                FileSize = fileInfo.Exists ? fileInfo.Length : 0,
                Verdict = result.Verdict.ToString(),
                RiskScore = result.RiskScore,
                Reasons = new List<string>(result.Reasons)
            };

            foreach (var engineResult in result.EngineResults)
            {
                metadata.EngineSummaries.Add(new EngineSummary
                {
                    EngineName = engineResult.EngineName,
                    Score = engineResult.Score,
                    Verdict = engineResult.Verdict.ToString()
                });
            }

            return metadata;
        }
    }

    /// <summary>
    /// ملخص نتيجة محرك واحد
    /// </summary>
    public class EngineSummary
    {
        public string EngineName { get; set; } = "";
        public int Score { get; set; }
        public string Verdict { get; set; } = "";
    }
}
