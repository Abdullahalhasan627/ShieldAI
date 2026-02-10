// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Detection/ThreatScoring/ThreatAggregator.cs
// المجمّع النهائي - يجمع نتائج جميع المحركات ويصدر قراراً
// =====================================================

using ShieldAI.Core.Configuration;
using ShieldAI.Core.Scanning;

namespace ShieldAI.Core.Detection.ThreatScoring
{
    /// <summary>
    /// إعدادات أوزان المحركات
    /// </summary>
    public class EngineWeights
    {
        public double SignatureEngine { get; set; } = 1.0;
        public double HeuristicEngine { get; set; } = 0.8;
        public double MlEngine { get; set; } = 0.7;
        public double ReputationEngine { get; set; } = 0.5;
        public double AmsiEngine { get; set; } = 0.6;
    }

    /// <summary>
    /// المجمّع النهائي - يشغّل جميع المحركات ويجمع النتائج
    /// </summary>
    public class ThreatAggregator
    {
        private readonly List<IThreatEngine> _engines;
        private readonly PEAnalyzer _peAnalyzer;
        private readonly EngineWeights _weights;
        private readonly ScanCache? _scanCache;

        /// <summary>
        /// حدود القرار
        /// </summary>
        public int BlockThreshold { get; set; } = 80;
        public int QuarantineThreshold { get; set; } = 55;
        public int ReviewThreshold { get; set; } = 30;

        /// <summary>
        /// هل هناك ضغط عالي لتقليل المحركات الثقيلة
        /// </summary>
        public bool HighPressureMode { get; set; }

        public ThreatAggregator(
            IEnumerable<IThreatEngine> engines,
            EngineWeights? weights = null,
            PEAnalyzer? peAnalyzer = null,
            ScanCache? scanCache = null)
        {
            _engines = engines.ToList();
            _weights = weights ?? new EngineWeights();
            _peAnalyzer = peAnalyzer ?? new PEAnalyzer();
            _scanCache = scanCache;
        }

        /// <summary>
        /// إنشاء مجمّع بالمحركات الافتراضية
        /// </summary>
        public static ThreatAggregator CreateDefault(
            SignatureDatabase? signatureDb = null,
            EngineWeights? weights = null,
            ScanCache? scanCache = null)
        {
            var sigDb = signatureDb ?? new SignatureDatabase();
            var engines = new List<IThreatEngine>
            {
                new SignatureEngine(sigDb),
                new HeuristicEngine(),
                new MlEngine(),
                new ReputationEngine(),
                new AmsiEngine()
            };

            return new ThreatAggregator(engines, weights, scanCache: scanCache);
        }

        /// <summary>
        /// فحص ملف بجميع المحركات وإرجاع النتيجة المجمّعة
        /// </summary>
        public async Task<AggregatedThreatResult> ScanAsync(string filePath, CancellationToken ct = default)
        {
            var context = BuildContext(filePath);
            return await ScanAsync(context, ct);
        }

        /// <summary>
        /// فحص بسياق جاهز
        /// </summary>
        public async Task<AggregatedThreatResult> ScanAsync(ThreatScanContext context, CancellationToken ct = default)
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var aggregated = new AggregatedThreatResult
            {
                FilePath = context.FilePath
            };

            if (_scanCache != null && !string.IsNullOrWhiteSpace(context.Sha256Hash))
            {
                if (_scanCache.TryGet(context.Sha256Hash, context.FileSize, context.LastWriteTime.ToUniversalTime(), out var cached))
                {
                    return cached ?? aggregated;
                }
            }

            // تشغيل جميع المحركات بالتوازي
            var enginesToRun = _engines
                .Where(e => e.IsReady)
                .Where(e => !HighPressureMode || !IsHeavyEngine(e.EngineName));

            var tasks = enginesToRun
                .Select(async engine =>
                {
                    try
                    {
                        return await engine.ScanAsync(context, ct);
                    }
                    catch (Exception ex)
                    {
                        return ThreatScanResult.Error(engine.EngineName, ex.Message);
                    }
                });

            var results = await Task.WhenAll(tasks);
            aggregated.EngineResults.AddRange(results);

            // حساب النتيجة المرجّحة
            aggregated.RiskScore = CalculateWeightedScore(results);

            // جمع الأسباب
            foreach (var result in results.Where(r => !r.HasError))
            {
                aggregated.Reasons.AddRange(result.Reasons);
            }

            // إزالة الأسباب المكررة
            aggregated.Reasons = aggregated.Reasons.Distinct().ToList();

            // تحديد القرار النهائي
            aggregated.Verdict = DetermineVerdict(aggregated.RiskScore, results);

            stopwatch.Stop();
            aggregated.Duration = stopwatch.Elapsed;

            if (_scanCache != null && !string.IsNullOrWhiteSpace(context.Sha256Hash))
            {
                _scanCache.Store(context.Sha256Hash, context.FileSize, context.LastWriteTime.ToUniversalTime(), aggregated);
            }

            return aggregated;
        }

        /// <summary>
        /// بناء سياق الفحص من مسار الملف
        /// </summary>
        public ThreatScanContext BuildContext(string filePath)
        {
            var context = ThreatScanContext.FromFile(filePath);

            if (!File.Exists(filePath))
                return context;

            try
            {
                // حساب الـ Hash
                context.Sha256Hash = PEAnalyzer.CalculateSha256(filePath);

                // تحليل PE
                var peInfo = _peAnalyzer.Analyze(filePath);
                context.PEInfo = peInfo;

                // التوقيع الرقمي
                context.HasValidSignature = peInfo.HasDigitalSignature;
            }
            catch
            {
                // تجاهل الأخطاء في بناء السياق
            }

            return context;
        }

        /// <summary>
        /// حساب النتيجة المرجّحة
        /// </summary>
        public int CalculateWeightedScore(ThreatScanResult[] results)
        {
            double totalWeight = 0;
            double weightedSum = 0;

            foreach (var result in results.Where(r => !r.HasError))
            {
                double weight = GetEngineWeight(result.EngineName);
                double effectiveWeight = weight * result.Confidence;

                weightedSum += result.Score * effectiveWeight;
                totalWeight += effectiveWeight;
            }

            if (totalWeight <= 0)
                return 0;

            int score = (int)(weightedSum / totalWeight);
            return Math.Clamp(score, 0, 100);
        }

        /// <summary>
        /// تحديد القرار النهائي
        /// </summary>
        public AggregatedVerdict DetermineVerdict(int riskScore, ThreatScanResult[] results)
        {
            // إذا أي محرك أعطى Malicious بثقة عالية → Block
            bool anyHighConfidenceMalicious = results.Any(r =>
                r.Verdict == EngineVerdict.Malicious && r.Confidence >= 0.9);

            if (anyHighConfidenceMalicious || riskScore >= BlockThreshold)
            {
                return AggregatedVerdict.Block;
            }

            // إذا أكثر من محرك أعطى Malicious → Quarantine
            int maliciousCount = results.Count(r => r.Verdict == EngineVerdict.Malicious);
            if (maliciousCount >= 2 || riskScore >= QuarantineThreshold)
            {
                return AggregatedVerdict.Quarantine;
            }

            // إذا أي محرك أعطى Suspicious → NeedsReview
            bool anySuspicious = results.Any(r => r.Verdict == EngineVerdict.Suspicious);
            if (anySuspicious || riskScore >= ReviewThreshold)
            {
                return AggregatedVerdict.NeedsReview;
            }

            return AggregatedVerdict.Allow;
        }

        /// <summary>
        /// الحصول على وزن المحرك
        /// </summary>
        private double GetEngineWeight(string engineName)
        {
            return engineName switch
            {
                "SignatureEngine" => _weights.SignatureEngine,
                "HeuristicEngine" => _weights.HeuristicEngine,
                "MlEngine" => _weights.MlEngine,
                "ReputationEngine" => _weights.ReputationEngine,
                "AmsiEngine" => _weights.AmsiEngine,
                _ => 0.5
            };
        }

        private static bool IsHeavyEngine(string engineName)
        {
            return engineName is "MlEngine" or "ReputationEngine" or "DefenderEngine" or "VirusTotalEngine";
        }
    }
}
