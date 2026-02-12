// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Detection/ThreatScoring/ThreatAggregator.cs
// المجمّع النهائي - يجمع نتائج جميع المحركات ويصدر قراراً
// =====================================================

using ShieldAI.Core.Configuration;
using ShieldAI.Core.Logging;
using ShieldAI.Core.Scanning;
using Microsoft.Extensions.Logging;
using MsILogger = Microsoft.Extensions.Logging.ILogger;

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
        private readonly AppSettings _settings;
        private readonly MsILogger? _logger;

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
            ScanCache? scanCache = null,
            MsILogger? logger = null)
        {
            _engines = engines.ToList();
            _weights = weights ?? new EngineWeights();
            _peAnalyzer = peAnalyzer ?? new PEAnalyzer();
            _scanCache = scanCache;
            _settings = ConfigManager.Instance.Settings;
            _logger = logger;
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
                new AmsiEngine(),
                new DefenderEngine()
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
            var correlationId = ScanDiagnosticLog.NewCorrelationId();
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var aggregated = new AggregatedThreatResult
            {
                FilePath = context.FilePath,
                CorrelationId = correlationId
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

            // === سياسة الرأي الثاني (Second Opinion) ===
            if (!HighPressureMode)
            {
                var secondOpinionResults = await RunSecondOpinionAsync(context, results, aggregated.RiskScore, ct);
                if (secondOpinionResults.Count > 0)
                {
                    aggregated.EngineResults.AddRange(secondOpinionResults);
                    var allResults = aggregated.EngineResults.ToArray();
                    aggregated.RiskScore = CalculateWeightedScore(allResults);
                    foreach (var r in secondOpinionResults.Where(r => !r.HasError))
                        aggregated.Reasons.AddRange(r.Reasons);
                    aggregated.Reasons = aggregated.Reasons.Distinct().ToList();
                    aggregated.Verdict = DetermineVerdict(aggregated.RiskScore, allResults);
                }
            }

            stopwatch.Stop();
            aggregated.Duration = stopwatch.Elapsed;

            // سجل تشخيصي موحّد
            ScanDiagnosticLog.LogScanResult(_logger, correlationId, context, aggregated);

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
            var validResults = results.Where(r => !r.HasError).ToArray();

            // مطابقة توقيع قاطعة لا يجب تخفيفها بمحركات أخرى نظيفة
            var definitiveMatch = validResults.FirstOrDefault(r =>
                r.Score >= 95 && r.Confidence >= 0.95);
            if (definitiveMatch != null)
                return definitiveMatch.Score;

            double totalWeight = 0;
            double weightedSum = 0;

            foreach (var result in validResults)
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

        /// <summary>
        /// تشغيل سياسة الرأي الثاني بناءً على قواعد AppSettings
        /// </summary>
        private async Task<List<ThreatScanResult>> RunSecondOpinionAsync(
            ThreatScanContext context,
            ThreatScanResult[] initialResults,
            int riskScore,
            CancellationToken ct)
        {
            var extra = new List<ThreatScanResult>();

            bool shouldRunVT = ShouldRunVirusTotal(context, initialResults, riskScore);
            bool shouldRunDefender = ShouldRunDefender(context, initialResults, riskScore);

            var secondOpinionEngines = _engines
                .Where(e => e.IsReady)
                .Where(e =>
                    (shouldRunVT && e.EngineName == "VirusTotalEngine") ||
                    (shouldRunDefender && e.EngineName == "DefenderEngine"));

            foreach (var engine in secondOpinionEngines)
            {
                try
                {
                    var reason = shouldRunDefender && engine.EngineName == "DefenderEngine"
                        ? (IsInSuspicionZone(riskScore) ? "SuspicionZone" : "PolicyRule")
                        : (IsInSuspicionZone(riskScore) ? "SuspicionZone" : "UnsignedSuspiciousPath");

                    ScanDiagnosticLog.LogSecondOpinion(
                        _logger, context.FilePath, engine.EngineName, riskScore, reason);

                    var result = await engine.ScanAsync(context, ct);
                    extra.Add(result);
                }
                catch (Exception ex)
                {
                    extra.Add(ThreatScanResult.Error(engine.EngineName, ex.Message));
                }
            }

            return extra;
        }

        private bool IsInSuspicionZone(int riskScore)
        {
            return riskScore >= _settings.SuspicionScoreMin &&
                   riskScore <= _settings.SuspicionScoreMax;
        }

        private bool ShouldRunVirusTotal(ThreatScanContext context, ThreatScanResult[] results, int riskScore)
        {
            if (!_settings.EnableVirusTotalSecondOpinion)
                return false;

            // القاعدة 1: داخل منطقة الشك
            if (IsInSuspicionZone(riskScore))
                return true;

            // القاعدة 2: غير موقع + مسار مشبوه
            if (_settings.VirusTotalWhenUnsignedSuspiciousPath &&
                context.IsUnsignedOrUntrustedPublisher &&
                context.IsFromTempOrAppData)
                return true;

            return false;
        }

        private bool ShouldRunDefender(ThreatScanContext context, ThreatScanResult[] results, int riskScore)
        {
            if (!_settings.EnableDefenderSecondOpinion)
                return false;

            // القاعدة 1: داخل منطقة الشك
            if (IsInSuspicionZone(riskScore))
                return true;

            // القاعدة 2: تعارض ML مع Heuristic
            if (_settings.DefenderWhenDisagree)
            {
                var mlResult = results.FirstOrDefault(r => r.EngineName == "MlEngine" && !r.HasError);
                var heuristicResult = results.FirstOrDefault(r => r.EngineName == "HeuristicEngine" && !r.HasError);

                if (mlResult != null && heuristicResult != null)
                {
                    bool mlSuspicious = mlResult.Verdict is EngineVerdict.Malicious or EngineVerdict.Suspicious;
                    bool heuristicSuspicious = heuristicResult.Verdict is EngineVerdict.Malicious or EngineVerdict.Suspicious;

                    if (mlSuspicious != heuristicSuspicious)
                        return true;
                }
            }

            // القاعدة 3: ملف من Temp/AppData
            if (_settings.DefenderWhenTempOrAppData && context.IsFromTempOrAppData)
                return true;

            return false;
        }
    }
}
