// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// ML/DeepAnalyzer.cs
// التحليل العميق بالذكاء الاصطناعي
// =====================================================

using ShieldAI.Core.Detection;
using ShieldAI.Core.Scanning;
using ShieldAI.Core.Logging;

// إعادة تسمية ThreatLevel لتجنب التضارب
using ThreatLevel = ShieldAI.Core.Detection.ThreatLevel;

namespace ShieldAI.Core.ML
{
    /// <summary>
    /// المحلل العميق - يجمع بين ML والتحليل السلوكي والتوقيعات
    /// للحصول على تحليل شامل للملفات
    /// </summary>
    public class DeepAnalyzer
    {
        private readonly MalwareClassifier _classifier;
        private readonly HeuristicAnalyzer _heuristicAnalyzer;
        private readonly Detection.SignatureDatabase _signatureDb;
        private readonly VirusTotalClient? _vtClient;
        private readonly PEAnalyzer _peAnalyzer;
        private readonly DefenderScanner _defenderScanner;
        private readonly ILogger? _logger;

        public DeepAnalyzer(
            string? vtApiKey = null,
            ILogger? logger = null,
            int defenderTimeoutSeconds = 60)
        {
            _logger = logger;
            _classifier = new MalwareClassifier();
            _heuristicAnalyzer = new HeuristicAnalyzer(logger);
            _signatureDb = new Detection.SignatureDatabase(logger);
            _peAnalyzer = new PEAnalyzer();
            _defenderScanner = new DefenderScanner(defenderTimeoutSeconds);
            
            if (!string.IsNullOrWhiteSpace(vtApiKey))
            {
                _vtClient = new VirusTotalClient(vtApiKey, logger);
            }
        }

        /// <summary>
        /// تحليل عميق للملف
        /// </summary>
        public async Task<DeepAnalysisResult> AnalyzeAsync(
            string filePath, 
            bool useVirusTotal = true,
            bool useDefender = true,
            IProgress<AnalysisProgress>? progress = null,
            CancellationToken cancellationToken = default)
        {
            var result = new DeepAnalysisResult
            {
                FilePath = filePath,
                FileName = Path.GetFileName(filePath),
                AnalysisStartTime = DateTime.Now
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    result.Error = "الملف غير موجود";
                    return result;
                }

                var fileInfo = new FileInfo(filePath);
                result.FileSize = fileInfo.Length;
                result.FileExtension = fileInfo.Extension;

                // 1. فحص التوقيعات (10%)
                progress?.Report(new AnalysisProgress { Stage = "فحص التوقيعات...", Percent = 5 });
                await Task.Run(() => AnalyzeSignatures(result), cancellationToken);
                progress?.Report(new AnalysisProgress { Stage = "فحص التوقيعات", Percent = 15 });

                // 2. التحليل السلوكي (30%)
                progress?.Report(new AnalysisProgress { Stage = "التحليل السلوكي...", Percent = 20 });
                await Task.Run(() => AnalyzeHeuristics(result), cancellationToken);
                progress?.Report(new AnalysisProgress { Stage = "التحليل السلوكي", Percent = 40 });

                // 3. تحليل ML (25%)
                progress?.Report(new AnalysisProgress { Stage = "تحليل الذكاء الاصطناعي...", Percent = 45 });
                await Task.Run(() => AnalyzeML(result), cancellationToken);
                progress?.Report(new AnalysisProgress { Stage = "تحليل الذكاء الاصطناعي", Percent = 65 });

                // 4. VirusTotal (اختياري - 25%)
                if (useVirusTotal && _vtClient != null && _vtClient.IsConfigured)
                {
                    progress?.Report(new AnalysisProgress { Stage = "فحص VirusTotal...", Percent = 70 });
                    await AnalyzeVirusTotalAsync(result, cancellationToken);
                }
                progress?.Report(new AnalysisProgress { Stage = "تجميع النتائج", Percent = 85 });

                // 5. Microsoft Defender (Second Opinion)
                if (useDefender && _defenderScanner.IsAvailable)
                {
                    progress?.Report(new AnalysisProgress { Stage = "فحص Windows Defender...", Percent = 88 });
                    await AnalyzeDefenderAsync(result, cancellationToken);
                }
                progress?.Report(new AnalysisProgress { Stage = "تجميع النتائج", Percent = 95 });

                // 6. حساب النتيجة النهائية
                CalculateFinalVerdict(result);
                
                result.AnalysisEndTime = DateTime.Now;
                progress?.Report(new AnalysisProgress { Stage = "اكتمل التحليل", Percent = 100 });
            }
            catch (OperationCanceledException)
            {
                result.Error = "تم إلغاء التحليل";
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                _logger?.Error(ex, "خطأ في التحليل العميق");
            }

            return result;
        }

        #region Private Analysis Methods
        private void AnalyzeSignatures(DeepAnalysisResult result)
        {
            var match = _signatureDb.CheckFile(result.FilePath);
            if (match != null)
            {
                result.SignatureMatch = match;
                result.Findings.Add(new AnalysisFinding
                {
                    Source = "Signature Database",
                    Type = FindingType.KnownMalware,
                    Severity = match.Signature.ThreatLevel,
                    Title = "تم اكتشاف توقيع معروف",
                    Description = $"{match.Signature.MalwareName} - {match.Signature.MalwareFamily}",
                    Confidence = 100
                });
            }
        }

        private void AnalyzeHeuristics(DeepAnalysisResult result)
        {
            var heuristicResult = _heuristicAnalyzer.Analyze(result.FilePath);
            result.HeuristicResult = heuristicResult;

            foreach (var indicator in heuristicResult.Indicators)
            {
                result.Findings.Add(new AnalysisFinding
                {
                    Source = "Heuristic Analysis",
                    Type = FindingType.SuspiciousBehavior,
                    Severity = MapSeverity(indicator.Severity),
                    Title = indicator.Name,
                    Description = indicator.Description,
                    Confidence = Math.Min(indicator.Score * 2, 100)
                });
            }
        }

        private void AnalyzeML(DeepAnalysisResult result)
        {
            try
            {
                var prediction = _classifier.Predict(result.FilePath);
                result.MLPrediction = prediction;

                if (prediction.IsMalware)
                {
                    result.Findings.Add(new AnalysisFinding
                    {
                        Source = "AI/ML Engine",
                        Type = FindingType.MLDetection,
                        Severity = prediction.Probability > 0.8 ? ThreatLevel.High : ThreatLevel.Medium,
                        Title = "اكتشاف بالذكاء الاصطناعي",
                        Description = $"النموذج يشير إلى برمجية خبيثة بنسبة ثقة {prediction.Probability:P0}",
                        Confidence = (int)(prediction.Probability * 100)
                    });
                }
            }
            catch (Exception ex)
            {
                _logger?.Warning("فشل تحليل ML: {0}", ex.Message);
            }
        }

        private async Task AnalyzeVirusTotalAsync(DeepAnalysisResult result, CancellationToken cancellationToken)
        {
            if (_vtClient == null) return;

            try
            {
                var vtResult = await _vtClient.ScanFileAsync(result.FilePath, cancellationToken);
                result.VirusTotalResult = vtResult;

                if (vtResult.IsThreat)
                {
                    result.Findings.Add(new AnalysisFinding
                    {
                        Source = "VirusTotal",
                        Type = FindingType.MultiEngineDetection,
                        Severity = vtResult.Malicious > 10 ? ThreatLevel.Critical : 
                                   vtResult.Malicious > 5 ? ThreatLevel.High : ThreatLevel.Medium,
                        Title = $"اكتشاف من {vtResult.Malicious} محرك",
                        Description = $"تم اكتشافه من {vtResult.Malicious}/{vtResult.TotalEngines} محرك antivirus",
                        Confidence = (int)vtResult.DetectionRate
                    });

                    // إضافة أسماء الاكتشافات
                    foreach (var detection in vtResult.Detections.Take(5))
                    {
                        result.DetectedNames.Add($"{detection.EngineName}: {detection.Result}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Warning("فشل فحص VirusTotal: {0}", ex.Message);
            }
        }

        /// <summary>
        /// فحص الملف باستخدام Windows Defender كرأي ثانٍ
        /// </summary>
        private async Task AnalyzeDefenderAsync(DeepAnalysisResult result, CancellationToken cancellationToken)
        {
            try
            {
                var defenderResult = await _defenderScanner.ScanFileAsync(result.FilePath, cancellationToken);
                result.DefenderResult = defenderResult;

                if (defenderResult.Success && defenderResult.IsThreat)
                {
                    result.Findings.Add(new AnalysisFinding
                    {
                        Source = "Microsoft Defender",
                        Type = FindingType.DefenderDetection,
                        Severity = ThreatLevel.High,
                        Title = defenderResult.ThreatName ?? "تهديد مكتشف من Defender",
                        Description = $"Windows Defender اكتشف: {defenderResult.ThreatName ?? "تهديد غير محدد"}",
                        Confidence = (int)(defenderResult.RiskScore * 100)
                    });

                    // إضافة اسم التهديد للقائمة
                    if (!string.IsNullOrEmpty(defenderResult.ThreatName))
                    {
                        result.DetectedNames.Add($"Defender: {defenderResult.ThreatName}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Warning("فشل فحص Windows Defender: {0}", ex.Message);
            }
        }

        private void CalculateFinalVerdict(DeepAnalysisResult result)
        {
            // حساب درجة الخطورة الإجمالية
            double totalScore = 0;
            double maxConfidence = 0;

            foreach (var finding in result.Findings)
            {
                var weight = finding.Type switch
                {
                    FindingType.KnownMalware => 1.0,
                    FindingType.MultiEngineDetection => 0.9,
                    FindingType.MLDetection => 0.7,
                    FindingType.SuspiciousBehavior => 0.5,
                    _ => 0.3
                };

                var severityScore = finding.Severity switch
                {
                    ThreatLevel.Critical => 100,
                    ThreatLevel.High => 75,
                    ThreatLevel.Medium => 50,
                    ThreatLevel.Low => 25,
                    _ => 0
                };

                totalScore += severityScore * weight * (finding.Confidence / 100.0);
                maxConfidence = Math.Max(maxConfidence, finding.Confidence);
            }

            // تحديد الحكم النهائي
            result.OverallRiskScore = Math.Min(totalScore, 100);
            result.OverallConfidence = maxConfidence;

            result.Verdict = result.OverallRiskScore switch
            {
                >= 80 => AnalysisVerdict.Malicious,
                >= 50 => AnalysisVerdict.Suspicious,
                >= 20 => AnalysisVerdict.PotentiallyUnwanted,
                _ => AnalysisVerdict.Clean
            };

            result.ThreatLevel = result.OverallRiskScore switch
            {
                >= 80 => ThreatLevel.Critical,
                >= 60 => ThreatLevel.High,
                >= 40 => ThreatLevel.Medium,
                >= 20 => ThreatLevel.Low,
                _ => ThreatLevel.None
            };

            // ملخص التحليل
            result.Summary = GenerateSummary(result);
        }

        private string GenerateSummary(DeepAnalysisResult result)
        {
            var parts = new List<string>();

            if (result.SignatureMatch != null)
                parts.Add($"تم اكتشاف توقيع: {result.SignatureMatch.Signature.MalwareName}");

            if (result.HeuristicResult?.IsMalicious == true)
                parts.Add($"سلوك مشبوه: {result.HeuristicResult.Indicators.Count} مؤشرات");

            if (result.MLPrediction?.IsMalware == true)
                parts.Add($"اكتشاف AI: {result.MLPrediction.Probability:P0}");

            if (result.VirusTotalResult?.IsThreat == true)
                parts.Add($"VirusTotal: {result.VirusTotalResult.Malicious} اكتشاف");

            return parts.Count > 0 
                ? string.Join(" | ", parts) 
                : "لم يتم اكتشاف تهديدات";
        }

        private ThreatLevel MapSeverity(IndicatorSeverity severity) => severity switch
        {
            IndicatorSeverity.Critical => ThreatLevel.Critical,
            IndicatorSeverity.High => ThreatLevel.High,
            IndicatorSeverity.Medium => ThreatLevel.Medium,
            IndicatorSeverity.Low => ThreatLevel.Low,
            _ => ThreatLevel.None
        };
        #endregion
    }

    #region Models
    /// <summary>
    /// نتيجة التحليل العميق
    /// </summary>
    public class DeepAnalysisResult
    {
        public string FilePath { get; set; } = "";
        public string FileName { get; set; } = "";
        public string FileExtension { get; set; } = "";
        public long FileSize { get; set; }
        
        public DateTime AnalysisStartTime { get; set; }
        public DateTime AnalysisEndTime { get; set; }
        public TimeSpan Duration => AnalysisEndTime - AnalysisStartTime;

        public SignatureMatch? SignatureMatch { get; set; }
        public HeuristicResult? HeuristicResult { get; set; }
        public MalwarePrediction? MLPrediction { get; set; }
        public VTScanResult? VirusTotalResult { get; set; }
        public DefenderScanResult? DefenderResult { get; set; }

        public List<AnalysisFinding> Findings { get; set; } = new();
        public List<string> DetectedNames { get; set; } = new();

        public double OverallRiskScore { get; set; }
        public double OverallConfidence { get; set; }
        public AnalysisVerdict Verdict { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
        public string Summary { get; set; } = "";
        public string? Error { get; set; }
        
        public bool HasError => !string.IsNullOrEmpty(Error);
        public bool IsThreat => Verdict != AnalysisVerdict.Clean;
    }

    /// <summary>
    /// اكتشاف من التحليل
    /// </summary>
    public class AnalysisFinding
    {
        public string Source { get; set; } = "";
        public FindingType Type { get; set; }
        public ThreatLevel Severity { get; set; }
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";
        public int Confidence { get; set; }
    }

    /// <summary>
    /// نوع الاكتشاف
    /// </summary>
    public enum FindingType
    {
        KnownMalware,
        SuspiciousBehavior,
        MLDetection,
        MultiEngineDetection,
        DefenderDetection,
        Other
    }

    /// <summary>
    /// الحكم النهائي
    /// </summary>
    public enum AnalysisVerdict
    {
        Clean,
        PotentiallyUnwanted,
        Suspicious,
        Malicious
    }

    /// <summary>
    /// تقدم التحليل
    /// </summary>
    public class AnalysisProgress
    {
        public string Stage { get; set; } = "";
        public int Percent { get; set; }
    }
    #endregion
}
