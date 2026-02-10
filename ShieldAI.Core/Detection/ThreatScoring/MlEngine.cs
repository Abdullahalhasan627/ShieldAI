// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Detection/ThreatScoring/MlEngine.cs
// محرك التعلم الآلي - يربط مع MalwareClassifier
// =====================================================

using ShieldAI.Core.ML;

namespace ShieldAI.Core.Detection.ThreatScoring
{
    /// <summary>
    /// محرك التعلم الآلي - يستخدم MalwareClassifier للتنبؤ
    /// </summary>
    public class MlEngine : IThreatEngine
    {
        private readonly MalwareClassifier _classifier;
        private readonly FeatureExtractor _featureExtractor;

        public string EngineName => "MlEngine";
        public double DefaultWeight => 0.7;
        public bool IsReady => true;

        public MlEngine(MalwareClassifier classifier, FeatureExtractor featureExtractor)
        {
            _classifier = classifier;
            _featureExtractor = featureExtractor;
        }

        public MlEngine() : this(new MalwareClassifier(), new FeatureExtractor())
        {
        }

        public Task<ThreatScanResult> ScanAsync(ThreatScanContext context, CancellationToken ct = default)
        {
            var result = new ThreatScanResult { EngineName = EngineName };

            try
            {
                if (context.PEInfo == null || !context.PEInfo.IsValidPE)
                {
                    // ML يعمل فقط على ملفات PE
                    result.Score = 0;
                    result.Verdict = EngineVerdict.Unknown;
                    result.Confidence = 0.0;
                    result.Reasons.Add("الملف ليس PE - تم تخطي تحليل ML");
                    return Task.FromResult(result);
                }

                // استخراج الخصائص
                var features = _featureExtractor.ExtractFeatures(context.PEInfo);

                // التنبؤ
                var prediction = _classifier.Predict(features);

                // تحويل النتيجة (0-1) إلى (0-100)
                result.Score = (int)(prediction.Probability * 100);
                result.Confidence = Math.Abs(prediction.Score);

                if (prediction.IsMalware)
                {
                    result.Verdict = prediction.Probability > 0.8
                        ? EngineVerdict.Malicious
                        : EngineVerdict.Suspicious;

                    result.Reasons.Add($"نموذج ML صنّف الملف كخبيث (ثقة: {prediction.Probability:P0})");

                    // تفسير الأسباب بناءً على الخصائص
                    AddFeatureExplanations(features, result);
                }
                else
                {
                    result.Verdict = EngineVerdict.Clean;
                    result.Reasons.Add($"نموذج ML صنّف الملف كآمن (ثقة: {1 - prediction.Probability:P0})");
                }

                result.Metadata["Probability"] = prediction.Probability;
                result.Metadata["RawScore"] = prediction.Score;
                result.Metadata["ModelLoaded"] = _classifier.IsModelLoaded;
            }
            catch (Exception ex)
            {
                result = ThreatScanResult.Error(EngineName, ex.Message);
            }

            return Task.FromResult(result);
        }

        private void AddFeatureExplanations(MalwareFeatures features, ThreatScanResult result)
        {
            if (features.Entropy > 7.0f)
                result.Reasons.Add($"إنتروبيا عالية: {features.Entropy:F2}");

            if (features.DangerousApiCount > 5)
                result.Reasons.Add($"عدد كبير من APIs الخطيرة: {features.DangerousApiCount}");

            if (features.SuspiciousDllCount > 3)
                result.Reasons.Add($"DLLs مشبوهة: {features.SuspiciousDllCount}");

            if (features.HasDigitalSignature == 0)
                result.Reasons.Add("غير موقّع رقمياً");
        }
    }
}
