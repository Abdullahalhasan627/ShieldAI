// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Detection/ThreatScoring/SignatureEngine.cs
// محرك التوقيعات - يربط مع SignatureDatabase
// =====================================================

namespace ShieldAI.Core.Detection.ThreatScoring
{
    /// <summary>
    /// محرك التوقيعات - يفحص الملف ضد قاعدة بيانات التوقيعات المعروفة
    /// </summary>
    public class SignatureEngine : IThreatEngine
    {
        private readonly SignatureDatabase _signatureDb;

        public string EngineName => "SignatureEngine";
        public double DefaultWeight => 1.0;
        public bool IsReady => _signatureDb.Count > 0;

        public SignatureEngine(SignatureDatabase signatureDb)
        {
            _signatureDb = signatureDb;
        }

        public Task<ThreatScanResult> ScanAsync(ThreatScanContext context, CancellationToken ct = default)
        {
            var result = new ThreatScanResult { EngineName = EngineName };

            try
            {
                SignatureMatch? match = null;

                // فحص بالـ Hash أولاً (أسرع)
                if (!string.IsNullOrEmpty(context.Sha256Hash))
                {
                    match = _signatureDb.CheckHash(context.Sha256Hash);
                }

                if (match == null && !string.IsNullOrEmpty(context.Md5Hash))
                {
                    match = _signatureDb.CheckHash(context.Md5Hash);
                }

                // فحص بالملف مباشرة إذا لم نجد بالـ Hash
                if (match == null && File.Exists(context.FilePath))
                {
                    match = _signatureDb.CheckFile(context.FilePath);
                }

                if (match != null)
                {
                    result.Score = 100;
                    result.Verdict = EngineVerdict.Malicious;
                    result.Confidence = 1.0;

                    result.Reasons.Add($"تطابق مع توقيع معروف: {match.Signature.MalwareName}");
                    result.Reasons.Add($"عائلة البرمجية الخبيثة: {match.Signature.MalwareFamily}");
                    result.Reasons.Add($"نوع المطابقة: {match.HashType}");

                    if (!string.IsNullOrEmpty(match.Signature.Description))
                    {
                        result.Reasons.Add(match.Signature.Description);
                    }

                    result.Metadata["MalwareName"] = match.Signature.MalwareName;
                    result.Metadata["MalwareFamily"] = match.Signature.MalwareFamily;
                    result.Metadata["HashType"] = match.HashType;
                }
                else
                {
                    result.Score = 0;
                    result.Verdict = EngineVerdict.Clean;
                    result.Confidence = 0.7;
                }
            }
            catch (Exception ex)
            {
                result = ThreatScanResult.Error(EngineName, ex.Message);
            }

            return Task.FromResult(result);
        }
    }
}
