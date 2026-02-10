// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Detection/ThreatScoring/ReputationEngine.cs
// محرك السمعة - يقيّم الملف بناءً على الناشر والمسار
// =====================================================

namespace ShieldAI.Core.Detection.ThreatScoring
{
    /// <summary>
    /// محرك السمعة - يقيّم الملف بناءً على الناشر والمسار والخصائص العامة
    /// </summary>
    public class ReputationEngine : IThreatEngine
    {
        public string EngineName => "ReputationEngine";
        public double DefaultWeight => 0.5;
        public bool IsReady => true;

        private readonly ReputationCache _cache = new(TimeSpan.FromMinutes(30));
        private readonly LocalPrevalenceStore _prevalenceStore = new();

        // ناشرون موثوقون
        private static readonly HashSet<string> TrustedPublishers = new(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft Corporation", "Microsoft Windows",
            "Google LLC", "Google Inc",
            "Mozilla Corporation",
            "Apple Inc.",
            "Adobe Inc.", "Adobe Systems Incorporated",
            "Oracle Corporation",
            "Intel Corporation",
            "NVIDIA Corporation",
            "Advanced Micro Devices",
            "Valve Corp.",
            "Realtek Semiconductor",
            "Logitech"
        };

        // مسارات موثوقة
        private static readonly string[] TrustedPaths = new[]
        {
            @"C:\Windows\",
            @"C:\Program Files\",
            @"C:\Program Files (x86)\",
            @"C:\Windows\System32\",
            @"C:\Windows\SysWOW64\"
        };

        // مسارات مشبوهة
        private static readonly string[] SuspiciousPaths = new[]
        {
            @"\Temp\", @"\Tmp\",
            @"\AppData\Local\Temp\",
            @"\AppData\Roaming\",
            @"\Users\Public\",
            @"\ProgramData\",
            @"\Downloads\"
        };

        // امتدادات عالية الخطورة
        private static readonly HashSet<string> HighRiskExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".scr", ".pif", ".com", ".hta", ".vbs", ".wsf", ".wsh",
            ".ps1", ".bat", ".cmd", ".reg", ".msi", ".msp"
        };

        public Task<ThreatScanResult> ScanAsync(ThreatScanContext context, CancellationToken ct = default)
        {
            var result = new ThreatScanResult { EngineName = EngineName };
            int score = 0;

            try
            {
                if (!string.IsNullOrWhiteSpace(context.Sha256Hash) &&
                    _cache.TryGet(context.Sha256Hash, out var cached))
                {
                    result.Score = cached!.Score;
                    result.Verdict = result.Score >= 40 ? EngineVerdict.Suspicious : EngineVerdict.Clean;
                    result.Reasons.AddRange(cached.Reasons);
                    result.Confidence = 0.5;
                    return Task.FromResult(result);
                }

                UpdateSignatureInfo(context, result);

                // === تقييم الناشر ===
                score += EvaluatePublisher(context, result);

                // === تقييم المسار ===
                score += EvaluatePath(context, result);

                // === تقييم الامتداد ===
                score += EvaluateExtension(context, result);

                // === تقييم العمر ===
                score += EvaluateAge(context, result);

                // === تقييم الانتشار المحلي ===
                score += EvaluatePrevalence(context, result);

                result.Score = Math.Clamp(score, 0, 100);

                result.Verdict = result.Score switch
                {
                    >= 60 => EngineVerdict.Suspicious,
                    >= 40 => EngineVerdict.Suspicious,
                    _ => EngineVerdict.Clean
                };

                result.Confidence = 0.5; // محرك السمعة أقل ثقة من المحركات الأخرى

                if (!string.IsNullOrWhiteSpace(context.Sha256Hash))
                {
                    _cache.Store(context.Sha256Hash, new ReputationResult
                    {
                        Score = result.Score,
                        Reasons = new List<string>(result.Reasons),
                        IsSigned = context.HasValidSignature,
                        SignerName = context.SignerName
                    });
                }
            }
            catch (Exception ex)
            {
                result = ThreatScanResult.Error(EngineName, ex.Message);
            }

            return Task.FromResult(result);
        }

        private int EvaluatePublisher(ThreatScanContext context, ThreatScanResult result)
        {
            int score = 0;

            if (!string.IsNullOrEmpty(context.SignerName))
            {
                if (TrustedPublishers.Contains(context.SignerName))
                {
                    score -= 20; // خصم نقاط للناشر الموثوق
                    result.Reasons.Add($"ناشر موثوق: {context.SignerName}");
                }
                else if (context.HasValidSignature)
                {
                    score -= 10;
                    result.Reasons.Add($"موقّع رقمياً بواسطة: {context.SignerName}");
                }
            }
            else
            {
                if (context.PEInfo?.IsValidPE == true)
                {
                    score += 15;
                    result.Reasons.Add("ملف تنفيذي بدون ناشر معروف");
                }
            }

            return score;
        }

        private void UpdateSignatureInfo(ThreatScanContext context, ThreatScanResult result)
        {
            if (!File.Exists(context.FilePath))
                return;

            try
            {
                var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(context.FilePath);
                if (cert != null)
                {
                    var x509 = new System.Security.Cryptography.X509Certificates.X509Certificate2(cert);
                    context.SignerName = x509.SubjectName.Name;
                    context.HasValidSignature = true;
                    result.Reasons.Add($"توقيع رقمي: {x509.Subject}");
                }
            }
            catch
            {
                // unsigned or invalid
            }
        }

        private int EvaluatePath(ThreatScanContext context, ThreatScanResult result)
        {
            int score = 0;
            var filePath = context.FilePath;

            // مسار موثوق
            foreach (var trusted in TrustedPaths)
            {
                if (filePath.StartsWith(trusted, StringComparison.OrdinalIgnoreCase))
                {
                    score -= 10;
                    result.Reasons.Add($"مسار موثوق: {trusted}");
                    return score;
                }
            }

            // مسار مشبوه
            foreach (var suspicious in SuspiciousPaths)
            {
                if (filePath.Contains(suspicious, StringComparison.OrdinalIgnoreCase))
                {
                    score += 15;
                    result.Reasons.Add($"مسار مشبوه: يحتوي على {suspicious.Trim('\\')}");
                    break;
                }
            }

            return score;
        }

        private int EvaluateExtension(ThreatScanContext context, ThreatScanResult result)
        {
            int score = 0;

            if (HighRiskExtensions.Contains(context.Extension))
            {
                score += 15;
                result.Reasons.Add($"امتداد عالي الخطورة: {context.Extension}");
            }

            return score;
        }

        private int EvaluateAge(ThreatScanContext context, ThreatScanResult result)
        {
            int score = 0;

            if (context.CreationTime != DateTime.MinValue)
            {
                var age = DateTime.Now - context.CreationTime;

                if (age.TotalMinutes < 5)
                {
                    score += 10;
                    result.Reasons.Add("ملف جديد جداً (أقل من 5 دقائق)");
                }
                else if (age.TotalHours < 1)
                {
                    score += 5;
                    result.Reasons.Add("ملف جديد (أقل من ساعة)");
                }
            }

            return score;
        }

        private int EvaluatePrevalence(ThreatScanContext context, ThreatScanResult result)
        {
            if (string.IsNullOrWhiteSpace(context.Sha256Hash))
                return 0;

            var entry = _prevalenceStore.Record(context.Sha256Hash);
            context.LocalSeenCount = entry.SeenCount;
            context.LastSeenTime = entry.LastSeenUtc;

            if (entry.SeenCount <= 1)
            {
                result.Reasons.Add("ملف نادر محلياً (مرّة واحدة)");
                return 10;
            }

            if ((DateTime.UtcNow - entry.FirstSeenUtc).TotalDays > 7 && entry.SeenCount > 5)
            {
                result.Reasons.Add("ملف شائع محلياً منذ مدة");
                return -5;
            }

            return 0;
        }
    }
}
