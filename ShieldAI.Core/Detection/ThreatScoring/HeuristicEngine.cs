// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Detection/ThreatScoring/HeuristicEngine.cs
// محرك التحليل السلوكي المتقدم لملفات PE
// =====================================================

using ShieldAI.Core.Models;
using ShieldAI.Core.Scanning;

namespace ShieldAI.Core.Detection.ThreatScoring
{
    /// <summary>
    /// محرك التحليل السلوكي - يحلل خصائص PE ويكتشف السلوك المشبوه
    /// </summary>
    public class HeuristicEngine : IThreatEngine
    {
        public string EngineName => "HeuristicEngine";
        public double DefaultWeight => 0.8;
        public bool IsReady => true;

        // APIs مشبوهة جداً (Process Injection / Code Execution)
        private static readonly HashSet<string> HighRiskApis = new(StringComparer.OrdinalIgnoreCase)
        {
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
            "QueueUserAPC", "SetThreadContext", "NtUnmapViewOfSection", "RtlCreateUserThread",
            "URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToFile",
            "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
            "RegSetValueA", "RegSetValueW", "RegSetValueExA", "RegSetValueExW",
            "RegCreateKeyA", "RegCreateKeyW", "RegCreateKeyExA", "RegCreateKeyExW"
        };

        // APIs متوسطة الخطورة
        private static readonly HashSet<string> MediumRiskApis = new(StringComparer.OrdinalIgnoreCase)
        {
            "CreateProcessA", "CreateProcessW", "CreateProcessAsUserA", "CreateProcessAsUserW",
            "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState",
            "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA",
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContextA",
            "InternetOpenA", "InternetOpenW", "HttpOpenRequestA", "HttpSendRequestA",
            "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW"
        };

        // أسماء Sections مشبوهة
        private static readonly HashSet<string> SuspiciousSectionNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "UPX0", "UPX1", "UPX2", ".packed", ".themida", ".vmp", ".enigma",
            ".aspack", ".adata", ".boom", ".MPRESS", ".nsp0", ".nsp1", ".petite"
        };

        // مسارات تشغيل مشبوهة
        private static readonly string[] SuspiciousPaths = new[]
        {
            @"\temp\", @"\tmp\", @"\appdata\local\temp\", @"\appdata\roaming\",
            @"\downloads\", @"\public\", @"\programdata\",
            @"\windows\temp\", @"\users\public\"
        };

        public Task<ThreatScanResult> ScanAsync(ThreatScanContext context, CancellationToken ct = default)
        {
            var result = new ThreatScanResult { EngineName = EngineName };
            int totalScore = 0;

            try
            {
                // === تحليل PE ===
                if (context.PEInfo != null && context.PEInfo.IsValidPE)
                {
                    totalScore += AnalyzeSuspiciousImports(context.PEInfo, result);
                    totalScore += AnalyzeEntropy(context.PEInfo, result);
                    totalScore += AnalyzeSections(context.PEInfo, result);
                    totalScore += AnalyzeSignature(context, result);
                    totalScore += AnalyzeTimestamp(context.PEInfo, result);
                }

                // === تحليل المسار ===
                totalScore += AnalyzePath(context, result);

                // === تحليل الحجم ===
                totalScore += AnalyzeFileSize(context, result);

                // === تحليل إشارات السياق ===
                totalScore += AnalyzeContextSignals(context, result);

                // تحديد النتيجة النهائية
                result.Score = Math.Clamp(totalScore, 0, 100);

                result.Verdict = result.Score switch
                {
                    >= 70 => EngineVerdict.Malicious,
                    >= 35 => EngineVerdict.Suspicious,
                    _ => EngineVerdict.Clean
                };

                result.Confidence = result.Score >= 50 ? 0.75 : 0.6;
            }
            catch (Exception ex)
            {
                result = ThreatScanResult.Error(EngineName, ex.Message);
            }

            return Task.FromResult(result);
        }

        #region Analysis Methods

        private int AnalyzeSuspiciousImports(PEFileInfo peInfo, ThreatScanResult result)
        {
            int score = 0;

            var highRiskFound = peInfo.ImportedApis
                .Where(api => HighRiskApis.Contains(api))
                .ToList();

            var mediumRiskFound = peInfo.ImportedApis
                .Where(api => MediumRiskApis.Contains(api))
                .ToList();

            if (highRiskFound.Count > 0)
            {
                int apiScore = Math.Min(highRiskFound.Count * 8, 35);
                score += apiScore;
                result.Reasons.Add(
                    $"يستورد {highRiskFound.Count} API عالية الخطورة: {string.Join(", ", highRiskFound.Take(5))}");
                result.Metadata["HighRiskApis"] = highRiskFound;
            }

            if (mediumRiskFound.Count > 0)
            {
                int apiScore = Math.Min(mediumRiskFound.Count * 4, 20);
                score += apiScore;
                result.Reasons.Add(
                    $"يستورد {mediumRiskFound.Count} API متوسطة الخطورة: {string.Join(", ", mediumRiskFound.Take(5))}");
                result.Metadata["MediumRiskApis"] = mediumRiskFound;
            }

            // مجموعات خطيرة (Process Injection pattern)
            bool hasVirtualAlloc = peInfo.ImportedApis.Any(a =>
                a.Contains("VirtualAlloc", StringComparison.OrdinalIgnoreCase));
            bool hasWriteProcess = peInfo.ImportedApis.Any(a =>
                a.Contains("WriteProcessMemory", StringComparison.OrdinalIgnoreCase));
            bool hasCreateThread = peInfo.ImportedApis.Any(a =>
                a.Contains("CreateRemoteThread", StringComparison.OrdinalIgnoreCase) ||
                a.Contains("NtCreateThreadEx", StringComparison.OrdinalIgnoreCase));

            if (hasVirtualAlloc && hasWriteProcess && hasCreateThread)
            {
                score += 20;
                result.Reasons.Add("نمط Process Injection مكتشف (VirtualAlloc + WriteProcessMemory + CreateRemoteThread)");
            }

            return score;
        }

        private int AnalyzeEntropy(PEFileInfo peInfo, ThreatScanResult result)
        {
            int score = 0;

            if (peInfo.Entropy > 7.5)
            {
                score += 25;
                result.Reasons.Add($"إنتروبيا عالية جداً ({peInfo.Entropy:F2}/8.0) - مؤشر قوي على تشفير أو ضغط (Packing)");
            }
            else if (peInfo.Entropy > 7.0)
            {
                score += 15;
                result.Reasons.Add($"إنتروبيا عالية ({peInfo.Entropy:F2}/8.0) - قد يكون الملف مضغوطاً أو مشفراً");
            }
            else if (peInfo.Entropy > 6.5)
            {
                score += 5;
                result.Reasons.Add($"إنتروبيا مرتفعة نسبياً ({peInfo.Entropy:F2}/8.0)");
            }

            return score;
        }

        private int AnalyzeSections(PEFileInfo peInfo, ThreatScanResult result)
        {
            int score = 0;

            // أسماء Sections مشبوهة (Packers)
            var suspiciousSections = peInfo.SectionNames
                .Where(s => SuspiciousSectionNames.Contains(s))
                .ToList();

            if (suspiciousSections.Count > 0)
            {
                score += 20;
                result.Reasons.Add($"أسماء Sections مشبوهة (Packer): {string.Join(", ", suspiciousSections)}");
            }

            // عدد Sections غير طبيعي
            if (peInfo.SectionCount < 2)
            {
                score += 10;
                result.Reasons.Add($"عدد Sections قليل جداً ({peInfo.SectionCount}) - قد يكون ملف مضغوط");
            }
            else if (peInfo.SectionCount > 10)
            {
                score += 8;
                result.Reasons.Add($"عدد Sections كبير غير طبيعي ({peInfo.SectionCount})");
            }

            // أسماء Sections غير قياسية
            var standardNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".text", ".data", ".rdata", ".rsrc", ".reloc", ".bss", ".idata",
                ".edata", ".pdata", ".tls", ".debug", "CODE", "DATA", ".CRT"
            };

            var nonStandard = peInfo.SectionNames
                .Where(s => !standardNames.Contains(s) && !SuspiciousSectionNames.Contains(s))
                .ToList();

            if (nonStandard.Count > 2)
            {
                score += 5;
                result.Reasons.Add($"أسماء Sections غير قياسية: {string.Join(", ", nonStandard)}");
            }

            return score;
        }

        private int AnalyzeSignature(ThreatScanContext context, ThreatScanResult result)
        {
            int score = 0;

            if (context.PEInfo != null && !context.PEInfo.HasDigitalSignature)
            {
                score += 10;
                result.Reasons.Add("الملف غير موقّع رقمياً");
            }
            else if (context.PEInfo?.HasDigitalSignature == true && !context.HasValidSignature)
            {
                score += 15;
                result.Reasons.Add("التوقيع الرقمي غير صالح أو منتهي الصلاحية");
            }

            if (string.IsNullOrEmpty(context.SignerName) && context.PEInfo?.HasDigitalSignature == false)
            {
                score += 5;
                result.Reasons.Add("ناشر غير معروف (Unknown Publisher)");
            }

            return score;
        }

        private int AnalyzeTimestamp(PEFileInfo peInfo, ThreatScanResult result)
        {
            int score = 0;

            if (peInfo.TimeDateStamp.HasValue)
            {
                var age = DateTime.Now - peInfo.TimeDateStamp.Value;

                if (age.TotalDays < 0)
                {
                    score += 10;
                    result.Reasons.Add("تاريخ بناء الملف في المستقبل - قد يكون مزوّراً");
                }
                else if (age.TotalDays > 365 * 30)
                {
                    score += 5;
                    result.Reasons.Add("تاريخ بناء قديم جداً (أكثر من 30 سنة)");
                }
            }

            return score;
        }

        private int AnalyzePath(ThreatScanContext context, ThreatScanResult result)
        {
            int score = 0;
            var lowerPath = context.FilePath.ToLowerInvariant();

            foreach (var suspPath in SuspiciousPaths)
            {
                if (lowerPath.Contains(suspPath, StringComparison.OrdinalIgnoreCase))
                {
                    score += 10;
                    result.Reasons.Add($"تشغيل من مسار مشبوه: {context.Directory}");
                    break;
                }
            }

            // ملف تنفيذي بامتداد مزدوج
            var fileName = context.FileName;
            if (fileName.Count(c => c == '.') > 1)
            {
                var parts = fileName.Split('.');
                var execExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "exe", "scr", "com", "bat", "cmd", "pif", "vbs", "js", "hta", "msi"
                };

                if (parts.Length >= 3 && execExtensions.Contains(parts[^1]))
                {
                    score += 15;
                    result.Reasons.Add($"امتداد مزدوج مشبوه: {fileName}");
                }
            }

            return score;
        }

        private int AnalyzeFileSize(ThreatScanContext context, ThreatScanResult result)
        {
            int score = 0;

            // ملفات تنفيذية صغيرة جداً مشبوهة
            if (context.PEInfo?.IsValidPE == true && context.FileSize < 10 * 1024)
            {
                score += 10;
                result.Reasons.Add($"ملف تنفيذي صغير جداً ({context.FileSize / 1024.0:F1} KB) - قد يكون dropper");
            }

            return score;
        }

        private int AnalyzeContextSignals(ThreatScanContext context, ThreatScanResult result)
        {
            int score = 0;

            // ملف غير موقع في مسار بدء التشغيل = مريب جداً
            if (context.IsStartupLocation && context.IsUnsignedOrUntrustedPublisher)
            {
                score += 20;
                result.Reasons.Add("ملف غير موقّع في مسار بدء التشغيل (Startup) - مريب جداً");
            }
            else if (context.IsStartupLocation)
            {
                score += 8;
                result.Reasons.Add("ملف في مسار بدء التشغيل (Startup)");
            }

            // ملف تنفيذي غير موقع من Temp/AppData
            if (context.IsFromTempOrAppData && context.IsUnsignedOrUntrustedPublisher
                && context.PEInfo?.IsValidPE == true)
            {
                score += 15;
                result.Reasons.Add("ملف تنفيذي غير موقّع من Temp/AppData - نمط dropper شائع");
            }
            else if (context.IsFromTempOrAppData && context.PEInfo?.IsValidPE == true)
            {
                score += 5;
                result.Reasons.Add("ملف تنفيذي من Temp/AppData");
            }

            // ملف تنفيذي جديد جداً وغير موقع
            if (context.PEInfo?.IsValidPE == true && context.IsUnsignedOrUntrustedPublisher)
            {
                var age = DateTime.Now - context.CreationTime;
                if (age.TotalMinutes < 2 && context.CreationTime != DateTime.MinValue)
                {
                    score += 12;
                    result.Reasons.Add("ملف تنفيذي غير موقّع تم إنشاؤه منذ أقل من دقيقتين");
                }
            }

            // فحص overlay (بيانات بعد نهاية PE)
            if (context.PEInfo?.IsValidPE == true && context.FileSize > 0)
            {
                try
                {
                    var peInfo = context.PEInfo;
                    // إذا كان حجم الملف أكبر بكثير من مجموع الـ Sections
                    if (peInfo.SectionCount > 0 && peInfo.FileSize > 0)
                    {
                        double ratio = (double)context.FileSize / peInfo.FileSize;
                        if (ratio > 2.0)
                        {
                            score += 8;
                            result.Reasons.Add($"الملف يحتوي على overlay كبير (بيانات إضافية بعد نهاية PE) - نسبة {ratio:F1}x");
                        }
                    }
                }
                catch { }
            }

            return score;
        }

        #endregion
    }
}
