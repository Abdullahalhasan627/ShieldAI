// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Detection/HeuristicAnalyzer.cs
// التحليل السلوكي للملفات
// =====================================================

using ShieldAI.Core.Scanning;
using ShieldAI.Core.Models;
using ShieldAI.Core.Logging;

namespace ShieldAI.Core.Detection
{
    /// <summary>
    /// المحلل السلوكي - يكتشف البرمجيات الخبيثة بناءً على سلوكها وخصائصها
    /// </summary>
    public class HeuristicAnalyzer
    {
        private readonly ILogger? _logger;
        private readonly PEAnalyzer _peAnalyzer;

        // قوائم APIs الخطيرة
        private static readonly HashSet<string> DangerousApis = new(StringComparer.OrdinalIgnoreCase)
        {
            // Process Injection
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
            "QueueUserAPC", "SetThreadContext", "NtUnmapViewOfSection",
            
            // Keylogging
            "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState",
            "RegisterRawInputDevices",
            
            // Anti-Debug
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "OutputDebugStringA", "OutputDebugStringW",
            
            // Privilege Escalation
            "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA",
            
            // Persistence
            "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
            
            // Network
            "InternetOpenA", "InternetOpenW", "URLDownloadToFileA", "URLDownloadToFileW",
            "WinHttpOpen", "HttpOpenRequestA",
            
            // Crypto (Ransomware)
            "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContextA",
            
            // File Operations
            "DeleteFileA", "DeleteFileW", "MoveFileA", "MoveFileW",
            "CreateFileA", "CreateFileW", "WriteFile",
            
            // Service
            "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW"
        };

        // أسماء Packers المعروفة
        private static readonly HashSet<string> KnownPackers = new(StringComparer.OrdinalIgnoreCase)
        {
            "UPX", "Themida", "VMProtect", "Armadillo", "ASPack", "PECompact",
            "FSG", "MEW", "MPRESS", "Obsidium", "Enigma", "PEtite"
        };

        // أنماط مشبوهة في Section Names
        private static readonly HashSet<string> SuspiciousSectionNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "UPX0", "UPX1", "UPX2", ".packed", ".themida", ".vmp", ".enigma",
            ".aspack", ".adata", ".boom", ".MPRESS"
        };

        public HeuristicAnalyzer(ILogger? logger = null)
        {
            _logger = logger;
            _peAnalyzer = new PEAnalyzer();
        }

        /// <summary>
        /// تحليل ملف وإرجاع النتيجة السلوكية
        /// </summary>
        public HeuristicResult Analyze(string filePath)
        {
            var result = new HeuristicResult { FilePath = filePath };

            try
            {
                if (!File.Exists(filePath))
                {
                    result.Error = "الملف غير موجود";
                    return result;
                }

                var fileInfo = new FileInfo(filePath);
                result.FileSize = fileInfo.Length;

                // تحليل PE إذا كان ملف تنفيذي
                var peInfo = _peAnalyzer.Analyze(filePath);
                if (peInfo != null && peInfo.IsValidPE)
                {
                    result.IsPE = true;
                    AnalyzePEFile(result, peInfo);
                }
                else
                {
                    // تحليل ملف غير PE
                    AnalyzeNonPEFile(result, filePath);
                }

                // حساب درجة الخطورة الإجمالية
                CalculateRiskScore(result);
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                _logger?.Error(ex, "خطأ أثناء التحليل السلوكي: {0}", filePath);
            }

            return result;
        }

        #region Private Methods
        private void AnalyzePEFile(HeuristicResult result, PEFileInfo peInfo)
        {
            // 1. فحص الـ Entropy (الملفات المشفرة/المضغوطة لها entropy عالي)
            result.Entropy = peInfo.Entropy;
            if (peInfo.Entropy > 7.0)
            {
                result.Indicators.Add(new HeuristicIndicator
                {
                    Name = "High Entropy",
                    Description = "الملف يحتوي على درجة عشوائية عالية (قد يكون مشفر أو مضغوط)",
                    Severity = IndicatorSeverity.Medium,
                    Score = 25
                });
            }

            // 2. فحص Sections
            foreach (var section in peInfo.SectionNames)
            {
                if (SuspiciousSectionNames.Contains(section))
                {
                    result.IsPacked = true;
                    result.Indicators.Add(new HeuristicIndicator
                    {
                        Name = "Packed Executable",
                        Description = $"تم اكتشاف Packer: {section}",
                        Severity = IndicatorSeverity.Medium,
                        Score = 20
                    });
                    break;
                }
            }

            // 3. فحص APIs الخطيرة
            var dangerousApisFound = peInfo.ImportedApis
                .Where(api => DangerousApis.Contains(api))
                .ToList();

            if (dangerousApisFound.Count > 0)
            {
                var severity = dangerousApisFound.Count switch
                {
                    > 10 => IndicatorSeverity.Critical,
                    > 5 => IndicatorSeverity.High,
                    > 2 => IndicatorSeverity.Medium,
                    _ => IndicatorSeverity.Low
                };

                result.DangerousApiCount = dangerousApisFound.Count;
                result.Indicators.Add(new HeuristicIndicator
                {
                    Name = "Dangerous APIs",
                    Description = $"تم اكتشاف {dangerousApisFound.Count} APIs خطيرة: {string.Join(", ", dangerousApisFound.Take(5))}",
                    Severity = severity,
                    Score = Math.Min(dangerousApisFound.Count * 5, 40)
                });
            }

            // 4. فحص التوقيع الرقمي
            if (!peInfo.HasDigitalSignature)
            {
                result.Indicators.Add(new HeuristicIndicator
                {
                    Name = "No Digital Signature",
                    Description = "الملف غير موقع رقمياً",
                    Severity = IndicatorSeverity.Low,
                    Score = 10
                });
            }

            // 5. عدد Sections غير طبيعي
            if (peInfo.SectionCount < 2 || peInfo.SectionCount > 10)
            {
                result.Indicators.Add(new HeuristicIndicator
                {
                    Name = "Unusual Section Count",
                    Description = $"عدد Sections غير طبيعي: {peInfo.SectionCount}",
                    Severity = IndicatorSeverity.Low,
                    Score = 10
                });
            }

            // 6. فحص التاريخ
            if (peInfo.TimeDateStamp.HasValue)
            {
                var age = DateTime.Now - peInfo.TimeDateStamp.Value;
                if (age.TotalDays < 0 || age.TotalDays > 365 * 30) // مستقبلي أو قديم جداً
                {
                    result.Indicators.Add(new HeuristicIndicator
                    {
                        Name = "Suspicious Timestamp",
                        Description = "تاريخ البناء غير منطقي",
                        Severity = IndicatorSeverity.Low,
                        Score = 5
                    });
                }
            }
        }

        private void AnalyzeNonPEFile(HeuristicResult result, string filePath)
        {
            var extension = Path.GetExtension(filePath).ToLower();
            var content = "";

            // قراءة محتوى للملفات النصية
            if (IsTextFile(extension))
            {
                try
                {
                    content = File.ReadAllText(filePath);
                    AnalyzeScriptContent(result, content, extension);
                }
                catch { }
            }

            // فحص امتدادات مشبوهة
            if (IsSuspiciousExtension(extension))
            {
                result.Indicators.Add(new HeuristicIndicator
                {
                    Name = "Suspicious Extension",
                    Description = $"امتداد مشبوه: {extension}",
                    Severity = IndicatorSeverity.Medium,
                    Score = 15
                });
            }
        }

        private void AnalyzeScriptContent(HeuristicResult result, string content, string extension)
        {
            var suspiciousPatterns = new Dictionary<string, string>
            {
                { @"powershell.*-enc", "PowerShell Encoded Command" },
                { @"Invoke-Expression", "PowerShell Code Execution" },
                { @"DownloadString|DownloadFile", "Remote Download" },
                { @"WScript\.Shell", "Script Shell Execution" },
                { @"CreateObject\s*\(\s*[""']WScript", "VBS Shell" },
                { @"base64", "Base64 Encoding" },
                { @"eval\s*\(", "Dynamic Code Execution" },
                { @"cmd\s*/c", "Command Execution" }
            };

            foreach (var pattern in suspiciousPatterns)
            {
                if (System.Text.RegularExpressions.Regex.IsMatch(content, pattern.Key, 
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                {
                    result.Indicators.Add(new HeuristicIndicator
                    {
                        Name = pattern.Value,
                        Description = $"تم اكتشاف نمط مشبوه في {extension}",
                        Severity = IndicatorSeverity.High,
                        Score = 25
                    });
                }
            }
        }

        private void CalculateRiskScore(HeuristicResult result)
        {
            result.TotalScore = result.Indicators.Sum(i => i.Score);
            
            result.RiskLevel = result.TotalScore switch
            {
                >= 70 => ThreatLevel.Critical,
                >= 50 => ThreatLevel.High,
                >= 30 => ThreatLevel.Medium,
                >= 10 => ThreatLevel.Low,
                _ => ThreatLevel.None
            };

            result.IsSuspicious = result.TotalScore >= 30;
            result.IsMalicious = result.TotalScore >= 50;
        }

        private bool IsTextFile(string extension) => extension switch
        {
            ".ps1" or ".bat" or ".cmd" or ".vbs" or ".js" or ".hta" => true,
            ".txt" or ".xml" or ".json" or ".ini" or ".cfg" => true,
            _ => false
        };

        private bool IsSuspiciousExtension(string extension) => extension switch
        {
            ".scr" or ".pif" or ".com" or ".hta" or ".vbs" or ".wsf" => true,
            ".ps1" or ".bat" or ".cmd" or ".reg" or ".msi" => true,
            _ => false
        };
        #endregion
    }

    #region Models
    /// <summary>
    /// نتيجة التحليل السلوكي
    /// </summary>
    public class HeuristicResult
    {
        public string FilePath { get; set; } = "";
        public long FileSize { get; set; }
        public bool IsPE { get; set; }
        public double Entropy { get; set; }
        public bool IsPacked { get; set; }
        public int DangerousApiCount { get; set; }
        public List<HeuristicIndicator> Indicators { get; set; } = new();
        public int TotalScore { get; set; }
        public ThreatLevel RiskLevel { get; set; }
        public bool IsSuspicious { get; set; }
        public bool IsMalicious { get; set; }
        public string? Error { get; set; }
    }

    /// <summary>
    /// مؤشر سلوكي
    /// </summary>
    public class HeuristicIndicator
    {
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public IndicatorSeverity Severity { get; set; }
        public int Score { get; set; }
    }

    /// <summary>
    /// شدة المؤشر
    /// </summary>
    public enum IndicatorSeverity
    {
        Info,
        Low,
        Medium,
        High,
        Critical
    }
    #endregion
}
