// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Detection/DefenderScanner.cs
// محرك Microsoft Defender كرأي ثانٍ
// =====================================================

using System.Diagnostics;
using System.Text.RegularExpressions;

namespace ShieldAI.Core.Detection
{
    /// <summary>
    /// ماسح Windows Defender - يستدعي MpCmdRun.exe للفحص
    /// يستخدم كمحرك رأي ثانٍ في التحليل العميق
    /// </summary>
    public class DefenderScanner
    {
        private readonly int _timeoutSeconds;
        private string? _mpCmdRunPath;

        /// <summary>
        /// هل Defender متاح على النظام
        /// </summary>
        public bool IsAvailable => FindMpCmdRunPath() != null;

        public DefenderScanner(int timeoutSeconds = 60)
        {
            _timeoutSeconds = timeoutSeconds;
        }

        /// <summary>
        /// البحث عن مسار MpCmdRun.exe
        /// </summary>
        public string? FindMpCmdRunPath()
        {
            if (_mpCmdRunPath != null)
                return _mpCmdRunPath;

            // المسار الأساسي
            var defaultPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Windows Defender", "MpCmdRun.exe");

            if (File.Exists(defaultPath))
            {
                _mpCmdRunPath = defaultPath;
                return _mpCmdRunPath;
            }

            // مسار Platform الأحدث
            var platformFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Microsoft", "Windows Defender", "Platform");

            if (Directory.Exists(platformFolder))
            {
                try
                {
                    // الحصول على أحدث إصدار
                    var latestVersion = Directory.GetDirectories(platformFolder)
                        .OrderByDescending(d => d)
                        .FirstOrDefault();

                    if (latestVersion != null)
                    {
                        var platformPath = Path.Combine(latestVersion, "MpCmdRun.exe");
                        if (File.Exists(platformPath))
                        {
                            _mpCmdRunPath = platformPath;
                            return _mpCmdRunPath;
                        }
                    }
                }
                catch
                {
                    // تجاهل أخطاء الوصول
                }
            }

            return null;
        }

        /// <summary>
        /// فحص ملف باستخدام Windows Defender
        /// </summary>
        /// <param name="filePath">مسار الملف</param>
        /// <param name="cancellationToken">رمز الإلغاء</param>
        /// <returns>نتيجة الفحص</returns>
        public async Task<DefenderScanResult> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
        {
            var result = new DefenderScanResult
            {
                FilePath = filePath,
                ScanTime = DateTime.Now
            };

            var mpCmdRunPath = FindMpCmdRunPath();
            if (mpCmdRunPath == null)
            {
                result.IsAvailable = false;
                result.ErrorMessage = "Windows Defender غير متاح على هذا النظام";
                return result;
            }

            result.IsAvailable = true;

            if (!File.Exists(filePath))
            {
                result.ErrorMessage = "الملف غير موجود";
                return result;
            }

            var stopwatch = Stopwatch.StartNew();

            try
            {
                // إعداد العملية
                var startInfo = new ProcessStartInfo
                {
                    FileName = mpCmdRunPath,
                    Arguments = $"-Scan -ScanType 3 -File \"{filePath}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = new Process { StartInfo = startInfo };
                var outputBuilder = new System.Text.StringBuilder();
                var errorBuilder = new System.Text.StringBuilder();

                process.OutputDataReceived += (_, e) =>
                {
                    if (e.Data != null)
                        outputBuilder.AppendLine(e.Data);
                };

                process.ErrorDataReceived += (_, e) =>
                {
                    if (e.Data != null)
                        errorBuilder.AppendLine(e.Data);
                };

                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                // انتظار مع timeout
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(_timeoutSeconds));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

                try
                {
                    await process.WaitForExitAsync(linkedCts.Token);
                }
                catch (OperationCanceledException)
                {
                    try { process.Kill(entireProcessTree: true); } catch { }
                    
                    if (timeoutCts.IsCancellationRequested)
                    {
                        result.ErrorMessage = $"انتهت مهلة الفحص ({_timeoutSeconds} ثانية)";
                        result.TimedOut = true;
                    }
                    else
                    {
                        result.ErrorMessage = "تم إلغاء الفحص";
                    }
                    
                    return result;
                }

                stopwatch.Stop();
                result.Duration = stopwatch.Elapsed;
                result.RawOutput = outputBuilder.ToString();
                result.ExitCode = process.ExitCode;

                // تحليل النتيجة
                ParseResult(result);
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                result.Duration = stopwatch.Elapsed;
                result.ErrorMessage = $"خطأ في التشغيل: {ex.Message}";
            }

            return result;
        }

        /// <summary>
        /// تحليل مخرجات MpCmdRun
        /// </summary>
        private void ParseResult(DefenderScanResult result)
        {
            var output = result.RawOutput ?? "";

            // Exit codes:
            // 0 = No threat found
            // 2 = Threat found
            // Other = Error
            
            switch (result.ExitCode)
            {
                case 0:
                    result.IsThreat = false;
                    result.RiskScore = 0;
                    break;

                case 2:
                    result.IsThreat = true;
                    result.RiskScore = 0.95; // ثقة عالية من Defender

                    // استخراج اسم التهديد
                    var threatMatch = Regex.Match(output, @"Threat\s*:\s*(.+)", RegexOptions.IgnoreCase);
                    if (threatMatch.Success)
                    {
                        result.ThreatName = threatMatch.Groups[1].Value.Trim();
                    }
                    else
                    {
                        // محاولة أخرى
                        threatMatch = Regex.Match(output, @"found\s+(?:malware|threat)\s*[:\-]?\s*(.+)", RegexOptions.IgnoreCase);
                        if (threatMatch.Success)
                        {
                            result.ThreatName = threatMatch.Groups[1].Value.Trim();
                        }
                        else
                        {
                            result.ThreatName = "Threat.Detected.ByDefender";
                        }
                    }

                    // استخراج نوع التهديد
                    var categoryMatch = Regex.Match(output, @"Category\s*:\s*(.+)", RegexOptions.IgnoreCase);
                    if (categoryMatch.Success)
                    {
                        result.ThreatCategory = categoryMatch.Groups[1].Value.Trim();
                    }
                    break;

                default:
                    // خطأ أو حالة غير معروفة
                    if (string.IsNullOrEmpty(result.ErrorMessage))
                    {
                        result.ErrorMessage = $"رمز خروج غير متوقع: {result.ExitCode}";
                    }
                    break;
            }
        }
    }

    /// <summary>
    /// نتيجة فحص Windows Defender
    /// </summary>
    public class DefenderScanResult
    {
        /// <summary>
        /// مسار الملف المفحوص
        /// </summary>
        public string FilePath { get; set; } = "";

        /// <summary>
        /// هل Defender متاح
        /// </summary>
        public bool IsAvailable { get; set; }

        /// <summary>
        /// هل الملف تهديد
        /// </summary>
        public bool IsThreat { get; set; }

        /// <summary>
        /// اسم التهديد المكتشف
        /// </summary>
        public string? ThreatName { get; set; }

        /// <summary>
        /// تصنيف التهديد
        /// </summary>
        public string? ThreatCategory { get; set; }

        /// <summary>
        /// درجة الخطورة (0-1)
        /// </summary>
        public double RiskScore { get; set; }

        /// <summary>
        /// رمز الخروج من MpCmdRun
        /// </summary>
        public int ExitCode { get; set; }

        /// <summary>
        /// المخرجات الخام
        /// </summary>
        public string RawOutput { get; set; } = "";

        /// <summary>
        /// مدة الفحص
        /// </summary>
        public TimeSpan Duration { get; set; }

        /// <summary>
        /// وقت الفحص
        /// </summary>
        public DateTime ScanTime { get; set; }

        /// <summary>
        /// هل انتهت المهلة
        /// </summary>
        public bool TimedOut { get; set; }

        /// <summary>
        /// رسالة خطأ إن وجدت
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// هل الفحص ناجح (بدون أخطاء)
        /// </summary>
        public bool Success => IsAvailable && string.IsNullOrEmpty(ErrorMessage) && !TimedOut;
    }
}
