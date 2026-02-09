using ShieldAI.Core.ML;
using ShieldAI.Core.Models;
using ShieldAI.Core.Detection;

namespace ShieldAI.Core.Scanning;

/// <summary>
/// فاحص الملفات الرئيسي
/// يدمج تحليل PE مع التعلم الآلي للكشف عن البرمجيات الخبيثة
/// </summary>
public class FileScanner
{
    private readonly PEAnalyzer _peAnalyzer;
    private readonly MalwareClassifier _classifier;
    private readonly SignatureDatabase _signatureDb;
    private readonly FeatureExtractor _featureExtractor;

    // الامتدادات القابلة للفحص
    private static readonly HashSet<string> ScannableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1",
        ".vbs", ".js", ".jse", ".wsf", ".wsh", ".msi", ".msp",
        // إضافة امتدادات أخرى شائعة
        ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".zip", ".rar", ".7z",
        ".lnk", ".pif", ".jar", ".py", ".rb", ".php", ".asp", ".aspx"
    };

    /// <summary>
    /// حدث عند اكتمال فحص ملف
    /// </summary>
    public event EventHandler<LegacyScanResult>? FileScanCompleted;
    
    /// <summary>
    /// حدث عند اكتشاف تهديد
    /// </summary>
    public event EventHandler<LegacyScanResult>? ThreatDetected;
    
    /// <summary>
    /// حدث لتتبع التقدم
    /// </summary>
    public event EventHandler<FileScanProgressEventArgs>? ScanProgress;

    public FileScanner(SignatureDatabase? signatureDb = null, MalwareClassifier? classifier = null)
    {
        _peAnalyzer = new PEAnalyzer();
        _featureExtractor = new FeatureExtractor(_peAnalyzer);
        _classifier = classifier ?? new MalwareClassifier();
        _signatureDb = signatureDb ?? new SignatureDatabase();
    }

    /// <summary>
    /// فحص ملف واحد
    /// </summary>
    public async Task<LegacyScanResult> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
#pragma warning disable CS0618 // LegacyScanResult is obsolete
        var result = new LegacyScanResult
        {
            FilePath = filePath,
            ScanTime = DateTime.Now
        };
#pragma warning restore CS0618

        try
        {
            // التحقق من وجود الملف
            if (!File.Exists(filePath))
            {
                result.ErrorMessage = "الملف غير موجود";
                return result;
            }

            var fileInfo = new FileInfo(filePath);
            result.FileSize = fileInfo.Length;

            // التحقق من الامتداد
            var extension = fileInfo.Extension.ToLowerInvariant();
            if (!ScannableExtensions.Contains(extension))
            {
                // ملف غير قابل للفحص - نعتبره آمنًا
                result.IsInfected = false;
                result.IsSuspicious = false;
                result.RiskScore = 0;
                return result;
            }

            // حساب بصمة الملف
            var hash = PEAnalyzer.CalculateSha256(filePath);

            // البحث في قاعدة البيانات أولاً
            var signatureMatch = _signatureDb.CheckHash(hash);
            if (signatureMatch != null && signatureMatch.Signature.ThreatLevel != ShieldAI.Core.Detection.ThreatLevel.None)
            {
                result.IsInfected = true;
                result.RiskScore = 1.0f;
                result.Threat = new ThreatInfo
                {
                    Name = signatureMatch.Signature.MalwareName,
                    Type = ThreatType.Unknown,
                    Severity = (int)signatureMatch.Signature.ThreatLevel * 25,
                    FileHash = hash,
                    Description = signatureMatch.Signature.Description ?? "تم اكتشاف هذا الملف في قاعدة البيانات كبرمجية خبيثة معروفة"
                };
                
                ThreatDetected?.Invoke(this, result);
                FileScanCompleted?.Invoke(this, result);
                return result;
            }

            // إذا كان في القائمة البيضاء (ThreatLevel.None)
            // if (signatureMatch != null && signatureMatch.Signature.ThreatLevel == ThreatLevel.None)
            // {
            //      TODO: Handle Whitelist
            // }

            // تحليل PE إذا كان ملف تنفيذي
            if (extension == ".exe" || extension == ".dll" || extension == ".sys")
            {
                await Task.Run(() => ScanPEFile(filePath, result), cancellationToken);
            }
            else
            {
                // لملفات السكريبت نستخدم فحص مبسط
                ScanScriptFile(filePath, result);
            }
        }
        catch (UnauthorizedAccessException)
        {
            result.ErrorMessage = "لا توجد صلاحية للوصول إلى الملف";
        }
        catch (IOException ex)
        {
            result.ErrorMessage = $"خطأ في قراءة الملف: {ex.Message}";
        }
        catch (Exception ex)
        {
            result.ErrorMessage = $"خطأ غير متوقع: {ex.Message}";
        }

        FileScanCompleted?.Invoke(this, result);
        return result;
    }

    /// <summary>
    /// فحص ملف PE
    /// </summary>
    private void ScanPEFile(string filePath, LegacyScanResult result)
    {
        var peInfo = _peAnalyzer.Analyze(filePath);
        
        if (!peInfo.IsValidPE)
        {
            // ليس ملف PE صالح
            result.IsInfected = false;
            result.IsSuspicious = true;
            result.RiskScore = 0.3f;
            return;
        }

        // استخراج الخصائص والتنبؤ
        var features = _featureExtractor.ExtractFeatures(peInfo);
        var prediction = _classifier.Predict(features);

        result.RiskScore = prediction.Probability;
        result.IsInfected = prediction.IsMalware && prediction.Probability > 0.7f;
        result.IsSuspicious = !result.IsInfected && prediction.Probability > 0.4f;

        if (result.IsInfected || result.IsSuspicious)
        {
            result.Threat = new ThreatInfo
            {
                Name = DetermineThreatName(features, prediction),
                Type = DetermineThreatType(features),
                Severity = prediction.Probability * 100,
                FileHash = peInfo.Sha256Hash,
                Description = GenerateThreatDescription(features, peInfo)
            };

            if (result.IsInfected)
            {
                ThreatDetected?.Invoke(this, result);
            }
        }
    }

    /// <summary>
    /// فحص ملف سكريبت
    /// </summary>
    private void ScanScriptFile(string filePath, LegacyScanResult result)
    {
        try
        {
            var content = File.ReadAllText(filePath);
            var suspiciousPatterns = new[]
            {
                "powershell", "invoke-expression", "iex", "downloadstring",
                "webclient", "hidden", "bypass", "encodedcommand",
                "wscript.shell", "cmd /c", "reg add", "schtasks"
            };

            int matchCount = suspiciousPatterns.Count(p => 
                content.Contains(p, StringComparison.OrdinalIgnoreCase));

            result.RiskScore = Math.Min(matchCount * 0.15f, 1f);
            result.IsInfected = result.RiskScore > 0.6f;
            result.IsSuspicious = !result.IsInfected && result.RiskScore > 0.3f;

            if (result.IsInfected || result.IsSuspicious)
            {
                result.Threat = new ThreatInfo
                {
                    Name = "Suspicious.Script",
                    Type = ThreatType.PotentiallyUnwanted,
                    Severity = result.RiskScore * 100,
                    Description = $"سكريبت يحتوي على {matchCount} أنماط مشبوهة"
                };
            }
        }
        catch
        {
            result.RiskScore = 0;
        }
    }

    /// <summary>
    /// فحص مجلد بالكامل
    /// </summary>
    public async Task<List<LegacyScanResult>> ScanDirectoryAsync(
        string directoryPath, 
        bool recursive = true,
        CancellationToken cancellationToken = default)
    {
        var results = new List<LegacyScanResult>();
        
        if (!Directory.Exists(directoryPath))
            return results;

        // استخدام enumeration آمن يتعامل مع مجلدات محمية
        var files = SafeEnumerateFiles(directoryPath, recursive)
            .Where(f => ScannableExtensions.Contains(Path.GetExtension(f).ToLowerInvariant()))
            .ToList();

        int total = files.Count;
        int current = 0;

        foreach (var file in files)
        {
            if (cancellationToken.IsCancellationRequested)
                break;

            current++;
            ScanProgress?.Invoke(this, new FileScanProgressEventArgs(current, total, file));

            try
            {
                var result = await ScanFileAsync(file, cancellationToken);
                results.Add(result);
                FileScanCompleted?.Invoke(this, result);
            }
            catch (Exception)
            {
                // تخطي الملفات التي لا يمكن الوصول إليها
            }
        }

        return results;
    }

    /// <summary>
    /// تعداد آمن للملفات يتعامل مع الأخطاء
    /// </summary>
    private static IEnumerable<string> SafeEnumerateFiles(string path, bool recursive)
    {
        var files = new List<string>();
        
        try
        {
            // الحصول على الملفات في المجلد الحالي
            files.AddRange(Directory.GetFiles(path));
        }
        catch (UnauthorizedAccessException) { }
        catch (PathTooLongException) { }
        catch (IOException) { }

        if (recursive)
        {
            try
            {
                foreach (var dir in Directory.GetDirectories(path))
                {
                    // تخطي مجلدات النظام المحمية
                    var dirName = Path.GetFileName(dir).ToLowerInvariant();
                    if (dirName is "$recycle.bin" or "system volume information" or "windows" or "program files" or "program files (x86)")
                        continue;

                    files.AddRange(SafeEnumerateFiles(dir, true));
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (PathTooLongException) { }
            catch (IOException) { }
        }

        return files;
    }

    /// <summary>
    /// تحديد اسم التهديد
    /// </summary>
    private string DetermineThreatName(MalwareFeatures features, MalwarePrediction prediction)
    {
        if (features.DangerousApiCount > 5)
            return "Trojan.Generic";
        if (features.Entropy > 7.5f)
            return "Packed.Suspicious";
        if (features.SuspiciousDllCount > 4)
            return "Malware.Generic";
        
        return prediction.Probability > 0.8f ? "Malware.HighRisk" : "Suspicious.Generic";
    }

    /// <summary>
    /// تحديد نوع التهديد
    /// </summary>
    private ThreatType DetermineThreatType(MalwareFeatures features)
    {
        if (features.DangerousApiCount > 8)
            return ThreatType.Trojan;
        if (features.Entropy > 7.5f)
            return ThreatType.PotentiallyUnwanted;
        
        return ThreatType.Unknown;
    }

    /// <summary>
    /// توليد وصف التهديد
    /// </summary>
    private string GenerateThreatDescription(MalwareFeatures features, PEFileInfo peInfo)
    {
        var parts = new List<string>();

        if (features.Entropy > 7.0f)
            parts.Add("ملف مشفر أو مضغوط بشكل مشبوه");
        
        if (features.DangerousApiCount > 3)
            parts.Add($"يستخدم {(int)features.DangerousApiCount} APIs خطيرة");
        
        if (features.SuspiciousDllCount > 2)
            parts.Add($"يستورد {(int)features.SuspiciousDllCount} DLLs مشبوهة");
        
        if (features.HasDigitalSignature == 0)
            parts.Add("بدون توقيع رقمي");

        return parts.Count > 0 ? string.Join(". ", parts) : "سلوك مشبوه عام";
    }

    /// <summary>
    /// الحصول على الامتدادات القابلة للفحص
    /// </summary>
    public static IReadOnlySet<string> GetScannableExtensions() => ScannableExtensions;
}

/// <summary>
/// معلومات تقدم الفحص
/// </summary>
public class FileScanProgressEventArgs : EventArgs
{
    public int CurrentFile { get; }
    public int TotalFiles { get; }
    public string CurrentFilePath { get; }
    public int PercentComplete => TotalFiles > 0 ? (CurrentFile * 100) / TotalFiles : 0;

    public FileScanProgressEventArgs(int currentFile, int totalFiles, string currentFilePath)
    {
        CurrentFile = currentFile;
        TotalFiles = totalFiles;
        CurrentFilePath = currentFilePath;
    }
}
