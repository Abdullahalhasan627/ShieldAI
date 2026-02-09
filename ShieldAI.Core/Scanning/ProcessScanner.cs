using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ShieldAI.Core.Models;

namespace ShieldAI.Core.Scanning;

/// <summary>
/// فاحص العمليات الجارية - نسخة محسنة
/// يعتمد على المسار والتوقيع الرقمي والـ Hash بدلاً من الاسم فقط
/// </summary>
public class ProcessScanner
{
    // المسارات الموثوقة
    private static readonly string[] TrustedPaths = 
    {
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
    };

    // المسارات المشبوهة
    private static readonly string[] SuspiciousPaths =
    {
        Path.GetTempPath(),
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
    };

    // العمليات الحرجة التي لا يمكن إنهاؤها
    private static readonly HashSet<string> CriticalProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "csrss", "wininit", "services", "lsass", "smss", 
        "winlogon", "System", "dwm", "svchost"
    };

    // الناشرون الموثوقون
    private static readonly HashSet<string> TrustedPublishers = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft Corporation",
        "Microsoft Windows",
        "Google LLC",
        "Mozilla Corporation",
        "Apple Inc."
    };

    public event EventHandler<ProcessInfo>? SuspiciousProcessDetected;

    /// <summary>
    /// الحصول على قائمة جميع العمليات مع تحليل الموثوقية
    /// </summary>
    public List<ProcessInfo> GetAllProcesses()
    {
        var result = new List<ProcessInfo>();

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                var info = new ProcessInfo
                {
                    ProcessId = proc.Id,
                    ProcessName = proc.ProcessName
                };

                // الذاكرة
                try { info.MemoryUsage = proc.WorkingSet64; } catch { }

                // المسار
                try { info.ExecutablePath = proc.MainModule?.FileName; } catch { }

                // تحليل الموثوقية بناءً على معايير متعددة
                AnalyzeTrust(info);

                result.Add(info);
            }
            catch { }
            finally
            {
                proc.Dispose();
            }
        }

        return result;
    }

    /// <summary>
    /// تحليل موثوقية العملية
    /// </summary>
    private void AnalyzeTrust(ProcessInfo info)
    {
        int trustScore = 0;
        int suspicionScore = 0;

        if (string.IsNullOrEmpty(info.ExecutablePath))
        {
            // لا يوجد مسار - مشبوه قليلاً
            suspicionScore += 1;
            info.IsTrusted = false;
            return;
        }

        // 1. فحص المسار
        var pathLower = info.ExecutablePath.ToLowerInvariant();

        // مسارات موثوقة
        foreach (var trustedPath in TrustedPaths)
        {
            if (!string.IsNullOrEmpty(trustedPath) && 
                pathLower.StartsWith(trustedPath.ToLowerInvariant()))
            {
                trustScore += 2;
                break;
            }
        }

        // مسارات مشبوهة
        foreach (var suspiciousPath in SuspiciousPaths)
        {
            if (!string.IsNullOrEmpty(suspiciousPath) && 
                pathLower.StartsWith(suspiciousPath.ToLowerInvariant()))
            {
                suspicionScore += 2;
                break;
            }
        }

        // 2. فحص التوقيع الرقمي
        var signatureInfo = GetDigitalSignature(info.ExecutablePath);
        if (signatureInfo.IsSigned)
        {
            trustScore += 2;
            
            if (TrustedPublishers.Contains(signatureInfo.Publisher ?? ""))
            {
                trustScore += 3; // ناشر موثوق = ثقة عالية
            }
        }
        else
        {
            suspicionScore += 1; // غير موقع = مشبوه قليلاً
        }

        // 3. حساب الـ Hash للسمعة (يمكن ربطه بقاعدة بيانات لاحقاً)
        try
        {
            info.FileHash = CalculateSha256(info.ExecutablePath);
        }
        catch { }

        // تحديد الحالة النهائية
        info.IsTrusted = trustScore >= 4;
        info.IsSuspicious = suspicionScore >= 2 && trustScore < 3;

        if (info.IsSuspicious)
        {
            SuspiciousProcessDetected?.Invoke(this, info);
        }
    }

    /// <summary>
    /// الحصول على معلومات التوقيع الرقمي
    /// </summary>
    private (bool IsSigned, string? Publisher) GetDigitalSignature(string filePath)
    {
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(filePath);
            var cert2 = new X509Certificate2(cert);
            
            // استخراج اسم الناشر من Subject
            var subject = cert2.Subject;
            var cnStart = subject.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
            if (cnStart >= 0)
            {
                cnStart += 3;
                var cnEnd = subject.IndexOf(',', cnStart);
                var publisher = cnEnd > cnStart 
                    ? subject.Substring(cnStart, cnEnd - cnStart).Trim('"')
                    : subject.Substring(cnStart).Trim('"');
                
                return (true, publisher);
            }
            
            return (true, cert2.Subject);
        }
        catch
        {
            return (false, null);
        }
    }

    /// <summary>
    /// حساب SHA256 للملف
    /// </summary>
    private string CalculateSha256(string filePath)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        var hashBytes = sha256.ComputeHash(stream);
        return Convert.ToHexString(hashBytes);
    }

    /// <summary>
    /// الحصول على العمليات بشكل غير متزامن
    /// </summary>
    public Task<List<ProcessInfo>> GetAllProcessesAsync(CancellationToken cancellationToken = default)
    {
        return Task.Run(() => GetAllProcesses(), cancellationToken);
    }

    /// <summary>
    /// فحص جميع العمليات
    /// </summary>
    public Task<List<ProcessInfo>> ScanAllProcessesAsync(CancellationToken cancellationToken = default)
    {
        return GetAllProcessesAsync(cancellationToken);
    }

    /// <summary>
    /// محاولة إنهاء عملية مع حماية العمليات الحرجة
    /// </summary>
    /// <param name="processId">معرف العملية</param>
    /// <param name="force">تجاوز الحماية (خطير)</param>
    /// <returns>نتيجة المحاولة</returns>
    public TerminateResult TerminateProcess(int processId, bool force = false)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            
            // التحقق من أن العملية ليست حرجة
            if (CriticalProcesses.Contains(process.ProcessName))
            {
                if (!force)
                {
                    return new TerminateResult
                    {
                        Success = false,
                        Reason = TerminateFailReason.CriticalProcess,
                        Message = $"العملية {process.ProcessName} حرجة للنظام ولا يمكن إنهاؤها"
                    };
                }
            }

            // التحقق من أن العملية ليست العملية الحالية
            if (processId == Environment.ProcessId)
            {
                return new TerminateResult
                {
                    Success = false,
                    Reason = TerminateFailReason.SelfTermination,
                    Message = "لا يمكن للتطبيق إنهاء نفسه"
                };
            }

            process.Kill();
            return new TerminateResult
            {
                Success = true,
                Message = $"تم إنهاء العملية {process.ProcessName} بنجاح"
            };
        }
        catch (ArgumentException)
        {
            return new TerminateResult
            {
                Success = false,
                Reason = TerminateFailReason.NotFound,
                Message = "العملية غير موجودة"
            };
        }
        catch (Exception ex)
        {
            return new TerminateResult
            {
                Success = false,
                Reason = TerminateFailReason.AccessDenied,
                Message = $"فشل إنهاء العملية: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// التحقق من أن العملية حرجة
    /// </summary>
    public bool IsCriticalProcess(string processName)
    {
        return CriticalProcesses.Contains(processName);
    }

    /// <summary>
    /// التحقق من أن العملية حرجة بمعرفها
    /// </summary>
    public bool IsCriticalProcess(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return IsCriticalProcess(process.ProcessName);
        }
        catch
        {
            return false;
        }
    }
}

/// <summary>
/// نتيجة محاولة إنهاء عملية
/// </summary>
public class TerminateResult
{
    public bool Success { get; set; }
    public TerminateFailReason Reason { get; set; }
    public string Message { get; set; } = string.Empty;
}

/// <summary>
/// أسباب فشل إنهاء العملية
/// </summary>
public enum TerminateFailReason
{
    None,
    CriticalProcess,
    SelfTermination,
    NotFound,
    AccessDenied
}
