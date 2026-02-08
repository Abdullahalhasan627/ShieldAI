using System.Diagnostics;
using ShieldAI.Core.Models;
using ShieldAI.Core.Detection;

namespace ShieldAI.Core.Scanning;

/// <summary>
/// فاحص العمليات الجارية
/// يراقب العمليات النشطة ويتحقق من سلامتها
/// </summary>
public class ProcessScanner
{
    private readonly FileScanner _fileScanner;
    private readonly SignatureDatabase _signatureDb;

    // قائمة العمليات الموثوقة من Microsoft
    private static readonly HashSet<string> TrustedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe", "svchost.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "smss.exe", "dwm.exe",
        "taskmgr.exe", "notepad.exe", "mmc.exe", "devenv.exe",
        "code.exe", "chrome.exe", "firefox.exe", "msedge.exe"
    };

    /// <summary>
    /// حدث عند اكتشاف عملية مشبوهة
    /// </summary>
    public event EventHandler<ProcessInfo>? SuspiciousProcessDetected;

    public ProcessScanner(FileScanner? fileScanner = null, SignatureDatabase? signatureDb = null)
    {
        _signatureDb = signatureDb ?? new SignatureDatabase();
        _fileScanner = fileScanner ?? new FileScanner(_signatureDb);
    }

    /// <summary>
    /// الحصول على قائمة جميع العمليات
    /// </summary>
    public async Task<List<ProcessInfo>> GetAllProcessesAsync(CancellationToken cancellationToken = default)
    {
        var processes = new List<ProcessInfo>();
        
        var systemProcesses = Process.GetProcesses();

        foreach (var process in systemProcesses)
        {
            if (cancellationToken.IsCancellationRequested)
                break;

            try
            {
                var info = await GetProcessInfoAsync(process, cancellationToken);
                if (info != null)
                {
                    processes.Add(info);
                }
            }
            catch
            {
                // تجاهل العمليات التي لا يمكن الوصول إليها
            }
            finally
            {
                process.Dispose();
            }
        }

        return processes;
    }

    /// <summary>
    /// الحصول على معلومات عملية واحدة
    /// </summary>
    public async Task<ProcessInfo?> GetProcessInfoAsync(Process process, CancellationToken cancellationToken = default)
    {
        try
        {
            var info = new ProcessInfo
            {
                ProcessId = process.Id,
                ProcessName = process.ProcessName,
                MemoryUsage = process.WorkingSet64
            };

            // محاولة الحصول على مسار الملف
            try
            {
                info.ExecutablePath = process.MainModule?.FileName;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // لا يمكن الوصول لمسار العملية (يتطلب صلاحيات أعلى)
            }

            // التحقق من كونها عملية موثوقة
            info.IsTrusted = IsTrustedProcess(info.ProcessName);

            // حساب البصمة إن أمكن
            if (!string.IsNullOrEmpty(info.ExecutablePath) && File.Exists(info.ExecutablePath))
            {
                info.FileHash = await Task.Run(() => 
                    PEAnalyzer.CalculateSha256(info.ExecutablePath), cancellationToken);
            }

            return info;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// فحص جميع العمليات
    /// </summary>
    public async Task<List<ProcessInfo>> ScanAllProcessesAsync(CancellationToken cancellationToken = default)
    {
        var processes = await GetAllProcessesAsync(cancellationToken);
        var results = new List<ProcessInfo>();

        foreach (var process in processes)
        {
            if (cancellationToken.IsCancellationRequested)
                break;

            // تخطي العمليات بدون مسار
            if (string.IsNullOrEmpty(process.ExecutablePath))
            {
                results.Add(process);
                continue;
            }

            // التحقق من قاعدة البيانات
            if (!string.IsNullOrEmpty(process.FileHash))
            {
                var signatureMatch = _signatureDb.CheckHash(process.FileHash);
                if (signatureMatch != null)
                {
                    if (signatureMatch.Signature.ThreatLevel != ShieldAI.Core.Detection.ThreatLevel.None)
                    {
                        process.IsSuspicious = true;
                        process.IsTrusted = false;
                        SuspiciousProcessDetected?.Invoke(this, process);
                    }
                    else
                    {
                        // Whitelisted (ThreatLevel.None)
                         process.IsTrusted = true;
                         process.IsSuspicious = false;
                    }
                }
            }

            // فحص الملف إذا لم يكن موثوقًا
            if (!process.IsTrusted && File.Exists(process.ExecutablePath))
            {
                var scanResult = await _fileScanner.ScanFileAsync(process.ExecutablePath, cancellationToken);
                process.ScanResult = scanResult;
                
                if (scanResult.IsInfected)
                {
                    process.IsSuspicious = true;
                    SuspiciousProcessDetected?.Invoke(this, process);
                }
                else if (scanResult.IsSuspicious)
                {
                    process.IsSuspicious = true;
                }
            }

            results.Add(process);
        }

        return results;
    }

    /// <summary>
    /// فحص عملية بمعرفها
    /// </summary>
    public async Task<ProcessInfo?> ScanProcessAsync(int processId, CancellationToken cancellationToken = default)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            var info = await GetProcessInfoAsync(process, cancellationToken);
            
            if (info != null && !string.IsNullOrEmpty(info.ExecutablePath))
            {
                var scanResult = await _fileScanner.ScanFileAsync(info.ExecutablePath, cancellationToken);
                info.ScanResult = scanResult;
                info.IsSuspicious = scanResult.IsInfected || scanResult.IsSuspicious;
            }

            return info;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// إنهاء عملية
    /// </summary>
    public bool TerminateProcess(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            process.Kill();
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// التحقق من كون العملية موثوقة
    /// </summary>
    private bool IsTrustedProcess(string processName)
    {
        var name = processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) 
            ? processName 
            : processName + ".exe";
            
        return TrustedProcesses.Contains(name);
    }

    /// <summary>
    /// الحصول على العمليات المشبوهة فقط
    /// </summary>
    public async Task<List<ProcessInfo>> GetSuspiciousProcessesAsync(CancellationToken cancellationToken = default)
    {
        var allProcesses = await ScanAllProcessesAsync(cancellationToken);
        return allProcesses.Where(p => p.IsSuspicious).ToList();
    }

    /// <summary>
    /// مراقبة العمليات الجديدة
    /// </summary>
    public async Task MonitorNewProcessesAsync(CancellationToken cancellationToken)
    {
        var knownProcessIds = new HashSet<int>();

        // الحصول على العمليات الحالية
        foreach (var process in Process.GetProcesses())
        {
            knownProcessIds.Add(process.Id);
            process.Dispose();
        }

        // مراقبة العمليات الجديدة
        while (!cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(1000, cancellationToken);

            foreach (var process in Process.GetProcesses())
            {
                if (!knownProcessIds.Contains(process.Id))
                {
                    knownProcessIds.Add(process.Id);
                    
                    var info = await ScanProcessAsync(process.Id, cancellationToken);
                    if (info?.IsSuspicious == true)
                    {
                        SuspiciousProcessDetected?.Invoke(this, info);
                    }
                }
                process.Dispose();
            }

            // تنظيف العمليات المنتهية
            var currentIds = Process.GetProcesses().Select(p => { var id = p.Id; p.Dispose(); return id; }).ToHashSet();
            knownProcessIds.IntersectWith(currentIds);
        }
    }
}
