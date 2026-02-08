using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using ShieldAI.Core.Models;

namespace ShieldAI.Core.Scanning;

/// <summary>
/// محلل ملفات PE (Portable Executable)
/// يقوم بتحليل هيكل الملفات التنفيذية واستخراج المعلومات المهمة
/// </summary>
public class PEAnalyzer
{
    // قائمة الـ DLLs المشبوهة التي تستخدمها البرمجيات الخبيثة عادةً
    private static readonly HashSet<string> SuspiciousDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "ws2_32.dll",      // Networking - للاتصال بالإنترنت
        "wininet.dll",     // Internet - للتحميل من الإنترنت
        "urlmon.dll",      // URL Moniker - للتحميل
        "crypt32.dll",     // Cryptography - للتشفير
        "advapi32.dll",    // Advanced API - للتعامل مع الريجستري
        "ntdll.dll",       // NT Layer - للوصول المباشر للنظام
        "kernel32.dll"     // Kernel - موجود في كل البرامج لكن بعض الاستخدامات مشبوهة
    };

    // قائمة الـ APIs الخطيرة
    private static readonly HashSet<string> DangerousApis = new(StringComparer.OrdinalIgnoreCase)
    {
        // Process Injection
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
        
        // Code Execution
        "ShellExecute", "ShellExecuteEx", "WinExec", "CreateProcess",
        "CreateProcessAsUser", "CreateProcessWithLogon",
        
        // Registry Manipulation
        "RegSetValue", "RegSetValueEx", "RegCreateKey", "RegCreateKeyEx",
        
        // File Operations
        "DeleteFile", "MoveFile", "CopyFile", "CreateFile",
        
        // Network Operations
        "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
        "URLDownloadToFile", "socket", "connect", "send", "recv",
        
        // Keylogging
        "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
        
        // Privilege Escalation
        "AdjustTokenPrivileges", "OpenProcessToken",
        
        // Anti-Debug
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        
        // Encryption (Ransomware)
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext"
    };

    /// <summary>
    /// تحليل ملف PE واستخراج معلوماته
    /// </summary>
    public PEFileInfo Analyze(string filePath)
    {
        var info = new PEFileInfo
        {
            FileSize = new FileInfo(filePath).Length
        };

        try
        {
            // حساب بصمة الملف
            info.Sha256Hash = CalculateSha256(filePath);

            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var peReader = new PEReader(stream);

            if (!peReader.HasMetadata && peReader.PEHeaders == null)
            {
                info.IsValidPE = false;
                return info;
            }

            info.IsValidPE = true;
            var headers = peReader.PEHeaders;

            // نوع الملف
            info.FileType = headers.IsDll ? "DLL" : "EXE";

            // المعمارية
            info.Architecture = headers.CoffHeader.Machine switch
            {
                Machine.I386 => "x86",
                Machine.Amd64 => "x64",
                Machine.Arm64 => "ARM64",
                _ => headers.CoffHeader.Machine.ToString()
            };

            // تاريخ البناء
            var timestamp = headers.CoffHeader.TimeDateStamp;
            if (timestamp > 0)
            {
                info.TimeDateStamp = DateTimeOffset.FromUnixTimeSeconds(timestamp).DateTime;
            }

            // تحليل الـ Sections
            foreach (var section in headers.SectionHeaders)
            {
                info.SectionNames.Add(section.Name);
            }
            info.SectionCount = info.SectionNames.Count;

            // حساب الإنتروبيا
            info.Entropy = CalculateEntropy(filePath);

            // استخراج الـ Imports
            ExtractImports(peReader, info);

            // التحقق من التوقيع الرقمي
            info.HasDigitalSignature = CheckDigitalSignature(filePath);
        }
        catch (BadImageFormatException)
        {
            info.IsValidPE = false;
        }
        catch (Exception)
        {
            info.IsValidPE = false;
        }

        return info;
    }

    /// <summary>
    /// استخراج الـ DLLs والـ APIs المستوردة
    /// </summary>
    private void ExtractImports(PEReader peReader, PEFileInfo info)
    {
        try
        {
            var headers = peReader.PEHeaders;
            var importDirectory = headers.PEHeader?.ImportTableDirectory;
            
            if (importDirectory == null || importDirectory.Value.Size == 0)
                return;

            // قراءة جدول الاستيراد
            var importTableRva = importDirectory.Value.RelativeVirtualAddress;
            var sectionData = peReader.GetSectionData(importTableRva);
            
            if (sectionData.Length == 0)
                return;

            // تحليل بسيط للـ Import Directory
            var reader = sectionData.GetReader();
            
            while (reader.RemainingBytes >= 20)
            {
                var originalFirstThunk = reader.ReadInt32();
                reader.ReadInt32(); // TimeDateStamp
                reader.ReadInt32(); // ForwarderChain
                var nameRva = reader.ReadInt32();
                reader.ReadInt32(); // FirstThunk

                if (nameRva == 0)
                    break;

                try
                {
                    var nameData = peReader.GetSectionData(nameRva);
                    if (nameData.Length > 0)
                    {
                        var nameReader = nameData.GetReader();
                        var dllName = ReadNullTerminatedString(nameReader);
                        if (!string.IsNullOrEmpty(dllName))
                        {
                            info.ImportedDlls.Add(dllName);
                        }
                    }
                }
                catch
                {
                    // تجاهل الأخطاء في قراءة الأسماء
                }
            }
        }
        catch
        {
            // تجاهل الأخطاء في تحليل الـ Imports
        }
    }

    /// <summary>
    /// قراءة سلسلة نصية منتهية بـ null
    /// </summary>
    private string ReadNullTerminatedString(BlobReader reader)
    {
        var bytes = new List<byte>();
        while (reader.RemainingBytes > 0)
        {
            var b = reader.ReadByte();
            if (b == 0)
                break;
            bytes.Add(b);
        }
        return System.Text.Encoding.ASCII.GetString(bytes.ToArray());
    }

    /// <summary>
    /// حساب بصمة SHA256 للملف
    /// </summary>
    public static string CalculateSha256(string filePath)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        var hash = sha256.ComputeHash(stream);
        return Convert.ToHexString(hash);
    }

    /// <summary>
    /// حساب الإنتروبيا للملف
    /// الإنتروبيا العالية (>7) تشير إلى ملف مشفر أو مضغوط
    /// </summary>
    public static double CalculateEntropy(string filePath)
    {
        var data = File.ReadAllBytes(filePath);
        if (data.Length == 0) return 0;

        var frequency = new int[256];
        foreach (var b in data)
        {
            frequency[b]++;
        }

        double entropy = 0;
        foreach (var count in frequency)
        {
            if (count > 0)
            {
                var probability = (double)count / data.Length;
                entropy -= probability * Math.Log2(probability);
            }
        }

        return entropy;
    }

    /// <summary>
    /// التحقق من وجود توقيع رقمي
    /// </summary>
    private bool CheckDigitalSignature(string filePath)
    {
        try
        {
            // استخدام WinTrust للتحقق من التوقيع
            // هذا تطبيق مبسط - في الإنتاج نستخدم WinVerifyTrust API
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var peReader = new PEReader(stream);
            
            var certificateDirectory = peReader.PEHeaders.PEHeader?.CertificateTableDirectory;
            return certificateDirectory?.Size > 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// الحصول على قائمة الـ DLLs المشبوهة
    /// </summary>
    public IReadOnlySet<string> GetSuspiciousDlls() => SuspiciousDlls;

    /// <summary>
    /// الحصول على قائمة الـ APIs الخطيرة
    /// </summary>
    public IReadOnlySet<string> GetDangerousApis() => DangerousApis;

    /// <summary>
    /// التحقق مما إذا كان الملف يستورد DLLs مشبوهة
    /// </summary>
    public int CountSuspiciousDlls(PEFileInfo info)
    {
        return info.ImportedDlls.Count(dll => SuspiciousDlls.Contains(dll));
    }

    /// <summary>
    /// التحقق مما إذا كان الملف يستورد APIs خطيرة
    /// </summary>
    public int CountDangerousApis(PEFileInfo info)
    {
        return info.ImportedApis.Count(api => DangerousApis.Contains(api));
    }
}
