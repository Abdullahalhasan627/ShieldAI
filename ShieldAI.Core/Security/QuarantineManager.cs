// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Core/Security/QuarantineManager.cs
// مدير الحجر الصحي
// =====================================================

using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using ShieldAI.Core.Configuration;
using ShieldAI.Core.Models;

namespace ShieldAI.Core.Security
{
    /// <summary>
    /// مدير الحجر الصحي - نقل وحفظ واستعادة الملفات الخبيثة
    /// </summary>
    public class QuarantineManager
    {
        private readonly ILogger? _logger;
        private readonly AppSettings _settings;
        private readonly string _quarantinePath;
        private readonly object _lock = new();

        public QuarantineManager(ILogger? logger = null)
        {
            _logger = logger;
            _settings = ConfigManager.Instance.Settings;
            _quarantinePath = _settings.QuarantinePath;
            
            EnsureQuarantineFolder();
        }

        /// <summary>
        /// التأكد من وجود مجلد الحجر مع ACL
        /// </summary>
        private void EnsureQuarantineFolder()
        {
            try
            {
                if (!Directory.Exists(_quarantinePath))
                {
                    Directory.CreateDirectory(_quarantinePath);
                    ApplyACLHardening(_quarantinePath);
                    _logger?.LogInformation("تم إنشاء مجلد الحجر: {Path}", _quarantinePath);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "فشل إنشاء مجلد الحجر: {Path}", _quarantinePath);
            }
        }

        /// <summary>
        /// تطبيق ACL صارم على مجلد الحجر
        /// </summary>
        private void ApplyACLHardening(string path)
        {
            try
            {
                var dirInfo = new DirectoryInfo(path);
                var security = dirInfo.GetAccessControl();
                
                // إزالة الوراثة
                security.SetAccessRuleProtection(true, false);
                
                // حذف جميع القواعد الموجودة
                var rules = security.GetAccessRules(true, true, typeof(NTAccount));
                foreach (FileSystemAccessRule rule in rules)
                {
                    security.RemoveAccessRule(rule);
                }
                
                // إضافة SYSTEM
                security.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));
                
                // إضافة Administrators
                security.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));
                
                dirInfo.SetAccessControl(security);
                _logger?.LogDebug("تم تطبيق ACL على مجلد الحجر");
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "فشل تطبيق ACL على مجلد الحجر");
            }
        }

        /// <summary>
        /// نقل ملف إلى الحجر
        /// </summary>
        public async Task<QuarantineEntry?> QuarantineFileAsync(
            string filePath, 
            ScanResult scanResult,
            CancellationToken ct = default)
        {
            lock (_lock)
            {
                try
                {
                    if (!File.Exists(filePath))
                    {
                        _logger?.LogWarning("الملف غير موجود: {Path}", filePath);
                        return null;
                    }

                    var entry = new QuarantineEntry
                    {
                        Id = Guid.NewGuid(),
                        OriginalPath = filePath,
                        OriginalName = Path.GetFileName(filePath),
                        SHA256 = scanResult.SHA256 ?? "",
                        MD5 = scanResult.MD5 ?? "",
                        FileSize = scanResult.FileSize,
                        ThreatName = scanResult.ThreatName ?? "Unknown",
                        Verdict = scanResult.Verdict.ToString(),
                        RiskScore = scanResult.RiskScore,
                        QuarantinedAt = DateTime.Now
                    };

                    // اسم الملف في الحجر
                    var quarantineFileName = $"{entry.Id}.qfile";
                    var quarantineFilePath = Path.Combine(_quarantinePath, quarantineFileName);
                    var manifestPath = Path.Combine(_quarantinePath, $"{entry.Id}.json");

                    // نقل الملف
                    File.Move(filePath, quarantineFilePath);
                    entry.QuarantinePath = quarantineFilePath;

                    // حفظ الـ Manifest
                    var json = JsonSerializer.Serialize(entry, new JsonSerializerOptions 
                    { 
                        WriteIndented = true 
                    });
                    File.WriteAllText(manifestPath, json);

                    _logger?.LogInformation("تم حجر الملف: {Original} -> {Quarantine}", 
                        filePath, quarantineFilePath);

                    return entry;
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "فشل حجر الملف: {Path}", filePath);
                    return null;
                }
            }
        }

        /// <summary>
        /// استعادة ملف من الحجر
        /// </summary>
        public bool RestoreFile(Guid entryId, string? restorePath = null)
        {
            lock (_lock)
            {
                try
                {
                    var entry = GetEntry(entryId);
                    if (entry == null)
                    {
                        _logger?.LogWarning("لم يتم العثور على الملف في الحجر: {Id}", entryId);
                        return false;
                    }

                    var targetPath = restorePath ?? entry.OriginalPath;
                    var quarantineFilePath = Path.Combine(_quarantinePath, $"{entryId}.qfile");

                    if (!File.Exists(quarantineFilePath))
                    {
                        _logger?.LogWarning("ملف الحجر غير موجود: {Path}", quarantineFilePath);
                        return false;
                    }

                    // التأكد من عدم وجود ملف بنفس الاسم
                    if (File.Exists(targetPath))
                    {
                        var dir = Path.GetDirectoryName(targetPath) ?? "";
                        var name = Path.GetFileNameWithoutExtension(targetPath);
                        var ext = Path.GetExtension(targetPath);
                        targetPath = Path.Combine(dir, $"{name}_restored{ext}");
                    }

                    // إنشاء المجلد إذا لم يكن موجوداً
                    var targetDir = Path.GetDirectoryName(targetPath);
                    if (!string.IsNullOrEmpty(targetDir) && !Directory.Exists(targetDir))
                    {
                        Directory.CreateDirectory(targetDir);
                    }

                    // نقل الملف
                    File.Move(quarantineFilePath, targetPath);

                    // حذف الـ Manifest
                    var manifestPath = Path.Combine(_quarantinePath, $"{entryId}.json");
                    if (File.Exists(manifestPath))
                    {
                        File.Delete(manifestPath);
                    }

                    _logger?.LogInformation("تم استعادة الملف: {Id} -> {Path}", entryId, targetPath);
                    return true;
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "فشل استعادة الملف: {Id}", entryId);
                    return false;
                }
            }
        }

        /// <summary>
        /// حذف ملف من الحجر نهائياً
        /// </summary>
        public bool DeleteFile(Guid entryId)
        {
            lock (_lock)
            {
                try
                {
                    var quarantineFilePath = Path.Combine(_quarantinePath, $"{entryId}.qfile");
                    var manifestPath = Path.Combine(_quarantinePath, $"{entryId}.json");

                    if (File.Exists(quarantineFilePath))
                    {
                        File.Delete(quarantineFilePath);
                    }

                    if (File.Exists(manifestPath))
                    {
                        File.Delete(manifestPath);
                    }

                    _logger?.LogInformation("تم حذف الملف من الحجر: {Id}", entryId);
                    return true;
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "فشل حذف الملف من الحجر: {Id}", entryId);
                    return false;
                }
            }
        }

        /// <summary>
        /// الحصول على جميع الملفات المحجورة
        /// </summary>
        public List<QuarantineEntry> GetAllEntries()
        {
            var entries = new List<QuarantineEntry>();
            
            try
            {
                var manifestFiles = Directory.GetFiles(_quarantinePath, "*.json");
                
                foreach (var file in manifestFiles)
                {
                    try
                    {
                        var json = File.ReadAllText(file);
                        var entry = JsonSerializer.Deserialize<QuarantineEntry>(json);
                        if (entry != null)
                        {
                            entries.Add(entry);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogDebug("فشل قراءة manifest: {File} - {Error}", file, ex.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "فشل قراءة قائمة الحجر");
            }

            return entries.OrderByDescending(e => e.QuarantinedAt).ToList();
        }

        /// <summary>
        /// الحصول على ملف محجور بواسطة ID
        /// </summary>
        public QuarantineEntry? GetEntry(Guid entryId)
        {
            try
            {
                var manifestPath = Path.Combine(_quarantinePath, $"{entryId}.json");
                if (!File.Exists(manifestPath))
                    return null;

                var json = File.ReadAllText(manifestPath);
                return JsonSerializer.Deserialize<QuarantineEntry>(json);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// الحصول على عدد الملفات المحجورة
        /// </summary>
        public int GetCount()
        {
            try
            {
                return Directory.GetFiles(_quarantinePath, "*.json").Length;
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// حذف جميع الملفات المحجورة
        /// </summary>
        public int ClearAll()
        {
            int count = 0;
            lock (_lock)
            {
                try
                {
                    var files = Directory.GetFiles(_quarantinePath);
                    foreach (var file in files)
                    {
                        try
                        {
                            File.Delete(file);
                            count++;
                        }
                        catch { }
                    }
                    
                    _logger?.LogInformation("تم حذف {Count} ملف من الحجر", count);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "فشل تنظيف الحجر");
                }
            }
            return count / 2; // كل ملف له manifest
        }
    }

    /// <summary>
    /// سجل ملف محجور
    /// </summary>
    public class QuarantineEntry
    {
        public Guid Id { get; set; }
        public string OriginalPath { get; set; } = "";
        public string OriginalName { get; set; } = "";
        public string QuarantinePath { get; set; } = "";
        public string SHA256 { get; set; } = "";
        public string MD5 { get; set; } = "";
        public long FileSize { get; set; }
        public string ThreatName { get; set; } = "";
        public string Verdict { get; set; } = "";
        public double RiskScore { get; set; }
        public DateTime QuarantinedAt { get; set; }
    }
}
