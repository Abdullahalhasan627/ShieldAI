using System.Security.Cryptography;
using System.Text.Json;

namespace ShieldAI.Core.Monitoring;

/// <summary>
/// مدير الحجر الصحي
/// ينقل الملفات المشبوهة إلى مجلد آمن ويشفرها
/// </summary>
public class QuarantineManager
{
    private readonly string _quarantinePath;
    private readonly string _metadataPath;
    private Dictionary<string, QuarantineEntry> _quarantinedFiles;
    private readonly object _lock = new();

    // مفتاح التشفير البسيط (في الإنتاج نستخدم مفتاح آمن)
    private static readonly byte[] EncryptionKey = new byte[32] 
    { 
        0x53, 0x68, 0x69, 0x65, 0x6C, 0x64, 0x41, 0x49,
        0x51, 0x75, 0x61, 0x72, 0x61, 0x6E, 0x74, 0x69,
        0x6E, 0x65, 0x4B, 0x65, 0x79, 0x32, 0x30, 0x32,
        0x34, 0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26
    };

    public QuarantineManager(string? customPath = null)
    {
        _quarantinePath = customPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ShieldAI", "Quarantine");

        _metadataPath = Path.Combine(_quarantinePath, "metadata.json");
        _quarantinedFiles = new Dictionary<string, QuarantineEntry>();

        EnsureQuarantineDirectory();
        LoadMetadata();
    }

    /// <summary>
    /// نقل ملف للحجر الصحي
    /// </summary>
    public async Task<bool> QuarantineFileAsync(string filePath)
    {
        if (!File.Exists(filePath)) return false;

        try
        {
            var fileInfo = new FileInfo(filePath);
            var quarantineId = Guid.NewGuid().ToString("N");
            var quarantineFilePath = Path.Combine(_quarantinePath, quarantineId + ".qar");

            // قراءة الملف الأصلي
            var originalData = await File.ReadAllBytesAsync(filePath);

            // تشفير البيانات
            var encryptedData = Encrypt(originalData);

            // حفظ الملف المشفر
            await File.WriteAllBytesAsync(quarantineFilePath, encryptedData);

            // حذف الملف الأصلي
            File.Delete(filePath);

            // حفظ البيانات الوصفية
            var entry = new QuarantineEntry
            {
                Id = quarantineId,
                OriginalPath = filePath,
                OriginalName = fileInfo.Name,
                OriginalSize = fileInfo.Length,
                QuarantineTime = DateTime.Now,
                FileHash = CalculateHash(originalData)
            };

            lock (_lock)
            {
                _quarantinedFiles[quarantineId] = entry;
            }

            SaveMetadata();
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// استعادة ملف من الحجر الصحي
    /// </summary>
    public async Task<bool> RestoreFileAsync(string quarantineId, string? restorePath = null)
    {
        QuarantineEntry? entry;
        
        lock (_lock)
        {
            if (!_quarantinedFiles.TryGetValue(quarantineId, out entry))
                return false;
        }

        var quarantineFilePath = Path.Combine(_quarantinePath, quarantineId + ".qar");
        if (!File.Exists(quarantineFilePath)) 
            throw new FileNotFoundException($"ملف الحجر غير موجود: {quarantineFilePath}");

        // قراءة الملف المشفر
        var encryptedData = await File.ReadAllBytesAsync(quarantineFilePath);

        // فك التشفير
        var originalData = Decrypt(encryptedData);

        // تحديد مسار الاستعادة
        var targetPath = restorePath ?? entry.OriginalPath;
        
        // التأكد من وجود المجلد
        var directory = Path.GetDirectoryName(targetPath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // إذا كان الملف موجودًا، نضيف رقم
        if (File.Exists(targetPath))
        {
            var baseName = Path.GetFileNameWithoutExtension(targetPath);
            var extension = Path.GetExtension(targetPath);
            var dir = Path.GetDirectoryName(targetPath) ?? "";
            int counter = 1;
            
            while (File.Exists(targetPath))
            {
                targetPath = Path.Combine(dir, $"{baseName}_{counter}{extension}");
                counter++;
            }
        }

        // كتابة الملف المستعاد
        await File.WriteAllBytesAsync(targetPath, originalData);

        // حذف ملف الحجر
        File.Delete(quarantineFilePath);

        // إزالة من القائمة
        lock (_lock)
        {
            _quarantinedFiles.Remove(quarantineId);
        }

        SaveMetadata();
        return true;
    }

    /// <summary>
    /// حذف ملف من الحجر نهائيًا
    /// </summary>
    public bool DeleteQuarantinedFile(string quarantineId)
    {
        lock (_lock)
        {
            if (!_quarantinedFiles.ContainsKey(quarantineId))
                return false;

            var quarantineFilePath = Path.Combine(_quarantinePath, quarantineId + ".qar");
            
            try
            {
                if (File.Exists(quarantineFilePath))
                {
                    File.Delete(quarantineFilePath);
                }

                _quarantinedFiles.Remove(quarantineId);
                SaveMetadata();
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// الحصول على قائمة الملفات المحجورة
    /// </summary>
    public IReadOnlyList<QuarantineEntry> GetQuarantinedFiles()
    {
        lock (_lock)
        {
            return _quarantinedFiles.Values.ToList();
        }
    }

    /// <summary>
    /// عدد الملفات المحجورة
    /// </summary>
    public int Count
    {
        get { lock (_lock) { return _quarantinedFiles.Count; } }
    }

    /// <summary>
    /// مسح جميع الملفات المحجورة
    /// </summary>
    public void ClearAll()
    {
        lock (_lock)
        {
            foreach (var entry in _quarantinedFiles.Values)
            {
                var filePath = Path.Combine(_quarantinePath, entry.Id + ".qar");
                try
                {
                    if (File.Exists(filePath))
                        File.Delete(filePath);
                }
                catch { }
            }

            _quarantinedFiles.Clear();
            SaveMetadata();
        }
    }

    /// <summary>
    /// تشفير البيانات
    /// </summary>
    private byte[] Encrypt(byte[] data)
    {
        using var aes = Aes.Create();
        aes.Key = EncryptionKey;
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor();
        var encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);

        // دمج IV مع البيانات المشفرة
        var result = new byte[aes.IV.Length + encryptedData.Length];
        Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
        Buffer.BlockCopy(encryptedData, 0, result, aes.IV.Length, encryptedData.Length);

        return result;
    }

    /// <summary>
    /// فك تشفير البيانات
    /// </summary>
    private byte[] Decrypt(byte[] encryptedData)
    {
        using var aes = Aes.Create();
        aes.Key = EncryptionKey;

        // استخراج IV
        var iv = new byte[16];
        Buffer.BlockCopy(encryptedData, 0, iv, 0, 16);
        aes.IV = iv;

        // فك التشفير
        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(encryptedData, 16, encryptedData.Length - 16);
    }

    /// <summary>
    /// حساب بصمة البيانات
    /// </summary>
    private string CalculateHash(byte[] data)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(data);
        return Convert.ToHexString(hash);
    }

    /// <summary>
    /// التأكد من وجود مجلد الحجر
    /// </summary>
    private void EnsureQuarantineDirectory()
    {
        if (!Directory.Exists(_quarantinePath))
        {
            Directory.CreateDirectory(_quarantinePath);
        }
    }

    /// <summary>
    /// تحميل البيانات الوصفية
    /// </summary>
    private void LoadMetadata()
    {
        lock (_lock)
        {
            try
            {
                if (File.Exists(_metadataPath))
                {
                    var json = File.ReadAllText(_metadataPath);
                    _quarantinedFiles = JsonSerializer.Deserialize<Dictionary<string, QuarantineEntry>>(json) 
                        ?? new Dictionary<string, QuarantineEntry>();

                    // إصلاح البيانات القديمة التي تحتوي على تواريخ فارغة
                    bool needsSave = false;
                    foreach (var entry in _quarantinedFiles.Values)
                    {
                        if (entry.QuarantineTime == DateTime.MinValue)
                        {
                            entry.QuarantineTime = DateTime.Now;
                            needsSave = true;
                        }
                    }
                    if (needsSave) SaveMetadata();
                }
            }
            catch
            {
                _quarantinedFiles = new Dictionary<string, QuarantineEntry>();
            }
        }
    }

    /// <summary>
    /// حفظ البيانات الوصفية
    /// </summary>
    private void SaveMetadata()
    {
        lock (_lock)
        {
            try
            {
                var json = JsonSerializer.Serialize(_quarantinedFiles, new JsonSerializerOptions
                {
                    WriteIndented = true
                });
                File.WriteAllText(_metadataPath, json);
            }
            catch
            {
                // تجاهل أخطاء الحفظ
            }
        }
    }
}

/// <summary>
/// بيانات ملف محجور
/// </summary>
public class QuarantineEntry
{
    public string Id { get; set; } = string.Empty;
    public string OriginalPath { get; set; } = string.Empty;
    public string OriginalName { get; set; } = string.Empty;
    public long OriginalSize { get; set; }
    public DateTime QuarantineTime { get; set; } = DateTime.Now;
    public string FileHash { get; set; } = string.Empty;
}
