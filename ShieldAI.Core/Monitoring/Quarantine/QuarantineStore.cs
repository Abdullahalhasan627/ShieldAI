// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Monitoring/Quarantine/QuarantineStore.cs
// مخزن الحجر الصحي الآمن مع DPAPI + metadata كاملة
// =====================================================

using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ShieldAI.Core.Detection.ThreatScoring;

namespace ShieldAI.Core.Monitoring.Quarantine
{
    /// <summary>
    /// مخزن الحجر الصحي - يدير تشفير/فك تشفير الملفات مع metadata شاملة
    /// </summary>
    public class QuarantineStore : IDisposable
    {
        private readonly string _quarantinePath;
        private readonly string _metadataPath;
        private readonly string _metadataHmacPath;
        private readonly QuarantineCrypto _crypto;
        private Dictionary<string, QuarantineItemMetadata> _items;
        private readonly object _lock = new();
        private bool _disposed;

        public QuarantineStore(string? quarantinePath = null)
        {
            _quarantinePath = quarantinePath ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "ShieldAI", "Quarantine");

            _metadataPath = Path.Combine(_quarantinePath, "metadata.json");
            _metadataHmacPath = Path.Combine(_quarantinePath, "metadata.hmac");
            _crypto = new QuarantineCrypto(_quarantinePath);
            _items = new Dictionary<string, QuarantineItemMetadata>();

            EnsureDirectory();
            LoadMetadata();
        }

        /// <summary>
        /// عدد العناصر المحجورة
        /// </summary>
        public int Count
        {
            get { lock (_lock) { return _items.Count; } }
        }

        /// <summary>
        /// حجر ملف مع نتيجة فحص مجمّعة
        /// </summary>
        public async Task<QuarantineItemMetadata?> QuarantineFileAsync(
            string filePath,
            AggregatedThreatResult? scanResult = null)
        {
            if (!File.Exists(filePath))
                return null;

            try
            {
                var fileInfo = new FileInfo(filePath);

                // إنشاء metadata
                var metadata = scanResult != null
                    ? QuarantineItemMetadata.FromAggregatedResult(filePath, scanResult)
                    : new QuarantineItemMetadata
                    {
                        OriginalPath = filePath,
                        OriginalName = fileInfo.Name,
                        FileSize = fileInfo.Length,
                        Verdict = "Manual"
                    };

                var quarantineFileName = metadata.Id + ".qar";
                metadata.QuarantineFileName = quarantineFileName;

                var quarantineFilePath = Path.Combine(_quarantinePath, quarantineFileName);

                // قراءة الملف الأصلي
                var originalData = await File.ReadAllBytesAsync(filePath);

                // حساب SHA256
                metadata.Sha256Hash = QuarantineCrypto.ComputeSha256(originalData);

                // تشفير وحفظ
                var encryptedData = _crypto.Encrypt(originalData);
                await File.WriteAllBytesAsync(quarantineFilePath, encryptedData);

                // حذف الملف الأصلي
                File.Delete(filePath);

                // حفظ metadata
                lock (_lock)
                {
                    _items[metadata.Id] = metadata;
                }

                await SaveMetadataAsync();

                return metadata;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// استعادة ملف من الحجر مع تحقق hash
        /// </summary>
        public async Task<bool> RestoreFileAsync(string itemId, string? restorePath = null)
        {
            QuarantineItemMetadata? metadata;

            lock (_lock)
            {
                if (!_items.TryGetValue(itemId, out metadata))
                    return false;
            }

            var quarantineFilePath = Path.Combine(_quarantinePath, metadata.QuarantineFileName);
            if (!File.Exists(quarantineFilePath))
                return false;

            try
            {
                // قراءة وفك التشفير
                var encryptedData = await File.ReadAllBytesAsync(quarantineFilePath);
                var originalData = _crypto.Decrypt(encryptedData);

                // تحقق hash قبل الإرجاع
                var currentHash = QuarantineCrypto.ComputeSha256(originalData);
                if (!string.IsNullOrEmpty(metadata.Sha256Hash) &&
                    !currentHash.Equals(metadata.Sha256Hash, StringComparison.OrdinalIgnoreCase))
                {
                    throw new CryptographicException(
                        "فشل التحقق من سلامة الملف - البصمة لا تتطابق مع الأصل");
                }

                // تحديد مسار الاستعادة
                var targetPath = restorePath ?? metadata.OriginalPath;
                if (!IsRestorePathSafe(targetPath) && !IsCurrentUserAdmin())
                {
                    throw new UnauthorizedAccessException("مسار الاستعادة غير آمن ويتطلب صلاحيات Admin");
                }

                // التأكد من وجود المجلد
                var directory = Path.GetDirectoryName(targetPath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                    Directory.CreateDirectory(directory);

                // إذا كان الملف موجودًا، نضيف رقم
                targetPath = GetUniqueFilePath(targetPath);

                // كتابة الملف المستعاد
                await File.WriteAllBytesAsync(targetPath, originalData);

                // حذف ملف الحجر
                File.Delete(quarantineFilePath);

                // تحديث metadata
                lock (_lock)
                {
                    metadata.IsRestored = true;
                    metadata.RestoredAt = DateTime.Now;
                    _items.Remove(itemId);
                }

                await SaveMetadataAsync();
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// حذف ملف من الحجر نهائياً
        /// </summary>
        public async Task<bool> DeleteFileAsync(string itemId)
        {
            lock (_lock)
            {
                if (!_items.ContainsKey(itemId))
                    return false;
            }

            try
            {
                QuarantineItemMetadata metadata;
                lock (_lock)
                {
                    metadata = _items[itemId];
                }

                var quarantineFilePath = Path.Combine(_quarantinePath, metadata.QuarantineFileName);
                if (File.Exists(quarantineFilePath))
                    File.Delete(quarantineFilePath);

                lock (_lock)
                {
                    _items.Remove(itemId);
                }

                await SaveMetadataAsync();
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// الحصول على جميع العناصر المحجورة
        /// </summary>
        public IReadOnlyList<QuarantineItemMetadata> GetAllItems()
        {
            lock (_lock)
            {
                return _items.Values.ToList();
            }
        }

        /// <summary>
        /// الحصول على عنصر بالمعرف
        /// </summary>
        public QuarantineItemMetadata? GetItem(string itemId)
        {
            lock (_lock)
            {
                return _items.TryGetValue(itemId, out var item) ? item : null;
            }
        }

        /// <summary>
        /// مسح جميع العناصر
        /// </summary>
        public async Task ClearAllAsync()
        {
            lock (_lock)
            {
                foreach (var item in _items.Values)
                {
                    var filePath = Path.Combine(_quarantinePath, item.QuarantineFileName);
                    try { if (File.Exists(filePath)) File.Delete(filePath); } catch { }
                }
                _items.Clear();
            }

            await SaveMetadataAsync();
        }

        #region Private Methods

        private void EnsureDirectory()
        {
            if (!Directory.Exists(_quarantinePath))
                Directory.CreateDirectory(_quarantinePath);

            ApplyDirectoryAcl(_quarantinePath);
        }

        private void LoadMetadata()
        {
            lock (_lock)
            {
                try
                {
                    if (File.Exists(_metadataPath))
                    {
                        if (!ValidateMetadataHmac())
                        {
                            _items = new Dictionary<string, QuarantineItemMetadata>();
                            return;
                        }

                        var json = File.ReadAllText(_metadataPath);
                        _items = JsonSerializer.Deserialize<Dictionary<string, QuarantineItemMetadata>>(json)
                            ?? new Dictionary<string, QuarantineItemMetadata>();
                    }
                }
                catch
                {
                    _items = new Dictionary<string, QuarantineItemMetadata>();
                }
            }
        }

        private async Task SaveMetadataAsync()
        {
            try
            {
                string json;
                lock (_lock)
                {
                    json = JsonSerializer.Serialize(_items, new JsonSerializerOptions
                    {
                        WriteIndented = true
                    });
                }

                await File.WriteAllTextAsync(_metadataPath, json, Encoding.UTF8);
                await SaveMetadataHmacAsync(json);
            }
            catch
            {
                // تجاهل أخطاء الحفظ
            }
        }

        private async Task SaveMetadataHmacAsync(string json)
        {
            var hmac = _crypto.ComputeHmac(Encoding.UTF8.GetBytes(json));
            await File.WriteAllTextAsync(_metadataHmacPath, Convert.ToBase64String(hmac), Encoding.UTF8);
        }

        private bool ValidateMetadataHmac()
        {
            if (!File.Exists(_metadataHmacPath))
                return false;

            try
            {
                var json = File.ReadAllText(_metadataPath, Encoding.UTF8);
                var expectedBase64 = File.ReadAllText(_metadataHmacPath, Encoding.UTF8);
                var expected = Convert.FromBase64String(expectedBase64);
                var actual = _crypto.ComputeHmac(Encoding.UTF8.GetBytes(json));
                return CryptographicOperations.FixedTimeEquals(expected, actual);
            }
            catch
            {
                return false;
            }
        }

        private static void ApplyDirectoryAcl(string path)
        {
            try
            {
                var dirInfo = new DirectoryInfo(path);
                var security = dirInfo.GetAccessControl();
                security.SetAccessRuleProtection(true, false);

                var rules = security.GetAccessRules(true, true, typeof(NTAccount));
                foreach (FileSystemAccessRule rule in rules)
                {
                    security.RemoveAccessRule(rule);
                }

                security.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                security.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                dirInfo.SetAccessControl(security);
            }
            catch
            {
                // ignore ACL errors
            }
        }

        private static bool IsRestorePathSafe(string path)
        {
            var fullPath = Path.GetFullPath(path);
            var temp = Path.GetFullPath(Path.GetTempPath());
            var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);

            if (fullPath.StartsWith(temp, StringComparison.OrdinalIgnoreCase))
                return false;

            if (!string.IsNullOrEmpty(startup) &&
                fullPath.StartsWith(Path.GetFullPath(startup), StringComparison.OrdinalIgnoreCase))
                return false;

            return true;
        }

        private static bool IsCurrentUserAdmin()
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private static string GetUniqueFilePath(string targetPath)
        {
            if (!File.Exists(targetPath))
                return targetPath;

            var baseName = Path.GetFileNameWithoutExtension(targetPath);
            var extension = Path.GetExtension(targetPath);
            var dir = Path.GetDirectoryName(targetPath) ?? "";
            int counter = 1;

            while (File.Exists(targetPath))
            {
                targetPath = Path.Combine(dir, $"{baseName}_{counter}{extension}");
                counter++;
            }

            return targetPath;
        }

        #endregion

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
        }
    }
}
