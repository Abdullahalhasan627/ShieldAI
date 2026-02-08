// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Security/IntegrityChecker.cs
// فحص سلامة الملفات
// =====================================================

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ShieldAI.Core.Logging;

namespace ShieldAI.Core.Security
{
    /// <summary>
    /// فاحص السلامة - يتحقق من سلامة ملفات التطبيق والتوقيعات
    /// </summary>
    public class IntegrityChecker
    {
        private readonly ILogger? _logger;
        private readonly string _hashDatabasePath;
        private Dictionary<string, FileHashInfo> _hashDatabase;

        public IntegrityChecker(ILogger? logger = null, string? hashDatabasePath = null)
        {
            _logger = logger;
            _hashDatabasePath = hashDatabasePath ?? @"C:\ProgramData\ShieldAI\integrity.json";
            _hashDatabase = new Dictionary<string, FileHashInfo>(StringComparer.OrdinalIgnoreCase);
            LoadHashDatabase();
        }

        #region Public Methods
        /// <summary>
        /// حساب hash لملف
        /// </summary>
        public string ComputeFileHash(string filePath, HashAlgorithmType algorithm = HashAlgorithmType.SHA256)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("الملف غير موجود", filePath);

            using var stream = File.OpenRead(filePath);
            using var hashAlgorithm = CreateHashAlgorithm(algorithm);
            var hash = hashAlgorithm.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        /// <summary>
        /// التحقق من سلامة ملف
        /// </summary>
        public IntegrityResult VerifyFile(string filePath)
        {
            var result = new IntegrityResult
            {
                FilePath = filePath,
                CheckTime = DateTime.Now
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    result.Status = IntegrityStatus.Missing;
                    result.Message = "الملف غير موجود";
                    return result;
                }

                var normalizedPath = Path.GetFullPath(filePath).ToLowerInvariant();
                
                if (!_hashDatabase.TryGetValue(normalizedPath, out var storedInfo))
                {
                    result.Status = IntegrityStatus.Unknown;
                    result.Message = "الملف غير مسجل في قاعدة البيانات";
                    return result;
                }

                var currentHash = ComputeFileHash(filePath, storedInfo.Algorithm);
                var fileInfo = new FileInfo(filePath);

                result.ExpectedHash = storedInfo.Hash;
                result.ActualHash = currentHash;

                if (currentHash != storedInfo.Hash)
                {
                    result.Status = IntegrityStatus.Modified;
                    result.Message = "تم تعديل الملف - الـ hash مختلف";
                    _logger?.SecurityEvent("INTEGRITY_VIOLATION", $"تم تعديل الملف: {filePath}", ThreatSeverity.Critical);
                }
                else if (fileInfo.Length != storedInfo.FileSize)
                {
                    result.Status = IntegrityStatus.Modified;
                    result.Message = "تم تعديل حجم الملف";
                }
                else
                {
                    result.Status = IntegrityStatus.Valid;
                    result.Message = "الملف سليم";
                }
            }
            catch (Exception ex)
            {
                result.Status = IntegrityStatus.Error;
                result.Message = $"خطأ أثناء التحقق: {ex.Message}";
                _logger?.Error(ex, "خطأ أثناء التحقق من سلامة الملف: {0}", filePath);
            }

            return result;
        }

        /// <summary>
        /// التحقق من سلامة مجلد كامل
        /// </summary>
        public List<IntegrityResult> VerifyDirectory(string directoryPath, bool recursive = true)
        {
            var results = new List<IntegrityResult>();

            if (!Directory.Exists(directoryPath))
            {
                results.Add(new IntegrityResult
                {
                    FilePath = directoryPath,
                    Status = IntegrityStatus.Missing,
                    Message = "المجلد غير موجود"
                });
                return results;
            }

            var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            var files = Directory.GetFiles(directoryPath, "*.*", searchOption);

            foreach (var file in files)
            {
                results.Add(VerifyFile(file));
            }

            return results;
        }

        /// <summary>
        /// تسجيل ملف في قاعدة البيانات
        /// </summary>
        public void RegisterFile(string filePath, HashAlgorithmType algorithm = HashAlgorithmType.SHA256)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("الملف غير موجود", filePath);

            var hash = ComputeFileHash(filePath, algorithm);
            var fileInfo = new FileInfo(filePath);
            var normalizedPath = Path.GetFullPath(filePath).ToLowerInvariant();

            _hashDatabase[normalizedPath] = new FileHashInfo
            {
                FilePath = normalizedPath,
                Hash = hash,
                Algorithm = algorithm,
                FileSize = fileInfo.Length,
                LastVerified = DateTime.Now,
                OriginalModifiedTime = fileInfo.LastWriteTimeUtc
            };

            SaveHashDatabase();
            _logger?.Debug("تم تسجيل الملف: {0}", filePath);
        }

        /// <summary>
        /// تسجيل جميع ملفات مجلد
        /// </summary>
        public int RegisterDirectory(string directoryPath, bool recursive = true, string searchPattern = "*.*")
        {
            if (!Directory.Exists(directoryPath))
                throw new DirectoryNotFoundException($"المجلد غير موجود: {directoryPath}");

            var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            var files = Directory.GetFiles(directoryPath, searchPattern, searchOption);
            var count = 0;

            foreach (var file in files)
            {
                try
                {
                    RegisterFile(file);
                    count++;
                }
                catch (Exception ex)
                {
                    _logger?.Warning("لا يمكن تسجيل الملف {0}: {1}", file, ex.Message);
                }
            }

            _logger?.Information("تم تسجيل {0} ملف من {1}", count, directoryPath);
            return count;
        }

        /// <summary>
        /// التحقق من سلامة تطبيق ShieldAI
        /// </summary>
        public IntegritySummary VerifyApplication()
        {
            var summary = new IntegritySummary
            {
                CheckTime = DateTime.Now
            };

            var appPath = AppDomain.CurrentDomain.BaseDirectory;
            var results = VerifyDirectory(appPath, true);

            summary.TotalFiles = results.Count;
            summary.ValidFiles = results.Count(r => r.Status == IntegrityStatus.Valid);
            summary.ModifiedFiles = results.Count(r => r.Status == IntegrityStatus.Modified);
            summary.MissingFiles = results.Count(r => r.Status == IntegrityStatus.Missing);
            summary.UnknownFiles = results.Count(r => r.Status == IntegrityStatus.Unknown);
            summary.Errors = results.Count(r => r.Status == IntegrityStatus.Error);
            summary.Details = results;

            summary.IsValid = summary.ModifiedFiles == 0 && summary.MissingFiles == 0;

            if (!summary.IsValid)
            {
                _logger?.SecurityEvent("APPLICATION_INTEGRITY_FAILED", 
                    $"Modified: {summary.ModifiedFiles}, Missing: {summary.MissingFiles}", 
                    ThreatSeverity.Critical);
            }

            return summary;
        }

        /// <summary>
        /// تهيئة قاعدة بيانات السلامة
        /// </summary>
        public void InitializeDatabase()
        {
            _hashDatabase.Clear();
            var appPath = AppDomain.CurrentDomain.BaseDirectory;
            RegisterDirectory(appPath, true, "*.dll");
            RegisterDirectory(appPath, true, "*.exe");
            SaveHashDatabase();
            _logger?.Information("تم تهيئة قاعدة بيانات السلامة");
        }
        #endregion

        #region Private Methods
        private HashAlgorithm CreateHashAlgorithm(HashAlgorithmType type)
        {
            return type switch
            {
                HashAlgorithmType.MD5 => MD5.Create(),
                HashAlgorithmType.SHA1 => SHA1.Create(),
                HashAlgorithmType.SHA256 => SHA256.Create(),
                HashAlgorithmType.SHA384 => SHA384.Create(),
                HashAlgorithmType.SHA512 => SHA512.Create(),
                _ => SHA256.Create()
            };
        }

        private void LoadHashDatabase()
        {
            try
            {
                if (File.Exists(_hashDatabasePath))
                {
                    var json = File.ReadAllText(_hashDatabasePath);
                    _hashDatabase = JsonSerializer.Deserialize<Dictionary<string, FileHashInfo>>(json) 
                                    ?? new Dictionary<string, FileHashInfo>(StringComparer.OrdinalIgnoreCase);
                }
            }
            catch (Exception ex)
            {
                _logger?.Warning("لا يمكن تحميل قاعدة بيانات السلامة: {0}", ex.Message);
                _hashDatabase = new Dictionary<string, FileHashInfo>(StringComparer.OrdinalIgnoreCase);
            }
        }

        private void SaveHashDatabase()
        {
            try
            {
                var directory = Path.GetDirectoryName(_hashDatabasePath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var json = JsonSerializer.Serialize(_hashDatabase, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_hashDatabasePath, json);
            }
            catch (Exception ex)
            {
                _logger?.Error(ex, "لا يمكن حفظ قاعدة بيانات السلامة");
            }
        }
        #endregion
    }

    #region Models
    /// <summary>
    /// نوع خوارزمية الـ Hash
    /// </summary>
    public enum HashAlgorithmType
    {
        MD5,
        SHA1,
        SHA256,
        SHA384,
        SHA512
    }

    /// <summary>
    /// حالة السلامة
    /// </summary>
    public enum IntegrityStatus
    {
        Valid,
        Modified,
        Missing,
        Unknown,
        Error
    }

    /// <summary>
    /// معلومات hash الملف
    /// </summary>
    public class FileHashInfo
    {
        public string FilePath { get; set; } = string.Empty;
        public string Hash { get; set; } = string.Empty;
        public HashAlgorithmType Algorithm { get; set; }
        public long FileSize { get; set; }
        public DateTime LastVerified { get; set; }
        public DateTime OriginalModifiedTime { get; set; }
    }

    /// <summary>
    /// نتيجة فحص السلامة
    /// </summary>
    public class IntegrityResult
    {
        public string FilePath { get; set; } = string.Empty;
        public IntegrityStatus Status { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? ExpectedHash { get; set; }
        public string? ActualHash { get; set; }
        public DateTime CheckTime { get; set; }
    }

    /// <summary>
    /// ملخص فحص السلامة
    /// </summary>
    public class IntegritySummary
    {
        public DateTime CheckTime { get; set; }
        public int TotalFiles { get; set; }
        public int ValidFiles { get; set; }
        public int ModifiedFiles { get; set; }
        public int MissingFiles { get; set; }
        public int UnknownFiles { get; set; }
        public int Errors { get; set; }
        public bool IsValid { get; set; }
        public List<IntegrityResult> Details { get; set; } = new();
    }
    #endregion
}
