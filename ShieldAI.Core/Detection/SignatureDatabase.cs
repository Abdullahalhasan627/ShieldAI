// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Detection/SignatureDatabase.cs
// قاعدة بيانات التوقيعات للكشف عن الفيروسات
// =====================================================

using System.Security.Cryptography;
using System.Text.Json;
using ShieldAI.Core.Logging;

namespace ShieldAI.Core.Detection
{
    /// <summary>
    /// قاعدة بيانات التوقيعات - تخزن hashes الملفات الخبيثة المعروفة
    /// </summary>
    public class SignatureDatabase
    {
        private readonly ILogger? _logger;
        private readonly string _databasePath;
        private Dictionary<string, MalwareSignature> _signatures;
        private DateTime _lastUpdate;

        /// <summary>
        /// عدد التوقيعات في القاعدة
        /// </summary>
        public int Count => _signatures.Count;

        /// <summary>
        /// تاريخ آخر تحديث
        /// </summary>
        public DateTime LastUpdate => _lastUpdate;

        public SignatureDatabase(ILogger? logger = null, string? databasePath = null)
        {
            _logger = logger;
            _databasePath = databasePath ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "ShieldAI", "Signatures", "signatures.json");
            _signatures = new Dictionary<string, MalwareSignature>(StringComparer.OrdinalIgnoreCase);
            
            LoadDatabase();
        }

        #region Public Methods
        /// <summary>
        /// فحص ملف ضد قاعدة التوقيعات
        /// </summary>
        public SignatureMatch? CheckFile(string filePath)
        {
            if (!File.Exists(filePath))
                return null;

            try
            {
                // حساب MD5 و SHA256
                var md5Hash = ComputeHash(filePath, "MD5");
                var sha256Hash = ComputeHash(filePath, "SHA256");

                // البحث في قاعدة البيانات
                if (_signatures.TryGetValue(sha256Hash, out var signature))
                {
                    return new SignatureMatch
                    {
                        FilePath = filePath,
                        MatchedHash = sha256Hash,
                        HashType = "SHA256",
                        Signature = signature,
                        MatchTime = DateTime.Now
                    };
                }

                if (_signatures.TryGetValue(md5Hash, out signature))
                {
                    return new SignatureMatch
                    {
                        FilePath = filePath,
                        MatchedHash = md5Hash,
                        HashType = "MD5",
                        Signature = signature,
                        MatchTime = DateTime.Now
                    };
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger?.Error(ex, "خطأ أثناء فحص الملف: {0}", filePath);
                return null;
            }
        }

        /// <summary>
        /// فحص hash مباشرة
        /// </summary>
        public SignatureMatch? CheckHash(string hash)
        {
            if (_signatures.TryGetValue(hash, out var signature))
            {
                return new SignatureMatch
                {
                    MatchedHash = hash,
                    Signature = signature,
                    MatchTime = DateTime.Now
                };
            }
            return null;
        }

        /// <summary>
        /// إضافة توقيع جديد
        /// </summary>
        public void AddSignature(MalwareSignature signature)
        {
            if (!string.IsNullOrEmpty(signature.Sha256Hash))
                _signatures[signature.Sha256Hash] = signature;
            
            if (!string.IsNullOrEmpty(signature.Md5Hash))
                _signatures[signature.Md5Hash] = signature;
        }

        /// <summary>
        /// استيراد توقيعات من ملف CSV
        /// </summary>
        public async Task<int> ImportFromCsvAsync(string csvPath)
        {
            int imported = 0;
            
            try
            {
                var lines = await File.ReadAllLinesAsync(csvPath);
                foreach (var line in lines.Skip(1)) // تخطي الهيدر
                {
                    var parts = line.Split(',');
                    if (parts.Length >= 3)
                    {
                        var signature = new MalwareSignature
                        {
                            Sha256Hash = parts[0].Trim(),
                            MalwareName = parts[1].Trim(),
                            ThreatLevel = parts.Length > 2 ? ParseThreatLevel(parts[2].Trim()) : ThreatLevel.Medium,
                            MalwareFamily = parts.Length > 3 ? parts[3].Trim() : "Unknown",
                            AddedDate = DateTime.Now
                        };
                        AddSignature(signature);
                        imported++;
                    }
                }
                
                await SaveDatabaseAsync();
                _logger?.Information("تم استيراد {0} توقيع", imported);
            }
            catch (Exception ex)
            {
                _logger?.Error(ex, "خطأ أثناء الاستيراد من CSV");
            }

            return imported;
        }

        /// <summary>
        /// تحميل قاعدة البيانات
        /// </summary>
        public void LoadDatabase()
        {
            try
            {
                if (File.Exists(_databasePath))
                {
                    var json = File.ReadAllText(_databasePath);
                    var data = JsonSerializer.Deserialize<SignatureDatabaseData>(json);
                    if (data != null)
                    {
                        _signatures = data.Signatures.ToDictionary(
                            s => s.Sha256Hash ?? s.Md5Hash ?? "",
                            s => s,
                            StringComparer.OrdinalIgnoreCase);
                        _lastUpdate = data.LastUpdate;
                    }
                }
                else
                {
                    // إنشاء قاعدة بيانات أولية مع توقيعات EICAR
                    InitializeDefaultSignatures();
                }
            }
            catch (Exception ex)
            {
                _logger?.Error(ex, "خطأ أثناء تحميل قاعدة البيانات");
                InitializeDefaultSignatures();
            }
        }

        /// <summary>
        /// حفظ قاعدة البيانات
        /// </summary>
        public async Task SaveDatabaseAsync()
        {
            try
            {
                var directory = Path.GetDirectoryName(_databasePath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                    Directory.CreateDirectory(directory);

                var data = new SignatureDatabaseData
                {
                    LastUpdate = DateTime.Now,
                    Signatures = _signatures.Values.Distinct().ToList()
                };

                var json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(_databasePath, json);
                _lastUpdate = data.LastUpdate;
            }
            catch (Exception ex)
            {
                _logger?.Error(ex, "خطأ أثناء حفظ قاعدة البيانات");
            }
        }
        #endregion

        #region Private Methods
        private void InitializeDefaultSignatures()
        {
            // EICAR Test File - ملف اختبار قياسي للـ Antivirus
            AddSignature(new MalwareSignature
            {
                Sha256Hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                Md5Hash = "44d88612fea8a8f36de82e1278abb02f",
                MalwareName = "EICAR-Test-File",
                MalwareFamily = "Test",
                Description = "ملف اختبار قياسي للتحقق من عمل برنامج مكافحة الفيروسات",
                ThreatLevel = ThreatLevel.Low,
                AddedDate = DateTime.Now
            });

            // بعض التوقيعات المعروفة (أمثلة)
            AddSignature(new MalwareSignature
            {
                Sha256Hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                MalwareName = "Empty-File-Suspicious",
                MalwareFamily = "Suspicious",
                Description = "ملف فارغ - قد يكون مشبوه",
                ThreatLevel = ThreatLevel.Low,
                AddedDate = DateTime.Now
            });

            _lastUpdate = DateTime.Now;
        }

        private string ComputeHash(string filePath, string algorithm)
        {
            using var stream = File.OpenRead(filePath);
            using var hasher = algorithm.ToUpper() switch
            {
                "MD5" => (HashAlgorithm)MD5.Create(),
                "SHA256" => SHA256.Create(),
                "SHA1" => SHA1.Create(),
                _ => SHA256.Create()
            };
            
            var hash = hasher.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        private ThreatLevel ParseThreatLevel(string level)
        {
            return level.ToLower() switch
            {
                "low" => ThreatLevel.Low,
                "medium" => ThreatLevel.Medium,
                "high" => ThreatLevel.High,
                "critical" => ThreatLevel.Critical,
                _ => ThreatLevel.Medium
            };
        }
        #endregion
    }

    #region Models
    /// <summary>
    /// توقيع البرمجية الخبيثة
    /// </summary>
    public class MalwareSignature
    {
        public string? Sha256Hash { get; set; }
        public string? Md5Hash { get; set; }
        public string MalwareName { get; set; } = "Unknown";
        public string MalwareFamily { get; set; } = "Unknown";
        public string? Description { get; set; }
        public ThreatLevel ThreatLevel { get; set; } = ThreatLevel.Medium;
        public DateTime AddedDate { get; set; }
        public string? Source { get; set; }
    }

    /// <summary>
    /// نتيجة مطابقة التوقيع
    /// </summary>
    public class SignatureMatch
    {
        public string? FilePath { get; set; }
        public string MatchedHash { get; set; } = "";
        public string HashType { get; set; } = "SHA256";
        public MalwareSignature Signature { get; set; } = new();
        public DateTime MatchTime { get; set; }
    }

    /// <summary>
    /// مستوى التهديد
    /// </summary>
    public enum ThreatLevel
    {
        None = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }

    /// <summary>
    /// بيانات قاعدة التوقيعات للتخزين
    /// </summary>
    internal class SignatureDatabaseData
    {
        public DateTime LastUpdate { get; set; }
        public List<MalwareSignature> Signatures { get; set; } = new();
    }
    #endregion
}
