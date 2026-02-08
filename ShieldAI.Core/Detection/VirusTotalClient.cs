// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Detection/VirusTotalClient.cs
// تكامل مع VirusTotal API
// =====================================================

using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using ShieldAI.Core.Logging;

namespace ShieldAI.Core.Detection
{
    /// <summary>
    /// عميل VirusTotal API - للفحص عبر 70+ محرك antivirus
    /// </summary>
    public class VirusTotalClient : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger? _logger;
        private readonly string _apiKey;
        private readonly Dictionary<string, VTCacheEntry> _cache;
        private bool _disposed;

        private const string BaseUrl = "https://www.virustotal.com/api/v3";
        private const int MaxFileSize = 32 * 1024 * 1024; // 32MB للخطة المجانية
        private static readonly TimeSpan CacheDuration = TimeSpan.FromHours(24);

        /// <summary>
        /// هل الـ API Key صالح ومتوفر
        /// </summary>
        public bool IsConfigured => !string.IsNullOrWhiteSpace(_apiKey);

        public VirusTotalClient(string? apiKey = null, ILogger? logger = null)
        {
            _apiKey = apiKey ?? "";
            _logger = logger;
            _cache = new Dictionary<string, VTCacheEntry>(StringComparer.OrdinalIgnoreCase);
            
            _httpClient = new HttpClient
            {
                BaseAddress = new Uri(BaseUrl),
                Timeout = TimeSpan.FromMinutes(5)
            };
            
            if (!string.IsNullOrWhiteSpace(_apiKey))
            {
                _httpClient.DefaultRequestHeaders.Add("x-apikey", _apiKey);
            }
        }

        #region Public Methods
        /// <summary>
        /// فحص ملف عبر VirusTotal
        /// </summary>
        public async Task<VTScanResult> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
        {
            if (!IsConfigured)
                return VTScanResult.Error("VirusTotal API Key غير مكتمل");

            if (!File.Exists(filePath))
                return VTScanResult.Error("الملف غير موجود");

            try
            {
                // حساب SHA256
                var sha256 = await ComputeSha256Async(filePath);

                // التحقق من الكاش أولاً
                if (_cache.TryGetValue(sha256, out var cached) && !cached.IsExpired)
                {
                    _logger?.Debug("نتيجة VT من الكاش: {0}", sha256);
                    return cached.Result;
                }

                // البحث عن التقرير الموجود
                var existingResult = await GetFileReportAsync(sha256, cancellationToken);
                if (existingResult.Found)
                {
                    CacheResult(sha256, existingResult);
                    return existingResult;
                }

                // رفع الملف إذا لم يكن موجوداً
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length > MaxFileSize)
                    return VTScanResult.Error($"حجم الملف أكبر من الحد المسموح ({MaxFileSize / 1024 / 1024}MB)");

                var uploadResult = await UploadFileAsync(filePath, cancellationToken);
                return uploadResult;
            }
            catch (HttpRequestException ex)
            {
                _logger?.Error(ex, "خطأ في الاتصال بـ VirusTotal");
                return VTScanResult.Error($"خطأ في الاتصال: {ex.Message}");
            }
            catch (Exception ex)
            {
                _logger?.Error(ex, "خطأ أثناء الفحص");
                return VTScanResult.Error(ex.Message);
            }
        }

        /// <summary>
        /// الحصول على تقرير ملف عبر Hash
        /// </summary>
        public async Task<VTScanResult> GetFileReportAsync(string sha256, CancellationToken cancellationToken = default)
        {
            if (!IsConfigured)
                return VTScanResult.Error("VirusTotal API Key غير مكتمل");

            try
            {
                var response = await _httpClient.GetAsync($"/files/{sha256}", cancellationToken);
                
                if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    return new VTScanResult { Found = false };

                response.EnsureSuccessStatusCode();
                
                var json = await response.Content.ReadAsStringAsync(cancellationToken);
                return ParseFileReport(json, sha256);
            }
            catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return new VTScanResult { Found = false };
            }
        }

        /// <summary>
        /// الحصول على حالة API
        /// </summary>
        public async Task<bool> TestConnectionAsync()
        {
            if (!IsConfigured) return false;

            try
            {
                // فحص hash بسيط للتأكد من صحة المفتاح
                var response = await _httpClient.GetAsync("/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
                return response.IsSuccessStatusCode || response.StatusCode == System.Net.HttpStatusCode.NotFound;
            }
            catch
            {
                return false;
            }
        }
        #endregion

        #region Private Methods
        private async Task<VTScanResult> UploadFileAsync(string filePath, CancellationToken cancellationToken)
        {
            using var content = new MultipartFormDataContent();
            using var fileStream = File.OpenRead(filePath);
            using var streamContent = new StreamContent(fileStream);
            
            streamContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            content.Add(streamContent, "file", Path.GetFileName(filePath));

            var response = await _httpClient.PostAsync("/files", content, cancellationToken);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            var uploadResponse = JsonSerializer.Deserialize<VTUploadResponse>(json);

            if (uploadResponse?.Data?.Id == null)
                return VTScanResult.Error("فشل رفع الملف");

            _logger?.Information("تم رفع الملف إلى VirusTotal: {0}", uploadResponse.Data.Id);

            // انتظار النتيجة
            return await WaitForAnalysisAsync(uploadResponse.Data.Id, cancellationToken);
        }

        private async Task<VTScanResult> WaitForAnalysisAsync(string analysisId, CancellationToken cancellationToken)
        {
            for (int i = 0; i < 30; i++) // 5 دقائق كحد أقصى
            {
                await Task.Delay(10000, cancellationToken); // 10 ثواني

                var response = await _httpClient.GetAsync($"/analyses/{analysisId}", cancellationToken);
                if (!response.IsSuccessStatusCode) continue;

                var json = await response.Content.ReadAsStringAsync(cancellationToken);
                var analysis = JsonSerializer.Deserialize<VTAnalysisResponse>(json);

                if (analysis?.Data?.Attributes?.Status == "completed")
                {
                    var sha256 = analysis.Data?.Meta?.FileInfo?.Sha256 ?? "";
                    if (!string.IsNullOrEmpty(sha256))
                    {
                        return await GetFileReportAsync(sha256, cancellationToken);
                    }
                }
            }

            return VTScanResult.Error("انتهت مهلة الانتظار");
        }

        private VTScanResult ParseFileReport(string json, string sha256)
        {
            try
            {
                var report = JsonSerializer.Deserialize<VTFileReport>(json);
                var stats = report?.Data?.Attributes?.LastAnalysisStats;
                var results = report?.Data?.Attributes?.LastAnalysisResults;

                if (stats == null)
                    return new VTScanResult { Found = true, Sha256 = sha256 };

                var detections = new List<VTDetection>();
                if (results != null)
                {
                    foreach (var kvp in results)
                    {
                        if (kvp.Value?.Category == "malicious" || kvp.Value?.Category == "suspicious")
                        {
                            detections.Add(new VTDetection
                            {
                                EngineName = kvp.Key,
                                Category = kvp.Value.Category,
                                Result = kvp.Value.Result ?? "Unknown"
                            });
                        }
                    }
                }

                return new VTScanResult
                {
                    Found = true,
                    Sha256 = sha256,
                    Malicious = stats.Malicious,
                    Suspicious = stats.Suspicious,
                    Harmless = stats.Harmless,
                    Undetected = stats.Undetected,
                    TotalEngines = stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected,
                    Detections = detections,
                    ScanDate = DateTime.Now
                };
            }
            catch (Exception ex)
            {
                _logger?.Error(ex, "خطأ في تحليل نتيجة VT");
                return VTScanResult.Error("خطأ في تحليل النتيجة");
            }
        }

        private void CacheResult(string sha256, VTScanResult result)
        {
            _cache[sha256] = new VTCacheEntry
            {
                Result = result,
                CachedAt = DateTime.Now
            };
        }

        private async Task<string> ComputeSha256Async(string filePath)
        {
            using var stream = File.OpenRead(filePath);
            using var sha256 = SHA256.Create();
            var hash = await Task.Run(() => sha256.ComputeHash(stream));
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _httpClient.Dispose();
        }
        #endregion
    }

    #region Models
    /// <summary>
    /// نتيجة فحص VirusTotal
    /// </summary>
    public class VTScanResult
    {
        public bool Found { get; set; }
        public string Sha256 { get; set; } = "";
        public int Malicious { get; set; }
        public int Suspicious { get; set; }
        public int Harmless { get; set; }
        public int Undetected { get; set; }
        public int TotalEngines { get; set; }
        public List<VTDetection> Detections { get; set; } = new();
        public DateTime ScanDate { get; set; }
        public string? ErrorMessage { get; set; }
        public bool HasError => !string.IsNullOrEmpty(ErrorMessage);

        /// <summary>
        /// نسبة الاكتشاف (0-100)
        /// </summary>
        public double DetectionRate => TotalEngines > 0 
            ? (double)(Malicious + Suspicious) / TotalEngines * 100 
            : 0;

        /// <summary>
        /// هل تم اكتشافه كتهديد
        /// </summary>
        public bool IsThreat => Malicious > 0 || Suspicious > 2;

        public static VTScanResult Error(string message) => new() { ErrorMessage = message };
    }

    /// <summary>
    /// اكتشاف من محرك معين
    /// </summary>
    public class VTDetection
    {
        public string EngineName { get; set; } = "";
        public string Category { get; set; } = "";
        public string Result { get; set; } = "";
    }

    internal class VTCacheEntry
    {
        public VTScanResult Result { get; set; } = new();
        public DateTime CachedAt { get; set; }
        public bool IsExpired => DateTime.Now - CachedAt > TimeSpan.FromHours(24);
    }

    // API Response Models
    internal class VTUploadResponse
    {
        [JsonPropertyName("data")]
        public VTUploadData? Data { get; set; }
    }

    internal class VTUploadData
    {
        [JsonPropertyName("id")]
        public string? Id { get; set; }
    }

    internal class VTAnalysisResponse
    {
        [JsonPropertyName("data")]
        public VTAnalysisData? Data { get; set; }
    }

    internal class VTAnalysisData
    {
        [JsonPropertyName("attributes")]
        public VTAnalysisAttributes? Attributes { get; set; }
        
        [JsonPropertyName("meta")]
        public VTAnalysisMeta? Meta { get; set; }
    }

    internal class VTAnalysisAttributes
    {
        [JsonPropertyName("status")]
        public string? Status { get; set; }
    }

    internal class VTAnalysisMeta
    {
        [JsonPropertyName("file_info")]
        public VTFileInfo? FileInfo { get; set; }
    }

    internal class VTFileInfo
    {
        [JsonPropertyName("sha256")]
        public string? Sha256 { get; set; }
    }

    internal class VTFileReport
    {
        [JsonPropertyName("data")]
        public VTFileReportData? Data { get; set; }
    }

    internal class VTFileReportData
    {
        [JsonPropertyName("attributes")]
        public VTFileReportAttributes? Attributes { get; set; }
    }

    internal class VTFileReportAttributes
    {
        [JsonPropertyName("last_analysis_stats")]
        public VTAnalysisStats? LastAnalysisStats { get; set; }
        
        [JsonPropertyName("last_analysis_results")]
        public Dictionary<string, VTEngineResult>? LastAnalysisResults { get; set; }
    }

    internal class VTAnalysisStats
    {
        [JsonPropertyName("malicious")]
        public int Malicious { get; set; }
        
        [JsonPropertyName("suspicious")]
        public int Suspicious { get; set; }
        
        [JsonPropertyName("harmless")]
        public int Harmless { get; set; }
        
        [JsonPropertyName("undetected")]
        public int Undetected { get; set; }
    }

    internal class VTEngineResult
    {
        [JsonPropertyName("category")]
        public string? Category { get; set; }
        
        [JsonPropertyName("result")]
        public string? Result { get; set; }
    }
    #endregion
}
