// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Core/Scanning/ScanOrchestrator.cs
// منسق الفحص الرئيسي
// =====================================================

using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using ShieldAI.Core.Configuration;
using ShieldAI.Core.ML;

// استخدام Types من Models مع alias لتجنب التضارب
using ScanType = ShieldAI.Core.Models.ScanType;
using ScanStatus = ShieldAI.Core.Models.ScanStatus;
using ScanVerdict = ShieldAI.Core.Models.ScanVerdict;
using ThreatLevel = ShieldAI.Core.Models.ThreatLevel;

namespace ShieldAI.Core.Scanning
{
    /// <summary>
    /// منسق الفحص - يدير Queue + Parallelism + Progress
    /// </summary>
    public class ScanOrchestrator : IDisposable
    {
        private readonly ILogger? _logger;
        private readonly AppSettings _settings;
        private readonly FileEnumerator _fileEnumerator;
        private readonly DeepAnalyzer _deepAnalyzer;
        private readonly SemaphoreSlim _scanSemaphore;
        private readonly ConcurrentDictionary<Guid, Models.ScanJob> _activeJobs = new();
        private readonly ConcurrentDictionary<Guid, CancellationTokenSource> _cancellationTokens = new();
        
        private bool _disposed;

        // الأحداث
        public event EventHandler<Models.ScanProgressEventArgs>? ScanProgress;
        public event EventHandler<Models.ThreatDetectedEventArgs>? ThreatDetected;
        public event EventHandler<Models.ScanCompletedEventArgs>? ScanCompleted;

        public ScanOrchestrator(ILogger? logger = null, string? virusTotalApiKey = null)
        {
            _logger = logger;
            _settings = ConfigManager.Instance.Settings;
            _fileEnumerator = new FileEnumerator(logger);
            _deepAnalyzer = new DeepAnalyzer(virusTotalApiKey);
            
            // عدد الـ Threads للفحص المتوازي
            int maxParallelism = Math.Min(Environment.ProcessorCount, 4);
            _scanSemaphore = new SemaphoreSlim(maxParallelism, maxParallelism);
            
            _logger?.LogInformation("تم تهيئة ScanOrchestrator مع {MaxParallelism} threads", maxParallelism);
        }

        /// <summary>
        /// بدء فحص جديد
        /// </summary>
        public async Task<Models.ScanReport> StartScanAsync(
            IEnumerable<string> paths, 
            ScanType scanType = ScanType.Custom,
            bool useVirusTotal = false,
            bool deepScan = true,
            CancellationToken externalToken = default)
        {
            var job = new Models.ScanJob
            {
                Paths = paths.ToList(),
                Type = scanType,
                UseVirusTotal = useVirusTotal,
                DeepScan = deepScan,
                Status = ScanStatus.Pending
            };

            return await ExecuteScanJobAsync(job, externalToken);
        }

        /// <summary>
        /// تنفيذ مهمة فحص
        /// </summary>
        public async Task<Models.ScanReport> ExecuteScanJobAsync(Models.ScanJob job, CancellationToken externalToken = default)
        {
            var cts = CancellationTokenSource.CreateLinkedTokenSource(externalToken);
            _cancellationTokens[job.Id] = cts;
            _activeJobs[job.Id] = job;

            var report = new Models.ScanReport
            {
                JobId = job.Id,
                ScanType = job.Type,
                StartTime = DateTime.Now
            };

            try
            {
                job.Status = ScanStatus.Running;
                job.StartedAt = DateTime.Now;
                
                _logger?.LogInformation("بدء الفحص: {JobId} - النوع: {Type}", job.Id, job.Type);

                // جمع الملفات
                var files = new List<FileInfo>();
                foreach (var path in job.Paths)
                {
                    files.AddRange(_fileEnumerator.EnumerateFiles(path, recursive: true));
                }

                job.TotalFiles = files.Count;
                report.TotalFiles = files.Count;
                
                _logger?.LogInformation("عدد الملفات للفحص: {Count}", files.Count);
                RaiseProgress(job);

                // فحص الملفات بالتوازي
                var tasks = new List<Task<Models.ScanResult>>();
                
                foreach (var file in files)
                {
                    if (cts.Token.IsCancellationRequested)
                        break;

                    await _scanSemaphore.WaitAsync(cts.Token);
                    
                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            return await ScanFileAsync(job, file, cts.Token);
                        }
                        finally
                        {
                            _scanSemaphore.Release();
                        }
                    }, cts.Token));
                }

                // جمع النتائج
                var results = await Task.WhenAll(tasks);
                
                foreach (var result in results.Where(r => r != null))
                {
                    report.Results.Add(result);
                    report.TotalBytesScanned += result.FileSize;
                    
                    if (result.IsThreat)
                    {
                        report.ThreatsFound++;
                    }
                    
                    if (result.Verdict == ScanVerdict.Error)
                    {
                        report.ErrorCount++;
                        if (result.ErrorMessage != null)
                            report.Errors.Add($"{result.FilePath}: {result.ErrorMessage}");
                    }
                }

                report.ScannedFiles = results.Length;
                job.Status = cts.Token.IsCancellationRequested 
                    ? ScanStatus.Cancelled 
                    : ScanStatus.Completed;
            }
            catch (OperationCanceledException)
            {
                job.Status = ScanStatus.Cancelled;
                _logger?.LogInformation("تم إلغاء الفحص: {JobId}", job.Id);
            }
            catch (Exception ex)
            {
                job.Status = ScanStatus.Failed;
                report.Errors.Add($"خطأ عام: {ex.Message}");
                _logger?.LogError(ex, "خطأ في الفحص: {JobId}", job.Id);
            }
            finally
            {
                job.CompletedAt = DateTime.Now;
                report.EndTime = DateTime.Now;
                report.FinalStatus = job.Status;
                
                _activeJobs.TryRemove(job.Id, out _);
                _cancellationTokens.TryRemove(job.Id, out var removedCts);
                removedCts?.Dispose();
                
                ScanCompleted?.Invoke(this, new Models.ScanCompletedEventArgs { Report = report });
                
                _logger?.LogInformation(
                    "اكتمل الفحص: {JobId} - {Scanned} ملف - {Threats} تهديد - {Duration}s",
                    job.Id, report.ScannedFiles, report.ThreatsFound, report.Duration.TotalSeconds);
            }

            return report;
        }

        /// <summary>
        /// فحص ملف واحد
        /// </summary>
        private async Task<Models.ScanResult> ScanFileAsync(Models.ScanJob job, FileInfo file, CancellationToken ct)
        {
            var result = new Models.ScanResult
            {
                JobId = job.Id,
                FilePath = file.FullName,
                FileSize = file.Length
            };

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                ct.ThrowIfCancellationRequested();

                // حساب الـ Hash
                var (sha256, md5) = await StreamingHasher.ComputeBothAsync(file.FullName, ct);
                result.SHA256 = sha256;
                result.MD5 = md5;

                // التحليل العميق
                if (job.DeepScan)
                {
                    var analysisResult = await _deepAnalyzer.AnalyzeAsync(
                        file.FullName, 
                        useVirusTotal: job.UseVirusTotal,
                        cancellationToken: ct);

                    // Map from AnalysisVerdict to ScanVerdict
                    result.Verdict = MapVerdict(analysisResult.Verdict);
                    result.RiskScore = analysisResult.OverallRiskScore;
                    result.Confidence = analysisResult.OverallConfidence;
                    result.ThreatName = analysisResult.DetectedNames.FirstOrDefault() ?? analysisResult.Summary;

                    // Copy findings
                    foreach (var finding in analysisResult.Findings)
                    {
                        result.Findings.Add(new Models.DetectionFinding
                        {
                            Source = finding.Source,
                            Type = finding.Type.ToString(),
                            Title = finding.Title,
                            Description = finding.Description,
                            Severity = MapSeverity(finding.Severity),
                            Confidence = finding.Confidence
                        });
                    }
                }

                // تحديث الإحصائيات
                job.ScannedFiles++;
                job.CurrentFile = file.Name;
                
                if (result.IsThreat)
                {
                    job.ThreatsFound++;
                    
                    // إرسال حدث اكتشاف تهديد
                    ThreatDetected?.Invoke(this, new Models.ThreatDetectedEventArgs
                    {
                        JobId = job.Id,
                        Result = result,
                        AutoQuarantined = false
                    });
                }

                RaiseProgress(job);
            }
            catch (OperationCanceledException)
            {
                result.Verdict = ScanVerdict.Unknown;
                throw;
            }
            catch (Exception ex)
            {
                result.Verdict = ScanVerdict.Error;
                result.ErrorMessage = ex.Message;
                job.ErrorCount++;
                _logger?.LogDebug("خطأ في فحص الملف: {File} - {Error}", file.FullName, ex.Message);
            }
            finally
            {
                stopwatch.Stop();
                result.Duration = stopwatch.Elapsed;
            }

            return result;
        }

        /// <summary>
        /// إيقاف فحص
        /// </summary>
        public void StopScan(Guid jobId)
        {
            if (_cancellationTokens.TryGetValue(jobId, out var cts))
            {
                cts.Cancel();
                _logger?.LogInformation("تم طلب إيقاف الفحص: {JobId}", jobId);
            }
        }

        /// <summary>
        /// إيقاف جميع عمليات الفحص
        /// </summary>
        public void StopAllScans()
        {
            foreach (var cts in _cancellationTokens.Values)
            {
                cts.Cancel();
            }
            _logger?.LogInformation("تم إيقاف جميع عمليات الفحص");
        }

        /// <summary>
        /// الحصول على حالة الفحص
        /// </summary>
        public Models.ScanJob? GetJobStatus(Guid jobId)
        {
            return _activeJobs.TryGetValue(jobId, out var job) ? job : null;
        }

        /// <summary>
        /// الحصول على جميع المهام النشطة
        /// </summary>
        public IEnumerable<Models.ScanJob> GetActiveJobs()
        {
            return _activeJobs.Values.ToList();
        }

        private void RaiseProgress(Models.ScanJob job)
        {
            ScanProgress?.Invoke(this, new Models.ScanProgressEventArgs
            {
                JobId = job.Id,
                TotalFiles = job.TotalFiles,
                ScannedFiles = job.ScannedFiles,
                ThreatsFound = job.ThreatsFound,
                CurrentFile = job.CurrentFile,
                ProgressPercent = job.ProgressPercent,
                Status = job.Status
            });
        }

        private static ScanVerdict MapVerdict(AnalysisVerdict verdict)
        {
            return verdict switch
            {
                AnalysisVerdict.Clean => ScanVerdict.Clean,
                AnalysisVerdict.Suspicious => ScanVerdict.Suspicious,
                AnalysisVerdict.Malicious => ScanVerdict.Malicious,
                AnalysisVerdict.PotentiallyUnwanted => ScanVerdict.PotentiallyUnwanted,
                _ => ScanVerdict.Unknown
            };
        }

        private static ThreatLevel MapSeverity(Detection.ThreatLevel severity)
        {
            return severity switch
            {
                Detection.ThreatLevel.Critical => ThreatLevel.Critical,
                Detection.ThreatLevel.High => ThreatLevel.High,
                Detection.ThreatLevel.Medium => ThreatLevel.Medium,
                Detection.ThreatLevel.Low => ThreatLevel.Low,
                _ => ThreatLevel.Low
            };
        }

        public void Dispose()
        {
            if (_disposed) return;
            
            StopAllScans();
            _scanSemaphore.Dispose();
            
            foreach (var cts in _cancellationTokens.Values)
            {
                cts.Dispose();
            }
            
            _disposed = true;
        }
    }
}
