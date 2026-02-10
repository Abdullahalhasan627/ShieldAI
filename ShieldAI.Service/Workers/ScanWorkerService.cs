// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Service/Workers/ScanWorkerService.cs
// عامل الفحص المجدول والمخصص
// =====================================================

using Microsoft.Extensions.Logging;
using ShieldAI.Core.Configuration;
using ShieldAI.Core.Detection;
using ShieldAI.Core.Detection.ThreatScoring;
using ShieldAI.Core.Models;
using ShieldAI.Core.Monitoring.Quarantine;
using ShieldAI.Core.Scanning;

namespace ShieldAI.Service.Workers
{
    /// <summary>
    /// عامل الفحص - يدير عمليات الفحص المجدولة والمخصصة
    /// </summary>
    public class ScanWorkerService : IDisposable
    {
        private readonly ILogger _logger;
        private readonly AppSettings _settings;
        private readonly ThreatAggregator _aggregator;
        private readonly FileEnumerator _fileEnumerator;
        private readonly QuarantineStore _quarantineStore;
        private readonly SemaphoreSlim _scanSemaphore;
        private readonly ScanCache _scanCache;

        private ScanJob? _currentJob;
        private CancellationTokenSource? _currentCts;
        private bool _disposed;

        // الأحداث
        public event EventHandler<ScanProgressEventArgs>? ScanProgress;
        public event EventHandler<AggregatedThreatResult>? ThreatDetected;
        public event EventHandler<ScanReport>? ScanCompleted;

        public bool IsScanning => _currentJob?.Status == ScanStatus.Running;
        public ScanJob? CurrentJob => _currentJob;

        public ScanWorkerService(
            ILogger logger,
            QuarantineStore quarantineStore,
            SignatureDatabase? signatureDb = null)
        {
            _logger = logger;
            _settings = ConfigManager.Instance.Settings;
            _quarantineStore = quarantineStore;

            var weights = new EngineWeights
            {
                SignatureEngine = _settings.SignatureEngineWeight,
                HeuristicEngine = _settings.HeuristicEngineWeight,
                MlEngine = _settings.MlEngineWeight,
                ReputationEngine = _settings.ReputationEngineWeight,
                AmsiEngine = _settings.AmsiEngineWeight
            };

            _scanCache = new ScanCache(TimeSpan.FromMinutes(_settings.ScanCacheTtlMinutes));
            _aggregator = ThreatAggregator.CreateDefault(signatureDb, weights, _scanCache);
            _fileEnumerator = new FileEnumerator(_logger);

            int maxParallelism = Math.Min(Environment.ProcessorCount, 4);
            _scanSemaphore = new SemaphoreSlim(maxParallelism, maxParallelism);
        }

        /// <summary>
        /// بدء فحص جديد
        /// </summary>
        public async Task<ScanReport> StartScanAsync(
            IEnumerable<string> paths,
            ScanType scanType = ScanType.Custom,
            bool deepScan = true,
            CancellationToken externalToken = default)
        {
            if (IsScanning)
                throw new InvalidOperationException("فحص آخر قيد التنفيذ");

            _currentCts = CancellationTokenSource.CreateLinkedTokenSource(externalToken);
            var ct = _currentCts.Token;

            _currentJob = new ScanJob
            {
                Paths = paths.ToList(),
                Type = scanType,
                DeepScan = deepScan,
                Status = ScanStatus.Running,
                StartedAt = DateTime.Now
            };

            var report = new ScanReport
            {
                JobId = _currentJob.Id,
                ScanType = scanType,
                StartTime = DateTime.Now
            };

            try
            {
                _logger.LogInformation("بدء فحص: {Type} - {Paths}",
                    scanType, string.Join(", ", _currentJob.Paths));

                // جمع الملفات
                var files = new List<FileInfo>();
                foreach (var path in _currentJob.Paths)
                {
                    files.AddRange(_fileEnumerator.EnumerateFiles(path, recursive: true));
                }

                _currentJob.TotalFiles = files.Count;
                report.TotalFiles = files.Count;
                RaiseProgress();

                // فحص الملفات بالتوازي
                var tasks = new List<Task>();

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) break;

                    await _scanSemaphore.WaitAsync(ct);

                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            var result = await _aggregator.ScanAsync(file.FullName, ct);

                            lock (_currentJob)
                            {
                                _currentJob.ScannedFiles++;
                                _currentJob.CurrentFile = file.Name;
                            }

                            lock (report)
                            {
                                report.TotalBytesScanned += file.Length;
                            }

                            if (result.Verdict != AggregatedVerdict.Allow)
                            {
                                lock (_currentJob)
                                {
                                    _currentJob.ThreatsFound++;
                                }
                                lock (report)
                                {
                                    report.ThreatsFound++;
                                }

                                ThreatDetected?.Invoke(this, result);

                                // الحجر التلقائي
                                if (_settings.AutoQuarantine &&
                                    (result.Verdict == AggregatedVerdict.Block ||
                                     result.Verdict == AggregatedVerdict.Quarantine))
                                {
                                    await _quarantineStore.QuarantineFileAsync(file.FullName, result);
                                }
                            }

                            RaiseProgress();
                        }
                        finally
                        {
                            _scanSemaphore.Release();
                        }
                    }, ct));
                }

                await Task.WhenAll(tasks);

                _currentJob.Status = ct.IsCancellationRequested
                    ? ScanStatus.Cancelled
                    : ScanStatus.Completed;
            }
            catch (OperationCanceledException)
            {
                _currentJob.Status = ScanStatus.Cancelled;
            }
            catch (Exception ex)
            {
                _currentJob.Status = ScanStatus.Failed;
                report.Errors.Add(ex.Message);
                _logger.LogError(ex, "خطأ في الفحص");
            }
            finally
            {
                _currentJob.CompletedAt = DateTime.Now;
                report.EndTime = DateTime.Now;
                report.FinalStatus = _currentJob.Status;
                report.ScannedFiles = _currentJob.ScannedFiles;

                ScanCompleted?.Invoke(this, report);

                _logger.LogInformation("اكتمل الفحص: {Scanned} ملف - {Threats} تهديد",
                    report.ScannedFiles, report.ThreatsFound);

                _currentCts?.Dispose();
                _currentCts = null;
            }

            return report;
        }

        /// <summary>
        /// إيقاف الفحص الحالي
        /// </summary>
        public void StopScan()
        {
            _currentCts?.Cancel();
        }

        private void RaiseProgress()
        {
            if (_currentJob == null) return;

            ScanProgress?.Invoke(this, new ScanProgressEventArgs
            {
                JobId = _currentJob.Id,
                TotalFiles = _currentJob.TotalFiles,
                ScannedFiles = _currentJob.ScannedFiles,
                ThreatsFound = _currentJob.ThreatsFound,
                CurrentFile = _currentJob.CurrentFile,
                ProgressPercent = _currentJob.ProgressPercent,
                Status = _currentJob.Status
            });
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _currentCts?.Cancel();
            _currentCts?.Dispose();
            _scanSemaphore.Dispose();
        }
    }

}
