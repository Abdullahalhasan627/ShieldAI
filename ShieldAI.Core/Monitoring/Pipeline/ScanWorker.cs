// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Monitoring/Pipeline/ScanWorker.cs
// عامل الفحص - يقرأ من القائمة ويفحص الملفات
// =====================================================

using Microsoft.Extensions.Logging;
using ShieldAI.Core.Configuration;
using ShieldAI.Core.Detection.ThreatScoring;
using ShieldAI.Core.Models;

namespace ShieldAI.Core.Monitoring.Pipeline
{
    /// <summary>
    /// عامل الفحص - يقرأ الأحداث من القائمة ويفحصها عبر ThreatAggregator
    /// </summary>
    public class PipelineScanWorker : IDisposable
    {
        private readonly FileEventQueue _queue;
        private readonly ThreatAggregator _aggregator;
        private readonly ILogger? _logger;
        private readonly AppSettings _settings;
        private readonly HashSet<string> _quarantinedPaths;
        private readonly object _quarantineLock = new();
        private CancellationTokenSource? _cts;
        private readonly List<Task> _workerTasks = new();
        private bool _disposed;

        // temp files معروفة لتجاهلها
        private static readonly HashSet<string> IgnoredExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".tmp", ".log", ".etl", ".lock", ".journal",
            ".partial", ".crdownload", ".download"
        };

        private static readonly HashSet<string> IgnoredPrefixes = new(StringComparer.OrdinalIgnoreCase)
        {
            "~$", "~WRL", ".~lock"
        };

        // الأحداث
        public event EventHandler<AggregatedThreatResult>? ThreatDetected;
        public event EventHandler<string>? FileScanStarted;
        public event EventHandler<AggregatedThreatResult>? FileScanCompleted;

        public bool IsRunning { get; private set; }

        public PipelineScanWorker(
            FileEventQueue queue,
            ThreatAggregator aggregator,
            ILogger? logger = null)
        {
            _queue = queue;
            _aggregator = aggregator;
            _logger = logger;
            _settings = ConfigManager.Instance.Settings;
            _quarantinedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// بدء عمال الفحص
        /// </summary>
        public void Start(int workerCount = 0)
        {
            if (IsRunning) return;

            workerCount = workerCount > 0 ? workerCount : _settings.PipelineScanWorkers;
            workerCount = Math.Clamp(workerCount, 1, Environment.ProcessorCount);

            _cts = new CancellationTokenSource();
            IsRunning = true;

            for (int i = 0; i < workerCount; i++)
            {
                int workerId = i;
                _workerTasks.Add(Task.Run(() => WorkerLoopAsync(workerId, _cts.Token)));
            }

            _logger?.LogInformation("بدأ {Count} عمال فحص في Pipeline", workerCount);
        }

        /// <summary>
        /// إيقاف عمال الفحص
        /// </summary>
        public async Task StopAsync()
        {
            if (!IsRunning) return;

            _cts?.Cancel();

            try
            {
                await Task.WhenAll(_workerTasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }

            _workerTasks.Clear();
            IsRunning = false;

            _logger?.LogInformation("توقف عمال الفحص في Pipeline");
        }

        /// <summary>
        /// إضافة مسار محجور (لمنع إعادة فحصه)
        /// </summary>
        public void AddQuarantinedPath(string path)
        {
            lock (_quarantineLock)
            {
                _quarantinedPaths.Add(Path.GetFullPath(path).ToLowerInvariant());
            }
        }

        /// <summary>
        /// حلقة العامل الرئيسية
        /// </summary>
        private async Task WorkerLoopAsync(int workerId, CancellationToken ct)
        {
            _logger?.LogDebug("عامل الفحص #{WorkerId} بدأ", workerId);

            try
            {
                await foreach (var fileEvent in _queue.ReadAllAsync(ct))
                {
                    if (ct.IsCancellationRequested) break;

                    try
                    {
                        await ProcessEventAsync(fileEvent, ct);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogDebug("خطأ في فحص {File}: {Error}",
                            fileEvent.FilePath, ex.Message);
                    }
                }
            }
            catch (OperationCanceledException) { }

            _logger?.LogDebug("عامل الفحص #{WorkerId} توقف", workerId);
        }

        /// <summary>
        /// معالجة حدث ملف واحد
        /// </summary>
        private async Task ProcessEventAsync(FileEvent fileEvent, CancellationToken ct)
        {
            var filePath = fileEvent.FilePath;

            // === فلاتر ===

            // تجاهل الملفات غير الموجودة
            if (!File.Exists(filePath))
                return;

            // منع loop: تجاهل ملفات الحجر
            if (IsQuarantinePath(filePath))
                return;

            // تجاهل temp files
            if (ShouldIgnore(filePath))
                return;

            // تجاهل الملفات الكبيرة
            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Length > _settings.MaxFileSizeMB * 1024L * 1024L)
                return;

            // === الفحص ===
            FileScanStarted?.Invoke(this, filePath);

            var context = _aggregator.BuildContext(filePath);
            var result = await _aggregator.ScanAsync(context, ct);

            FileScanCompleted?.Invoke(this, result);

            // إذا كان تهديداً
            if (result.Verdict != AggregatedVerdict.Allow)
            {
                _logger?.LogWarning("تهديد Pipeline: {File} - Score: {Score} - Verdict: {Verdict}",
                    filePath, result.RiskScore, result.Verdict);

                ThreatDetected?.Invoke(this, result);
            }
        }

        /// <summary>
        /// هل المسار ضمن مسارات الحجر
        /// </summary>
        private bool IsQuarantinePath(string filePath)
        {
            var normalized = Path.GetFullPath(filePath).ToLowerInvariant();

            // فحص مسار الحجر من الإعدادات
            if (normalized.Contains(_settings.QuarantinePath.ToLowerInvariant()))
                return true;

            lock (_quarantineLock)
            {
                return _quarantinedPaths.Any(qp => normalized.StartsWith(qp));
            }
        }

        /// <summary>
        /// هل يجب تجاهل هذا الملف
        /// </summary>
        private static bool ShouldIgnore(string filePath)
        {
            var fileName = Path.GetFileName(filePath);
            var ext = Path.GetExtension(filePath);

            // امتدادات مؤقتة
            if (IgnoredExtensions.Contains(ext))
                return true;

            // بادئات مؤقتة
            foreach (var prefix in IgnoredPrefixes)
            {
                if (fileName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _cts?.Cancel();
            _cts?.Dispose();
        }
    }
}
