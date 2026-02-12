// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Service/Workers/RealtimeWorker.cs
// عامل المراقبة الفورية باستخدام Pipeline
// =====================================================

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ShieldAI.Core.Configuration;
using ShieldAI.Core.Contracts;
using ShieldAI.Core.Detection;
using ShieldAI.Core.Detection.ThreatScoring;
using ShieldAI.Core.Logging;
using ShieldAI.Core.Monitoring.Pipeline;
using ShieldAI.Core.Monitoring.Quarantine;
using ShieldAI.Core.Scanning;

namespace ShieldAI.Service.Workers
{
    /// <summary>
    /// عامل المراقبة الفورية - يستخدم Pipeline (Channel + Coalescer + ScanWorker)
    /// </summary>
    public class RealtimeWorker : IDisposable
    {
        private readonly Microsoft.Extensions.Logging.ILogger _logger;
        private readonly AppSettings _settings;
        private readonly SignatureDatabase _signatureDb;

        private readonly FileEventQueue _eventQueue;
        private readonly EventCoalescer _coalescer;
        private readonly PipelineScanWorker _scanWorker;
        private readonly ThreatAggregator _aggregator;
        private readonly QuarantineStore _quarantineStore;
        private readonly ScanCache _scanCache;
        private readonly HeuristicEngine _heuristicEngine = new();
        private readonly AmsiEngine _amsiEngine = new();
        private readonly ThreatActionExecutor _actionExecutor;

        private readonly List<FileSystemWatcher> _watchers = new();
        private readonly HashSet<string> _excludedExtensions;
        private readonly HashSet<string> _excludedFolders;

        private bool _isRunning;
        private bool _disposed;

        // الأحداث
        public event EventHandler<AggregatedThreatResult>? ThreatDetected;

        /// <summary>
        /// منفّذ إجراءات التهديد — للاشتراك في أحداثه من الخارج
        /// </summary>
        public ThreatActionExecutor ActionExecutor => _actionExecutor;

        public bool IsRunning => _isRunning;
        public int PendingCount => _eventQueue.PendingCount + _coalescer.PendingCount;

        public RealtimeWorker(
            Microsoft.Extensions.Logging.ILogger logger,
            QuarantineStore quarantineStore,
            SignatureDatabase? signatureDb = null)
        {
            _logger = logger;
            _settings = ConfigManager.Instance.Settings;
            _quarantineStore = quarantineStore;
            _signatureDb = signatureDb ?? new SignatureDatabase();

            // إنشاء الأوزان من الإعدادات
            var weights = new EngineWeights
            {
                SignatureEngine = _settings.SignatureEngineWeight,
                HeuristicEngine = _settings.HeuristicEngineWeight,
                MlEngine = _settings.MlEngineWeight,
                ReputationEngine = _settings.ReputationEngineWeight,
                AmsiEngine = _settings.AmsiEngineWeight
            };

            _scanCache = new ScanCache(
                TimeSpan.FromMinutes(_settings.ScanCacheTtlMinutes),
                _settings.ScanCacheMaxEntries);
            _aggregator = ThreatAggregator.CreateDefault(signatureDb, weights, _scanCache);
            _aggregator.BlockThreshold = _settings.BlockThreshold;
            _aggregator.QuarantineThreshold = _settings.QuarantineThreshold;
            _aggregator.ReviewThreshold = _settings.ReviewThreshold;

            // Pipeline
            _eventQueue = new FileEventQueue(_settings.PipelineQueueCapacity);
            _coalescer = new EventCoalescer(_eventQueue, _settings.EventCoalesceMs);
            _scanWorker = new PipelineScanWorker(_eventQueue, _aggregator, logger);

            // منفّذ الإجراءات
            _actionExecutor = new ThreatActionExecutor(_quarantineStore, _settings, logger);

            // ربط أحداث الفحص
            _scanWorker.ThreatDetected += OnThreatDetected;

            _excludedExtensions = _settings.ExcludedExtensions
                .Select(e => e.Trim().ToLowerInvariant())
                .ToHashSet();

            _excludedFolders = _settings.ExcludedFolders
                .Select(f => f.Trim().ToLowerInvariant())
                .ToHashSet();
        }

        /// <summary>
        /// بدء المراقبة
        /// </summary>
        public void Start(IEnumerable<string>? paths = null)
        {
            if (_isRunning) return;

            var monitorPaths = paths?.ToList() ?? GetDefaultMonitorPaths();

            foreach (var path in monitorPaths)
            {
                try
                {
                    if (!Directory.Exists(path)) continue;

                    var watcher = new FileSystemWatcher(path)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName |
                                       NotifyFilters.LastWrite |
                                       NotifyFilters.CreationTime,
                        EnableRaisingEvents = false
                    };

                    watcher.Created += OnFileEvent;
                    watcher.Changed += OnFileEvent;
                    watcher.Renamed += OnFileRenamed;
                    watcher.Error += OnWatcherError;

                    watcher.EnableRaisingEvents = true;
                    _watchers.Add(watcher);

                    _logger.LogInformation("مراقبة: {Path}", path);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "فشل إنشاء watcher: {Path}", path);
                }
            }

            // بدء عمال الفحص
            _scanWorker.Start(_settings.PipelineScanWorkers);

            // إضافة مسار الحجر لمنع loop
            _scanWorker.AddQuarantinedPath(_settings.QuarantinePath);

            _isRunning = true;
            _logger.LogInformation("بدأت المراقبة الفورية - {Count} مجلدات", _watchers.Count);
        }

        /// <summary>
        /// إيقاف المراقبة
        /// </summary>
        public async Task StopAsync()
        {
            if (!_isRunning) return;

            foreach (var watcher in _watchers)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch { }
            }

            _watchers.Clear();
            _coalescer.Clear();
            await _scanWorker.StopAsync();

            _isRunning = false;
            _logger.LogInformation("توقفت المراقبة الفورية");
        }

        private void OnFileEvent(object sender, FileSystemEventArgs e)
        {
            _ = HandleFileEventAsync(e.FullPath, e.ChangeType);
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            _ = HandleFileEventAsync(e.FullPath, WatcherChangeTypes.Renamed);
        }

        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            _logger.LogError(e.GetException(), "خطأ في FileSystemWatcher");
        }

        private async void OnThreatDetected(object? sender, AggregatedThreatResult result)
        {
            ThreatDetected?.Invoke(this, result);

            // تنفيذ الإجراء عبر ThreatActionExecutor بناءً على السياسة
            if (result.Verdict == AggregatedVerdict.Allow)
                return;

            try
            {
                var context = _aggregator.BuildContext(result.FilePath);
                var dto = await _actionExecutor.ApplyActionAsync(result, context);

                if (dto.ActionTaken && dto.ActionResult?.Contains("Quarantine") == true)
                {
                    _scanWorker.AddQuarantinedPath(result.FilePath);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "فشل تنفيذ إجراء التهديد: {File}", result.FilePath);
            }
        }

        private async Task HandleFileEventAsync(string filePath, WatcherChangeTypes changeType)
        {
            if (!ShouldProcess(filePath)) return;

            UpdatePressureMode();

            try
            {
                var quickGateScore = await GetQuickGateScoreAsync(filePath).ConfigureAwait(false);
                if (quickGateScore >= _settings.QuickGateSuspiciousScore)
                {
                    await TryAtomicQuarantineAsync(filePath, quickGateScore).ConfigureAwait(false);
                    return;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "فشل Quick Gate: {File}", filePath);
            }

            _coalescer.Add(filePath, changeType);
        }

        private async Task<int> GetQuickGateScoreAsync(string filePath)
        {
            if (!File.Exists(filePath))
                return 0;

            var context = _aggregator.BuildContext(filePath);
            var engines = new IThreatEngine[]
            {
                new SignatureEngine(_signatureDb),
                _heuristicEngine,
                _amsiEngine
            };

            var tasks = engines
                .Where(e => e.IsReady)
                .Select(engine => engine.ScanAsync(context));

            var results = await Task.WhenAll(tasks).ConfigureAwait(false);
            return _aggregator.CalculateWeightedScore(results);
        }

        private async Task TryAtomicQuarantineAsync(string filePath, int quickGateScore)
        {
            if (!_settings.AutoQuarantine || !File.Exists(filePath))
                return;

            var correlationId = ScanDiagnosticLog.NewCorrelationId();
            ScanDiagnosticLog.LogQuickGate(_logger, correlationId, filePath, quickGateScore, true);

            var (success, movedPath) = await _quarantineStore.TryAtomicMoveToQuarantineAsync(
                filePath,
                _settings.AtomicMoveMaxRetries,
                _settings.AtomicMoveInitialDelayMs,
                _settings.AtomicMoveMaxDelayMs).ConfigureAwait(false);

            if (!success || string.IsNullOrWhiteSpace(movedPath))
            {
                _logger.LogWarning("[Scan:{CorrelationId}] AtomicMove FAILED for {File}",
                    correlationId, filePath);
                return;
            }

            _scanWorker.AddQuarantinedPath(movedPath);

            var context = _aggregator.BuildContext(movedPath);
            var result = await _aggregator.ScanAsync(context).ConfigureAwait(false);
            result.FilePath = filePath;

            if (result.Reasons.All(r => !r.Contains("Quick Gate", StringComparison.OrdinalIgnoreCase)))
            {
                result.Reasons.Add($"Quick Gate: Score {quickGateScore}");
            }

            if (_settings.AutoQuarantine)
            {
                var entry = await _quarantineStore.QuarantineMovedFileAsync(movedPath, filePath, result)
                    .ConfigureAwait(false);

                ScanDiagnosticLog.LogScanResult(
                    _logger, correlationId, context, result,
                    policyDecision: $"QuickGate={quickGateScore}",
                    quarantineAttempted: true,
                    quarantineSuccess: entry != null);

                if (entry != null)
                {
                    ThreatDetected?.Invoke(this, result);
                }
            }
        }

        private bool ShouldProcess(string filePath)
        {
            try
            {
                var ext = Path.GetExtension(filePath).TrimStart('.').ToLowerInvariant();
                if (_excludedExtensions.Contains(ext))
                    return false;

                var dirName = Path.GetDirectoryName(filePath)?.ToLowerInvariant() ?? "";
                foreach (var excluded in _excludedFolders)
                {
                    if (dirName.Contains(excluded))
                        return false;
                }

                if (filePath.Contains(_settings.QuarantinePath, StringComparison.OrdinalIgnoreCase))
                    return false;

                return true;
            }
            catch
            {
                return false;
            }
        }

        private void UpdatePressureMode()
        {
            _aggregator.HighPressureMode = PendingCount >= _settings.PipelineHighPressureThreshold;
        }

        private static List<string> GetDefaultMonitorPaths()
        {
            var paths = new List<string>();
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            var downloads = Path.Combine(userProfile, "Downloads");
            if (Directory.Exists(downloads)) paths.Add(downloads);

            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            if (Directory.Exists(desktop)) paths.Add(desktop);

            var temp = Path.GetTempPath();
            if (Directory.Exists(temp)) paths.Add(temp);

            return paths;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            foreach (var w in _watchers)
            {
                try { w.Dispose(); } catch { }
            }

            _coalescer.Dispose();
            _eventQueue.Dispose();
            _scanWorker.Dispose();
        }
    }
}
