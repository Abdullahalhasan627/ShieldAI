// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Service/Workers/RealtimeWorker.cs
// عامل المراقبة الفورية باستخدام Pipeline
// =====================================================

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ShieldAI.Core.Configuration;
using ShieldAI.Core.Detection;
using ShieldAI.Core.Detection.ThreatScoring;
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
        private readonly ILogger _logger;
        private readonly AppSettings _settings;

        private readonly FileEventQueue _eventQueue;
        private readonly EventCoalescer _coalescer;
        private readonly PipelineScanWorker _scanWorker;
        private readonly ThreatAggregator _aggregator;
        private readonly QuarantineStore _quarantineStore;
        private readonly ScanCache _scanCache;

        private readonly List<FileSystemWatcher> _watchers = new();
        private readonly HashSet<string> _excludedExtensions;
        private readonly HashSet<string> _excludedFolders;

        private bool _isRunning;
        private bool _disposed;

        // الأحداث
        public event EventHandler<AggregatedThreatResult>? ThreatDetected;

        public bool IsRunning => _isRunning;
        public int PendingCount => _eventQueue.PendingCount + _coalescer.PendingCount;

        public RealtimeWorker(
            ILogger logger,
            QuarantineStore quarantineStore,
            SignatureDatabase? signatureDb = null)
        {
            _logger = logger;
            _settings = ConfigManager.Instance.Settings;
            _quarantineStore = quarantineStore;

            // إنشاء الأوزان من الإعدادات
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
            _aggregator.BlockThreshold = _settings.BlockThreshold;
            _aggregator.QuarantineThreshold = _settings.QuarantineThreshold;
            _aggregator.ReviewThreshold = _settings.ReviewThreshold;

            // Pipeline
            _eventQueue = new FileEventQueue(_settings.PipelineQueueCapacity);
            _coalescer = new EventCoalescer(_eventQueue, _settings.EventCoalesceMs);
            _scanWorker = new PipelineScanWorker(_eventQueue, _aggregator, logger);

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
            if (!ShouldProcess(e.FullPath)) return;
            UpdatePressureMode();
            _coalescer.Add(e.FullPath, e.ChangeType);
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            if (!ShouldProcess(e.FullPath)) return;
            UpdatePressureMode();
            _coalescer.Add(e.FullPath, WatcherChangeTypes.Renamed);
        }

        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            _logger.LogError(e.GetException(), "خطأ في FileSystemWatcher");
        }

        private async void OnThreatDetected(object? sender, AggregatedThreatResult result)
        {
            ThreatDetected?.Invoke(this, result);

            // الحجر التلقائي
            if (_settings.AutoQuarantine &&
                (result.Verdict == AggregatedVerdict.Block || result.Verdict == AggregatedVerdict.Quarantine))
            {
                try
                {
                    var entry = await _quarantineStore.QuarantineFileAsync(result.FilePath, result);
                    if (entry != null)
                    {
                        _scanWorker.AddQuarantinedPath(result.FilePath);
                        _logger.LogInformation("تم حجر: {File}", result.FilePath);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "فشل حجر: {File}", result.FilePath);
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
