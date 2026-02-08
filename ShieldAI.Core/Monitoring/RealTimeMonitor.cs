// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Core/Monitoring/RealTimeMonitor.cs
// مراقبة الملفات في الوقت الفعلي
// =====================================================

using Microsoft.Extensions.Logging;
using ShieldAI.Core.Configuration;
using ShieldAI.Core.Models;
using ShieldAI.Core.Scanning;

namespace ShieldAI.Core.Monitoring
{
    /// <summary>
    /// مراقب الملفات في الوقت الفعلي
    /// يستخدم FileSystemWatcher مع Debounce
    /// </summary>
    public class RealTimeMonitor : IDisposable
    {
        private readonly ILogger? _logger;
        private readonly AppSettings _settings;
        private readonly List<FileSystemWatcher> _watchers = new();
        private readonly FileEventDebouncer _debouncer;
        private readonly ScanOrchestrator _scanOrchestrator;
        private readonly HashSet<string> _excludedExtensions;
        private readonly HashSet<string> _excludedFolders;
        private bool _isRunning;
        private bool _disposed;

        // الأحداث
        public event EventHandler<RealTimeEventArgs>? FileDetected;
        public event EventHandler<ThreatDetectedEventArgs>? ThreatFound;
        public event EventHandler<string>? MonitorError;

        public bool IsRunning => _isRunning;

        public RealTimeMonitor(ILogger? logger = null, string? virusTotalApiKey = null)
        {
            _logger = logger;
            _settings = ConfigManager.Instance.Settings;
            _scanOrchestrator = new ScanOrchestrator(logger, virusTotalApiKey);
            _debouncer = new FileEventDebouncer(OnFileReady, 1000);

            _excludedExtensions = _settings.ExcludedExtensions
                .Select(e => e.Trim().ToLowerInvariant())
                .ToHashSet();

            _excludedFolders = _settings.ExcludedFolders
                .Select(f => f.Trim().ToLowerInvariant())
                .ToHashSet();

            // ربط أحداث الفحص
            _scanOrchestrator.ThreatDetected += (s, e) =>
            {
                ThreatFound?.Invoke(this, e);
            };
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
                    if (!Directory.Exists(path))
                    {
                        _logger?.LogWarning("مجلد المراقبة غير موجود: {Path}", path);
                        continue;
                    }

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

                    _logger?.LogInformation("بدأت مراقبة: {Path}", path);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "فشل إنشاء watcher: {Path}", path);
                }
            }

            _isRunning = true;
            _logger?.LogInformation("بدأت الحماية في الوقت الفعلي - {Count} مجلدات", _watchers.Count);
        }

        /// <summary>
        /// إيقاف المراقبة
        /// </summary>
        public void Stop()
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
            _debouncer.Clear();
            _isRunning = false;

            _logger?.LogInformation("توقفت الحماية في الوقت الفعلي");
        }

        /// <summary>
        /// المسارات الافتراضية للمراقبة
        /// </summary>
        private static List<string> GetDefaultMonitorPaths()
        {
            var paths = new List<string>();

            // مجلد المستخدم
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (Directory.Exists(userProfile))
                paths.Add(userProfile);

            // مجلد Downloads
            var downloads = Path.Combine(userProfile, "Downloads");
            if (Directory.Exists(downloads))
                paths.Add(downloads);

            // مجلد Desktop
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            if (Directory.Exists(desktop))
                paths.Add(desktop);

            // Temp
            var temp = Path.GetTempPath();
            if (Directory.Exists(temp))
                paths.Add(temp);

            return paths;
        }

        /// <summary>
        /// معالجة حدث ملف
        /// </summary>
        private void OnFileEvent(object sender, FileSystemEventArgs e)
        {
            if (!ShouldProcess(e.FullPath))
                return;

            _debouncer.Add(e.FullPath, e.ChangeType);
        }

        /// <summary>
        /// معالجة إعادة تسمية
        /// </summary>
        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            if (!ShouldProcess(e.FullPath))
                return;

            _debouncer.Add(e.FullPath, WatcherChangeTypes.Renamed);
        }

        /// <summary>
        /// معالجة خطأ في الـ Watcher
        /// </summary>
        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            var ex = e.GetException();
            _logger?.LogError(ex, "خطأ في FileSystemWatcher");
            MonitorError?.Invoke(this, ex.Message);
        }

        /// <summary>
        /// معالجة ملف جاهز للفحص
        /// </summary>
        private async void OnFileReady(string filePath, WatcherChangeTypes changeType)
        {
            try
            {
                if (!File.Exists(filePath))
                    return;

                var fileInfo = new FileInfo(filePath);
                
                // تخطي الملفات الكبيرة
                if (fileInfo.Length > _settings.MaxFileSizeMB * 1024 * 1024)
                    return;

                FileDetected?.Invoke(this, new RealTimeEventArgs
                {
                    FilePath = filePath,
                    ChangeType = changeType,
                    DetectedAt = DateTime.Now
                });

                _logger?.LogDebug("فحص ملف جديد: {Path}", filePath);

                // فحص الملف
                var report = await _scanOrchestrator.StartScanAsync(
                    new[] { filePath },
                    ScanType.Single,
                    useVirusTotal: false, // لا نستخدم VT للمراقبة الفورية
                    deepScan: true);

                // التعامل مع التهديدات
                foreach (var threat in report.Threats)
                {
                    _logger?.LogWarning("تهديد في الوقت الفعلي: {File} - {Threat}", 
                        threat.FilePath, threat.ThreatName);

                    // الحجر التلقائي إذا كان مفعلاً
                    if (_settings.AutoQuarantine)
                    {
                        // TODO: استدعاء QuarantineManager
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogDebug("خطأ في فحص الملف: {Path} - {Error}", filePath, ex.Message);
            }
        }

        /// <summary>
        /// هل يجب معالجة هذا الملف؟
        /// </summary>
        private bool ShouldProcess(string filePath)
        {
            try
            {
                // تخطي الامتدادات المستثناة
                var ext = Path.GetExtension(filePath).TrimStart('.').ToLowerInvariant();
                if (_excludedExtensions.Contains(ext))
                    return false;

                // تخطي المجلدات المستثناة
                var dirName = Path.GetDirectoryName(filePath)?.ToLowerInvariant() ?? "";
                foreach (var excluded in _excludedFolders)
                {
                    if (dirName.Contains(excluded))
                        return false;
                }

                // تخطي ملفات الحجر
                if (filePath.Contains(_settings.QuarantinePath, StringComparison.OrdinalIgnoreCase))
                    return false;

                return true;
            }
            catch
            {
                return false;
            }
        }

        public void Dispose()
        {
            if (_disposed) return;

            Stop();
            _debouncer.Dispose();
            _scanOrchestrator.Dispose();

            _disposed = true;
        }
    }

    /// <summary>
    /// حدث اكتشاف ملف جديد
    /// </summary>
    public class RealTimeEventArgs : EventArgs
    {
        public string FilePath { get; set; } = "";
        public WatcherChangeTypes ChangeType { get; set; }
        public DateTime DetectedAt { get; set; }
    }
}
