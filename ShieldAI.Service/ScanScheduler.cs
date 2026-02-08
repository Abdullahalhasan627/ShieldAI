// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Service/ScanScheduler.cs
// مجدول الفحص
// =====================================================

using ShieldAI.Core.Configuration;
using ShieldAI.Core.Logging;
using ShieldAI.Core.Scanning;

namespace ShieldAI.Service
{
    /// <summary>
    /// مجدول الفحص - يدير الفحوصات المجدولة
    /// </summary>
    public class ScanScheduler
    {
        private readonly Core.Logging.ILogger _logger;
        private readonly FileScanner _fileScanner;
        private readonly List<ScheduledScan> _scheduledScans;
        private CancellationTokenSource? _cts;
        private Task? _schedulerTask;
        private bool _isRunning;

        /// <summary>
        /// هل المجدول يعمل
        /// </summary>
        public bool IsRunning => _isRunning;

        /// <summary>
        /// الفحوصات المجدولة
        /// </summary>
        public IReadOnlyList<ScheduledScan> ScheduledScans => _scheduledScans.AsReadOnly();

        /// <summary>
        /// حدث عند بدء فحص مجدول
        /// </summary>
        public event EventHandler<ScheduledScan>? ScanStarted;

        /// <summary>
        /// حدث عند انتهاء فحص مجدول
        /// </summary>
        public event EventHandler<ScheduledScanResult>? ScanCompleted;

        public ScanScheduler(Core.Logging.ILogger? logger = null)
        {
            _logger = logger ?? new ServiceNullLogger();
            _fileScanner = new FileScanner();
            _scheduledScans = new List<ScheduledScan>();

            // تحميل الفحوصات المجدولة الافتراضية
            LoadDefaultSchedules();
        }

        /// <summary>
        /// بدء المجدول
        /// </summary>
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            if (_isRunning)
                return;

            _logger.Information("بدء مجدول الفحص...");

            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _schedulerTask = Task.Run(() => SchedulerLoopAsync(_cts.Token), _cts.Token);

            _isRunning = true;
            _logger.Information("مجدول الفحص يعمل");

            await Task.CompletedTask;
        }

        /// <summary>
        /// إيقاف المجدول
        /// </summary>
        public async Task StopAsync(CancellationToken cancellationToken)
        {
            if (!_isRunning)
                return;

            _logger.Information("إيقاف مجدول الفحص...");

            _cts?.Cancel();

            if (_schedulerTask != null)
            {
                try
                {
                    await _schedulerTask.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);
                }
                catch (TimeoutException)
                {
                    _logger.Warning("انتهت مهلة إيقاف المجدول");
                }
                catch (OperationCanceledException)
                {
                    // طبيعي
                }
            }

            _isRunning = false;
            _logger.Information("تم إيقاف مجدول الفحص");
        }

        #region Public Methods
        /// <summary>
        /// إضافة فحص مجدول
        /// </summary>
        public void AddScheduledScan(ScheduledScan scan)
        {
            _scheduledScans.Add(scan);
            UpdateNextRunTime(scan);
            _logger.Information("تم إضافة فحص مجدول: {0}", scan.Name);
        }

        /// <summary>
        /// حذف فحص مجدول
        /// </summary>
        public bool RemoveScheduledScan(Guid scanId)
        {
            var scan = _scheduledScans.FirstOrDefault(s => s.Id == scanId);
            if (scan != null)
            {
                _scheduledScans.Remove(scan);
                _logger.Information("تم حذف فحص مجدول: {0}", scan.Name);
                return true;
            }
            return false;
        }

        /// <summary>
        /// تحديث فحص مجدول
        /// </summary>
        public void UpdateScheduledScan(ScheduledScan scan)
        {
            var existing = _scheduledScans.FirstOrDefault(s => s.Id == scan.Id);
            if (existing != null)
            {
                var index = _scheduledScans.IndexOf(existing);
                _scheduledScans[index] = scan;
                UpdateNextRunTime(scan);
                _logger.Information("تم تحديث فحص مجدول: {0}", scan.Name);
            }
        }

        /// <summary>
        /// تشغيل فحص مجدول فوراً
        /// </summary>
        public async Task<ScheduledScanResult> RunNowAsync(Guid scanId, CancellationToken cancellationToken)
        {
            var scan = _scheduledScans.FirstOrDefault(s => s.Id == scanId);
            if (scan == null)
            {
                return new ScheduledScanResult
                {
                    ScanId = scanId,
                    Success = false,
                    Error = "الفحص غير موجود"
                };
            }

            return await ExecuteScheduledScanAsync(scan, cancellationToken);
        }
        #endregion

        #region Private Methods
        private void LoadDefaultSchedules()
        {
            // فحص سريع يومي
            _scheduledScans.Add(new ScheduledScan
            {
                Name = "الفحص السريع اليومي",
                Profile = ScanProfile.QuickScan,
                Schedule = new ScanSchedule
                {
                    Type = ScheduleType.Daily,
                    Time = new TimeSpan(12, 0, 0)
                },
                IsEnabled = true
            });

            // فحص كامل أسبوعي
            _scheduledScans.Add(new ScheduledScan
            {
                Name = "الفحص الكامل الأسبوعي",
                Profile = ScanProfile.FullScan,
                Schedule = new ScanSchedule
                {
                    Type = ScheduleType.Weekly,
                    Time = new TimeSpan(2, 0, 0),
                    DayOfWeek = DayOfWeek.Saturday
                },
                IsEnabled = true
            });

            // حساب أوقات التشغيل التالية
            foreach (var scan in _scheduledScans)
            {
                UpdateNextRunTime(scan);
            }
        }

        private async Task SchedulerLoopAsync(CancellationToken cancellationToken)
        {
            _logger.Debug("بدء حلقة المجدول");

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // التحقق من الفحوصات المستحقة
                    var dueScans = _scheduledScans
                        .Where(s => s.IsEnabled && s.NextRunTime.HasValue && s.NextRunTime <= DateTime.Now)
                        .ToList();

                    foreach (var scan in dueScans)
                    {
                        if (cancellationToken.IsCancellationRequested)
                            break;

                        _logger.Information("تنفيذ فحص مجدول: {0}", scan.Name);
                        await ExecuteScheduledScanAsync(scan, cancellationToken);
                        UpdateNextRunTime(scan);
                    }

                    // انتظار دقيقة قبل التحقق مرة أخرى
                    await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "خطأ في حلقة المجدول");
                    await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
                }
            }

            _logger.Debug("انتهاء حلقة المجدول");
        }

        private void UpdateNextRunTime(ScheduledScan scan)
        {
            var now = DateTime.Now;
            DateTime? nextRun = null;

            switch (scan.Schedule.Type)
            {
                case ScheduleType.Daily:
                    nextRun = now.Date.Add(scan.Schedule.Time);
                    if (nextRun <= now)
                        nextRun = nextRun.Value.AddDays(1);
                    break;

                case ScheduleType.Weekly:
                    nextRun = now.Date.Add(scan.Schedule.Time);
                    while (nextRun.Value.DayOfWeek != scan.Schedule.DayOfWeek || nextRun <= now)
                    {
                        nextRun = nextRun.Value.AddDays(1);
                    }
                    break;

                case ScheduleType.Monthly:
                    nextRun = new DateTime(now.Year, now.Month, scan.Schedule.DayOfMonth).Add(scan.Schedule.Time);
                    if (nextRun <= now)
                        nextRun = nextRun.Value.AddMonths(1);
                    break;

                case ScheduleType.Once:
                    if (!scan.LastRunTime.HasValue)
                        nextRun = now.Date.Add(scan.Schedule.Time);
                    break;
            }

            scan.NextRunTime = nextRun;
        }

        private async Task<ScheduledScanResult> ExecuteScheduledScanAsync(ScheduledScan scan, CancellationToken cancellationToken)
        {
            var result = new ScheduledScanResult
            {
                ScanId = scan.Id,
                StartTime = DateTime.Now
            };

            try
            {
                ScanStarted?.Invoke(this, scan);

                // تنفيذ الفحص على كل مسار
                int totalScanned = 0;
                int totalThreats = 0;
                
                foreach (var targetPath in scan.Profile.TargetPaths)
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    
                    var results = await _fileScanner.ScanDirectoryAsync(targetPath, true, cancellationToken);
                    totalScanned += results.Count;
                    totalThreats += results.Count(r => r.IsInfected);
                }

                result.Success = true;
                result.FilesScanned = totalScanned;
                result.ThreatsFound = totalThreats;
                result.EndTime = DateTime.Now;

                scan.LastRunTime = result.EndTime;

                _logger.Information("اكتمل الفحص المجدول: {0} - {1} ملف، {2} تهديد",
                    scan.Name, result.FilesScanned, result.ThreatsFound);
            }
            catch (OperationCanceledException)
            {
                result.Success = false;
                result.Error = "تم إلغاء الفحص";
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Error = ex.Message;
                _logger.Error(ex, "خطأ في الفحص المجدول: {0}", scan.Name);
            }
            finally
            {
                ScanCompleted?.Invoke(this, result);
            }

            return result;
        }
        #endregion
    }

    /// <summary>
    /// Logger فارغ للاستخدام في الخدمة
    /// </summary>
    internal class ServiceNullLogger : Core.Logging.ILogger
    {
        public void Trace(string message, params object[] args) { }
        public void Debug(string message, params object[] args) { }
        public void Information(string message, params object[] args) { }
        public void Warning(string message, params object[] args) { }
        public void Error(string message, params object[] args) { }
        public void Error(Exception exception, string message, params object[] args) { }
        public void Critical(string message, params object[] args) { }
        public void Critical(Exception exception, string message, params object[] args) { }
        public void SecurityEvent(string eventType, string details, ThreatSeverity? severity = null) { }
        public void ScanEvent(string filePath, bool isThreat, string? threatName = null) { }
        public IEnumerable<LogEvent> GetRecentEvents(int count = 100) => Array.Empty<LogEvent>();
        public IEnumerable<LogEvent> GetEvents(DateTime? from = null, DateTime? to = null, Core.Configuration.LogLevel? minLevel = null) => Array.Empty<LogEvent>();
        public void CleanupOldLogs(int retentionDays) { }
    }

    #region Models
    /// <summary>
    /// فحص مجدول
    /// </summary>
    public class ScheduledScan
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Name { get; set; } = string.Empty;
        public ScanProfile Profile { get; set; } = ScanProfile.QuickScan;
        public ScanSchedule Schedule { get; set; } = new();
        public bool IsEnabled { get; set; } = true;
        public DateTime? LastRunTime { get; set; }
        public DateTime? NextRunTime { get; set; }
    }

    /// <summary>
    /// جدول الفحص
    /// </summary>
    public class ScanSchedule
    {
        public ScheduleType Type { get; set; } = ScheduleType.Daily;
        public TimeSpan Time { get; set; } = new TimeSpan(12, 0, 0);
        public DayOfWeek DayOfWeek { get; set; } = DayOfWeek.Saturday;
        public int DayOfMonth { get; set; } = 1;
    }

    /// <summary>
    /// نوع الجدولة
    /// </summary>
    public enum ScheduleType
    {
        Daily,
        Weekly,
        Monthly,
        Once
    }

    /// <summary>
    /// نتيجة الفحص المجدول
    /// </summary>
    public class ScheduledScanResult
    {
        public Guid ScanId { get; set; }
        public bool Success { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public int FilesScanned { get; set; }
        public int ThreatsFound { get; set; }
        public string? Error { get; set; }

        public TimeSpan Duration => EndTime.HasValue 
            ? EndTime.Value - StartTime 
            : TimeSpan.Zero;
    }
    #endregion
}
