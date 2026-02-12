// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Service/Workers/ShieldAIWorker.cs
// Worker الرئيسي للخدمة
// =====================================================

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ShieldAI.Core.Configuration;
using ShieldAI.Core.Contracts;
using ShieldAI.Core.Detection;
using ShieldAI.Core.Monitoring;
using ShieldAI.Core.Monitoring.Quarantine;
using ShieldAI.Core.Scanning;
using ShieldAI.Core.Security;
using ShieldAI.Service.Ipc;

namespace ShieldAI.Service.Workers
{
    /// <summary>
    /// Worker الرئيسي - يدير جميع مكونات الخدمة
    /// </summary>
    public class ShieldAIWorker : BackgroundService
    {
        private readonly ILogger<ShieldAIWorker> _logger;
        private readonly AppSettings _settings;
        
        private ScanOrchestrator? _scanOrchestrator;
        private RealTimeMonitor? _realTimeMonitor;
        private RealtimeWorker? _realtimeWorker;
        private Core.Security.QuarantineManager? _quarantineManager;
        private QuarantineStore? _quarantineStore;
        private PipeServer? _pipeServer;

        private bool _isDegradedMode;
        private int _watchdogRestartCount;

        public static ShieldAIWorker? Instance { get; private set; }

        // المكونات العامة
        public ScanOrchestrator ScanOrchestrator => _scanOrchestrator 
            ?? throw new InvalidOperationException("Service not started");
        public RealTimeMonitor RealTimeMonitor => _realTimeMonitor 
            ?? throw new InvalidOperationException("Service not started");
        public Core.Security.QuarantineManager QuarantineManager => _quarantineManager 
            ?? throw new InvalidOperationException("Service not started");

        // الإحصائيات
        public DateTime StartTime { get; private set; }
        public int TotalThreatsBlocked { get; private set; }
        public bool IsRealTimeEnabled => _realtimeWorker?.IsRunning ?? _realTimeMonitor?.IsRunning ?? false;
        public bool IsDegradedMode => _isDegradedMode;
        public int WatchdogRestartCount => _watchdogRestartCount;

        /// <summary>
        /// منفّذ إجراءات التهديد — للوصول من IPC command handler
        /// </summary>
        public ThreatActionExecutor? ActionExecutor => _realtimeWorker?.ActionExecutor;

        public ShieldAIWorker(ILogger<ShieldAIWorker> logger, PipeServer? pipeServer = null)
        {
            _logger = logger;
            _settings = ConfigManager.Instance.Settings;
            _pipeServer = pipeServer;
            Instance = this;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("===========================================");
            _logger.LogInformation("ShieldAI Service بدأت");
            _logger.LogInformation("===========================================");

            StartTime = DateTime.Now;

            try
            {
                // تهيئة المكونات
                InitializeComponents();

                // بدء الحماية الفورية إذا كانت مفعلة
                if (_settings.EnableRealTimeProtection)
                {
                    _realTimeMonitor?.Start();
                    _realtimeWorker?.Start();
                    _logger.LogInformation("الحماية الفورية: مفعلة");
                }
                else
                {
                    _logger.LogInformation("الحماية الفورية: معطلة");
                }

                // حلقة المراقبة الرئيسية مع watchdog
                while (!stoppingToken.IsCancellationRequested)
                {
                    await Task.Delay(5000, stoppingToken);
                    RunWatchdogCheck();
                    UpdateDegradedMode();
                }
            }
            catch (OperationCanceledException)
            {
                // إيقاف عادي
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "خطأ في ShieldAIWorker");
            }
            finally
            {
                Cleanup();
            }

            _logger.LogInformation("ShieldAI Service توقفت");
        }

        private void InitializeComponents()
        {
            var vtApiKey = _settings.VirusTotalApiKey;

            // منسق الفحص
            _scanOrchestrator = new ScanOrchestrator(_logger, vtApiKey);
            _scanOrchestrator.ThreatDetected += OnThreatDetected;
            _scanOrchestrator.ScanCompleted += OnScanCompleted;

            // مدير الحجر
            _quarantineManager = new Core.Security.QuarantineManager(_logger);

            // مخزن الحجر الآمن
            _quarantineStore = new QuarantineStore();

            // مراقب الوقت الفعلي (Legacy)
            _realTimeMonitor = new RealTimeMonitor(_logger, vtApiKey);
            _realTimeMonitor.ThreatFound += OnRealTimeThreat;

            // مراقب Pipeline الفوري مع Quick Gate
            _realtimeWorker = new RealtimeWorker(_logger, _quarantineStore);
            _realtimeWorker.ThreatDetected += OnRealtimeWorkerThreat;

            // ربط أحداث إجراءات التهديد بالبث عبر IPC
            _realtimeWorker.ActionExecutor.ThreatActionRequired += OnThreatActionRequired;
            _realtimeWorker.ActionExecutor.ThreatActionApplied += OnThreatActionApplied;

            _logger.LogInformation("تم تهيئة جميع المكونات");
        }

        private void OnThreatDetected(object? sender, Core.Models.ThreatDetectedEventArgs e)
        {
            TotalThreatsBlocked++;
            _logger.LogWarning("تهديد: {File} - {Threat}", 
                e.Result.FilePath, e.Result.ThreatName);

            // الحجر التلقائي
            if (_settings.AutoQuarantine && _quarantineManager != null)
            {
                Task.Run(async () =>
                {
                    await _quarantineManager.QuarantineFileAsync(e.Result.FilePath, e.Result);
                });
            }

            // TODO: إرسال Event للـ UI عبر IPC
        }

        private void OnScanCompleted(object? sender, Core.Models.ScanCompletedEventArgs e)
        {
            _logger.LogInformation("اكتمل الفحص: {Scanned} ملف - {Threats} تهديد",
                e.Report.ScannedFiles, e.Report.ThreatsFound);
        }

        private void OnRealTimeThreat(object? sender, Core.Models.ThreatDetectedEventArgs e)
        {
            TotalThreatsBlocked++;
            _logger.LogWarning("تهديد فوري: {File}", e.Result.FilePath);

            // الحجر التلقائي
            if (_settings.AutoQuarantine && _quarantineManager != null)
            {
                Task.Run(async () =>
                {
                    var entry = await _quarantineManager.QuarantineFileAsync(e.Result.FilePath, e.Result);
                    if (entry != null)
                    {
                        _logger.LogInformation("تم حجر الملف: {File}", e.Result.FilePath);
                    }
                });
            }
        }

        /// <summary>
        /// تفعيل/إيقاف الحماية الفورية
        /// </summary>
        public void SetRealTimeProtection(bool enabled)
        {
            if (enabled)
            {
                _realTimeMonitor?.Start();
                _logger.LogInformation("تم تفعيل الحماية الفورية");
            }
            else
            {
                _realTimeMonitor?.Stop();
                _logger.LogInformation("تم إيقاف الحماية الفورية");
            }
        }

        /// <summary>
        /// مراقب صحة RealtimeWorker - يعيد تشغيله إذا توقف
        /// </summary>
        private void RunWatchdogCheck()
        {
            if (!_settings.EnableRealTimeProtection)
                return;

            if (_realtimeWorker != null && !_realtimeWorker.IsRunning)
            {
                _watchdogRestartCount++;
                _logger.LogWarning(
                    "Watchdog: RealtimeWorker توقف، إعادة تشغيل (المرة #{Count})",
                    _watchdogRestartCount);

                try
                {
                    _realtimeWorker.Dispose();
                    _realtimeWorker = new RealtimeWorker(_logger, _quarantineStore!);
                    _realtimeWorker.ThreatDetected += OnRealtimeWorkerThreat;
                    _realtimeWorker.Start();
                    _logger.LogInformation("Watchdog: تم إعادة تشغيل RealtimeWorker بنجاح");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Watchdog: فشل إعادة تشغيل RealtimeWorker");
                }
            }
        }

        /// <summary>
        /// تحديث حالة الوضع المخفف بناءً على ضغط الطابور
        /// </summary>
        private void UpdateDegradedMode()
        {
            if (_realtimeWorker == null)
                return;

            var pending = _realtimeWorker.PendingCount;

            if (!_isDegradedMode && pending >= _settings.DegradedModeThreshold)
            {
                _isDegradedMode = true;
                _logger.LogWarning(
                    "Degraded Mode: تفعيل - الطابور {Pending} >= {Threshold}",
                    pending, _settings.DegradedModeThreshold);
            }
            else if (_isDegradedMode && pending <= _settings.DegradedRecoveryThreshold)
            {
                _isDegradedMode = false;
                _logger.LogInformation(
                    "Degraded Mode: تعطيل - الطابور {Pending} <= {Threshold}",
                    pending, _settings.DegradedRecoveryThreshold);
            }
        }

        private void OnRealtimeWorkerThreat(object? sender, Core.Detection.ThreatScoring.AggregatedThreatResult result)
        {
            TotalThreatsBlocked++;
            _logger.LogWarning("تهديد Pipeline: {File} - Score: {Score}",
                result.FilePath, result.RiskScore);

            // بث حدث ThreatDetected للواجهة
            if (_pipeServer != null)
            {
                var evt = new ThreatDetectedEvent
                {
                    FilePath = result.FilePath,
                    ThreatName = result.Reasons.FirstOrDefault() ?? "تهديد",
                    Verdict = result.Verdict.ToString(),
                    RiskScore = result.RiskScore,
                    AutoQuarantined = result.Verdict == Core.Detection.ThreatScoring.AggregatedVerdict.Block
                };
                _ = _pipeServer.BroadcastAsync(Events.ThreatDetected, evt);
            }
        }

        private void OnThreatActionRequired(object? sender, ThreatEventDto dto)
        {
            _logger.LogInformation("[IPC] بث ThreatActionRequired: {EventId} {File}", dto.EventId, dto.FilePath);
            if (_pipeServer != null)
            {
                _ = _pipeServer.BroadcastAsync(Events.ThreatActionRequired, dto);
            }
        }

        private void OnThreatActionApplied(object? sender, ThreatEventDto dto)
        {
            _logger.LogInformation("[IPC] بث ThreatActionApplied: {EventId} {Action}", dto.EventId, dto.ActionResult);
            if (_pipeServer != null)
            {
                _ = _pipeServer.BroadcastAsync(Events.ThreatActionApplied, dto);
            }
        }

        private void Cleanup()
        {
            _realtimeWorker?.Dispose();
            _realTimeMonitor?.Dispose();
            _scanOrchestrator?.Dispose();
            _quarantineStore?.Dispose();
            _logger.LogInformation("تم تنظيف الموارد");
        }
    }
}
