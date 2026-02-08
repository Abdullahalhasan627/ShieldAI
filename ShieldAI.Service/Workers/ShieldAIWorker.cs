// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Service/Workers/ShieldAIWorker.cs
// Worker الرئيسي للخدمة
// =====================================================

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ShieldAI.Core.Configuration;
using ShieldAI.Core.Monitoring;
using ShieldAI.Core.Scanning;
using ShieldAI.Core.Security;

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
        private Core.Security.QuarantineManager? _quarantineManager;

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
        public bool IsRealTimeEnabled => _realTimeMonitor?.IsRunning ?? false;

        public ShieldAIWorker(ILogger<ShieldAIWorker> logger)
        {
            _logger = logger;
            _settings = ConfigManager.Instance.Settings;
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
                    _logger.LogInformation("الحماية الفورية: مفعلة");
                }
                else
                {
                    _logger.LogInformation("الحماية الفورية: معطلة");
                }

                // انتظار إشارة الإيقاف
                while (!stoppingToken.IsCancellationRequested)
                {
                    await Task.Delay(1000, stoppingToken);
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

            // مراقب الوقت الفعلي
            _realTimeMonitor = new RealTimeMonitor(_logger, vtApiKey);
            _realTimeMonitor.ThreatFound += OnRealTimeThreat;

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

        private void Cleanup()
        {
            _realTimeMonitor?.Dispose();
            _scanOrchestrator?.Dispose();
            _logger.LogInformation("تم تنظيف الموارد");
        }
    }
}
