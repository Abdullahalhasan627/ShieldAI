// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Service/Ipc/PipeContracts.cs
// عقود Named Pipes - DTOs للطلبات والردود
// =====================================================

using ShieldAI.Core.Detection.ThreatScoring;
using ShieldAI.Core.Monitoring.Quarantine;

namespace ShieldAI.Service.Ipc
{
    /// <summary>
    /// أنواع الأوامر المدعومة
    /// </summary>
    public static class PipeCommands
    {
        public const string Ping = "ping";
        public const string GetStatus = "get_status";
        public const string Shutdown = "shutdown";

        public const string StartScan = "start_scan";
        public const string StopScan = "stop_scan";
        public const string GetScanProgress = "get_scan_progress";

        public const string EnableRealTime = "enable_realtime";
        public const string DisableRealTime = "disable_realtime";

        public const string GetQuarantineList = "get_quarantine_list";
        public const string RestoreFromQuarantine = "restore_quarantine";
        public const string DeleteFromQuarantine = "delete_quarantine";

        public const string GetHistory = "get_history";
        public const string GetSettings = "get_settings";
        public const string UpdateSettings = "update_settings";
    }

    /// <summary>
    /// طلب بدء فحص
    /// </summary>
    public class PipeScanRequest
    {
        public List<string> Paths { get; set; } = new();
        public string ScanType { get; set; } = "Custom";
        public bool DeepScan { get; set; } = true;
    }

    /// <summary>
    /// استجابة حالة الخدمة
    /// </summary>
    public class PipeStatusResponse
    {
        public bool IsRunning { get; set; }
        public bool RealTimeEnabled { get; set; }
        public DateTime StartTime { get; set; }
        public int ActiveScans { get; set; }
        public int QuarantineCount { get; set; }
        public int TotalThreatsBlocked { get; set; }
        public int PipelinePendingCount { get; set; }
        public string Version { get; set; } = "2.0.0";
    }

    /// <summary>
    /// استجابة تقدم الفحص
    /// </summary>
    public class PipeScanProgressResponse
    {
        public string Status { get; set; } = "Idle";
        public int TotalFiles { get; set; }
        public int ScannedFiles { get; set; }
        public int ThreatsFound { get; set; }
        public double ProgressPercent { get; set; }
        public string? CurrentFile { get; set; }
    }

    /// <summary>
    /// عنصر حجر في الاستجابة
    /// </summary>
    public class PipeQuarantineItem
    {
        public string Id { get; set; } = "";
        public string OriginalPath { get; set; } = "";
        public string OriginalName { get; set; } = "";
        public long FileSize { get; set; }
        public string Sha256Hash { get; set; } = "";
        public DateTime QuarantinedAt { get; set; }
        public string Verdict { get; set; } = "";
        public int RiskScore { get; set; }
        public List<string> Reasons { get; set; } = new();
        public string? ThreatName { get; set; }

        public static PipeQuarantineItem FromMetadata(QuarantineItemMetadata m) => new()
        {
            Id = m.Id,
            OriginalPath = m.OriginalPath,
            OriginalName = m.OriginalName,
            FileSize = m.FileSize,
            Sha256Hash = m.Sha256Hash,
            QuarantinedAt = m.QuarantinedAt,
            Verdict = m.Verdict,
            RiskScore = m.RiskScore,
            Reasons = m.Reasons,
            ThreatName = m.ThreatName
        };
    }

    /// <summary>
    /// استجابة قائمة الحجر
    /// </summary>
    public class PipeQuarantineListResponse
    {
        public List<PipeQuarantineItem> Items { get; set; } = new();
        public int TotalCount { get; set; }
    }

    /// <summary>
    /// طلب عملية على عنصر حجر
    /// </summary>
    public class PipeQuarantineActionRequest
    {
        public string ItemId { get; set; } = "";
        public string? RestorePath { get; set; }
    }

    /// <summary>
    /// سجل تهديد للتاريخ
    /// </summary>
    public class PipeThreatRecord
    {
        public string FilePath { get; set; } = "";
        public string FileName { get; set; } = "";
        public int RiskScore { get; set; }
        public string Verdict { get; set; } = "";
        public List<string> Reasons { get; set; } = new();
        public List<PipeEngineResult> EngineResults { get; set; } = new();
        public DateTime DetectedAt { get; set; }
        public string? Action { get; set; }
    }

    /// <summary>
    /// نتيجة محرك في سجل التهديد
    /// </summary>
    public class PipeEngineResult
    {
        public string EngineName { get; set; } = "";
        public int Score { get; set; }
        public string Verdict { get; set; } = "";
    }

    /// <summary>
    /// استجابة التاريخ
    /// </summary>
    public class PipeHistoryResponse
    {
        public List<PipeThreatRecord> Records { get; set; } = new();
        public int TotalCount { get; set; }
    }
}
