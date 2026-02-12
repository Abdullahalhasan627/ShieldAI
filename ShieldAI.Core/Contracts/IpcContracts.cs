// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Core/Contracts/IpcContracts.cs
// عقود الاتصال بين UI و Service
// =====================================================

using System.Text.Json;
using System.Text.Json.Serialization;
using ShieldAI.Core.Models;

namespace ShieldAI.Core.Contracts
{
    #region Base Envelopes
    
    /// <summary>
    /// غلاف الأوامر
    /// </summary>
    public class CommandEnvelope
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string CommandType { get; set; } = "";
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string? SessionToken { get; set; }
        public string? Payload { get; set; }

        public T? GetPayload<T>() where T : class
        {
            if (string.IsNullOrEmpty(Payload)) return null;
            return JsonSerializer.Deserialize<T>(Payload, JsonOptions.Default);
        }

        public static CommandEnvelope Create<T>(string commandType, T payload) where T : class
        {
            return new CommandEnvelope
            {
                CommandType = commandType,
                Payload = JsonSerializer.Serialize(payload, JsonOptions.Default)
            };
        }

        public static CommandEnvelope Create(string commandType)
        {
            return new CommandEnvelope { CommandType = commandType };
        }

        public string ToJson() => JsonSerializer.Serialize(this, JsonOptions.Default);
        public static CommandEnvelope? FromJson(string json) => 
            JsonSerializer.Deserialize<CommandEnvelope>(json, JsonOptions.Default);
    }

    /// <summary>
    /// غلاف الاستجابات
    /// </summary>
    public class ResponseEnvelope
    {
        public Guid CommandId { get; set; }
        public bool Success { get; set; }
        public string? Error { get; set; }
        public string? Payload { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.Now;

        public T? GetPayload<T>() where T : class
        {
            if (string.IsNullOrEmpty(Payload)) return null;
            return JsonSerializer.Deserialize<T>(Payload, JsonOptions.Default);
        }

        public static ResponseEnvelope Ok<T>(Guid commandId, T payload) where T : class
        {
            return new ResponseEnvelope
            {
                CommandId = commandId,
                Success = true,
                Payload = JsonSerializer.Serialize(payload, JsonOptions.Default)
            };
        }

        public static ResponseEnvelope Ok(Guid commandId)
        {
            return new ResponseEnvelope { CommandId = commandId, Success = true };
        }

        public static ResponseEnvelope Fail(Guid commandId, string error)
        {
            return new ResponseEnvelope { CommandId = commandId, Success = false, Error = error };
        }

        public string ToJson() => JsonSerializer.Serialize(this, JsonOptions.Default);
        public static ResponseEnvelope? FromJson(string json) => 
            JsonSerializer.Deserialize<ResponseEnvelope>(json, JsonOptions.Default);
    }

    #endregion

    #region Auth

    public class HelloResponse
    {
        public string SessionToken { get; set; } = "";
        public int ExpiresInSeconds { get; set; } = 3600;
    }

    #endregion

    #region Command Types

    public static class Commands
    {
        // المصادقة
        public const string Hello = "hello";

        // الخدمة
        public const string Ping = "ping";
        public const string GetStatus = "get_status";
        public const string Shutdown = "shutdown";

        // الفحص
        public const string StartScan = "start_scan";
        public const string StopScan = "stop_scan";
        public const string GetScanProgress = "get_scan_progress";
        public const string GetScanReport = "get_scan_report";

        // الحماية الفورية
        public const string EnableRealTime = "enable_realtime";
        public const string DisableRealTime = "disable_realtime";
        public const string GetRealTimeStatus = "get_realtime_status";

        // الحجر
        public const string GetQuarantineList = "get_quarantine_list";
        public const string RestoreFromQuarantine = "restore_quarantine";
        public const string DeleteFromQuarantine = "delete_quarantine";
        public const string ClearQuarantine = "clear_quarantine";

        // الإعدادات
        public const string UpdateSettings = "update_settings";
        public const string GetSettings = "get_settings";

        // السجلات
        public const string GetLogs = "get_logs";
        public const string ClearLogs = "clear_logs";

        // قرارات التهديد
        public const string ResolveThreatAction = "resolve_threat_action";
        public const string GetPendingThreats = "get_pending_threats";
    }

    #endregion

    #region Scan Commands

    public class StartScanRequest
    {
        public List<string> Paths { get; set; } = new();
        public ScanType ScanType { get; set; } = ScanType.Custom;
        public bool UseVirusTotal { get; set; } = false;
        public bool DeepScan { get; set; } = true;
    }

    public class StartScanResponse
    {
        public Guid JobId { get; set; }
        public int TotalFiles { get; set; }
    }

    public class StopScanRequest
    {
        public Guid JobId { get; set; }
    }

    public class ScanProgressResponse
    {
        public Guid JobId { get; set; }
        public ScanStatus Status { get; set; }
        public int TotalFiles { get; set; }
        public int ScannedFiles { get; set; }
        public int ThreatsFound { get; set; }
        public double ProgressPercent { get; set; }
        public string? CurrentFile { get; set; }
    }

    #endregion

    #region Quarantine Commands

    public class QuarantineListResponse
    {
        public List<QuarantineItemDto> Items { get; set; } = new();
        public int TotalCount { get; set; }
    }

    public class QuarantineItemDto
    {
        public Guid Id { get; set; }
        public string OriginalPath { get; set; } = "";
        public string OriginalName { get; set; } = "";
        public string ThreatName { get; set; } = "";
        public long FileSize { get; set; }
        public DateTime QuarantinedAt { get; set; }
    }

    public class QuarantineActionRequest
    {
        public Guid EntryId { get; set; }
        public string? RestorePath { get; set; } // للاستعادة فقط
    }

    #endregion

    #region Service Status

    public class ServiceStatusResponse
    {
        public bool IsRunning { get; set; }
        public bool RealTimeEnabled { get; set; }
        public DateTime StartTime { get; set; }
        public int ActiveScans { get; set; }
        public int QuarantineCount { get; set; }
        public int TotalThreatsBlocked { get; set; }
        public string Version { get; set; } = "1.0.0";
    }

    #endregion

    #region Events (Service → UI)

    public static class Events
    {
        public const string ScanProgress = "event_scan_progress";
        public const string ThreatDetected = "event_threat_detected";
        public const string ScanCompleted = "event_scan_completed";
        public const string RealTimeAlert = "event_realtime_alert";
        public const string LogEntry = "event_log_entry";
        public const string ThreatActionRequired = "event_threat_action_required";
        public const string ThreatActionApplied = "event_threat_action_applied";
    }

    public class EventEnvelope
    {
        public string EventType { get; set; } = "";
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string? Payload { get; set; }

        public T? GetPayload<T>() where T : class
        {
            if (string.IsNullOrEmpty(Payload)) return null;
            return JsonSerializer.Deserialize<T>(Payload, JsonOptions.Default);
        }

        public static EventEnvelope Create<T>(string eventType, T payload) where T : class
        {
            return new EventEnvelope
            {
                EventType = eventType,
                Payload = JsonSerializer.Serialize(payload, JsonOptions.Default)
            };
        }

        public string ToJson() => JsonSerializer.Serialize(this, JsonOptions.Default);
        public static EventEnvelope? FromJson(string json) => 
            JsonSerializer.Deserialize<EventEnvelope>(json, JsonOptions.Default);
    }

    public class ThreatDetectedEvent
    {
        public Guid JobId { get; set; }
        public string FilePath { get; set; } = "";
        public string ThreatName { get; set; } = "";
        public string Verdict { get; set; } = "";
        public double RiskScore { get; set; }
        public bool AutoQuarantined { get; set; }
    }

    /// <summary>
    /// DTO شامل لحدث تهديد — يُرسل عبر IPC للواجهة
    /// </summary>
    public class ThreatEventDto
    {
        public string EventId { get; set; } = Guid.NewGuid().ToString("N")[..12];
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
        public string FilePath { get; set; } = "";
        public string FileName { get; set; } = "";
        public string? Sha256 { get; set; }
        public int AggregatedScore { get; set; }
        public string Verdict { get; set; } = "";
        public string RecommendedAction { get; set; } = "";
        public List<ThreatEngineBreakdown> EngineBreakdown { get; set; } = new();
        public List<string> Reasons { get; set; } = new();
        public string? QuarantineId { get; set; }
        public bool ActionTaken { get; set; }
        public string? ActionResult { get; set; }
    }

    public class ThreatEngineBreakdown
    {
        public string Engine { get; set; } = "";
        public int Score { get; set; }
        public string Verdict { get; set; } = "";
    }

    /// <summary>
    /// الإجراءات المتاحة للتهديد
    /// </summary>
    public enum ThreatAction
    {
        Quarantine,
        Delete,
        Allow
    }

    /// <summary>
    /// طلب حل تهديد من الواجهة
    /// </summary>
    public class ResolveThreatRequest
    {
        public string EventId { get; set; } = "";
        public ThreatAction Action { get; set; }
        public bool AddToExclusions { get; set; }
    }

    /// <summary>
    /// استجابة حل تهديد
    /// </summary>
    public class ResolveThreatResponse
    {
        public bool Success { get; set; }
        public string EventId { get; set; } = "";
        public string ActionApplied { get; set; } = "";
        public string? Error { get; set; }
    }

    /// <summary>
    /// قائمة التهديدات المعلّقة
    /// </summary>
    public class PendingThreatsResponse
    {
        public List<ThreatEventDto> PendingThreats { get; set; } = new();
    }

    public class LogEntryEvent
    {
        public DateTime Timestamp { get; set; }
        public string Level { get; set; } = "Info";
        public string Message { get; set; } = "";
        public string? Source { get; set; }
    }

    #endregion

    #region Settings

    public class SettingsDto
    {
        public bool RealTimeProtection { get; set; }
        public bool AutoQuarantine { get; set; }
        public int MaxFileSizeMB { get; set; }
        public string ExcludedExtensions { get; set; } = "";
        public string ExcludedFolders { get; set; } = "";
        public string VirusTotalApiKey { get; set; } = "";
        public bool UseVirusTotalInAIScan { get; set; }
    }

    #endregion

    #region Logs

    public class GetLogsRequest
    {
        public int Count { get; set; } = 100;
        public string? Level { get; set; }
        public DateTime? From { get; set; }
    }

    public class LogsResponse
    {
        public List<LogEntryEvent> Entries { get; set; } = new();
        public int TotalCount { get; set; }
    }

    #endregion

    #region JSON Options

    public static class JsonOptions
    {
        public static readonly JsonSerializerOptions Default = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Converters = { new JsonStringEnumConverter() }
        };
    }

    #endregion
}
