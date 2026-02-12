// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Core/Detection/ThreatActionExecutor.cs
// منفّذ إجراءات التهديد — Quarantine / Delete / Allow
// =====================================================

using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using ShieldAI.Core.Configuration;
using ShieldAI.Core.Contracts;
using ShieldAI.Core.Detection.ThreatScoring;
using ShieldAI.Core.Monitoring.Quarantine;

namespace ShieldAI.Core.Detection
{
    /// <summary>
    /// منفّذ إجراءات التهديد — يقرر ماذا يفعل بناءً على السياسة وينفذ
    /// </summary>
    public class ThreatActionExecutor
    {
        private readonly QuarantineStore _quarantineStore;
        private readonly AppSettings _settings;
        private readonly Microsoft.Extensions.Logging.ILogger? _logger;
        private readonly ConcurrentDictionary<string, ThreatEventDto> _pendingThreats = new();

        /// <summary>
        /// حدث يُطلق عند الحاجة لقرار المستخدم
        /// </summary>
        public event EventHandler<ThreatEventDto>? ThreatActionRequired;

        /// <summary>
        /// حدث يُطلق عند تنفيذ إجراء على تهديد
        /// </summary>
        public event EventHandler<ThreatEventDto>? ThreatActionApplied;

        public ThreatActionExecutor(
            QuarantineStore quarantineStore,
            AppSettings? settings = null,
            Microsoft.Extensions.Logging.ILogger? logger = null)
        {
            _quarantineStore = quarantineStore;
            _settings = settings ?? ConfigManager.Instance.Settings;
            _logger = logger;
        }

        /// <summary>
        /// تطبيق الإجراء بناءً على سياسة RealTimeActionMode
        /// </summary>
        public async Task<ThreatEventDto> ApplyActionAsync(
            AggregatedThreatResult result,
            ThreatScanContext context,
            CancellationToken ct = default)
        {
            var dto = BuildDto(result, context);

            // تحقق من Allowlist
            if (!string.IsNullOrWhiteSpace(context.Sha256Hash) &&
                _settings.Sha256Allowlist.Contains(context.Sha256Hash, StringComparer.OrdinalIgnoreCase))
            {
                dto.ActionTaken = true;
                dto.ActionResult = "Allowed (Allowlist)";
                dto.RecommendedAction = "Allow";
                _logger?.LogInformation("[ThreatAction] File in allowlist: {Path}", context.FilePath);
                return dto;
            }

            // لا إجراء إذا كان الملف نظيف
            if (result.Verdict == AggregatedVerdict.Allow)
            {
                dto.ActionTaken = false;
                dto.RecommendedAction = "None";
                return dto;
            }

            var mode = _settings.RealTimeActionMode;
            var score = result.RiskScore;

            switch (mode)
            {
                case "AutoQuarantine":
                    await ExecuteQuarantineAsync(dto, context.FilePath);
                    break;

                case "AutoBlock":
                    await ExecuteDeleteAsync(dto, context.FilePath);
                    break;

                case "AskUser":
                    if (score >= _settings.AutoQuarantineMinScore ||
                        result.EngineResults.Any(e => e.Confidence >= 0.95 && e.Score >= 95))
                    {
                        // خطير جداً — حجر مباشر + إشعار
                        await ExecuteQuarantineAsync(dto, context.FilePath);
                    }
                    else if (score >= _settings.AskUserMinScore)
                    {
                        // منطقة الشك — اسأل المستخدم
                        dto.RecommendedAction = "NeedsReview";
                        dto.ActionTaken = false;
                        _pendingThreats[dto.EventId] = dto;
                        ThreatActionRequired?.Invoke(this, dto);
                        _logger?.LogInformation("[ThreatAction] AskUser for {Path} score={Score}",
                            context.FilePath, score);
                    }
                    else
                    {
                        dto.RecommendedAction = "Monitor";
                        dto.ActionTaken = false;
                    }
                    break;

                default:
                    await ExecuteQuarantineAsync(dto, context.FilePath);
                    break;
            }

            if (dto.ActionTaken)
            {
                ThreatActionApplied?.Invoke(this, dto);
            }

            return dto;
        }

        /// <summary>
        /// حل تهديد معلّق بقرار المستخدم
        /// </summary>
        public async Task<ResolveThreatResponse> ResolveThreatAsync(ResolveThreatRequest request)
        {
            if (!_pendingThreats.TryRemove(request.EventId, out var dto))
            {
                return new ResolveThreatResponse
                {
                    Success = false,
                    EventId = request.EventId,
                    Error = "Threat not found or already resolved"
                };
            }

            try
            {
                switch (request.Action)
                {
                    case ThreatAction.Quarantine:
                        await ExecuteQuarantineAsync(dto, dto.FilePath);
                        break;

                    case ThreatAction.Delete:
                        await ExecuteDeleteAsync(dto, dto.FilePath);
                        break;

                    case ThreatAction.Allow:
                        ExecuteAllow(dto, request.AddToExclusions);
                        break;
                }

                ThreatActionApplied?.Invoke(this, dto);

                return new ResolveThreatResponse
                {
                    Success = true,
                    EventId = request.EventId,
                    ActionApplied = request.Action.ToString()
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "[ThreatAction] Failed to resolve {EventId}", request.EventId);
                return new ResolveThreatResponse
                {
                    Success = false,
                    EventId = request.EventId,
                    Error = ex.Message
                };
            }
        }

        /// <summary>
        /// الحصول على التهديدات المعلقة
        /// </summary>
        public List<ThreatEventDto> GetPendingThreats() => _pendingThreats.Values.ToList();

        #region Execution

        private async Task ExecuteQuarantineAsync(ThreatEventDto dto, string filePath)
        {
            if (!File.Exists(filePath))
            {
                dto.ActionTaken = false;
                dto.ActionResult = "File not found";
                return;
            }

            try
            {
                var (success, movedPath) = await _quarantineStore.TryAtomicMoveToQuarantineAsync(
                    filePath,
                    _settings.AtomicMoveMaxRetries,
                    _settings.AtomicMoveInitialDelayMs,
                    _settings.AtomicMoveMaxDelayMs);

                if (success && !string.IsNullOrWhiteSpace(movedPath))
                {
                    var metadata = await _quarantineStore.QuarantineMovedFileAsync(movedPath, filePath);
                    dto.QuarantineId = metadata?.Id;
                    dto.ActionTaken = true;
                    dto.ActionResult = "Quarantined";
                    dto.RecommendedAction = "Quarantine";
                    _logger?.LogInformation("[ThreatAction] Quarantined {Path}", filePath);
                }
                else
                {
                    dto.ActionTaken = false;
                    dto.ActionResult = "Quarantine failed - file locked or inaccessible";
                    _logger?.LogWarning("[ThreatAction] Quarantine FAILED for {Path}", filePath);
                }
            }
            catch (Exception ex)
            {
                dto.ActionTaken = false;
                dto.ActionResult = $"Quarantine error: {ex.Message}";
                _logger?.LogError(ex, "[ThreatAction] Quarantine error {Path}", filePath);
            }
        }

        private async Task ExecuteDeleteAsync(ThreatEventDto dto, string filePath)
        {
            // أولاً: حاول الحذف من الحجر إذا كان محجوراً
            if (!string.IsNullOrWhiteSpace(dto.QuarantineId))
            {
                try
                {
                    await _quarantineStore.DeleteFileAsync(dto.QuarantineId);
                    dto.ActionTaken = true;
                    dto.ActionResult = "Deleted from quarantine";
                    _logger?.LogInformation("[ThreatAction] Deleted quarantined {Id}", dto.QuarantineId);
                    return;
                }
                catch { /* fall through to direct delete */ }
            }

            // حذف مباشر مع retry
            for (int i = 0; i < 3; i++)
            {
                try
                {
                    if (File.Exists(filePath))
                    {
                        File.Delete(filePath);
                    }
                    dto.ActionTaken = true;
                    dto.ActionResult = "Deleted";
                    dto.RecommendedAction = "Delete";
                    _logger?.LogInformation("[ThreatAction] Deleted {Path}", filePath);
                    return;
                }
                catch (IOException) when (i < 2)
                {
                    await Task.Delay(100 * (i + 1));
                }
                catch (UnauthorizedAccessException) when (i < 2)
                {
                    await Task.Delay(100 * (i + 1));
                }
            }

            dto.ActionTaken = false;
            dto.ActionResult = "Delete failed - file locked";
        }

        private void ExecuteAllow(ThreatEventDto dto, bool addToExclusions)
        {
            if (addToExclusions && !string.IsNullOrWhiteSpace(dto.Sha256))
            {
                if (!_settings.Sha256Allowlist.Contains(dto.Sha256, StringComparer.OrdinalIgnoreCase))
                {
                    _settings.Sha256Allowlist.Add(dto.Sha256);
                    ConfigManager.Instance.Save();
                    _logger?.LogInformation("[ThreatAction] Added {Hash} to allowlist", dto.Sha256);
                }
            }

            // إذا كان الملف محجوراً → استعده
            if (!string.IsNullOrWhiteSpace(dto.QuarantineId))
            {
                try
                {
                    _quarantineStore.RestoreFileAsync(dto.QuarantineId).GetAwaiter().GetResult();
                    _logger?.LogInformation("[ThreatAction] Restored {Id} from quarantine", dto.QuarantineId);
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "[ThreatAction] Failed to restore {Id}", dto.QuarantineId);
                }
            }

            dto.ActionTaken = true;
            dto.ActionResult = addToExclusions ? "Allowed + Added to exclusions" : "Allowed";
            dto.RecommendedAction = "Allow";
        }

        #endregion

        #region Helpers

        private static ThreatEventDto BuildDto(AggregatedThreatResult result, ThreatScanContext context)
        {
            return new ThreatEventDto
            {
                TimestampUtc = DateTime.UtcNow,
                FilePath = result.FilePath,
                FileName = Path.GetFileName(result.FilePath),
                Sha256 = context.Sha256Hash,
                AggregatedScore = result.RiskScore,
                Verdict = result.Verdict.ToString(),
                Reasons = result.Reasons.Take(5).ToList(),
                EngineBreakdown = result.EngineResults
                    .Where(e => !e.HasError)
                    .Select(e => new ThreatEngineBreakdown
                    {
                        Engine = e.EngineName,
                        Score = e.Score,
                        Verdict = e.Verdict.ToString()
                    }).ToList()
            };
        }

        #endregion
    }
}
