// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Logging/ScanDiagnosticLog.cs
// سجل تشخيصي موحّد لكل عملية فحص مع CorrelationId
// =====================================================

using Microsoft.Extensions.Logging;
using ShieldAI.Core.Detection.ThreatScoring;
using MsILogger = Microsoft.Extensions.Logging.ILogger;
using MsLogLevel = Microsoft.Extensions.Logging.LogLevel;

namespace ShieldAI.Core.Logging
{
    /// <summary>
    /// سجل تشخيصي موحّد - ينشئ CorrelationId ويسجل كل خطوة في عملية الفحص
    /// </summary>
    public static class ScanDiagnosticLog
    {
        /// <summary>
        /// تسجيل نتيجة فحص كاملة مع CorrelationId وكل تفاصيل المحركات
        /// </summary>
        public static void LogScanResult(
            MsILogger? logger,
            string correlationId,
            ThreatScanContext context,
            AggregatedThreatResult result,
            string? policyDecision = null,
            bool? quarantineAttempted = null,
            bool? quarantineSuccess = null,
            int? quarantineRetries = null)
        {
            if (logger == null) return;

            // سجل ملخص أساسي
            logger.LogInformation(
                "[Scan:{CorrelationId}] Path={Path} SHA256={Hash} Size={Size} " +
                "AggScore={Score} Verdict={Verdict} Engines={EngineCount} Duration={Duration}ms",
                correlationId,
                context.FilePath,
                context.Sha256Hash ?? "N/A",
                context.FileSize,
                result.RiskScore,
                result.Verdict,
                result.EngineResults.Count,
                (int)result.Duration.TotalMilliseconds);

            // سجل نتيجة كل محرك
            foreach (var engineResult in result.EngineResults)
            {
                var level = engineResult.Verdict switch
                {
                    EngineVerdict.Malicious => MsLogLevel.Warning,
                    EngineVerdict.Suspicious => MsLogLevel.Warning,
                    _ => MsLogLevel.Debug
                };

                logger.Log(level,
                    "[Scan:{CorrelationId}]   Engine={Engine} Score={Score} Verdict={Verdict} " +
                    "Confidence={Confidence:F2} Error={HasError} Reasons=[{Reasons}]",
                    correlationId,
                    engineResult.EngineName,
                    engineResult.Score,
                    engineResult.Verdict,
                    engineResult.Confidence,
                    engineResult.HasError,
                    string.Join("; ", engineResult.Reasons.Take(3)));
            }

            // سجل قرار السياسة إن وُجد
            if (!string.IsNullOrWhiteSpace(policyDecision))
            {
                logger.LogInformation(
                    "[Scan:{CorrelationId}] PolicyDecision={Decision}",
                    correlationId, policyDecision);
            }

            // سجل نتيجة الحجر إن وُجدت
            if (quarantineAttempted == true)
            {
                if (quarantineSuccess == true)
                {
                    logger.LogInformation(
                        "[Scan:{CorrelationId}] Quarantine=SUCCESS Retries={Retries}",
                        correlationId, quarantineRetries ?? 0);
                }
                else
                {
                    logger.LogWarning(
                        "[Scan:{CorrelationId}] Quarantine=FAILED Retries={Retries}",
                        correlationId, quarantineRetries ?? 0);
                }
            }
        }

        /// <summary>
        /// تسجيل بدء فحص Quick Gate
        /// </summary>
        public static void LogQuickGate(
            MsILogger? logger,
            string correlationId,
            string filePath,
            int quickGateScore,
            bool atomicQuarantine)
        {
            if (logger == null) return;

            logger.LogInformation(
                "[Scan:{CorrelationId}] QuickGate Path={Path} Score={Score} AtomicQuarantine={AQ}",
                correlationId, filePath, quickGateScore, atomicQuarantine);
        }

        /// <summary>
        /// تسجيل قرار الرأي الثاني
        /// </summary>
        public static void LogSecondOpinion(
            MsILogger? logger,
            string correlationId,
            string engineName,
            int riskScore,
            string reason)
        {
            if (logger == null) return;

            logger.LogInformation(
                "[Scan:{CorrelationId}] SecondOpinion Engine={Engine} RiskScore={Score} Reason={Reason}",
                correlationId, engineName, riskScore, reason);
        }

        /// <summary>
        /// إنشاء CorrelationId فريد
        /// </summary>
        public static string NewCorrelationId() => Guid.NewGuid().ToString("N")[..12];
    }
}
