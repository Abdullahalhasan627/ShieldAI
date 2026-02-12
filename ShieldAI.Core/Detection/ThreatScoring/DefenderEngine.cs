// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Detection/ThreatScoring/DefenderEngine.cs
// محرك Windows Defender كرأي ثانٍ عبر MpCmdRun.exe
// =====================================================

using System.Diagnostics;
using ShieldAI.Core.Configuration;

namespace ShieldAI.Core.Detection.ThreatScoring
{
    /// <summary>
    /// محرك Windows Defender - يستدعي MpCmdRun.exe لفحص ملف واحد
    /// </summary>
    public class DefenderEngine : IThreatEngine
    {
        public string EngineName => "DefenderEngine";
        public double DefaultWeight => 0.9;

        private static readonly string[] MpCmdRunPaths =
        {
            @"C:\Program Files\Windows Defender\MpCmdRun.exe",
            @"C:\ProgramData\Microsoft\Windows Defender\Platform"
        };

        private readonly int _timeoutSeconds;
        private readonly Lazy<string?> _mpCmdRunPath;

        public DefenderEngine(int timeoutSeconds = 60)
        {
            _timeoutSeconds = timeoutSeconds;
            _mpCmdRunPath = new Lazy<string?>(FindMpCmdRun);
        }

        public bool IsReady =>
            OperatingSystem.IsWindows() &&
            ConfigManager.Instance.Settings.EnableDefenderSecondOpinion &&
            _mpCmdRunPath.Value != null;

        public async Task<ThreatScanResult> ScanAsync(ThreatScanContext context, CancellationToken ct = default)
        {
            var result = new ThreatScanResult { EngineName = EngineName };

            if (!IsReady || !File.Exists(context.FilePath))
                return ThreatScanResult.Clean(EngineName);

            try
            {
                var (exitCode, output) = await RunMpCmdRunAsync(context.FilePath, ct);

                // MpCmdRun exit codes:
                // 0 = no threats found
                // 2 = threats found and remediated/detected
                if (exitCode == 2 || ContainsThreatIndicator(output))
                {
                    var threatName = ExtractThreatName(output);
                    result.Score = 95;
                    result.Verdict = EngineVerdict.Malicious;
                    result.Confidence = 0.95;
                    result.Reasons.Add($"Windows Defender اكتشف تهديد: {threatName}");
                    result.Metadata["DefenderThreatName"] = threatName;
                    result.Metadata["DefenderExitCode"] = exitCode;
                }
                else
                {
                    result.Score = 0;
                    result.Verdict = EngineVerdict.Clean;
                    result.Confidence = 0.85;
                    result.Metadata["DefenderExitCode"] = exitCode;
                }
            }
            catch (OperationCanceledException)
            {
                result = ThreatScanResult.Error(EngineName, "Defender scan timed out");
            }
            catch (Exception ex)
            {
                result = ThreatScanResult.Error(EngineName, ex.Message);
            }

            return result;
        }

        private async Task<(int ExitCode, string Output)> RunMpCmdRunAsync(string filePath, CancellationToken ct)
        {
            var mpPath = _mpCmdRunPath.Value
                ?? throw new InvalidOperationException("MpCmdRun.exe not found");

            var psi = new ProcessStartInfo
            {
                FileName = mpPath,
                Arguments = $"-Scan -ScanType 3 -File \"{filePath}\" -DisableRemediation",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = psi };
            process.Start();

            var outputTask = process.StandardOutput.ReadToEndAsync(ct);
            var errorTask = process.StandardError.ReadToEndAsync(ct);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(_timeoutSeconds));

            try
            {
                await process.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                throw;
            }

            var output = await outputTask;
            var error = await errorTask;

            return (process.ExitCode, output + "\n" + error);
        }

        private static bool ContainsThreatIndicator(string output)
        {
            if (string.IsNullOrWhiteSpace(output)) return false;
            var lower = output.ToLowerInvariant();
            return lower.Contains("threat") ||
                   lower.Contains("found") ||
                   lower.Contains("detected") ||
                   lower.Contains("malware");
        }

        private static string ExtractThreatName(string output)
        {
            if (string.IsNullOrWhiteSpace(output))
                return "Unknown";

            // Try to parse "Threat  : ThreatName" pattern
            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("Threat", StringComparison.OrdinalIgnoreCase) &&
                    trimmed.Contains(':'))
                {
                    var name = trimmed[(trimmed.IndexOf(':') + 1)..].Trim();
                    if (!string.IsNullOrWhiteSpace(name))
                        return name;
                }
            }

            return "Defender-Detected";
        }

        private static string? FindMpCmdRun()
        {
            // Direct path
            var directPath = MpCmdRunPaths[0];
            if (File.Exists(directPath))
                return directPath;

            // Search in platform-versioned folders
            var platformBase = MpCmdRunPaths[1];
            if (Directory.Exists(platformBase))
            {
                try
                {
                    var latest = Directory.GetDirectories(platformBase)
                        .OrderByDescending(d => d)
                        .FirstOrDefault();

                    if (latest != null)
                    {
                        var candidate = Path.Combine(latest, "MpCmdRun.exe");
                        if (File.Exists(candidate))
                            return candidate;
                    }
                }
                catch { }
            }

            return null;
        }
    }
}
