// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Detection/ThreatScoring/AmsiEngine.cs
// محرك AMSI لفحص السكربتات (User-mode)
// =====================================================

using System.Runtime.InteropServices;

namespace ShieldAI.Core.Detection.ThreatScoring
{
    /// <summary>
    /// محرك AMSI - يفحص السكربتات النصية عبر AmsiScanBuffer
    /// </summary>
    public class AmsiEngine : IThreatEngine
    {
        public string EngineName => "AmsiEngine";
        public double DefaultWeight => 0.6;
        public bool IsReady => OperatingSystem.IsWindows();

        private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".ps1", ".vbs", ".js", ".bat", ".cmd"
        };

        public Task<ThreatScanResult> ScanAsync(ThreatScanContext context, CancellationToken ct = default)
        {
            var result = new ThreatScanResult { EngineName = EngineName };

            try
            {
                if (!ScriptExtensions.Contains(context.Extension))
                    return Task.FromResult(ThreatScanResult.Clean(EngineName));

                if (!File.Exists(context.FilePath))
                    return Task.FromResult(ThreatScanResult.Clean(EngineName));

                var fileInfo = new FileInfo(context.FilePath);
                if (fileInfo.Length > 5 * 1024 * 1024) // 5MB حد معقول للسكربت
                {
                    result.Score = 0;
                    result.Verdict = EngineVerdict.Clean;
                    result.Reasons.Add("تجاوز حد حجم السكربت لفحص AMSI");
                    return Task.FromResult(result);
                }

                var content = File.ReadAllBytes(context.FilePath);
                var amsiResult = AmsiScan(content, Path.GetFileName(context.FilePath));

                if (amsiResult >= AmsiNative.AMSI_RESULT_DETECTED)
                {
                    result.Score = 90;
                    result.Verdict = EngineVerdict.Malicious;
                    result.Confidence = 0.85;
                    result.Reasons.Add("AMSI اكتشف سلوك خبيث في السكربت");
                }
                else if (amsiResult >= AmsiNative.AMSI_RESULT_BLOCKED_BY_ADMIN)
                {
                    result.Score = 60;
                    result.Verdict = EngineVerdict.Suspicious;
                    result.Confidence = 0.7;
                    result.Reasons.Add("AMSI منع تنفيذ السكربت حسب السياسة");
                }
                else
                {
                    result.Score = 0;
                    result.Verdict = EngineVerdict.Clean;
                }
            }
            catch (Exception ex)
            {
                result = ThreatScanResult.Error(EngineName, ex.Message);
            }

            return Task.FromResult(result);
        }

        private static int AmsiScan(byte[] buffer, string contentName)
        {
            if (!AmsiNative.AmsiInitialize("ShieldAI", out var amsiContext))
                return AmsiNative.AMSI_RESULT_NOT_DETECTED;

            try
            {
                if (!AmsiNative.AmsiOpenSession(amsiContext, out var session))
                    return AmsiNative.AMSI_RESULT_NOT_DETECTED;

                try
                {
                    var scanResult = AmsiNative.AMSI_RESULT_NOT_DETECTED;
                    var hresult = AmsiNative.AmsiScanBuffer(
                        amsiContext,
                        buffer,
                        (uint)buffer.Length,
                        contentName,
                        session,
                        out scanResult);

                    return hresult == 0 ? scanResult : AmsiNative.AMSI_RESULT_NOT_DETECTED;
                }
                finally
                {
                    AmsiNative.AmsiCloseSession(amsiContext, session);
                }
            }
            finally
            {
                AmsiNative.AmsiUninitialize(amsiContext);
            }
        }

        private static class AmsiNative
        {
            public const int AMSI_RESULT_NOT_DETECTED = 0;
            public const int AMSI_RESULT_BLOCKED_BY_ADMIN = 0x4000;
            public const int AMSI_RESULT_DETECTED = 0x8000;

            [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
            public static extern int AmsiInitializeNative(string appName, out IntPtr amsiContext);

            public static bool AmsiInitialize(string appName, out IntPtr amsiContext)
            {
                var hr = AmsiInitializeNative(appName, out amsiContext);
                return hr == 0 && amsiContext != IntPtr.Zero;
            }

            [DllImport("amsi.dll")]
            public static extern void AmsiUninitialize(IntPtr amsiContext);

            [DllImport("amsi.dll")]
            public static extern int AmsiOpenSessionNative(IntPtr amsiContext, out IntPtr session);

            public static bool AmsiOpenSession(IntPtr amsiContext, out IntPtr session)
            {
                var hr = AmsiOpenSessionNative(amsiContext, out session);
                return hr == 0 && session != IntPtr.Zero;
            }

            [DllImport("amsi.dll")]
            public static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr session);

            [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
            public static extern int AmsiScanBuffer(
                IntPtr amsiContext,
                byte[] buffer,
                uint length,
                string contentName,
                IntPtr session,
                out int result);
        }
    }
}
