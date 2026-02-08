// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/Services/ShieldServiceClient.cs
// عميل اتصال بالخدمة
// =====================================================

using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using ShieldAI.Core.Contracts;
using ShieldAI.Core.Models;

namespace ShieldAI.UI.Services
{
    /// <summary>
    /// عميل للاتصال بخدمة ShieldAI
    /// </summary>
    public class ShieldServiceClient : IDisposable
    {
        private NamedPipeClientStream? _pipe;
        private readonly SemaphoreSlim _sendLock = new(1, 1);
        private CancellationTokenSource? _eventCts;
        private bool _disposed;

        private const string PipeName = "ShieldAI_IPC";
        private const int ConnectTimeout = 5000;
        private const int MaxMessageSize = 1024 * 1024;

        // الأحداث
        public event EventHandler<ServiceStatusResponse>? StatusChanged;
        public event EventHandler<ScanProgressResponse>? ScanProgressChanged;
        public event EventHandler<ThreatDetectedEvent>? ThreatDetected;
        public event EventHandler<string>? ConnectionStateChanged;

        public bool IsConnected => _pipe?.IsConnected ?? false;

        /// <summary>
        /// الاتصال بالخدمة
        /// </summary>
        public async Task<bool> ConnectAsync(CancellationToken ct = default)
        {
            try
            {
                if (IsConnected) return true;

                _pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                await _pipe.ConnectAsync(ConnectTimeout, ct);

                ConnectionStateChanged?.Invoke(this, "متصل");
                
                // بدء استماع للأحداث
                StartEventListener();

                return true;
            }
            catch (TimeoutException)
            {
                ConnectionStateChanged?.Invoke(this, "الخدمة غير متاحة");
                return false;
            }
            catch (Exception ex)
            {
                ConnectionStateChanged?.Invoke(this, $"خطأ: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// قطع الاتصال
        /// </summary>
        public void Disconnect()
        {
            _eventCts?.Cancel();
            _pipe?.Dispose();
            _pipe = null;
            ConnectionStateChanged?.Invoke(this, "غير متصل");
        }

        /// <summary>
        /// إعادة الاتصال
        /// </summary>
        public async Task<bool> ReconnectAsync(CancellationToken ct = default)
        {
            Disconnect();
            await Task.Delay(500, ct);
            return await ConnectAsync(ct);
        }

        #region Commands

        /// <summary>
        /// Ping للخدمة
        /// </summary>
        public async Task<bool> PingAsync()
        {
            var response = await SendCommandAsync(CommandEnvelope.Create(Commands.Ping));
            return response?.Success ?? false;
        }

        /// <summary>
        /// الحصول على حالة الخدمة
        /// </summary>
        public async Task<ServiceStatusResponse?> GetStatusAsync()
        {
            var response = await SendCommandAsync(CommandEnvelope.Create(Commands.GetStatus));
            return response?.GetPayload<ServiceStatusResponse>();
        }

        /// <summary>
        /// بدء فحص
        /// </summary>
        public async Task<StartScanResponse?> StartScanAsync(
            IEnumerable<string> paths, 
            ScanType scanType = ScanType.Custom,
            bool useVirusTotal = false,
            bool deepScan = true)
        {
            var request = new StartScanRequest
            {
                Paths = paths.ToList(),
                ScanType = scanType,
                UseVirusTotal = useVirusTotal,
                DeepScan = deepScan
            };

            var response = await SendCommandAsync(
                CommandEnvelope.Create(Commands.StartScan, request));
            
            return response?.GetPayload<StartScanResponse>();
        }

        /// <summary>
        /// إيقاف الفحص
        /// </summary>
        public async Task<bool> StopScanAsync(Guid? jobId = null)
        {
            var cmd = jobId.HasValue
                ? CommandEnvelope.Create(Commands.StopScan, new StopScanRequest { JobId = jobId.Value })
                : CommandEnvelope.Create(Commands.StopScan);

            var response = await SendCommandAsync(cmd);
            return response?.Success ?? false;
        }

        /// <summary>
        /// الحصول على تقدم الفحص
        /// </summary>
        public async Task<ScanProgressResponse?> GetScanProgressAsync()
        {
            var response = await SendCommandAsync(CommandEnvelope.Create(Commands.GetScanProgress));
            return response?.GetPayload<ScanProgressResponse>();
        }

        /// <summary>
        /// تفعيل الحماية الفورية
        /// </summary>
        public async Task<bool> EnableRealTimeAsync()
        {
            var response = await SendCommandAsync(CommandEnvelope.Create(Commands.EnableRealTime));
            return response?.Success ?? false;
        }

        /// <summary>
        /// إيقاف الحماية الفورية
        /// </summary>
        public async Task<bool> DisableRealTimeAsync()
        {
            var response = await SendCommandAsync(CommandEnvelope.Create(Commands.DisableRealTime));
            return response?.Success ?? false;
        }

        /// <summary>
        /// الحصول على قائمة الحجر
        /// </summary>
        public async Task<QuarantineListResponse?> GetQuarantineListAsync()
        {
            var response = await SendCommandAsync(CommandEnvelope.Create(Commands.GetQuarantineList));
            return response?.GetPayload<QuarantineListResponse>();
        }

        /// <summary>
        /// استعادة ملف من الحجر
        /// </summary>
        public async Task<bool> RestoreFromQuarantineAsync(Guid entryId, string? restorePath = null)
        {
            var request = new QuarantineActionRequest
            {
                EntryId = entryId,
                RestorePath = restorePath
            };

            var response = await SendCommandAsync(
                CommandEnvelope.Create(Commands.RestoreFromQuarantine, request));
            
            return response?.Success ?? false;
        }

        /// <summary>
        /// حذف ملف من الحجر
        /// </summary>
        public async Task<bool> DeleteFromQuarantineAsync(Guid entryId)
        {
            var request = new QuarantineActionRequest { EntryId = entryId };
            var response = await SendCommandAsync(
                CommandEnvelope.Create(Commands.DeleteFromQuarantine, request));
            
            return response?.Success ?? false;
        }

        #endregion

        #region Communication

        private async Task<ResponseEnvelope?> SendCommandAsync(CommandEnvelope command)
        {
            if (!IsConnected)
            {
                if (!await ConnectAsync())
                    return null;
            }

            await _sendLock.WaitAsync();
            try
            {
                await SendMessageAsync(command.ToJson());
                var responseJson = await ReadMessageAsync();
                return responseJson != null ? ResponseEnvelope.FromJson(responseJson) : null;
            }
            catch (Exception)
            {
                Disconnect();
                return null;
            }
            finally
            {
                _sendLock.Release();
            }
        }

        private async Task SendMessageAsync(string message)
        {
            if (_pipe == null) throw new InvalidOperationException("Not connected");

            var messageBytes = Encoding.UTF8.GetBytes(message);
            var lengthBytes = BitConverter.GetBytes(messageBytes.Length);

            await _pipe.WriteAsync(lengthBytes);
            await _pipe.WriteAsync(messageBytes);
            await _pipe.FlushAsync();
        }

        private async Task<string?> ReadMessageAsync()
        {
            if (_pipe == null) return null;

            var lengthBuffer = new byte[4];
            var bytesRead = await _pipe.ReadAsync(lengthBuffer);
            if (bytesRead < 4) return null;

            var length = BitConverter.ToInt32(lengthBuffer, 0);
            if (length <= 0 || length > MaxMessageSize) return null;

            var messageBuffer = new byte[length];
            bytesRead = await _pipe.ReadAsync(messageBuffer);
            if (bytesRead < length) return null;

            return Encoding.UTF8.GetString(messageBuffer);
        }

        private void StartEventListener()
        {
            _eventCts = new CancellationTokenSource();
            
            Task.Run(async () =>
            {
                while (!_eventCts.Token.IsCancellationRequested && IsConnected)
                {
                    try
                    {
                        // TODO: استماع للأحداث من الخدمة
                        await Task.Delay(1000, _eventCts.Token);
                    }
                    catch { break; }
                }
            });
        }

        #endregion

        public void Dispose()
        {
            if (_disposed) return;
            Disconnect();
            _sendLock.Dispose();
            _disposed = true;
        }
    }
}
