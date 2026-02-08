// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/Services/IpcClient.cs
// عميل IPC للتواصل مع الخدمة
// =====================================================

using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace ShieldAI.UI.Services
{
    /// <summary>
    /// عميل IPC - للتواصل مع خدمة ShieldAI
    /// </summary>
    public class IpcClient : IDisposable
    {
        private NamedPipeClientStream? _pipe;
        private bool _isConnected;
        private bool _disposed;

        public const string PipeName = "ShieldAI_IPC";
        public const int ConnectionTimeout = 5000;
        public const int MaxMessageSize = 1024 * 1024;

        /// <summary>
        /// هل متصل بالخدمة
        /// </summary>
        public bool IsConnected => _isConnected && _pipe?.IsConnected == true;

        /// <summary>
        /// حدث عند تغيير حالة الاتصال
        /// </summary>
        public event EventHandler<bool>? ConnectionStateChanged;

        /// <summary>
        /// الاتصال بالخدمة
        /// </summary>
        public async Task<bool> ConnectAsync(CancellationToken cancellationToken = default)
        {
            if (IsConnected)
                return true;

            try
            {
                _pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                await _pipe.ConnectAsync(ConnectionTimeout, cancellationToken);
                _pipe.ReadMode = PipeTransmissionMode.Message;

                _isConnected = true;
                ConnectionStateChanged?.Invoke(this, true);
                return true;
            }
            catch
            {
                Disconnect();
                return false;
            }
        }

        /// <summary>
        /// قطع الاتصال
        /// </summary>
        public void Disconnect()
        {
            if (_pipe != null)
            {
                try { _pipe.Close(); } catch { }
                _pipe.Dispose();
                _pipe = null;
            }

            if (_isConnected)
            {
                _isConnected = false;
                ConnectionStateChanged?.Invoke(this, false);
            }
        }

        /// <summary>
        /// إرسال أمر واستلام الاستجابة
        /// </summary>
        public async Task<IpcResponse> SendCommandAsync(IpcCommand command, CancellationToken cancellationToken = default)
        {
            if (!IsConnected)
            {
                var connected = await ConnectAsync(cancellationToken);
                if (!connected)
                    return IpcResponse.CreateError("لا يمكن الاتصال بالخدمة");
            }

            try
            {
                // إرسال الأمر
                await WriteCommandAsync(command, cancellationToken);

                // استلام الاستجابة
                return await ReadResponseAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                Disconnect();
                return IpcResponse.CreateError(ex.Message);
            }
        }

        #region Command Shortcuts
        /// <summary>
        /// اختبار الاتصال
        /// </summary>
        public async Task<bool> PingAsync()
        {
            var response = await SendCommandAsync(IpcCommand.Ping());
            return response.Success;
        }

        /// <summary>
        /// الحصول على حالة الخدمة
        /// </summary>
        public async Task<IpcResponse> GetStatusAsync()
        {
            return await SendCommandAsync(IpcCommand.GetStatus());
        }

        /// <summary>
        /// بدء فحص
        /// </summary>
        public async Task<IpcResponse> StartScanAsync(string path)
        {
            return await SendCommandAsync(IpcCommand.StartScan(path));
        }

        /// <summary>
        /// إيقاف الفحص
        /// </summary>
        public async Task<IpcResponse> StopScanAsync()
        {
            return await SendCommandAsync(IpcCommand.StopScan());
        }

        /// <summary>
        /// الحصول على التهديدات
        /// </summary>
        public async Task<IpcResponse> GetThreatsAsync()
        {
            return await SendCommandAsync(IpcCommand.GetThreats());
        }

        /// <summary>
        /// الحصول على السجلات
        /// </summary>
        public async Task<IpcResponse> GetLogsAsync(int count = 100)
        {
            return await SendCommandAsync(IpcCommand.GetLogs(count));
        }

        /// <summary>
        /// الحصول على الملفات المحجورة
        /// </summary>
        public async Task<IpcResponse> GetQuarantineAsync()
        {
            return await SendCommandAsync(IpcCommand.GetQuarantine());
        }
        #endregion

        #region Private Methods
        private async Task WriteCommandAsync(IpcCommand command, CancellationToken cancellationToken)
        {
            if (_pipe == null || !_pipe.IsConnected)
                throw new InvalidOperationException("غير متصل");

            var json = command.ToJson();
            var messageBytes = Encoding.UTF8.GetBytes(json);
            var lengthBytes = BitConverter.GetBytes(messageBytes.Length);

            await _pipe.WriteAsync(lengthBytes, 0, 4, cancellationToken);
            await _pipe.WriteAsync(messageBytes, 0, messageBytes.Length, cancellationToken);
            await _pipe.FlushAsync(cancellationToken);
        }

        private async Task<IpcResponse> ReadResponseAsync(CancellationToken cancellationToken)
        {
            if (_pipe == null || !_pipe.IsConnected)
                throw new InvalidOperationException("غير متصل");

            // قراءة طول الرسالة
            var lengthBuffer = new byte[4];
            var bytesRead = await _pipe.ReadAsync(lengthBuffer, 0, 4, cancellationToken);
            if (bytesRead < 4)
                throw new IOException("فشل قراءة طول الرسالة");

            var length = BitConverter.ToInt32(lengthBuffer, 0);
            if (length <= 0 || length > MaxMessageSize)
                throw new IOException("طول الرسالة غير صالح");

            // قراءة الرسالة
            var messageBuffer = new byte[length];
            bytesRead = await _pipe.ReadAsync(messageBuffer, 0, length, cancellationToken);
            if (bytesRead < length)
                throw new IOException("فشل قراءة الرسالة");

            var json = Encoding.UTF8.GetString(messageBuffer);
            return IpcResponse.FromJson(json) ?? IpcResponse.CreateError("فشل تحليل الاستجابة");
        }
        #endregion

        #region IDisposable
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Disconnect();
            GC.SuppressFinalize(this);
        }
        #endregion
    }

    #region IPC Models (Shared with Service)
    public class IpcCommand
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string CommandType { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public Dictionary<string, string>? Parameters { get; set; }
        public string? Data { get; set; }

        public static IpcCommand Ping() => new() { CommandType = "Ping" };
        public static IpcCommand GetStatus() => new() { CommandType = "GetStatus" };
        public static IpcCommand GetThreats() => new() { CommandType = "GetThreats" };
        public static IpcCommand GetLogs(int count) => new() 
        { 
            CommandType = "GetLogs",
            Parameters = new() { ["count"] = count.ToString() }
        };
        public static IpcCommand GetQuarantine() => new() { CommandType = "GetQuarantine" };
        public static IpcCommand StartScan(string path) => new() 
        { 
            CommandType = "StartScan",
            Parameters = new() { ["path"] = path }
        };
        public static IpcCommand StopScan() => new() { CommandType = "StopScan" };

        public string ToJson() => JsonSerializer.Serialize(this);
    }

    public class IpcResponse
    {
        public Guid CommandId { get; set; }
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public DateTime Timestamp { get; set; }
        public string? Data { get; set; }

        public static IpcResponse CreateError(string message) => new() { Success = false, ErrorMessage = message };
        public static IpcResponse CreateSuccess(object? data = null) => new() 
        { 
            Success = true, 
            Data = data != null ? JsonSerializer.Serialize(data) : null 
        };
        public static IpcResponse? FromJson(string json) => JsonSerializer.Deserialize<IpcResponse>(json);
        
        public T? GetData<T>() => string.IsNullOrEmpty(Data) ? default : JsonSerializer.Deserialize<T>(Data);
    }
    #endregion
}
