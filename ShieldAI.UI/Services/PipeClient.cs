// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/Services/PipeClient.cs
// عميل Named Pipes v2 للتواصل مع الخدمة
// =====================================================

using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Concurrent;

namespace ShieldAI.UI.Services
{
    /// <summary>
    /// عميل Named Pipes v2 - للتواصل مع خدمة ShieldAI
    /// يعمل حتى لو الخدمة غير شغالة (يعرض رسالة مناسبة)
    /// </summary>
    public partial class PipeClient : IDisposable
    {
        private NamedPipeClientStream? _pipe;
        private readonly SemaphoreSlim _sendLock = new(1, 1);
        private string? _sessionToken;
        private readonly ConcurrentQueue<TaskCompletionSource<PipeClientResponse>> _pendingResponses = new();
        private CancellationTokenSource? _listenerCts;
        private Task? _listenerTask;
        private bool _disposed;

        public const string PipeName = "ShieldAI_IPC_v2";
        private const int ConnectTimeout = 3000;
        private const int MaxMessageSize = 2 * 1024 * 1024;

        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Converters = { new JsonStringEnumConverter() }
        };

        /// <summary>
        /// هل متصل بالخدمة
        /// </summary>
        public bool IsConnected => _pipe?.IsConnected ?? false;

        /// <summary>
        /// حدث تغيير حالة الاتصال
        /// </summary>
        public event EventHandler<bool>? ConnectionStateChanged;

        /// <summary>
        /// حدث خطأ
        /// </summary>
        public event EventHandler<string>? ErrorOccurred;

        /// <summary>
        /// الاتصال بالخدمة
        /// </summary>
        public async Task<bool> ConnectAsync(CancellationToken ct = default)
        {
            if (IsConnected) return true;

            try
            {
                _pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                await _pipe.ConnectAsync(ConnectTimeout, ct);

                if (!await AuthenticateAsync(ct))
                {
                    ErrorOccurred?.Invoke(this, "فشل المصادقة مع الخدمة");
                    Disconnect();
                    return false;
                }

                StartListener();

                ConnectionStateChanged?.Invoke(this, true);
                return true;
            }
            catch (TimeoutException)
            {
                ErrorOccurred?.Invoke(this, "الخدمة غير متاحة - تأكد من تشغيل ShieldAI Service");
                Disconnect();
                return false;
            }
            catch (Exception ex)
            {
                ErrorOccurred?.Invoke(this, $"فشل الاتصال: {ex.Message}");
                Disconnect();
                return false;
            }
        }

        /// <summary>
        /// قطع الاتصال
        /// </summary>
        public void Disconnect()
        {
            var cts = _listenerCts;
            _listenerCts = null;

            if (cts != null)
            {
                try { cts.Cancel(); } catch { }
                cts.Dispose();
            }

            if (_pipe != null)
            {
                try { _pipe.Close(); } catch { }
                _pipe.Dispose();
                _pipe = null;
            }

            _sessionToken = null;

            ConnectionStateChanged?.Invoke(this, false);
        }

        /// <summary>
        /// إرسال أمر واستلام الاستجابة
        /// </summary>
        public async Task<PipeClientResponse> SendAsync(string command, object? payload = null, CancellationToken ct = default)
        {
            if (!IsConnected)
            {
                var connected = await ConnectAsync(ct);
                if (!connected)
                    return PipeClientResponse.Fail("الخدمة غير متاحة. تأكد من تشغيل ShieldAI Service.");
            }

            await _sendLock.WaitAsync(ct);
            try
            {
                var tcs = new TaskCompletionSource<PipeClientResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
                _pendingResponses.Enqueue(tcs);

                var request = new PipeClientRequest
                {
                    Command = command,
                    SessionToken = _sessionToken,
                    Payload = payload != null ? JsonSerializer.Serialize(payload, JsonOpts) : null
                };

                var requestJson = JsonSerializer.Serialize(request, JsonOpts);
                await SendMessageAsync(requestJson, ct);

                var response = await tcs.Task;
                return response;
            }
            catch (Exception ex)
            {
                Disconnect();
                return PipeClientResponse.Fail($"خطأ في الاتصال: {ex.Message}");
            }
            finally
            {
                _sendLock.Release();
            }
        }

        /// <summary>
        /// الحصول على بيانات مفككة من الاستجابة
        /// </summary>
        public async Task<T?> SendAndGetAsync<T>(string command, object? payload = null, CancellationToken ct = default)
            where T : class
        {
            var response = await SendAsync(command, payload, ct);
            if (!response.Success || string.IsNullOrEmpty(response.Data))
                return null;

            try
            {
                return JsonSerializer.Deserialize<T>(response.Data, JsonOpts);
            }
            catch
            {
                return null;
            }
        }

        #region IO

        private async Task<bool> AuthenticateAsync(CancellationToken ct)
        {
            var helloRequest = new PipeClientRequest
            {
                Command = ShieldAI.Core.Contracts.Commands.Hello
            };

            var requestJson = JsonSerializer.Serialize(helloRequest, JsonOpts);
            await SendMessageAsync(requestJson, ct);

            var responseJson = await ReadMessageAsync(ct);
            if (responseJson == null) return false;

            var response = JsonSerializer.Deserialize<PipeClientResponse>(responseJson, JsonOpts);
            if (response == null || !response.Success || string.IsNullOrEmpty(response.Data))
                return false;

            var hello = JsonSerializer.Deserialize<ShieldAI.Core.Contracts.HelloResponse>(response.Data, JsonOpts);
            if (hello == null || string.IsNullOrWhiteSpace(hello.SessionToken))
                return false;

            _sessionToken = hello.SessionToken;
            return true;
        }

        private async Task SendMessageAsync(string message, CancellationToken ct)
        {
            if (_pipe == null || !_pipe.IsConnected)
                throw new InvalidOperationException("غير متصل");

            var messageBytes = Encoding.UTF8.GetBytes(message);
            var lengthBytes = BitConverter.GetBytes(messageBytes.Length);

            await _pipe.WriteAsync(lengthBytes.AsMemory(0, 4), ct);
            await _pipe.WriteAsync(messageBytes.AsMemory(), ct);
            await _pipe.FlushAsync(ct);
        }

        private async Task<string?> ReadMessageAsync(CancellationToken ct)
        {
            if (_pipe == null) return null;

            var lengthBuffer = new byte[4];
            int bytesRead = await _pipe.ReadAsync(lengthBuffer.AsMemory(0, 4), ct);
            if (bytesRead < 4) return null;

            int length = BitConverter.ToInt32(lengthBuffer, 0);
            if (length <= 0 || length > MaxMessageSize) return null;

            var messageBuffer = new byte[length];
            int totalRead = 0;
            while (totalRead < length)
            {
                int read = await _pipe.ReadAsync(
                    messageBuffer.AsMemory(totalRead, length - totalRead), ct);
                if (read == 0) return null;
                totalRead += read;
            }

            return Encoding.UTF8.GetString(messageBuffer);
        }

        #endregion

        #region Event Listener

        /// <summary>
        /// حدث استقبال ThreatActionRequired من الخدمة
        /// </summary>
        public event EventHandler<ShieldAI.Core.Contracts.ThreatEventDto>? ThreatActionRequired;

        /// <summary>
        /// حدث استقبال ThreatActionApplied من الخدمة
        /// </summary>
        public event EventHandler<ShieldAI.Core.Contracts.ThreatEventDto>? ThreatActionApplied;

        /// <summary>
        /// حدث استقبال ThreatDetected من الخدمة
        /// </summary>
        public event EventHandler<ShieldAI.Core.Contracts.ThreatDetectedEvent>? ThreatDetectedFromService;

        /// <summary>
        /// معالجة رسالة واردة — تحقق إذا كانت event (server push) أو response
        /// </summary>
        public bool TryDispatchEvent(string json)
        {
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("eventType", out var etProp))
                {
                    var eventType = etProp.GetString();
                    var payloadStr = doc.RootElement.TryGetProperty("payload", out var pProp)
                        ? pProp.GetString() : null;

                    switch (eventType)
                    {
                        case ShieldAI.Core.Contracts.Events.ThreatActionRequired:
                            if (payloadStr != null)
                            {
                                var dto = JsonSerializer.Deserialize<ShieldAI.Core.Contracts.ThreatEventDto>(payloadStr, JsonOpts);
                                if (dto != null) ThreatActionRequired?.Invoke(this, dto);
                            }
                            return true;

                        case ShieldAI.Core.Contracts.Events.ThreatActionApplied:
                            if (payloadStr != null)
                            {
                                var dto = JsonSerializer.Deserialize<ShieldAI.Core.Contracts.ThreatEventDto>(payloadStr, JsonOpts);
                                if (dto != null) ThreatActionApplied?.Invoke(this, dto);
                            }
                            return true;

                        case ShieldAI.Core.Contracts.Events.ThreatDetected:
                            if (payloadStr != null)
                            {
                                var evt = JsonSerializer.Deserialize<ShieldAI.Core.Contracts.ThreatDetectedEvent>(payloadStr, JsonOpts);
                                if (evt != null) ThreatDetectedFromService?.Invoke(this, evt);
                            }
                            return true;
                    }
                }
            }
            catch
            {
                // Not an event, ignore
            }

            return false;
        }

        #endregion

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Disconnect();
            _sendLock.Dispose();
        }
    }

    #region Listener

    public partial class PipeClient
    {
        private void StartListener()
        {
            if (_pipe == null || !_pipe.IsConnected)
                return;

            if (_listenerTask != null && !_listenerTask.IsCompleted)
                return;

            _listenerCts = new CancellationTokenSource();
            _listenerTask = Task.Run(() => ListenLoopAsync(_listenerCts.Token));
        }

        private async Task ListenLoopAsync(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested && _pipe != null && _pipe.IsConnected)
                {
                    var json = await ReadMessageAsync(ct);
                    if (json == null)
                        break;

                    if (TryDispatchEvent(json))
                        continue;

                    PipeClientResponse? response = null;
                    try
                    {
                        response = JsonSerializer.Deserialize<PipeClientResponse>(json, JsonOpts);
                    }
                    catch
                    {
                        // Ignore invalid response shapes
                    }

                    if (response == null)
                        continue;

                    if (_pendingResponses.TryDequeue(out var tcs))
                    {
                        tcs.TrySetResult(response);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Expected on disconnect
            }
            catch (Exception ex)
            {
                ErrorOccurred?.Invoke(this, $"خطأ في قناة الأحداث: {ex.Message}");
            }
            finally
            {
                // Fail any pending requests
                while (_pendingResponses.TryDequeue(out var tcs))
                {
                    tcs.TrySetResult(PipeClientResponse.Fail("انقطع الاتصال بالخدمة"));
                }
            }
        }
    }

    #endregion

    #region DTOs

    public class PipeClientRequest
    {
        public string Command { get; set; } = "";
        public string? SessionToken { get; set; }
        public string? Payload { get; set; }
    }

    public class PipeClientResponse
    {
        public bool Success { get; set; }
        public string? Error { get; set; }
        public string? Data { get; set; }

        public T? GetData<T>() where T : class
        {
            if (string.IsNullOrEmpty(Data)) return null;
            try
            {
                return JsonSerializer.Deserialize<T>(Data, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    Converters = { new JsonStringEnumConverter() }
                });
            }
            catch { return null; }
        }

        public static PipeClientResponse Fail(string error) => new() { Success = false, Error = error };
    }

    #endregion
}
