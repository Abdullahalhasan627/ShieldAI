// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Service/Ipc/PipeServer.cs
// خادم Named Pipes محسّن
// =====================================================

using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ShieldAI.Core.Contracts;

namespace ShieldAI.Service.Ipc
{
    /// <summary>
    /// خادم Named Pipes محسّن - يستقبل الأوامر من UI ويعالجها
    /// </summary>
    public class PipeServer : BackgroundService
    {
        private readonly ILogger<PipeServer> _logger;
        private readonly ConcurrentDictionary<Guid, NamedPipeServerStream> _clients = new();
        private readonly ConcurrentDictionary<Guid, ClientSession> _sessions = new();
        private readonly Func<string, string?, Task<string>> _commandHandler;

        public const string PipeName = "ShieldAI_IPC_v2";
        private const int MaxMessageSize = 2 * 1024 * 1024;
        private const int TokenTtlSeconds = 60 * 60;
        private const int MaxRequestsPerMinute = 50;

        private static readonly HashSet<string> AdminCommands = new(StringComparer.OrdinalIgnoreCase)
        {
            Commands.RestoreFromQuarantine,
            Commands.DeleteFromQuarantine,
            Commands.DisableRealTime
        };

        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Converters = { new JsonStringEnumConverter() }
        };

        public PipeServer(
            ILogger<PipeServer> logger,
            Func<string, string?, Task<string>> commandHandler)
        {
            _logger = logger;
            _commandHandler = commandHandler;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("PipeServer v2 بدأ على pipe: {PipeName}", PipeName);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var pipeServer = new NamedPipeServerStream(
                        PipeName,
                        PipeDirection.InOut,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous);

                    try
                    {
                        pipeServer.SetAccessControl(CreatePipeSecurity());
                    }
                    catch
                    {
                        // ignore ACL failures
                    }

                    await pipeServer.WaitForConnectionAsync(stoppingToken);

                    var clientId = Guid.NewGuid();
                    var identityName = GetClientIdentityName(pipeServer);
                    _clients[clientId] = pipeServer;
                    _sessions[clientId] = new ClientSession(identityName);

                    _logger.LogDebug("عميل جديد: {ClientId}", clientId);

                    _ = HandleClientAsync(clientId, pipeServer, stoppingToken);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "خطأ في PipeServer");
                    await Task.Delay(1000, stoppingToken);
                }
            }

            foreach (var client in _clients.Values)
            {
                try { client.Dispose(); } catch { }
            }

            _logger.LogInformation("PipeServer v2 توقف");
        }

        private async Task HandleClientAsync(Guid clientId, NamedPipeServerStream pipe, CancellationToken ct)
        {
            try
            {
                while (pipe.IsConnected && !ct.IsCancellationRequested)
                {
                    var request = await ReadMessageAsync(pipe, ct);
                    if (request == null) break;

                    // تحليل الطلب
                    var envelope = JsonSerializer.Deserialize<PipeRequest>(request, JsonOpts);
                    if (envelope == null) continue;

                    _logger.LogDebug("أمر: {Type} من {Client}", envelope.Command, clientId);

                    if (!IsRateLimitAllowed(clientId))
                    {
                        await SendMessageAsync(pipe,
                            JsonSerializer.Serialize(PipeResponse.Fail("Rate limit exceeded"), JsonOpts),
                            ct);
                        continue;
                    }

                    if (envelope.Command.Equals(Commands.Hello, StringComparison.OrdinalIgnoreCase))
                    {
                        var token = CreateSessionToken(clientId);
                        var helloResponse = new HelloResponse
                        {
                            SessionToken = token,
                            ExpiresInSeconds = TokenTtlSeconds
                        };

                        await SendMessageAsync(pipe,
                            JsonSerializer.Serialize(PipeResponse.Ok(helloResponse), JsonOpts),
                            ct);
                        continue;
                    }

                    if (!IsSessionValid(clientId, envelope.SessionToken))
                    {
                        await SendMessageAsync(pipe,
                            JsonSerializer.Serialize(PipeResponse.Fail("Unauthorized: invalid session"), JsonOpts),
                            ct);
                        continue;
                    }

                    if (AdminCommands.Contains(envelope.Command) && !IsClientAdmin(clientId))
                    {
                        await SendMessageAsync(pipe,
                            JsonSerializer.Serialize(PipeResponse.Fail("Forbidden: admin required"), JsonOpts),
                            ct);
                        continue;
                    }

                    // معالجة الأمر
                    string responseJson;
                    try
                    {
                        responseJson = await _commandHandler(envelope.Command, envelope.Payload);
                    }
                    catch (Exception ex)
                    {
                        responseJson = JsonSerializer.Serialize(
                            PipeResponse.Fail(ex.Message), JsonOpts);
                    }

                    await SendMessageAsync(pipe, responseJson, ct);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug("انقطع {Client}: {Error}", clientId, ex.Message);
            }
            finally
            {
                _clients.TryRemove(clientId, out _);
                _sessions.TryRemove(clientId, out _);
                try { pipe.Dispose(); } catch { }
            }
        }

        /// <summary>
        /// بث حدث لجميع العملاء المتصلين
        /// </summary>
        public async Task BroadcastAsync(string eventType, object payload)
        {
            var json = JsonSerializer.Serialize(new PipeEvent
            {
                EventType = eventType,
                Payload = JsonSerializer.Serialize(payload, JsonOpts)
            }, JsonOpts);

            foreach (var kvp in _clients.ToArray())
            {
                try
                {
                    if (kvp.Value.IsConnected)
                    {
                        await SendMessageAsync(kvp.Value, json, CancellationToken.None);
                    }
                }
                catch
                {
                    _clients.TryRemove(kvp.Key, out _);
                }
            }
        }

        #region IO

        private static async Task<string?> ReadMessageAsync(NamedPipeServerStream pipe, CancellationToken ct)
        {
            try
            {
                var lengthBuffer = new byte[4];
                int bytesRead = await pipe.ReadAsync(lengthBuffer.AsMemory(0, 4), ct);
                if (bytesRead < 4) return null;

                int length = BitConverter.ToInt32(lengthBuffer, 0);
                if (length <= 0 || length > MaxMessageSize) return null;

                var messageBuffer = new byte[length];
                int totalRead = 0;
                while (totalRead < length)
                {
                    int read = await pipe.ReadAsync(
                        messageBuffer.AsMemory(totalRead, length - totalRead), ct);
                    if (read == 0) return null;
                    totalRead += read;
                }

                return Encoding.UTF8.GetString(messageBuffer);
            }
            catch
            {
                return null;
            }
        }

        private static async Task SendMessageAsync(NamedPipeServerStream pipe, string message, CancellationToken ct)
        {
            var messageBytes = Encoding.UTF8.GetBytes(message);
            var lengthBytes = BitConverter.GetBytes(messageBytes.Length);

            await pipe.WriteAsync(lengthBytes.AsMemory(0, 4), ct);
            await pipe.WriteAsync(messageBytes.AsMemory(), ct);
            await pipe.FlushAsync(ct);
        }

        #endregion

        #region Security

        private static PipeSecurity CreatePipeSecurity()
        {
            var security = new PipeSecurity();

            security.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                PipeAccessRights.FullControl,
                AccessControlType.Allow));

            security.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                PipeAccessRights.FullControl,
                AccessControlType.Allow));

            try
            {
                var currentUser = WindowsIdentity.GetCurrent().User;
                if (currentUser != null)
                {
                    security.AddAccessRule(new PipeAccessRule(
                        currentUser,
                        PipeAccessRights.ReadWrite,
                        AccessControlType.Allow));
                }
            }
            catch
            {
                // ignore user ACL issues
            }

            return security;
        }

        private static string GetClientIdentityName(NamedPipeServerStream pipe)
        {
            try
            {
                return pipe.GetImpersonationUserName() ?? "";
            }
            catch
            {
                return "";
            }
        }

        private bool IsClientAdmin(Guid clientId)
        {
            if (!_sessions.TryGetValue(clientId, out var session))
                return false;

            if (string.IsNullOrWhiteSpace(session.IdentityName))
                return false;

            try
            {
                using var identity = new WindowsIdentity(session.IdentityName);
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private string CreateSessionToken(Guid clientId)
        {
            var token = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
            if (_sessions.TryGetValue(clientId, out var session))
            {
                session.SessionToken = token;
                session.TokenExpiresAtUtc = DateTime.UtcNow.AddSeconds(TokenTtlSeconds);
            }
            return token;
        }

        private bool IsSessionValid(Guid clientId, string? token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return false;

            if (!_sessions.TryGetValue(clientId, out var session))
                return false;

            if (!string.Equals(session.SessionToken, token, StringComparison.Ordinal))
                return false;

            return session.TokenExpiresAtUtc > DateTime.UtcNow;
        }

        private bool IsRateLimitAllowed(Guid clientId)
        {
            if (!_sessions.TryGetValue(clientId, out var session))
                return false;

            var windowStart = DateTime.UtcNow.AddMinutes(-1);
            session.RequestTimestamps.Enqueue(DateTime.UtcNow);

            while (session.RequestTimestamps.TryPeek(out var ts) && ts < windowStart)
                session.RequestTimestamps.TryDequeue(out _);

            return session.RequestTimestamps.Count <= MaxRequestsPerMinute;
        }

        private sealed class ClientSession
        {
            public ClientSession(string identityName)
            {
                IdentityName = identityName;
            }

            public string IdentityName { get; }
            public string? SessionToken { get; set; }
            public DateTime TokenExpiresAtUtc { get; set; }
            public ConcurrentQueue<DateTime> RequestTimestamps { get; } = new();
        }

        #endregion
    }

    #region Pipe DTOs

    public class PipeRequest
    {
        public string Command { get; set; } = "";
        public string? SessionToken { get; set; }
        public string? Payload { get; set; }
    }

    public class PipeResponse
    {
        public bool Success { get; set; }
        public string? Error { get; set; }
        public string? Data { get; set; }

        public static PipeResponse Ok(object? data = null) => new()
        {
            Success = true,
            Data = data != null ? JsonSerializer.Serialize(data, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                Converters = { new JsonStringEnumConverter() }
            }) : null
        };

        public static PipeResponse Fail(string error) => new()
        {
            Success = false,
            Error = error
        };
    }

    public class PipeEvent
    {
        public string EventType { get; set; } = "";
        public string? Payload { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.Now;
    }

    #endregion
}
