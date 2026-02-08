// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Service/Workers/IpcServerWorker.cs
// خادم IPC كـ BackgroundService
// =====================================================

using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ShieldAI.Core.Contracts;
using ShieldAI.Core.Models;
using ShieldAI.Core.Security;

namespace ShieldAI.Service.Workers
{
    /// <summary>
    /// خادم IPC - يستقبل الأوامر من UI
    /// </summary>
    public class IpcServerWorker : BackgroundService
    {
        private readonly ILogger<IpcServerWorker> _logger;
        private readonly ConcurrentDictionary<Guid, NamedPipeServerStream> _clients = new();
        private const string PipeName = "ShieldAI_IPC";
        private const int MaxMessageSize = 1024 * 1024;

        public IpcServerWorker(ILogger<IpcServerWorker> logger)
        {
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("IPC Server بدأ على pipe: {PipeName}", PipeName);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var pipeServer = new NamedPipeServerStream(
                        PipeName,
                        PipeDirection.InOut,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Message,
                        PipeOptions.Asynchronous);

                    await pipeServer.WaitForConnectionAsync(stoppingToken);
                    
                    var clientId = Guid.NewGuid();
                    _clients[clientId] = pipeServer;
                    
                    _logger.LogDebug("عميل جديد متصل: {ClientId}", clientId);
                    
                    // معالجة العميل في thread منفصل
                    _ = HandleClientAsync(clientId, pipeServer, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "خطأ في IPC Server");
                    await Task.Delay(1000, stoppingToken);
                }
            }

            // إغلاق جميع الاتصالات
            foreach (var client in _clients.Values)
            {
                try { client.Dispose(); } catch { }
            }

            _logger.LogInformation("IPC Server توقف");
        }

        private async Task HandleClientAsync(Guid clientId, NamedPipeServerStream pipe, CancellationToken ct)
        {
            try
            {
                while (pipe.IsConnected && !ct.IsCancellationRequested)
                {
                    var command = await ReadMessageAsync(pipe, ct);
                    if (command == null) break;

                    _logger.LogDebug("استلام أمر: {Type}", command.CommandType);
                    
                    var response = await ProcessCommandAsync(command);
                    await SendMessageAsync(pipe, response.ToJson(), ct);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug("انقطع الاتصال بالعميل {ClientId}: {Error}", clientId, ex.Message);
            }
            finally
            {
                _clients.TryRemove(clientId, out _);
                try { pipe.Dispose(); } catch { }
            }
        }

        private async Task<CommandEnvelope?> ReadMessageAsync(NamedPipeServerStream pipe, CancellationToken ct)
        {
            try
            {
                var lengthBuffer = new byte[4];
                var bytesRead = await pipe.ReadAsync(lengthBuffer, ct);
                if (bytesRead < 4) return null;

                var length = BitConverter.ToInt32(lengthBuffer, 0);
                if (length <= 0 || length > MaxMessageSize) return null;

                var messageBuffer = new byte[length];
                bytesRead = await pipe.ReadAsync(messageBuffer, ct);
                if (bytesRead < length) return null;

                var json = Encoding.UTF8.GetString(messageBuffer);
                return CommandEnvelope.FromJson(json);
            }
            catch
            {
                return null;
            }
        }

        private async Task SendMessageAsync(NamedPipeServerStream pipe, string message, CancellationToken ct)
        {
            var messageBytes = Encoding.UTF8.GetBytes(message);
            var lengthBytes = BitConverter.GetBytes(messageBytes.Length);
            
            await pipe.WriteAsync(lengthBytes, ct);
            await pipe.WriteAsync(messageBytes, ct);
            await pipe.FlushAsync(ct);
        }

        /// <summary>
        /// معالجة الأوامر
        /// </summary>
        private async Task<ResponseEnvelope> ProcessCommandAsync(CommandEnvelope command)
        {
            try
            {
                var worker = ShieldAIWorker.Instance;
                if (worker == null)
                {
                    return ResponseEnvelope.Fail(command.Id, "Service not ready");
                }

                return command.CommandType switch
                {
                    Commands.Ping => ResponseEnvelope.Ok(command.Id),
                    
                    Commands.GetStatus => ResponseEnvelope.Ok(command.Id, new ServiceStatusResponse
                    {
                        IsRunning = true,
                        RealTimeEnabled = worker.IsRealTimeEnabled,
                        StartTime = worker.StartTime,
                        ActiveScans = worker.ScanOrchestrator.GetActiveJobs().Count(),
                        QuarantineCount = worker.QuarantineManager.GetCount(),
                        TotalThreatsBlocked = worker.TotalThreatsBlocked
                    }),

                    Commands.StartScan => await HandleStartScanAsync(command, worker),
                    Commands.StopScan => HandleStopScan(command, worker),
                    Commands.GetScanProgress => HandleGetScanProgress(command, worker),

                    Commands.EnableRealTime => HandleRealTime(command, worker, true),
                    Commands.DisableRealTime => HandleRealTime(command, worker, false),

                    Commands.GetQuarantineList => HandleGetQuarantineList(command, worker),
                    Commands.RestoreFromQuarantine => HandleQuarantineRestore(command, worker),
                    Commands.DeleteFromQuarantine => HandleQuarantineDelete(command, worker),

                    _ => ResponseEnvelope.Fail(command.Id, $"Unknown command: {command.CommandType}")
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "خطأ في معالجة الأمر: {Type}", command.CommandType);
                return ResponseEnvelope.Fail(command.Id, ex.Message);
            }
        }

        #region Command Handlers

        private async Task<ResponseEnvelope> HandleStartScanAsync(CommandEnvelope command, ShieldAIWorker worker)
        {
            var request = command.GetPayload<StartScanRequest>();
            if (request == null || request.Paths.Count == 0)
            {
                return ResponseEnvelope.Fail(command.Id, "No paths specified");
            }

            // بدء الفحص في thread منفصل
            var job = new Core.Models.ScanJob
            {
                Paths = request.Paths,
                Type = request.ScanType,
                UseVirusTotal = request.UseVirusTotal,
                DeepScan = request.DeepScan
            };

            _ = Task.Run(() => worker.ScanOrchestrator.ExecuteScanJobAsync(job));

            return ResponseEnvelope.Ok(command.Id, new StartScanResponse
            {
                JobId = job.Id,
                TotalFiles = 0 // سيتم تحديثه لاحقاً
            });
        }

        private ResponseEnvelope HandleStopScan(CommandEnvelope command, ShieldAIWorker worker)
        {
            var request = command.GetPayload<StopScanRequest>();
            if (request != null)
            {
                worker.ScanOrchestrator.StopScan(request.JobId);
            }
            else
            {
                worker.ScanOrchestrator.StopAllScans();
            }
            return ResponseEnvelope.Ok(command.Id);
        }

        private ResponseEnvelope HandleGetScanProgress(CommandEnvelope command, ShieldAIWorker worker)
        {
            var jobs = worker.ScanOrchestrator.GetActiveJobs();
            var firstJob = jobs.FirstOrDefault();
            
            if (firstJob == null)
            {
                return ResponseEnvelope.Ok(command.Id, new ScanProgressResponse
                {
                    Status = ScanStatus.Completed
                });
            }

            return ResponseEnvelope.Ok(command.Id, new ScanProgressResponse
            {
                JobId = firstJob.Id,
                Status = firstJob.Status,
                TotalFiles = firstJob.TotalFiles,
                ScannedFiles = firstJob.ScannedFiles,
                ThreatsFound = firstJob.ThreatsFound,
                ProgressPercent = firstJob.ProgressPercent,
                CurrentFile = firstJob.CurrentFile
            });
        }

        private ResponseEnvelope HandleRealTime(CommandEnvelope command, ShieldAIWorker worker, bool enable)
        {
            worker.SetRealTimeProtection(enable);
            return ResponseEnvelope.Ok(command.Id);
        }

        private ResponseEnvelope HandleGetQuarantineList(CommandEnvelope command, ShieldAIWorker worker)
        {
            var entries = worker.QuarantineManager.GetAllEntries();
            return ResponseEnvelope.Ok(command.Id, new QuarantineListResponse
            {
                Items = entries.Select(e => new QuarantineItemDto
                {
                    Id = e.Id,
                    OriginalPath = e.OriginalPath,
                    OriginalName = e.OriginalName,
                    ThreatName = e.ThreatName,
                    FileSize = e.FileSize,
                    QuarantinedAt = e.QuarantinedAt
                }).ToList(),
                TotalCount = entries.Count
            });
        }

        private ResponseEnvelope HandleQuarantineRestore(CommandEnvelope command, ShieldAIWorker worker)
        {
            var request = command.GetPayload<QuarantineActionRequest>();
            if (request == null)
            {
                return ResponseEnvelope.Fail(command.Id, "Invalid request");
            }

            var success = worker.QuarantineManager.RestoreFile(request.EntryId, request.RestorePath);
            return success 
                ? ResponseEnvelope.Ok(command.Id) 
                : ResponseEnvelope.Fail(command.Id, "Failed to restore file");
        }

        private ResponseEnvelope HandleQuarantineDelete(CommandEnvelope command, ShieldAIWorker worker)
        {
            var request = command.GetPayload<QuarantineActionRequest>();
            if (request == null)
            {
                return ResponseEnvelope.Fail(command.Id, "Invalid request");
            }

            var success = worker.QuarantineManager.DeleteFile(request.EntryId);
            return success 
                ? ResponseEnvelope.Ok(command.Id) 
                : ResponseEnvelope.Fail(command.Id, "Failed to delete file");
        }

        #endregion

        /// <summary>
        /// بث event لجميع العملاء
        /// </summary>
        public async Task BroadcastEventAsync(EventEnvelope eventEnvelope)
        {
            var json = eventEnvelope.ToJson();
            var messageBytes = Encoding.UTF8.GetBytes(json);
            var lengthBytes = BitConverter.GetBytes(messageBytes.Length);

            foreach (var kvp in _clients.ToArray())
            {
                try
                {
                    if (kvp.Value.IsConnected)
                    {
                        await kvp.Value.WriteAsync(lengthBytes);
                        await kvp.Value.WriteAsync(messageBytes);
                        await kvp.Value.FlushAsync();
                    }
                }
                catch
                {
                    _clients.TryRemove(kvp.Key, out _);
                }
            }
        }
    }
}
