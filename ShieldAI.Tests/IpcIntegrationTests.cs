using System.IO.Pipes;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ShieldAI.Core.Contracts;
using ShieldAI.Core.Models;
using ShieldAI.Service.Ipc;
using ShieldAI.UI.Services;

namespace ShieldAI.Tests;

public class IpcIntegrationTests : IAsyncLifetime
{
    private IHost? _host;
    private readonly TestScanState _scanState = new();

    public async Task InitializeAsync()
    {
        var self = this;
        _host = Host.CreateDefaultBuilder()
            .ConfigureServices(services =>
            {
                services.AddHostedService(provider => new PipeServer(
                    provider.GetRequiredService<Microsoft.Extensions.Logging.ILogger<PipeServer>>(),
                    self.HandleCommandAsync));
            })
            .Build();

        await _host.StartAsync();
    }

    public async Task DisposeAsync()
    {
        if (_host != null)
        {
            await _host.StopAsync();
            _host.Dispose();
        }
    }

    private sealed class TestScanState
    {
        public Guid JobId { get; set; }
        public ScanStatus Status { get; set; } = ScanStatus.Completed;
        public int TotalFiles { get; set; } = 1;
        public int ScannedFiles { get; set; } = 1;
    }

    [Fact]
    public async Task Hello_Then_Ping_ShouldSucceed()
    {
        using var client = new PipeClient();
        var response = await client.SendAsync(Commands.Ping);
        Assert.True(response.Success);
    }

    [Fact]
    public async Task StartScan_Then_GetProgress_ShouldReturnJob()
    {
        using var client = new PipeClient();
        var startResponse = await client.SendAsync(Commands.StartScan, new StartScanRequest
        {
            Paths = new List<string> { Path.GetTempPath() }
        });

        Assert.True(startResponse.Success);

        var progressResponse = await client.SendAndGetAsync<ScanProgressResponse>(Commands.GetScanProgress);
        Assert.NotNull(progressResponse);
        Assert.NotEqual(Guid.Empty, progressResponse!.JobId);
    }

    [Fact]
    public async Task Request_Without_Token_ShouldBeRejected()
    {
        using var pipe = new NamedPipeClientStream(".", PipeServer.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(2000);

        var request = new ShieldAI.Service.Ipc.PipeRequest
        {
            Command = Commands.Ping
        };

        var json = JsonSerializer.Serialize(request, JsonOptions.Default);
        await SendMessageAsync(pipe, json);

        var responseJson = await ReadMessageAsync(pipe);
        Assert.NotNull(responseJson);

        var response = JsonSerializer.Deserialize<ShieldAI.Service.Ipc.PipeResponse>(responseJson!, JsonOptions.Default);
        Assert.NotNull(response);
        Assert.False(response!.Success);
    }

    [Fact]
    public async Task Admin_Command_ShouldRespectPrivileges()
    {
        using var client = new PipeClient();
        var response = await client.SendAsync(Commands.DisableRealTime);

        var isAdmin = IsCurrentUserAdmin();
        Assert.Equal(isAdmin, response.Success);
    }

    private Task<string> HandleCommandAsync(string command, string? payload)
    {
        var response = command switch
        {
            Commands.Ping => ShieldAI.Service.Ipc.PipeResponse.Ok(),
            Commands.StartScan => CreateStartScanResponse(payload),
            Commands.GetScanProgress => CreateProgressResponse(),
            _ => ShieldAI.Service.Ipc.PipeResponse.Fail("Unknown")
        };

        return Task.FromResult(JsonSerializer.Serialize(response, JsonOptions.Default));
    }

    private ShieldAI.Service.Ipc.PipeResponse CreateStartScanResponse(string? payload)
    {
        var request = payload != null
            ? JsonSerializer.Deserialize<StartScanRequest>(payload, JsonOptions.Default)
            : null;

        _scanState.JobId = Guid.NewGuid();
        _scanState.Status = ScanStatus.Running;
        _scanState.TotalFiles = request?.Paths.Count ?? 1;
        _scanState.ScannedFiles = 1;

        return ShieldAI.Service.Ipc.PipeResponse.Ok(new StartScanResponse
        {
            JobId = _scanState.JobId,
            TotalFiles = _scanState.TotalFiles
        });
    }

    private ShieldAI.Service.Ipc.PipeResponse CreateProgressResponse()
    {
        return ShieldAI.Service.Ipc.PipeResponse.Ok(new ScanProgressResponse
        {
            JobId = _scanState.JobId,
            Status = _scanState.Status,
            TotalFiles = _scanState.TotalFiles,
            ScannedFiles = _scanState.ScannedFiles,
            ThreatsFound = 0,
            ProgressPercent = 100,
            CurrentFile = "test.file"
        });
    }

    private static async Task SendMessageAsync(NamedPipeClientStream pipe, string message)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(message);
        var len = BitConverter.GetBytes(bytes.Length);
        await pipe.WriteAsync(len.AsMemory(0, 4));
        await pipe.WriteAsync(bytes.AsMemory());
        await pipe.FlushAsync();
    }

    private static async Task<string?> ReadMessageAsync(NamedPipeClientStream pipe)
    {
        var lenBuffer = new byte[4];
        var read = await pipe.ReadAsync(lenBuffer.AsMemory(0, 4));
        if (read < 4) return null;
        var len = BitConverter.ToInt32(lenBuffer, 0);
        var buffer = new byte[len];
        var total = 0;
        while (total < len)
        {
            var r = await pipe.ReadAsync(buffer.AsMemory(total, len - total));
            if (r == 0) return null;
            total += r;
        }
        return System.Text.Encoding.UTF8.GetString(buffer);
    }

    private static bool IsCurrentUserAdmin()
    {
        try
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    
}
