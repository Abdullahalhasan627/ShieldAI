// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Service/Program.cs
// نقطة دخول Windows Service
// =====================================================

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ShieldAI.Service.Workers;

namespace ShieldAI.Service
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .UseWindowsService(options =>
                {
                    options.ServiceName = "ShieldAI Antivirus";
                })
                .ConfigureLogging((context, logging) =>
                {
                    logging.ClearProviders();
                    logging.AddConsole();
                    logging.AddEventLog(settings =>
                    {
                        settings.SourceName = "ShieldAI";
                        settings.LogName = "Application";
                    });
                    
                    // ملف log
                    var logPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "ShieldAI", "Logs", $"service_{DateTime.Now:yyyyMMdd}.log");
                    
                    var logDir = Path.GetDirectoryName(logPath);
                    if (!string.IsNullOrEmpty(logDir) && !Directory.Exists(logDir))
                    {
                        Directory.CreateDirectory(logDir);
                    }
                    
                    logging.AddFile(logPath, LogLevel.Information);
                })
                .ConfigureServices((hostContext, services) =>
                {
                    // Worker الرئيسي
                    services.AddHostedService<ShieldAIWorker>();
                    
                    // خادم IPC
                    services.AddHostedService<IpcServerWorker>();
                });
    }

    /// <summary>
    /// امتداد بسيط لإضافة ملف log
    /// </summary>
    public static class LoggingExtensions
    {
        public static ILoggingBuilder AddFile(this ILoggingBuilder builder, string path, LogLevel minLevel)
        {
            builder.AddProvider(new FileLoggerProvider(path, minLevel));
            return builder;
        }
    }

    /// <summary>
    /// مزود Logger للملفات
    /// </summary>
    public class FileLoggerProvider : ILoggerProvider
    {
        private readonly string _path;
        private readonly LogLevel _minLevel;
        private readonly object _lock = new();

        public FileLoggerProvider(string path, LogLevel minLevel)
        {
            _path = path;
            _minLevel = minLevel;
        }

        public ILogger CreateLogger(string categoryName)
        {
            return new FileLogger(_path, categoryName, _minLevel, _lock);
        }

        public void Dispose() { }
    }

    /// <summary>
    /// Logger يكتب للملف
    /// </summary>
    public class FileLogger : ILogger
    {
        private readonly string _path;
        private readonly string _category;
        private readonly LogLevel _minLevel;
        private readonly object _lock;

        public FileLogger(string path, string category, LogLevel minLevel, object lockObj)
        {
            _path = path;
            _category = category;
            _minLevel = minLevel;
            _lock = lockObj;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= _minLevel;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, 
            Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;

            var message = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{logLevel}] [{_category}] {formatter(state, exception)}";
            if (exception != null)
            {
                message += $"\n{exception}";
            }

            lock (_lock)
            {
                try
                {
                    File.AppendAllText(_path, message + Environment.NewLine);
                }
                catch { }
            }
        }
    }
}
