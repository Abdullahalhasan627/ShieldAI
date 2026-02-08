// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Security/SelfProtection.cs
// حماية ذاتية للتطبيق
// =====================================================

using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using ShieldAI.Core.Logging;

namespace ShieldAI.Core.Security
{
    /// <summary>
    /// الحماية الذاتية - تحمي ملفات وعمليات ShieldAI من التعديل أو الإنهاء
    /// ملاحظة: هذا تنفيذ user-mode فقط، الحماية الكاملة تتطلب Kernel Driver
    /// </summary>
    public class SelfProtection
    {
        private readonly ILogger? _logger;
        private readonly List<string> _protectedPaths;
        private readonly List<int> _protectedProcessIds;
        private FileSystemWatcher? _watcher;
        private bool _isEnabled;

        /// <summary>
        /// حدث عند اكتشاف محاولة تلاعب
        /// </summary>
        public event EventHandler<TamperEventArgs>? TamperDetected;

        /// <summary>
        /// هل الحماية مفعلة
        /// </summary>
        public bool IsEnabled => _isEnabled;

        public SelfProtection(ILogger? logger = null)
        {
            _logger = logger;
            _protectedPaths = new List<string>();
            _protectedProcessIds = new List<int>();
        }

        #region Public Methods
        /// <summary>
        /// تفعيل الحماية الذاتية
        /// </summary>
        public void Enable()
        {
            if (_isEnabled)
                return;

            try
            {
                // حماية مجلد التطبيق
                var appPath = AppDomain.CurrentDomain.BaseDirectory;
                ProtectPath(appPath);

                // حماية مجلد البيانات
                ProtectPath(@"C:\ProgramData\ShieldAI");

                // حماية العملية الحالية
                ProtectCurrentProcess();

                // مراقبة الملفات المحمية
                StartFileWatcher();

                _isEnabled = true;
                _logger?.Information("تم تفعيل الحماية الذاتية");
            }
            catch (Exception ex)
            {
                _logger?.Error(ex, "خطأ أثناء تفعيل الحماية الذاتية");
            }
        }

        /// <summary>
        /// إيقاف الحماية الذاتية
        /// </summary>
        public void Disable()
        {
            if (!_isEnabled)
                return;

            try
            {
                StopFileWatcher();
                _protectedPaths.Clear();
                _protectedProcessIds.Clear();
                _isEnabled = false;
                _logger?.Information("تم إيقاف الحماية الذاتية");
            }
            catch (Exception ex)
            {
                _logger?.Error(ex, "خطأ أثناء إيقاف الحماية الذاتية");
            }
        }

        /// <summary>
        /// إضافة مسار للحماية
        /// </summary>
        public void ProtectPath(string path)
        {
            if (string.IsNullOrEmpty(path) || _protectedPaths.Contains(path))
                return;

            _protectedPaths.Add(path);
            
            // TODO: تطبيق ACL لتقييد الوصول
            // هذا يتطلب صلاحيات Administrator
            TrySetRestrictivePermissions(path);
            
            _logger?.Debug("تمت إضافة مسار للحماية: {0}", path);
        }

        /// <summary>
        /// حماية العملية الحالية
        /// </summary>
        public void ProtectCurrentProcess()
        {
            var currentProcess = Process.GetCurrentProcess();
            _protectedProcessIds.Add(currentProcess.Id);
            
            // TODO: في بيئة حقيقية، استخدم SetProcessMitigationPolicy أو Kernel Driver
            // لمنع إنهاء العملية أو حقن الكود
            
            _logger?.Debug("تمت حماية العملية: {0} (PID: {1})", currentProcess.ProcessName, currentProcess.Id);
        }

        /// <summary>
        /// التحقق من سلامة عملية محمية
        /// </summary>
        public bool IsProcessProtected(int processId)
        {
            return _protectedProcessIds.Contains(processId);
        }

        /// <summary>
        /// التحقق من سلامة مسار محمي
        /// </summary>
        public bool IsPathProtected(string path)
        {
            return _protectedPaths.Any(p => 
                path.StartsWith(p, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// اكتشاف محاولات التصحيح (Anti-Debug)
        /// </summary>
        public bool IsDebuggerAttached()
        {
            // فحص Debugger الأساسي
            if (Debugger.IsAttached)
                return true;

            // TODO: فحوصات إضافية مثل:
            // - IsDebuggerPresent (P/Invoke)
            // - CheckRemoteDebuggerPresent
            // - NtQueryInformationProcess

            return false;
        }

        /// <summary>
        /// اكتشاف بيئة افتراضية
        /// </summary>
        public VirtualizationInfo DetectVirtualization()
        {
            var info = new VirtualizationInfo();

            try
            {
                // فحص الـ BIOS
                // TODO: استخدام WMI للحصول على معلومات BIOS

                // فحص الخدمات المعروفة للـ VM
                var vmServices = new[] { "VBoxService", "VMTools", "vmicheartbeat" };
                foreach (var service in vmServices)
                {
                    try
                    {
                        var sc = System.ServiceProcess.ServiceController.GetServices()
                            .FirstOrDefault(s => s.ServiceName.Equals(service, StringComparison.OrdinalIgnoreCase));
                        if (sc != null)
                        {
                            info.IsVirtualMachine = true;
                            info.VirtualizationType = service.Contains("VBox") ? "VirtualBox" : 
                                                     service.Contains("VM") ? "VMware" : "Hyper-V";
                            break;
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                _logger?.Debug("خطأ أثناء اكتشاف الافتراضية: {0}", ex.Message);
            }

            return info;
        }
        #endregion

        #region Private Methods
        private void StartFileWatcher()
        {
            foreach (var path in _protectedPaths)
            {
                if (!Directory.Exists(path))
                    continue;

                _watcher = new FileSystemWatcher(path)
                {
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | 
                                   NotifyFilters.DirectoryName | NotifyFilters.Security,
                    IncludeSubdirectories = true,
                    EnableRaisingEvents = true
                };

                _watcher.Changed += OnFileChanged;
                _watcher.Deleted += OnFileDeleted;
                _watcher.Renamed += OnFileRenamed;
            }
        }

        private void StopFileWatcher()
        {
            if (_watcher != null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Dispose();
                _watcher = null;
            }
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            OnTamperDetected(TamperType.FileModified, e.FullPath);
        }

        private void OnFileDeleted(object sender, FileSystemEventArgs e)
        {
            OnTamperDetected(TamperType.FileDeleted, e.FullPath);
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            OnTamperDetected(TamperType.FileRenamed, e.FullPath, e.OldFullPath);
        }

        private void OnTamperDetected(TamperType type, string path, string? oldPath = null)
        {
            var args = new TamperEventArgs
            {
                Type = type,
                Path = path,
                OldPath = oldPath,
                Timestamp = DateTime.Now
            };

            _logger?.SecurityEvent("TAMPER_DETECTED", $"{type}: {path}", ThreatSeverity.High);
            TamperDetected?.Invoke(this, args);
        }

        private void TrySetRestrictivePermissions(string path)
        {
            // TODO: تطبيق ACL لتقييد الوصول
            // هذا مثال مبسط - في الإنتاج يجب استخدام ACL صحيح
            try
            {
                if (Directory.Exists(path))
                {
                    var dirInfo = new DirectoryInfo(path);
                    // يمكن تطبيق DirectorySecurity هنا
                }
            }
            catch (Exception ex)
            {
                _logger?.Debug("لا يمكن تطبيق الصلاحيات على: {0} - {1}", path, ex.Message);
            }
        }
        #endregion
    }

    /// <summary>
    /// معلومات حدث التلاعب
    /// </summary>
    public class TamperEventArgs : EventArgs
    {
        public TamperType Type { get; set; }
        public string Path { get; set; } = string.Empty;
        public string? OldPath { get; set; }
        public DateTime Timestamp { get; set; }
    }

    /// <summary>
    /// أنواع التلاعب
    /// </summary>
    public enum TamperType
    {
        FileModified,
        FileDeleted,
        FileRenamed,
        ProcessTerminated,
        RegistryModified,
        DebuggerAttached
    }

    /// <summary>
    /// معلومات الافتراضية
    /// </summary>
    public class VirtualizationInfo
    {
        public bool IsVirtualMachine { get; set; }
        public string? VirtualizationType { get; set; }
        public bool IsSandbox { get; set; }
    }
}
