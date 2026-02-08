using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ShieldAI.Core.Configuration;
using ShieldAI.Core.Detection;
using ShieldAI.Core.Models;
using ShieldAI.Core.Monitoring;
using ShieldAI.Core.Scanning;
using QuarantineManager = ShieldAI.Core.Monitoring.QuarantineManager;
using QuarantineEntry = ShieldAI.Core.Monitoring.QuarantineEntry;

namespace ShieldAI.UI.ViewModels;

/// <summary>
/// ViewModel الرئيسي للتطبيق
/// </summary>
public partial class MainViewModel : ObservableObject
{
    private readonly FileScanner _fileScanner;
    private readonly ProcessScanner _processScanner;
    private readonly RealTimeMonitor _realTimeMonitor;
    private readonly QuarantineManager _quarantineManager;
    private readonly SignatureDatabase _signatureDb;
    private CancellationTokenSource? _scanCts;
    private readonly HashSet<string> _scannedHashes = new();

    public MainViewModel()
    {
        _signatureDb = new SignatureDatabase();
        _quarantineManager = new QuarantineManager();
        _fileScanner = new FileScanner(_signatureDb);
        _processScanner = new ProcessScanner(_fileScanner, _signatureDb);
        _realTimeMonitor = new RealTimeMonitor();

        // الاشتراك في أحداث المراقبة
        _realTimeMonitor.ThreatFound += OnThreatFound;
        _realTimeMonitor.FileDetected += OnFileDetected;
        _fileScanner.FileScanCompleted += OnFileScanCompleted;
        _fileScanner.ScanProgress += OnScanProgress;

        // تحميل البيانات الأولية
        LoadQuarantinedFiles();
        UpdateStatistics();
        LoadSettings();
    }

    private void LoadSettings()
    {
        var settings = ConfigManager.Instance.Settings;
        IsMonitoringEnabled = settings.EnableRealTimeProtection;
        VirusTotalApiKey = settings.VirusTotalApiKey ?? string.Empty;
    }

    private void SaveSettings()
    {
        var settings = ConfigManager.Instance.Settings;
        settings.EnableRealTimeProtection = IsMonitoringEnabled;
        settings.VirusTotalApiKey = VirusTotalApiKey;
        ConfigManager.Instance.Save();
    }

    // ==================== الخصائص ====================

    [ObservableProperty]
    private string _protectionStatus = "محمي";

    [ObservableProperty]
    private SolidColorBrush _protectionStatusColor = new(Colors.LimeGreen);

    [ObservableProperty]
    private bool _isMonitoringEnabled;

    [ObservableProperty]
    private int _selectedViewIndex;

    [ObservableProperty]
    private string _virusTotalApiKey = string.Empty;

    [ObservableProperty]
    private string _apiKeyStatus = string.Empty;

    [ObservableProperty]
    private string _apiKeyStatusIcon = string.Empty;

    [ObservableProperty]
    private SolidColorBrush _apiKeyStatusColor = new(Colors.Gray);

    [ObservableProperty]
    private string _monitoringStatusText = "متوقف";

    [ObservableProperty]
    private int _quarantineCount;

    [ObservableProperty]
    private Visibility _quarantineCountVisibility = Visibility.Collapsed;

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private int _scanProgress;

    [ObservableProperty]
    private string _scanStatusText = "جاهز للفحص";

    [ObservableProperty]
    private string _currentScanFile = string.Empty;

    [ObservableProperty]
    private int _scannedFilesCount;

    [ObservableProperty]
    private int _threatsFoundCount;

    [ObservableProperty]
    private int _totalFilesScanned;

    [ObservableProperty]
    private int _totalThreatsDetected;

    [ObservableProperty]
    private ObservableCollection<LegacyScanResult> _scanResults = new();

    [ObservableProperty]
    private ObservableCollection<ProcessInfo> _processes = new();

    [ObservableProperty]
    private ObservableCollection<QuarantineEntry> _quarantinedFiles = new();

    [ObservableProperty]
    private ObservableCollection<ThreatDetectedEventArgs> _recentThreats = new();

    [ObservableProperty]
    private string? _selectedPath;

    // ==================== أوامر الفحص ====================

    [RelayCommand]
    private async Task QuickScanAsync()
    {
        SelectedViewIndex = 1; // Navigate to ScanView
        var paths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup)
        };

        await ScanPathsAsync(paths, "الفحص السريع");
    }

    [RelayCommand]
    private async Task FullScanAsync()
    {
        SelectedViewIndex = 1; // Navigate to ScanView
        var drives = DriveInfo.GetDrives()
            .Where(d => d.IsReady && d.DriveType == DriveType.Fixed)
            .Select(d => d.RootDirectory.FullName)
            .ToArray();

        await ScanPathsAsync(drives, "الفحص الكامل");
    }

    [RelayCommand]
    private async Task CustomScanAsync()
    {
        if (string.IsNullOrEmpty(SelectedPath)) return;
        SelectedViewIndex = 1; // Navigate to ScanView
        await ScanPathsAsync(new[] { SelectedPath }, "الفحص المخصص");
    }

    [RelayCommand]
    private void CancelScan()
    {
        _scanCts?.Cancel();
        ScanStatusText = "تم إلغاء الفحص";
        IsScanning = false;
    }

    private async Task ScanPathsAsync(string[] paths, string scanType)
    {
        if (IsScanning) return;

        IsScanning = true;
        _scanCts = new CancellationTokenSource();
        ScanResults.Clear();
        _scannedHashes.Clear(); // Reset hash tracking for new scan
        ScannedFilesCount = 0;
        ThreatsFoundCount = 0;
        ScanProgress = 0;
        ScanStatusText = $"جاري {scanType}...";

        try
        {
            foreach (var path in paths)
            {
                if (_scanCts.Token.IsCancellationRequested) break;

                if (Directory.Exists(path))
                {
                    var results = await _fileScanner.ScanDirectoryAsync(path, true, _scanCts.Token);
                    foreach (var result in results)
                    {
                        await ProcessScanResultAsync(result);
                    }
                }
                else if (File.Exists(path))
                {
                    var result = await _fileScanner.ScanFileAsync(path, _scanCts.Token);
                    await ProcessScanResultAsync(result);
                }
            }

            ScanStatusText = $"اكتمل الفحص - {ScannedFilesCount} ملف، {ThreatsFoundCount} تهديد";
            TotalFilesScanned += ScannedFilesCount;
            TotalThreatsDetected += ThreatsFoundCount;
        }
        catch (OperationCanceledException)
        {
            ScanStatusText = "تم إلغاء الفحص";
        }
        catch (Exception ex)
        {
            ScanStatusText = $"خطأ: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
            ScanProgress = 100;
            _scanCts?.Dispose();
            _scanCts = null;
        }
    }

    /// <summary>
    /// معالجة نتيجة الفحص مع منع التكرار والحجر التلقائي
    /// </summary>
    private async Task ProcessScanResultAsync(LegacyScanResult result)
    {
        // Calculate file hash for duplicate detection
        string fileHash = result.Threat?.FileHash ?? result.FilePath;
        
        // Skip if already processed
        if (_scannedHashes.Contains(fileHash))
        {
            return;
        }
        _scannedHashes.Add(fileHash);

        Application.Current.Dispatcher.Invoke(() =>
        {
            ScanResults.Add(result);
        });

        if (result.IsInfected)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                ThreatsFoundCount++;
            });

            // Auto-quarantine infected files
            try
            {
                await _quarantineManager.QuarantineFileAsync(result.FilePath);
                
                Application.Current.Dispatcher.Invoke(() =>
                {
                    LoadQuarantinedFiles();
                });
            }
            catch (Exception)
            {
                // Log error but don't stop scan
            }
        }
    }

    [RelayCommand]
    private async Task TestApiKeyAsync()
    {
        if (string.IsNullOrEmpty(VirusTotalApiKey))
        {
            ApiKeyStatus = "يرجى إدخال مفتاح API";
            ApiKeyStatusIcon = "❌";
            ApiKeyStatusColor = new SolidColorBrush(Colors.Red);
            return;
        }

        ApiKeyStatus = "جاري الاختبار...";
        ApiKeyStatusIcon = "⏳";
        ApiKeyStatusColor = new SolidColorBrush(Colors.Gray);

        try
        {
            using var httpClient = new System.Net.Http.HttpClient();
            httpClient.DefaultRequestHeaders.Add("x-apikey", VirusTotalApiKey);
            httpClient.Timeout = TimeSpan.FromSeconds(10);

            var response = await httpClient.GetAsync("https://www.virustotal.com/api/v3/users/me");

            if (response.IsSuccessStatusCode)
            {
                ApiKeyStatus = "تم الاتصال بنجاح ✓";
                ApiKeyStatusIcon = "✅";
                ApiKeyStatusColor = new SolidColorBrush(Colors.LimeGreen);
                SaveSettings();
            }
            else if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                ApiKeyStatus = "مفتاح API غير صالح";
                ApiKeyStatusIcon = "❌";
                ApiKeyStatusColor = new SolidColorBrush(Colors.Red);
            }
            else
            {
                ApiKeyStatus = $"خطأ: {response.StatusCode}";
                ApiKeyStatusIcon = "⚠️";
                ApiKeyStatusColor = new SolidColorBrush(Colors.Orange);
            }
        }
        catch (Exception ex)
        {
            ApiKeyStatus = $"فشل الاتصال: {ex.Message}";
            ApiKeyStatusIcon = "❌";
            ApiKeyStatusColor = new SolidColorBrush(Colors.Red);
        }
    }

    // ==================== أوامر العمليات ====================

    [RelayCommand]
    private async Task ScanProcessesAsync()
    {
        ScanStatusText = "جاري فحص العمليات...";
        IsScanning = true;

        try
        {
            var processes = await _processScanner.ScanAllProcessesAsync();
            
            Application.Current.Dispatcher.Invoke(() =>
            {
                Processes.Clear();
                foreach (var p in processes.OrderByDescending(x => x.IsSuspicious))
                {
                    Processes.Add(p);
                }
            });

            ScanStatusText = $"تم فحص {processes.Count} عملية";
        }
        catch (Exception ex)
        {
            ScanStatusText = $"خطأ: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
        }
    }

    [RelayCommand]
    private void TerminateProcess(ProcessInfo? process)
    {
        if (process == null) return;
        
        var result = MessageBox.Show(
            $"هل تريد إنهاء العملية {process.ProcessName}؟",
            "تأكيد",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
        {
            if (_processScanner.TerminateProcess(process.ProcessId))
            {
                Processes.Remove(process);
            }
        }
    }

    // ==================== أوامر الحجر الصحي ====================

    [RelayCommand]
    private async Task RestoreFileAsync(QuarantineEntry? entry)
    {
        if (entry == null) return;

        var result = MessageBox.Show(
            $"هل تريد استعادة الملف {entry.OriginalName}؟\nتحذير: قد يكون هذا الملف خطيراً!",
            "تأكيد الاستعادة",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
        {
            if (await _quarantineManager.RestoreFileAsync(entry.Id))
            {
                QuarantinedFiles.Remove(entry);
                UpdateQuarantineCount();
            }
        }
    }

    [RelayCommand]
    private void DeleteQuarantinedFile(QuarantineEntry? entry)
    {
        if (entry == null) return;

        var result = MessageBox.Show(
            $"هل تريد حذف الملف {entry.OriginalName} نهائياً؟",
            "تأكيد الحذف",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
        {
            if (_quarantineManager.DeleteQuarantinedFile(entry.Id))
            {
                QuarantinedFiles.Remove(entry);
                UpdateQuarantineCount();
            }
        }
    }

    // ==================== المراقبة ====================

    partial void OnIsMonitoringEnabledChanged(bool value)
    {
        if (value)
        {
            _realTimeMonitor.Start();
            MonitoringStatusText = "نشط";
            ProtectionStatus = "محمي";
            ProtectionStatusColor = new SolidColorBrush(Colors.LimeGreen);
        }
        else
        {
            _realTimeMonitor.Stop();
            MonitoringStatusText = "متوقف";
            ProtectionStatus = "غير محمي";
            ProtectionStatusColor = new SolidColorBrush(Colors.Orange);
        }
        SaveSettings(); // Persist settings
    }

    public void StopMonitoring()
    {
        _realTimeMonitor.Stop();
        _realTimeMonitor.Dispose();
    }

    // ==================== معالجات الأحداث ====================

    private void OnThreatFound(object? sender, ThreatDetectedEventArgs e)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            RecentThreats.Insert(0, e);
            if (RecentThreats.Count > 50) // الاحتفاظ بآخر 50 تهديد
                RecentThreats.RemoveAt(RecentThreats.Count - 1);

            TotalThreatsDetected++;
            LoadQuarantinedFiles();

            // إظهار إشعار
            MessageBox.Show(
                $"تم اكتشاف تهديد!\n\nالملف: {Path.GetFileName(e.Result?.FilePath ?? "")}\nالتهديد: {e.Result?.ThreatName ?? "غير معروف"}\n\n{(e.Result?.Verdict == ScanVerdict.Malicious ? "تم نقل الملف للحجر الصحي" : "الملف مشبوه")}",
                "تحذير - ShieldAI",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        });
    }

    private void OnFileDetected(object? sender, RealTimeEventArgs e)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            CurrentScanFile = Path.GetFileName(e.FilePath);
        });
    }

    private void OnFileScanCompleted(object? sender, LegacyScanResult result)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            ScannedFilesCount++;
        });
    }

    private void OnScanProgress(object? sender, FileScanProgressEventArgs e)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            ScanProgress = e.PercentComplete;
            CurrentScanFile = Path.GetFileName(e.CurrentFilePath);
        });
    }

    // ==================== المساعدة ====================

    private void LoadQuarantinedFiles()
    {
        var files = _quarantineManager.GetQuarantinedFiles();
        QuarantinedFiles.Clear();
        foreach (var file in files)
        {
            QuarantinedFiles.Add(file);
        }
        UpdateQuarantineCount();
    }

    private void UpdateQuarantineCount()
    {
        QuarantineCount = QuarantinedFiles.Count;
        QuarantineCountVisibility = QuarantineCount > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void UpdateStatistics()
    {
        // يمكن تحميل الإحصائيات من ملف أو قاعدة بيانات
    }

    [RelayCommand]
    private void BrowseFolder()
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "اختر مجلداً للفحص"
        };

        if (dialog.ShowDialog() == true)
        {
            SelectedPath = dialog.FolderName;
        }
    }
}
