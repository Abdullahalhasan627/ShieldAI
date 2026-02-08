using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ShieldAI.Core.Models;
using ShieldAI.Core.Monitoring;
using ShieldAI.Core.Scanning;

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
    }

    // ==================== الخصائص ====================

    [ObservableProperty]
    private string _protectionStatus = "محمي";

    [ObservableProperty]
    private SolidColorBrush _protectionStatusColor = new(Colors.LimeGreen);

    [ObservableProperty]
    private bool _isMonitoringEnabled;

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
                        Application.Current.Dispatcher.Invoke(() =>
                        {
                            ScanResults.Add(result);
                            if (result.IsInfected) ThreatsFoundCount++;
                        });
                    }
                }
                else if (File.Exists(path))
                {
                    var result = await _fileScanner.ScanFileAsync(path, _scanCts.Token);
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        ScanResults.Add(result);
                        if (result.IsInfected) ThreatsFoundCount++;
                    });
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
