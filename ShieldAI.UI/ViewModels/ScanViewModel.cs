// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/ViewModels/ScanViewModel.cs
// ViewModel للفحص
// =====================================================

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using ShieldAI.UI.Services;

namespace ShieldAI.UI.ViewModels
{
    /// <summary>
    /// ViewModel لصفحة الفحص
    /// </summary>
    public class ScanViewModel : INotifyPropertyChanged
    {
        private readonly IpcClient _ipcClient;
        private bool _isScanning;
        private int _progress;
        private string _currentFile;
        private int _scannedFiles;
        private int _threatsFound;
        private string _scanStatus;

        public event PropertyChangedEventHandler? PropertyChanged;

        #region Properties
        public bool IsScanning
        {
            get => _isScanning;
            set { _isScanning = value; OnPropertyChanged(); OnPropertyChanged(nameof(CanStartScan)); }
        }

        public int Progress
        {
            get => _progress;
            set { _progress = value; OnPropertyChanged(); }
        }

        public string CurrentFile
        {
            get => _currentFile;
            set { _currentFile = value; OnPropertyChanged(); }
        }

        public int ScannedFiles
        {
            get => _scannedFiles;
            set { _scannedFiles = value; OnPropertyChanged(); }
        }

        public int ThreatsFound
        {
            get => _threatsFound;
            set { _threatsFound = value; OnPropertyChanged(); }
        }

        public string ScanStatus
        {
            get => _scanStatus;
            set { _scanStatus = value; OnPropertyChanged(); }
        }

        public bool CanStartScan => !IsScanning;

        public ObservableCollection<ScanResultItem> Results { get; } = new();
        #endregion

        #region Commands
        public ICommand QuickScanCommand { get; }
        public ICommand FullScanCommand { get; }
        public ICommand CustomScanCommand { get; }
        public ICommand StopScanCommand { get; }
        #endregion

        public ScanViewModel()
        {
            _ipcClient = new IpcClient();
            _currentFile = "";
            _scanStatus = "جاهز للفحص";

            QuickScanCommand = new RelayCommand(ExecuteQuickScan, () => CanStartScan);
            FullScanCommand = new RelayCommand(ExecuteFullScan, () => CanStartScan);
            CustomScanCommand = new RelayCommand(ExecuteCustomScan, () => CanStartScan);
            StopScanCommand = new RelayCommand(ExecuteStopScan, () => IsScanning);
        }

        private async void ExecuteQuickScan()
        {
            await StartScanAsync(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "فحص سريع");
        }

        private async void ExecuteFullScan()
        {
            await StartScanAsync(@"C:\", "فحص كامل");
        }

        private async void ExecuteCustomScan()
        {
            // TODO: فتح حوار اختيار مجلد
            var dialog = new DialogService();
            var path = dialog.ShowFolderBrowserDialog("اختر مجلد للفحص");
            if (!string.IsNullOrEmpty(path))
            {
                await StartScanAsync(path, "فحص مخصص");
            }
        }

        private async void ExecuteStopScan()
        {
            await _ipcClient.StopScanAsync();
            IsScanning = false;
            ScanStatus = "تم إيقاف الفحص";
        }

        private async Task StartScanAsync(string path, string scanType)
        {
            IsScanning = true;
            Progress = 0;
            ScannedFiles = 0;
            ThreatsFound = 0;
            Results.Clear();
            ScanStatus = $"جاري {scanType}...";

            var response = await _ipcClient.StartScanAsync(path);
            if (!response.Success)
            {
                IsScanning = false;
                ScanStatus = $"خطأ: {response.ErrorMessage}";
            }
        }

        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public class ScanResultItem
    {
        public string FileName { get; set; } = "";
        public string FilePath { get; set; } = "";
        public string Status { get; set; } = "";
        public string ThreatName { get; set; } = "";
        public bool IsThreat { get; set; }
    }
}
