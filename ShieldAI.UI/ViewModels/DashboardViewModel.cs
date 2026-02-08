// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/ViewModels/DashboardViewModel.cs
// ViewModel للـ Dashboard
// =====================================================

using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using ShieldAI.UI.Services;

namespace ShieldAI.UI.ViewModels
{
    /// <summary>
    /// ViewModel للوحة التحكم الرئيسية
    /// </summary>
    public class DashboardViewModel : INotifyPropertyChanged
    {
        private readonly IpcClient _ipcClient;
        private bool _isProtectionEnabled;
        private int _threatsDetected;
        private int _filesScanned;
        private DateTime _lastScanTime;
        private string _protectionStatus;
        private bool _isServiceConnected;

        public event PropertyChangedEventHandler? PropertyChanged;

        #region Properties
        public bool IsProtectionEnabled
        {
            get => _isProtectionEnabled;
            set { _isProtectionEnabled = value; OnPropertyChanged(); OnPropertyChanged(nameof(ProtectionStatusText)); }
        }

        public int ThreatsDetected
        {
            get => _threatsDetected;
            set { _threatsDetected = value; OnPropertyChanged(); }
        }

        public int FilesScanned
        {
            get => _filesScanned;
            set { _filesScanned = value; OnPropertyChanged(); }
        }

        public DateTime LastScanTime
        {
            get => _lastScanTime;
            set { _lastScanTime = value; OnPropertyChanged(); OnPropertyChanged(nameof(LastScanTimeText)); }
        }

        public string ProtectionStatus
        {
            get => _protectionStatus;
            set { _protectionStatus = value; OnPropertyChanged(); }
        }

        public bool IsServiceConnected
        {
            get => _isServiceConnected;
            set { _isServiceConnected = value; OnPropertyChanged(); }
        }

        public string ProtectionStatusText => IsProtectionEnabled ? "الحماية مفعلة" : "الحماية معطلة";
        
        public string LastScanTimeText => LastScanTime == DateTime.MinValue 
            ? "لم يتم الفحص بعد" 
            : LastScanTime.ToString("yyyy/MM/dd HH:mm");
        #endregion

        #region Commands
        public ICommand QuickScanCommand { get; }
        public ICommand FullScanCommand { get; }
        public ICommand ToggleProtectionCommand { get; }
        public ICommand RefreshCommand { get; }
        #endregion

        public DashboardViewModel()
        {
            _ipcClient = new IpcClient();
            _protectionStatus = "جاري الاتصال...";
            _isProtectionEnabled = true;

            QuickScanCommand = new RelayCommand(ExecuteQuickScan);
            FullScanCommand = new RelayCommand(ExecuteFullScan);
            ToggleProtectionCommand = new RelayCommand(ExecuteToggleProtection);
            RefreshCommand = new RelayCommand(ExecuteRefresh);

            // تحميل البيانات
            _ = LoadDataAsync();
        }

        #region Command Implementations
        private async void ExecuteQuickScan()
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var response = await _ipcClient.StartScanAsync(userProfile);
            if (response.Success)
            {
                ProtectionStatus = "جاري الفحص السريع...";
            }
        }

        private async void ExecuteFullScan()
        {
            var response = await _ipcClient.StartScanAsync(@"C:\");
            if (response.Success)
            {
                ProtectionStatus = "جاري الفحص الكامل...";
            }
        }

        private void ExecuteToggleProtection()
        {
            IsProtectionEnabled = !IsProtectionEnabled;
            ProtectionStatus = IsProtectionEnabled ? "الحماية مفعلة" : "الحماية معطلة";
        }

        private async void ExecuteRefresh()
        {
            await LoadDataAsync();
        }
        #endregion

        private async Task LoadDataAsync()
        {
            try
            {
                var connected = await _ipcClient.PingAsync();
                IsServiceConnected = connected;

                if (connected)
                {
                    var response = await _ipcClient.GetStatusAsync();
                    if (response.Success)
                    {
                        // TODO: Parse response data
                        ProtectionStatus = "الحماية مفعلة";
                        IsProtectionEnabled = true;
                    }
                }
                else
                {
                    ProtectionStatus = "الخدمة غير متصلة";
                }
            }
            catch
            {
                ProtectionStatus = "خطأ في الاتصال";
                IsServiceConnected = false;
            }
        }

        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    /// <summary>
    /// تنفيذ بسيط لـ ICommand
    /// </summary>
    public class RelayCommand : ICommand
    {
        private readonly Action _execute;
        private readonly Func<bool>? _canExecute;

        public event EventHandler? CanExecuteChanged;

        public RelayCommand(Action execute, Func<bool>? canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public bool CanExecute(object? parameter) => _canExecute?.Invoke() ?? true;
        public void Execute(object? parameter) => _execute();
        public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
    }
}
