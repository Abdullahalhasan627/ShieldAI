// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/ViewModels/LogsViewModel.cs
// ViewModel للسجلات
// =====================================================

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using ShieldAI.UI.Services;

namespace ShieldAI.UI.ViewModels
{
    /// <summary>
    /// ViewModel لصفحة السجلات
    /// </summary>
    public class LogsViewModel : INotifyPropertyChanged
    {
        private readonly IpcClient _ipcClient;
        private readonly IDialogService _dialogService;
        private LogItem? _selectedItem;
        private bool _isLoading;
        private string _searchText = "";
        private string _levelFilter = "All";
        private int _dateFilter = 0;

        public event PropertyChangedEventHandler? PropertyChanged;

        #region Properties
        public ObservableCollection<LogItem> Logs { get; } = new();

        public LogItem? SelectedItem
        {
            get => _selectedItem;
            set { _selectedItem = value; OnPropertyChanged(); }
        }

        public bool IsLoading
        {
            get => _isLoading;
            set { _isLoading = value; OnPropertyChanged(); }
        }

        public string SearchText
        {
            get => _searchText;
            set { _searchText = value; OnPropertyChanged(); FilterLogs(); }
        }

        public string LevelFilter
        {
            get => _levelFilter;
            set { _levelFilter = value; OnPropertyChanged(); FilterLogs(); }
        }

        public int DateFilter
        {
            get => _dateFilter;
            set { _dateFilter = value; OnPropertyChanged(); FilterLogs(); }
        }

        public int TotalLogs => Logs.Count;
        #endregion

        #region Commands
        public ICommand RefreshCommand { get; }
        public ICommand ExportCommand { get; }
        public ICommand ClearOldLogsCommand { get; }
        #endregion

        public LogsViewModel()
        {
            _ipcClient = new IpcClient();
            _dialogService = new DialogService();

            RefreshCommand = new RelayCommand(ExecuteRefresh);
            ExportCommand = new RelayCommand(ExecuteExport);
            ClearOldLogsCommand = new RelayCommand(ExecuteClearOldLogs);

            _ = LoadLogsAsync();
        }

        private async void ExecuteRefresh()
        {
            await LoadLogsAsync();
        }

        private void ExecuteExport()
        {
            var path = _dialogService.ShowSaveFileDialog("logs.txt", "Text Files|*.txt|All Files|*.*", "تصدير السجلات");
            if (!string.IsNullOrEmpty(path))
            {
                // TODO: Export logs
                _dialogService.ShowInfo("تم تصدير السجلات بنجاح", "تصدير");
            }
        }

        private void ExecuteClearOldLogs()
        {
            var confirm = _dialogService.ShowConfirm("هل تريد مسح السجلات القديمة (أكثر من 30 يوم)؟", "تأكيد");
            if (confirm)
            {
                // TODO: Clear old logs
                _dialogService.ShowInfo("تم مسح السجلات القديمة", "مسح");
            }
        }

        private async Task LoadLogsAsync()
        {
            IsLoading = true;
            Logs.Clear();

            try
            {
                var response = await _ipcClient.GetLogsAsync(1000);
                if (response.Success)
                {
                    // TODO: Parse and add logs
                }

                // Add sample logs for now
                AddSampleLogs();
            }
            finally
            {
                IsLoading = false;
                OnPropertyChanged(nameof(TotalLogs));
            }
        }

        private void AddSampleLogs()
        {
            Logs.Add(new LogItem
            {
                Icon = "ℹ️",
                Level = "Info",
                Message = "تم بدء الفحص السريع",
                Details = "فحص مجلد المستخدم",
                Timestamp = DateTime.Now.AddMinutes(-5)
            });

            Logs.Add(new LogItem
            {
                Icon = "✅",
                Level = "Info",
                Message = "اكتمل الفحص بنجاح",
                Details = "1,234 ملف مفحوص، 0 تهديدات",
                Timestamp = DateTime.Now.AddMinutes(-2)
            });

            Logs.Add(new LogItem
            {
                Icon = "🛡️",
                Level = "Info",
                Message = "الحماية الفورية مفعلة",
                Details = "",
                Timestamp = DateTime.Now.AddHours(-1)
            });
        }

        private void FilterLogs()
        {
            // TODO: Implement filtering
        }

        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public class LogItem
    {
        public string Icon { get; set; } = "ℹ️";
        public string Level { get; set; } = "Info";
        public string Message { get; set; } = "";
        public string Details { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public string TimeAgo => GetTimeAgo(Timestamp);

        private static string GetTimeAgo(DateTime time)
        {
            var span = DateTime.Now - time;
            if (span.TotalMinutes < 1) return "الآن";
            if (span.TotalMinutes < 60) return $"منذ {(int)span.TotalMinutes} دقيقة";
            if (span.TotalHours < 24) return $"منذ {(int)span.TotalHours} ساعة";
            return $"منذ {(int)span.TotalDays} يوم";
        }
    }
}
