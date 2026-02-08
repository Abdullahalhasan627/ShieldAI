// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/ViewModels/QuarantineViewModel.cs
// ViewModel للحجر الصحي
// =====================================================

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using ShieldAI.UI.Services;

namespace ShieldAI.UI.ViewModels
{
    /// <summary>
    /// ViewModel لصفحة الحجر الصحي
    /// </summary>
    public class QuarantineViewModel : INotifyPropertyChanged
    {
        private readonly IpcClient _ipcClient;
        private readonly IDialogService _dialogService;
        private QuarantinedFileItem? _selectedItem;
        private bool _isLoading;

        public event PropertyChangedEventHandler? PropertyChanged;

        #region Properties
        public ObservableCollection<QuarantinedFileItem> QuarantinedFiles { get; } = new();

        public QuarantinedFileItem? SelectedItem
        {
            get => _selectedItem;
            set { _selectedItem = value; OnPropertyChanged(); }
        }

        public bool IsLoading
        {
            get => _isLoading;
            set { _isLoading = value; OnPropertyChanged(); }
        }

        public int TotalFiles => QuarantinedFiles.Count;
        public long TotalSize => QuarantinedFiles.Sum(f => f.Size);
        #endregion

        #region Commands
        public ICommand RestoreCommand { get; }
        public ICommand DeleteCommand { get; }
        public ICommand DeleteAllCommand { get; }
        public ICommand RefreshCommand { get; }
        #endregion

        public QuarantineViewModel()
        {
            _ipcClient = new IpcClient();
            _dialogService = new DialogService();

            RestoreCommand = new RelayCommand(ExecuteRestore, () => SelectedItem != null);
            DeleteCommand = new RelayCommand(ExecuteDelete, () => SelectedItem != null);
            DeleteAllCommand = new RelayCommand(ExecuteDeleteAll, () => QuarantinedFiles.Count > 0);
            RefreshCommand = new RelayCommand(ExecuteRefresh);

            _ = LoadDataAsync();
        }

        private async void ExecuteRestore()
        {
            if (SelectedItem == null) return;

            var confirm = _dialogService.ShowConfirm(
                $"هل تريد استعادة الملف '{SelectedItem.FileName}'؟\nتحذير: قد يحتوي على تهديدات!",
                "تأكيد الاستعادة");

            if (confirm)
            {
                // TODO: Send restore command to service
                QuarantinedFiles.Remove(SelectedItem);
                OnPropertyChanged(nameof(TotalFiles));
                OnPropertyChanged(nameof(TotalSize));
            }
        }

        private void ExecuteDelete()
        {
            if (SelectedItem == null) return;

            var confirm = _dialogService.ShowConfirm(
                $"هل تريد حذف الملف '{SelectedItem.FileName}' نهائياً؟",
                "تأكيد الحذف");

            if (confirm)
            {
                QuarantinedFiles.Remove(SelectedItem);
                OnPropertyChanged(nameof(TotalFiles));
                OnPropertyChanged(nameof(TotalSize));
            }
        }

        private void ExecuteDeleteAll()
        {
            var confirm = _dialogService.ShowConfirm(
                "هل تريد حذف جميع الملفات المحجورة نهائياً؟",
                "تأكيد الحذف");

            if (confirm)
            {
                QuarantinedFiles.Clear();
                OnPropertyChanged(nameof(TotalFiles));
                OnPropertyChanged(nameof(TotalSize));
            }
        }

        private async void ExecuteRefresh()
        {
            await LoadDataAsync();
        }

        private async Task LoadDataAsync()
        {
            IsLoading = true;
            QuarantinedFiles.Clear();

            try
            {
                var response = await _ipcClient.GetQuarantineAsync();
                if (response.Success)
                {
                    // TODO: Parse and add files
                }
            }
            finally
            {
                IsLoading = false;
            }
        }

        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public class QuarantinedFileItem
    {
        public Guid Id { get; set; }
        public string FileName { get; set; } = "";
        public string OriginalPath { get; set; } = "";
        public string ThreatName { get; set; } = "";
        public DateTime QuarantinedDate { get; set; }
        public long Size { get; set; }
        public string SizeText => FormatSize(Size);

        private static string FormatSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }
    }
}
