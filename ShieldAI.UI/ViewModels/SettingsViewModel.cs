// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/ViewModels/SettingsViewModel.cs
// ViewModel للإعدادات
// =====================================================

using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using ShieldAI.UI.Services;

namespace ShieldAI.UI.ViewModels
{
    /// <summary>
    /// ViewModel لصفحة الإعدادات
    /// </summary>
    public class SettingsViewModel : INotifyPropertyChanged
    {
        private readonly IDialogService _dialogService;
        private bool _realTimeProtection;
        private bool _autoUpdate;
        private bool _scanArchives;
        private bool _cloudProtection;
        private int _maxFileSizeMB;
        private string _quarantinePath;
        private float _malwareThreshold;

        public event PropertyChangedEventHandler? PropertyChanged;

        #region Properties
        public bool RealTimeProtection
        {
            get => _realTimeProtection;
            set { _realTimeProtection = value; OnPropertyChanged(); }
        }

        public bool AutoUpdate
        {
            get => _autoUpdate;
            set { _autoUpdate = value; OnPropertyChanged(); }
        }

        public bool ScanArchives
        {
            get => _scanArchives;
            set { _scanArchives = value; OnPropertyChanged(); }
        }

        public bool CloudProtection
        {
            get => _cloudProtection;
            set { _cloudProtection = value; OnPropertyChanged(); }
        }

        public int MaxFileSizeMB
        {
            get => _maxFileSizeMB;
            set { _maxFileSizeMB = value; OnPropertyChanged(); }
        }

        public string QuarantinePath
        {
            get => _quarantinePath;
            set { _quarantinePath = value; OnPropertyChanged(); }
        }

        public float MalwareThreshold
        {
            get => _malwareThreshold;
            set { _malwareThreshold = value; OnPropertyChanged(); OnPropertyChanged(nameof(MalwareThresholdPercent)); }
        }

        public int MalwareThresholdPercent => (int)(_malwareThreshold * 100);
        #endregion

        #region Commands
        public ICommand SaveCommand { get; }
        public ICommand ResetCommand { get; }
        public ICommand BrowseQuarantineCommand { get; }
        public ICommand CheckUpdatesCommand { get; }
        #endregion

        public SettingsViewModel()
        {
            _dialogService = new DialogService();
            _quarantinePath = @"C:\ProgramData\ShieldAI\Quarantine";

            SaveCommand = new RelayCommand(ExecuteSave);
            ResetCommand = new RelayCommand(ExecuteReset);
            BrowseQuarantineCommand = new RelayCommand(ExecuteBrowseQuarantine);
            CheckUpdatesCommand = new RelayCommand(ExecuteCheckUpdates);

            LoadSettings();
        }

        private void LoadSettings()
        {
            // Default values
            RealTimeProtection = true;
            AutoUpdate = true;
            ScanArchives = true;
            CloudProtection = true;
            MaxFileSizeMB = 100;
            MalwareThreshold = 0.7f;
        }

        private void ExecuteSave()
        {
            // TODO: Save settings to config
            _dialogService.ShowInfo("تم حفظ الإعدادات بنجاح", "حفظ");
        }

        private void ExecuteReset()
        {
            var confirm = _dialogService.ShowConfirm("هل تريد إعادة الإعدادات للقيم الافتراضية؟", "تأكيد");
            if (confirm)
            {
                LoadSettings();
            }
        }

        private void ExecuteBrowseQuarantine()
        {
            var path = _dialogService.ShowFolderBrowserDialog("اختر مجلد الحجر الصحي");
            if (!string.IsNullOrEmpty(path))
            {
                QuarantinePath = path;
            }
        }

        private void ExecuteCheckUpdates()
        {
            // TODO: Check for updates
            _dialogService.ShowInfo("لا توجد تحديثات جديدة", "التحديثات");
        }

        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
