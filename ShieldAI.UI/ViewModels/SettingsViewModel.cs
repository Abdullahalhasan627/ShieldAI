// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/ViewModels/SettingsViewModel.cs
// ViewModel للإعدادات
// =====================================================

using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using ShieldAI.Core.Configuration;
using ShieldAI.Core.Updates;
using ShieldAI.UI.Services;

namespace ShieldAI.UI.ViewModels
{
    /// <summary>
    /// ViewModel لصفحة الإعدادات
    /// </summary>
    public class SettingsViewModel : INotifyPropertyChanged
    {
        private readonly IDialogService _dialogService;
        private readonly UpdateManager _updateManager;
        private bool _realTimeProtection;
        private bool _autoUpdate;
        private bool _autoUpdateEnabled;
        private bool _scanArchives;
        private bool _cloudProtection;
        private int _maxFileSizeMB;
        private string _quarantinePath;
        private float _malwareThreshold;
        private string _updateStatus = "";
        private bool _isUpdating;

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

        public bool AutoUpdateEnabled
        {
            get => _autoUpdateEnabled;
            set { _autoUpdateEnabled = value; OnPropertyChanged(); }
        }

        public string UpdateStatus
        {
            get => _updateStatus;
            set { _updateStatus = value; OnPropertyChanged(); }
        }

        public bool IsUpdating
        {
            get => _isUpdating;
            set { _isUpdating = value; OnPropertyChanged(); }
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
        public ICommand UpdateNowCommand { get; }
        #endregion

        public SettingsViewModel()
        {
            _dialogService = new DialogService();
            _updateManager = new UpdateManager();
            _quarantinePath = @"C:\ProgramData\ShieldAI\Quarantine";

            SaveCommand = new RelayCommand(ExecuteSave);
            ResetCommand = new RelayCommand(ExecuteReset);
            BrowseQuarantineCommand = new RelayCommand(ExecuteBrowseQuarantine);
            CheckUpdatesCommand = new RelayCommand(ExecuteCheckUpdates);
            UpdateNowCommand = new RelayCommand(ExecuteUpdateNow);

            LoadSettings();
        }

        private void LoadSettings()
        {
            var settings = ConfigManager.Instance.Settings;
            RealTimeProtection = settings.EnableRealTimeProtection;
            AutoUpdateEnabled = settings.AutoUpdate;
            AutoUpdate = settings.AutoUpdate;
            ScanArchives = true;
            CloudProtection = settings.AllowVirusTotalUpload;
            MaxFileSizeMB = settings.MaxFileSizeMB;
            MalwareThreshold = settings.MalwareThreshold;
        }

        private void ExecuteSave()
        {
            var settings = ConfigManager.Instance.Settings;
            settings.EnableRealTimeProtection = RealTimeProtection;
            settings.AutoUpdate = AutoUpdateEnabled;
            settings.AllowVirusTotalUpload = CloudProtection;
            settings.MaxFileSizeMB = MaxFileSizeMB;
            settings.MalwareThreshold = MalwareThreshold;
            ConfigManager.Instance.Save();
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
            _ = CheckUpdatesAsync();
        }

        private void ExecuteUpdateNow()
        {
            _ = CheckUpdatesAsync(applyUpdates: true);
        }

        private async Task CheckUpdatesAsync(bool applyUpdates = false)
        {
            if (IsUpdating) return;
            IsUpdating = true;
            UpdateStatus = "جاري التحقق من التحديثات...";

            try
            {
                var channels = new[] { UpdateChannel.Signatures, UpdateChannel.MlModel };
                foreach (var channel in channels)
                {
                    var update = await _updateManager.CheckForUpdatesAsync(channel);
                    if (update != null && applyUpdates)
                    {
                        UpdateStatus = $"تطبيق تحديث: {channel}";
                    }
                }

                UpdateStatus = "لا توجد تحديثات جديدة";
            }
            catch (Exception ex)
            {
                UpdateStatus = $"فشل التحديث: {ex.Message}";
            }
            finally
            {
                IsUpdating = false;
            }
        }

        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
