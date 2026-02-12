// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/ViewModels/SettingsViewModel.cs
// ViewModel للإعدادات
// =====================================================

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Windows;
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
        private readonly GitHubUpdateService _gitHubUpdateService;
        
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
        private double _updateProgress;
        private bool _hasUpdate;
        private string _latestVersion = "";
        private string _releaseNotes = "";
        private bool _isGitHubUpdateAvailable;

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

        public double UpdateProgress
        {
            get => _updateProgress;
            set { _updateProgress = value; OnPropertyChanged(); }
        }

        public bool HasUpdate
        {
            get => _hasUpdate;
            set { _hasUpdate = value; OnPropertyChanged(); }
        }

        public string LatestVersion
        {
            get => _latestVersion;
            set { _latestVersion = value; OnPropertyChanged(); }
        }

        public string ReleaseNotes
        {
            get => _releaseNotes;
            set { _releaseNotes = value; OnPropertyChanged(); }
        }

        public bool IsGitHubUpdateAvailable
        {
            get => _isGitHubUpdateAvailable;
            set { _isGitHubUpdateAvailable = value; OnPropertyChanged(); }
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
        public ICommand DownloadUpdateCommand { get; }
        #endregion

        public SettingsViewModel()
        {
            _dialogService = new DialogService();
            _updateManager = new UpdateManager();
            _gitHubUpdateService = new GitHubUpdateService("Abdullahalhasan627", "innovative-idea");
            
            _quarantinePath = @"C:\ProgramData\ShieldAI\Quarantine";

            SaveCommand = new RelayCommand(ExecuteSave);
            ResetCommand = new RelayCommand(ExecuteReset);
            BrowseQuarantineCommand = new RelayCommand(ExecuteBrowseQuarantine);
            CheckUpdatesCommand = new RelayCommand(ExecuteCheckUpdates);
            UpdateNowCommand = new RelayCommand(ExecuteUpdateNow);
            DownloadUpdateCommand = new RelayCommand(ExecuteDownloadUpdate);

            LoadSettings();
            
            // التحقق التلقائي من التحديثات عند البدء
            _ = CheckGitHubUpdatesAsync();
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

        /// <summary>
        /// التحقق من تحديثات GitHub
        /// </summary>
        private async Task CheckGitHubUpdatesAsync()
        {
            try
            {
                UpdateStatus = "جاري التحقق من التحديثات...";
                var result = await _gitHubUpdateService.CheckForUpdateAsync();

                if (result.HasUpdate)
                {
                    HasUpdate = true;
                    LatestVersion = result.LatestVersion;
                    ReleaseNotes = result.ReleaseNotes;
                    IsGitHubUpdateAvailable = true;
                    UpdateStatus = $"تحديث جديد متاح: {result.LatestVersion}";
                    
                    // إشعار المستخدم
                    App.Notifications?.ShowInfo(
                        "تحديث جديد متاح",
                        $"الإصدار {result.LatestVersion} متاح للتحميل");
                }
                else
                {
                    HasUpdate = false;
                    IsGitHubUpdateAvailable = false;
                    UpdateStatus = "لديك أحدث إصدار ✅";
                }
            }
            catch (Exception ex)
            {
                UpdateStatus = "تعذر التحقق من التحديثات";
                Debug.WriteLine($"خطأ: {ex.Message}");
            }
        }

        private async void ExecuteCheckUpdates()
        {
            Debug.WriteLine("ExecuteCheckUpdates clicked");
            try
            {
                await CheckGitHubUpdatesAsync();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error in ExecuteCheckUpdates: {ex}");
                UpdateStatus = "فشل التحقق من التحديثات";
                _dialogService.ShowError($"خطأ: {ex.Message}", "خطأ");
            }
        }

        private async void ExecuteUpdateNow()
        {
            Debug.WriteLine("ExecuteUpdateNow clicked");
            try
            {
                await CheckUpdatesAsync(applyUpdates: true);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error in ExecuteUpdateNow: {ex}");
                UpdateStatus = "فشل التحديث";
                _dialogService.ShowError($"خطأ: {ex.Message}", "خطأ");
            }
        }

        /// <summary>
        /// تحميل وتثبيت التحديث من GitHub
        /// </summary>
        private async void ExecuteDownloadUpdate()
        {
            Debug.WriteLine("ExecuteDownloadUpdate started");
            
            if (IsUpdating) 
            {
                Debug.WriteLine("Already updating, returning");
                return;
            }

            try
            {
                UpdateStatus = "جاري التحقق من التحديث...";
                var result = await _gitHubUpdateService.CheckForUpdateAsync();
                
                Debug.WriteLine($"CheckForUpdateAsync result: HasUpdate={result.HasUpdate}, DownloadUrl={result.DownloadUrl ?? "null"}");

                if (!result.HasUpdate)
                {
                    _dialogService.ShowInfo("لا توجد تحديثات متاحة", "تحديث");
                    return;
                }

                if (string.IsNullOrEmpty(result.DownloadUrl))
                {
                    _dialogService.ShowError(
                        "تم العثور على تحديث ولكن لا يوجد ملف قابل للتحميل في GitHub Release.\n\n" +
                        "تأكد من إرفاق ملف (.zip أو .exe) في Release.", 
                        "خطأ في التحديث");
                    UpdateStatus = "لا يوجد ملف تحديث";
                    return;
                }

                // تأكيد التحديث
                var confirm = _dialogService.ShowConfirm(
                    $"سيتم تحديث ShieldAI من {result.CurrentVersion} إلى {result.LatestVersion}\n\n" +
                    "سيتم إغلاق التطبيق وإعادة تشغيله تلقائياً.\n\n" +
                    "هل تريد المتابعة؟",
                    "تأكيد التحديث");

                Debug.WriteLine($"User confirmation: {confirm}");
                
                if (!confirm) return;

                IsUpdating = true;
                UpdateStatus = "جاري تحميل التحديث...";

                var progress = new Progress<double>(p =>
                {
                    UpdateProgress = p;
                    UpdateStatus = $"جاري التحميل... {p:P0}";
                });

                Debug.WriteLine("Starting DownloadAndApplyUpdateAsync...");
                var success = await _gitHubUpdateService.DownloadAndApplyUpdateAsync(result.DownloadUrl, progress);
                Debug.WriteLine($"DownloadAndApplyUpdateAsync result: {success}");

                if (success)
                {
                    UpdateStatus = "تم التحميل! جاري التثبيت...";
                    
                    // عرض رسالة نهائية
                    var restartConfirm = _dialogService.ShowConfirm(
                        "تم تحميل التحديث بنجاح!\n\n" +
                        "سيتم إغلاق التطبيق الآن وتثبيت التحديث.\n" +
                        "سيعاد تشغيل التطبيق تلقائياً كمسؤول.",
                        "تثبيت التحديث");

                    if (restartConfirm)
                    {
                        _gitHubUpdateService.ExecuteUpdate();
                    }
                }
                else
                {
                    _dialogService.ShowError("فشل تحميل التحديث", "خطأ");
                    UpdateStatus = "فشل التحديث ❌";
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Exception in ExecuteDownloadUpdate: {ex}");
                _dialogService.ShowError($"خطأ أثناء التحديث:\n{ex.Message}", "خطأ");
                UpdateStatus = "فشل التحديث ❌";
            }
            finally
            {
                IsUpdating = false;
            }
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
