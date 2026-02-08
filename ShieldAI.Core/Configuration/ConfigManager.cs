// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Configuration/ConfigManager.cs
// إدارة الإعدادات
// =====================================================

using System.Text.Json;

namespace ShieldAI.Core.Configuration
{
    /// <summary>
    /// مدير الإعدادات - يتولى تحميل وحفظ وإدارة إعدادات التطبيق
    /// </summary>
    public class ConfigManager
    {
        private static readonly string ConfigDirectory = @"C:\ProgramData\ShieldAI\Config";
        private static readonly string SettingsFile = Path.Combine(ConfigDirectory, "settings.json");
        private static readonly string ProfilesFile = Path.Combine(ConfigDirectory, "profiles.json");

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        private static ConfigManager? _instance;
        private static readonly object _lock = new();

        /// <summary>
        /// الإعدادات الحالية
        /// </summary>
        public AppSettings Settings { get; private set; }

        /// <summary>
        /// ملفات تعريف الفحص المحفوظة
        /// </summary>
        public List<ScanProfile> Profiles { get; private set; }

        /// <summary>
        /// حدث عند تغيير الإعدادات
        /// </summary>
        public event EventHandler<AppSettings>? SettingsChanged;

        /// <summary>
        /// الحصول على مثيل ConfigManager (Singleton)
        /// </summary>
        public static ConfigManager Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        _instance ??= new ConfigManager();
                    }
                }
                return _instance;
            }
        }

        private ConfigManager()
        {
            Settings = new AppSettings();
            Profiles = new List<ScanProfile>();
            EnsureDirectoryExists();
            Load();
        }

        #region Public Methods
        /// <summary>
        /// تحميل الإعدادات من الملفات
        /// </summary>
        public void Load()
        {
            LoadSettings();
            LoadProfiles();
        }

        /// <summary>
        /// حفظ جميع الإعدادات
        /// </summary>
        public void Save()
        {
            SaveSettings();
            SaveProfiles();
        }

        /// <summary>
        /// تحديث الإعدادات
        /// </summary>
        public void UpdateSettings(AppSettings newSettings)
        {
            Settings = newSettings ?? throw new ArgumentNullException(nameof(newSettings));
            SaveSettings();
            SettingsChanged?.Invoke(this, Settings);
        }

        /// <summary>
        /// إضافة ملف تعريف فحص جديد
        /// </summary>
        public void AddProfile(ScanProfile profile)
        {
            if (profile == null)
                throw new ArgumentNullException(nameof(profile));

            // التحقق من عدم وجود ملف تعريف بنفس الاسم
            if (Profiles.Any(p => p.Name.Equals(profile.Name, StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException($"Profile with name '{profile.Name}' already exists.");
            }

            Profiles.Add(profile);
            SaveProfiles();
        }

        /// <summary>
        /// حذف ملف تعريف فحص
        /// </summary>
        public bool RemoveProfile(string profileName)
        {
            var profile = Profiles.FirstOrDefault(p => 
                p.Name.Equals(profileName, StringComparison.OrdinalIgnoreCase));
            
            if (profile != null)
            {
                Profiles.Remove(profile);
                SaveProfiles();
                return true;
            }
            return false;
        }

        /// <summary>
        /// الحصول على ملف تعريف بالاسم
        /// </summary>
        public ScanProfile? GetProfile(string profileName)
        {
            return Profiles.FirstOrDefault(p => 
                p.Name.Equals(profileName, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// إعادة تعيين الإعدادات للقيم الافتراضية
        /// </summary>
        public void ResetToDefaults()
        {
            Settings = new AppSettings();
            Profiles = new List<ScanProfile>
            {
                ScanProfile.QuickScan,
                ScanProfile.FullScan,
                ScanProfile.Custom
            };
            Save();
            SettingsChanged?.Invoke(this, Settings);
        }
        #endregion

        #region Private Methods
        private void EnsureDirectoryExists()
        {
            if (!Directory.Exists(ConfigDirectory))
            {
                Directory.CreateDirectory(ConfigDirectory);
            }
        }

        private void LoadSettings()
        {
            try
            {
                if (File.Exists(SettingsFile))
                {
                    var json = File.ReadAllText(SettingsFile);
                    Settings = JsonSerializer.Deserialize<AppSettings>(json, JsonOptions) ?? new AppSettings();
                }
                else
                {
                    Settings = new AppSettings();
                    SaveSettings();
                }
            }
            catch (Exception)
            {
                // TODO: Log error
                Settings = new AppSettings();
            }
        }

        private void SaveSettings()
        {
            try
            {
                EnsureDirectoryExists();
                var json = JsonSerializer.Serialize(Settings, JsonOptions);
                File.WriteAllText(SettingsFile, json);
            }
            catch (Exception)
            {
                // TODO: Log error
            }
        }

        private void LoadProfiles()
        {
            try
            {
                if (File.Exists(ProfilesFile))
                {
                    var json = File.ReadAllText(ProfilesFile);
                    Profiles = JsonSerializer.Deserialize<List<ScanProfile>>(json, JsonOptions) ?? new List<ScanProfile>();
                }
                else
                {
                    // إنشاء ملفات التعريف الافتراضية
                    Profiles = new List<ScanProfile>
                    {
                        ScanProfile.QuickScan,
                        ScanProfile.FullScan,
                        ScanProfile.Custom
                    };
                    SaveProfiles();
                }
            }
            catch (Exception)
            {
                // TODO: Log error
                Profiles = new List<ScanProfile>();
            }
        }

        private void SaveProfiles()
        {
            try
            {
                EnsureDirectoryExists();
                var json = JsonSerializer.Serialize(Profiles, JsonOptions);
                File.WriteAllText(ProfilesFile, json);
            }
            catch (Exception)
            {
                // TODO: Log error
            }
        }
        #endregion
    }
}
