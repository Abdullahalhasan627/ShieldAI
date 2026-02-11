// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/Services/GitHubUpdateService.cs
// خدمة التحديث من GitHub
// =====================================================

using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Windows;

namespace ShieldAI.UI.Services
{
    /// <summary>
    /// معلومات الإصدار من GitHub
    /// </summary>
    public class GitHubRelease
    {
        public string TagName { get; set; } = "";
        public string Name { get; set; } = "";
        public string Body { get; set; } = "";
        public DateTime PublishedAt { get; set; }
        public List<GitHubAsset> Assets { get; set; } = new();
    }

    public class GitHubAsset
    {
        public string Name { get; set; } = "";
        public string BrowserDownloadUrl { get; set; } = "";
        public long Size { get; set; }
    }

    /// <summary>
    /// نتيجة التحقق من التحديثات
    /// </summary>
    public class UpdateCheckResult
    {
        public bool HasUpdate { get; set; }
        public string CurrentVersion { get; set; } = "";
        public string LatestVersion { get; set; } = "";
        public string ReleaseNotes { get; set; } = "";
        public string DownloadUrl { get; set; } = "";
        public DateTime ReleaseDate { get; set; }
    }

    /// <summary>
    /// خدمة التحديث من GitHub
    /// </summary>
    public class GitHubUpdateService
    {
        private readonly HttpClient _httpClient;
        private readonly string _owner;
        private readonly string _repo;
        private readonly string _currentVersion;
        
        // ملف لتحديد أن التطبيق تم إعادة تشغيله بعد تحديث
        private readonly string _updateFlagPath;
        private readonly string _backupFolder;

        public GitHubUpdateService(string owner, string repo)
        {
            _owner = owner;
            _repo = repo;
            _currentVersion = GetCurrentVersion();
            _updateFlagPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "update_pending.flag");
            _backupFolder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "backup");
            
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "ShieldAI-Updater");
            _httpClient.DefaultRequestHeaders.Add("Accept", "application/vnd.github.v3+json");
        }

        /// <summary>
        /// الحصول على الإصدار الحالي
        /// </summary>
        private string GetCurrentVersion()
        {
            var version = Assembly.GetExecutingAssembly().GetName().Version;
            return $"v{version?.Major}.{version?.Minor}.{version?.Build}";
        }

        /// <summary>
        /// التحقق من وجود تحديثات
        /// </summary>
        public async Task<UpdateCheckResult> CheckForUpdateAsync()
        {
            try
            {
                var url = $"https://api.github.com/repos/{_owner}/{_repo}/releases/latest";
                var response = await _httpClient.GetStringAsync(url);
                var release = JsonSerializer.Deserialize<GitHubRelease>(response, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (release == null)
                    return new UpdateCheckResult { HasUpdate = false };

                // مقارنة الإصدارات
                var hasUpdate = IsNewerVersion(release.TagName, _currentVersion);
                
                // البحث عن ملف التحديث (ShieldAI.zip أو ShieldAI.exe)
                var asset = release.Assets.FirstOrDefault(a => 
                    a.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) ||
                    a.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));

                return new UpdateCheckResult
                {
                    HasUpdate = hasUpdate,
                    CurrentVersion = _currentVersion,
                    LatestVersion = release.TagName,
                    ReleaseNotes = release.Body,
                    DownloadUrl = asset?.BrowserDownloadUrl ?? "",
                    ReleaseDate = release.PublishedAt
                };
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"خطأ في التحقق من التحديثات: {ex.Message}");
                return new UpdateCheckResult { HasUpdate = false };
            }
        }

        /// <summary>
        /// مقارنة الإصدارات
        /// </summary>
        private bool IsNewerVersion(string latest, string current)
        {
            try
            {
                // إزالة 'v' من البداية
                latest = latest.TrimStart('v', 'V');
                current = current.TrimStart('v', 'V');
                
                var latestVersion = Version.Parse(latest);
                var currentVersion = Version.Parse(current);
                
                return latestVersion > currentVersion;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// تحميل وتطبيق التحديث
        /// </summary>
        public async Task<bool> DownloadAndApplyUpdateAsync(string downloadUrl, IProgress<double> progress)
        {
            try
            {
                var appDir = AppDomain.CurrentDomain.BaseDirectory;
                var tempDir = Path.Combine(Path.GetTempPath(), "ShieldAI_Update");
                var zipPath = Path.Combine(tempDir, "update.zip");

                // 1. إنشاء مجلد مؤقت
                if (Directory.Exists(tempDir))
                    Directory.Delete(tempDir, true);
                Directory.CreateDirectory(tempDir);

                // 2. تحميل الملف
                progress?.Report(0.1);
                var response = await _httpClient.GetAsync(downloadUrl, HttpCompletionOption.ResponseHeadersRead);
                var totalBytes = response.Content.Headers.ContentLength ?? -1L;
                
                await using (var stream = await response.Content.ReadAsStreamAsync())
                await using (var fileStream = File.Create(zipPath))
                {
                    var buffer = new byte[8192];
                    long readBytes = 0;
                    int bytesRead;
                    
                    while ((bytesRead = await stream.ReadAsync(buffer)) > 0)
                    {
                        await fileStream.WriteAsync(buffer.AsMemory(0, bytesRead));
                        readBytes += bytesRead;
                        
                        if (totalBytes > 0)
                        {
                            var percent = 0.1 + (0.5 * readBytes / totalBytes); // 10% - 60%
                            progress?.Report(percent);
                        }
                    }
                }

                // 3. فك الضغط
                progress?.Report(0.7);
                System.IO.Compression.ZipFile.ExtractToDirectory(zipPath, tempDir);

                // 4. عمل نسخة احتياطية
                progress?.Report(0.8);
                CreateBackup(appDir);

                // 5. كتابة سكريبت التحديث
                progress?.Report(0.9);
                WriteUpdateScript(appDir, tempDir);

                // 6. كتابة علم التحديث
                File.WriteAllText(_updateFlagPath, DateTime.Now.ToString());

                progress?.Report(1.0);
                return true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"خطأ في تحميل التحديث: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// عمل نسخة احتياطية
        /// </summary>
        private void CreateBackup(string appDir)
        {
            if (Directory.Exists(_backupFolder))
                Directory.Delete(_backupFolder, true);
            
            Directory.CreateDirectory(_backupFolder);
            
            // نسخ الملفات الرئيسية
            var filesToBackup = new[] { "ShieldAI.exe", "ShieldAI.dll", "ShieldAI.Core.dll" };
            foreach (var file in filesToBackup)
            {
                var sourcePath = Path.Combine(appDir, file);
                if (File.Exists(sourcePath))
                {
                    File.Copy(sourcePath, Path.Combine(_backupFolder, file), true);
                }
            }
        }

        /// <summary>
        /// كتابة سكريبت PowerShell للتحديث
        /// </summary>
        private void WriteUpdateScript(string appDir, string updateDir)
        {
            var scriptPath = Path.Combine(Path.GetTempPath(), "shieldai_update.ps1");
            
            var script = $@"
# سكريبت تحديث ShieldAI
$ErrorActionPreference = 'Stop'
$appDir = '{appDir.TrimEnd('\\')}'
$updateDir = '{updateDir.TrimEnd('\\')}'
$exePath = Join-Path $appDir 'ShieldAI.exe'

# انتظار إغلاق التطبيق
Write-Host 'انتظار إغلاق ShieldAI...'
$timeout = 30
$elapsed = 0
while ((Get-Process -Name 'ShieldAI' -ErrorAction SilentlyContinue) -and $elapsed -lt $timeout) {{
    Start-Sleep -Milliseconds 500
    $elapsed += 0.5
}}

# إيقاف force إذا استمر
Stop-Process -Name 'ShieldAI' -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# نسخ الملفات الجديدة
Write-Host 'تثبيت التحديث...'
Get-ChildItem -Path $updateDir -Recurse -File | ForEach-Object {{
    $targetPath = $_.FullName.Replace($updateDir, $appDir)
    $targetDir = Split-Path $targetPath -Parent
    
    if (-not (Test-Path $targetDir)) {{
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }}
    
    Copy-Item $_.FullName $targetPath -Force
}}

# تنظيف
Remove-Item $updateDir -Recurse -Force

# إعادة تشغيل التطبيق
Write-Host 'إعادة تشغيل ShieldAI...'
Start-Process $exePath -Verb RunAs

# حذف السكريبت نفسه
Remove-Item $PSCommandPath -Force
";
            
            File.WriteAllText(scriptPath, script);
        }

        /// <summary>
        /// تنفيذ التحديث (إيقاف التطبيق وإعادة تشغيله)
        /// </summary>
        public void ExecuteUpdate()
        {
            var scriptPath = Path.Combine(Path.GetTempPath(), "shieldai_update.ps1");
            
            if (!File.Exists(scriptPath))
            {
                throw new InvalidOperationException("لم يتم العثور على سكريبت التحديث");
            }

            // تشغيل PowerShell كمسؤول
            var startInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-ExecutionPolicy Bypass -File \"{scriptPath}\"",
                Verb = "runas",
                UseShellExecute = true,
                CreateNoWindow = true
            };

            Process.Start(startInfo);
            
            // إغلاق التطبيق الحالي
            Application.Current.Shutdown();
        }

        /// <summary>
        /// التحقق مما إذا كان هناك تحديث معلق
        /// </summary>
        public bool IsUpdatePending()
        {
            return File.Exists(_updateFlagPath);
        }

        /// <summary>
        /// مسح علم التحديث
        /// </summary>
        public void ClearUpdateFlag()
        {
            if (File.Exists(_updateFlagPath))
            {
                File.Delete(_updateFlagPath);
            }
        }
    }
}
