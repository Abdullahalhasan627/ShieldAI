// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Core/Scanning/FileEnumerator.cs
// تعداد الملفات بشكل آمن
// =====================================================

using Microsoft.Extensions.Logging;
using ShieldAI.Core.Configuration;

namespace ShieldAI.Core.Scanning
{
    /// <summary>
    /// تعداد الملفات مع معالجة الأخطاء
    /// يتعامل مع: AccessDenied, Reparse Points, Files in use
    /// </summary>
    public class FileEnumerator
    {
        private readonly ILogger? _logger;
        private readonly AppSettings _settings;
        private readonly HashSet<string> _excludedExtensions;
        private readonly HashSet<string> _excludedFolders;
        private readonly HashSet<string> _visitedPaths = new(StringComparer.OrdinalIgnoreCase);

        public FileEnumerator(ILogger? logger = null)
        {
            _logger = logger;
            _settings = ConfigManager.Instance.Settings;
            
            _excludedExtensions = _settings.ExcludedExtensions
                .Select(e => e.Trim().ToLowerInvariant())
                .ToHashSet();
            
            _excludedFolders = _settings.ExcludedFolders
                .Select(f => f.Trim().ToLowerInvariant())
                .ToHashSet();
        }

        /// <summary>
        /// تعداد الملفات في مسار
        /// </summary>
        public IEnumerable<FileInfo> EnumerateFiles(string path, bool recursive = true)
        {
            if (File.Exists(path))
            {
                var fileInfo = new FileInfo(path);
                if (ShouldIncludeFile(fileInfo))
                    yield return fileInfo;
                yield break;
            }

            if (!Directory.Exists(path))
            {
                _logger?.LogWarning("المسار غير موجود: {Path}", path);
                yield break;
            }

            foreach (var file in EnumerateDirectorySafe(path, recursive))
            {
                yield return file;
            }
        }

        /// <summary>
        /// تعداد مجلد بشكل آمن
        /// </summary>
        private IEnumerable<FileInfo> EnumerateDirectorySafe(string directory, bool recursive)
        {
            // تجنب الحلقات اللانهائية
            var realPath = GetRealPath(directory);
            if (!_visitedPaths.Add(realPath))
            {
                _logger?.LogDebug("تم تخطي مسار مكرر: {Path}", directory);
                yield break;
            }

            // التحقق من المجلدات المستثناة
            if (IsExcludedFolder(directory))
            {
                _logger?.LogDebug("مجلد مستثنى: {Path}", directory);
                yield break;
            }

            // تعداد الملفات
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(directory);
            }
            catch (UnauthorizedAccessException)
            {
                _logger?.LogDebug("لا يوجد صلاحية للوصول: {Path}", directory);
                yield break;
            }
            catch (DirectoryNotFoundException)
            {
                yield break;
            }
            catch (IOException ex)
            {
                _logger?.LogDebug("خطأ IO: {Path} - {Error}", directory, ex.Message);
                yield break;
            }

            foreach (var filePath in files)
            {
                FileInfo? fileInfo = null;
                bool shouldInclude = false;
                try
                {
                    fileInfo = new FileInfo(filePath);
                    shouldInclude = ShouldIncludeFile(fileInfo);
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or PathTooLongException)
                {
                    _logger?.LogDebug("تعذر الوصول للملف: {Path}", filePath);
                }
                
                if (shouldInclude && fileInfo != null)
                    yield return fileInfo;
            }

            // المجلدات الفرعية
            if (!recursive) yield break;

            IEnumerable<string> subdirectories;
            try
            {
                subdirectories = Directory.EnumerateDirectories(directory);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                yield break;
            }

            foreach (var subdir in subdirectories)
            {
                // تخطي Reparse Points (Symlinks, Junctions)
                if (IsReparsePoint(subdir))
                {
                    _logger?.LogDebug("تم تخطي Reparse Point: {Path}", subdir);
                    continue;
                }

                foreach (var file in EnumerateDirectorySafe(subdir, true))
                {
                    yield return file;
                }
            }
        }

        /// <summary>
        /// هل يجب تضمين الملف؟
        /// </summary>
        private bool ShouldIncludeFile(FileInfo file)
        {
            // تخطي الملفات الكبيرة جداً
            if (file.Length > _settings.MaxFileSizeMB * 1024 * 1024)
            {
                _logger?.LogDebug("ملف كبير جداً: {Path} ({Size}MB)", 
                    file.FullName, file.Length / (1024 * 1024));
                return false;
            }

            // تخطي الامتدادات المستثناة
            var ext = file.Extension.TrimStart('.').ToLowerInvariant();
            if (_excludedExtensions.Contains(ext))
                return false;

            // تخطي ملفات النظام المخفية (اختياري)
            if ((file.Attributes & FileAttributes.System) != 0 &&
                (file.Attributes & FileAttributes.Hidden) != 0)
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// هل المجلد مستثنى؟
        /// </summary>
        private bool IsExcludedFolder(string path)
        {
            var dirName = Path.GetFileName(path)?.ToLowerInvariant() ?? "";
            
            if (_excludedFolders.Contains(dirName))
                return true;

            // مجلدات النظام الشائعة
            var systemFolders = new[] 
            { 
                "$recycle.bin", "system volume information", 
                "windows", "program files", "program files (x86)",
                "programdata"
            };

            return systemFolders.Contains(dirName);
        }

        /// <summary>
        /// هل هو Reparse Point؟
        /// </summary>
        private static bool IsReparsePoint(string path)
        {
            try
            {
                var attributes = File.GetAttributes(path);
                return (attributes & FileAttributes.ReparsePoint) != 0;
            }
            catch
            {
                return true; // افترض أنه reparse point إذا فشلنا
            }
        }

        /// <summary>
        /// الحصول على المسار الحقيقي
        /// </summary>
        private static string GetRealPath(string path)
        {
            try
            {
                return Path.GetFullPath(path).ToLowerInvariant();
            }
            catch
            {
                return path.ToLowerInvariant();
            }
        }

        /// <summary>
        /// حساب عدد الملفات (للتقدم)
        /// </summary>
        public int CountFiles(string path, bool recursive = true)
        {
            try
            {
                return EnumerateFiles(path, recursive).Count();
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// حساب عدد الملفات بشكل سريع (تقريبي)
        /// </summary>
        public int EstimateFileCount(IEnumerable<string> paths)
        {
            int count = 0;
            foreach (var path in paths)
            {
                try
                {
                    if (File.Exists(path))
                    {
                        count++;
                    }
                    else if (Directory.Exists(path))
                    {
                        // تقدير سريع
                        count += Directory.EnumerateFiles(path, "*", 
                            new EnumerationOptions 
                            { 
                                IgnoreInaccessible = true,
                                RecurseSubdirectories = true,
                                AttributesToSkip = FileAttributes.ReparsePoint
                            }).Take(10000).Count();
                    }
                }
                catch { }
            }
            return count;
        }
    }
}
