// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Configuration/ScanProfile.cs
// ملفات تعريف الفحص
// =====================================================

using ShieldAI.Core.Models;

namespace ShieldAI.Core.Configuration
{
    /// <summary>
    /// ملف تعريف الفحص - يحدد خيارات الفحص المختلفة
    /// </summary>
    public class ScanProfile
    {
        /// <summary>
        /// اسم ملف التعريف
        /// </summary>
        public string Name { get; set; } = "Default";

        /// <summary>
        /// وصف ملف التعريف
        /// </summary>
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// نوع الفحص
        /// </summary>
        public ScanType Type { get; set; } = ScanType.Quick;

        /// <summary>
        /// المجلدات المستهدفة للفحص
        /// </summary>
        public List<string> TargetPaths { get; set; } = new();

        /// <summary>
        /// فحص الملفات المضغوطة
        /// </summary>
        public bool ScanArchives { get; set; } = true;

        /// <summary>
        /// فحص الملفات المخفية
        /// </summary>
        public bool ScanHiddenFiles { get; set; } = true;

        /// <summary>
        /// فحص ملفات النظام
        /// </summary>
        public bool ScanSystemFiles { get; set; } = false;

        /// <summary>
        /// الفحص العميق للملفات (تحليل PE)
        /// </summary>
        public bool DeepScan { get; set; } = false;

        /// <summary>
        /// استخدام الذكاء الاصطناعي
        /// </summary>
        public bool UseAI { get; set; } = true;

        /// <summary>
        /// استخدام التوقيعات
        /// </summary>
        public bool UseSignatures { get; set; } = true;

        /// <summary>
        /// الحد الأقصى لعمق المجلدات
        /// </summary>
        public int MaxDepth { get; set; } = 10;

        /// <summary>
        /// الأولوية (1-10)
        /// </summary>
        public int Priority { get; set; } = 5;

        #region Static Profiles
        /// <summary>
        /// ملف تعريف الفحص السريع
        /// </summary>
        public static ScanProfile QuickScan => new()
        {
            Name = "Quick Scan",
            Description = "فحص سريع للمناطق الحرجة",
            Type = ScanType.Quick,
            TargetPaths = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
                Path.GetTempPath()
            },
            ScanArchives = false,
            ScanSystemFiles = false,
            DeepScan = false,
            MaxDepth = 3,
            Priority = 8
        };

        /// <summary>
        /// ملف تعريف الفحص الكامل
        /// </summary>
        public static ScanProfile FullScan => new()
        {
            Name = "Full Scan",
            Description = "فحص شامل للنظام بالكامل",
            Type = ScanType.Full,
            TargetPaths = DriveInfo.GetDrives()
                .Where(d => d.IsReady && d.DriveType == DriveType.Fixed)
                .Select(d => d.RootDirectory.FullName)
                .ToList(),
            ScanArchives = true,
            ScanHiddenFiles = true,
            ScanSystemFiles = true,
            DeepScan = true,
            MaxDepth = -1, // unlimited
            Priority = 3
        };

        /// <summary>
        /// ملف تعريف الفحص المخصص
        /// </summary>
        public static ScanProfile Custom => new()
        {
            Name = "Custom Scan",
            Description = "فحص مخصص حسب اختيار المستخدم",
            Type = ScanType.Custom,
            TargetPaths = new List<string>(),
            Priority = 5
        };
        #endregion
    }
}
