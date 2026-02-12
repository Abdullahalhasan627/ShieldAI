// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// Detection/ThreatScoring/ThreatScanContext.cs
// سياق الفحص - يحمل جميع المعلومات اللازمة للمحركات
// =====================================================

using ShieldAI.Core.Models;

namespace ShieldAI.Core.Detection.ThreatScoring
{
    /// <summary>
    /// سياق الفحص - يحتوي على جميع المعلومات المستخرجة من الملف
    /// يُمرر لكل محرك كشف
    /// </summary>
    public class ThreatScanContext
    {
        /// <summary>
        /// مسار الملف الكامل
        /// </summary>
        public string FilePath { get; set; } = "";

        /// <summary>
        /// اسم الملف
        /// </summary>
        public string FileName => Path.GetFileName(FilePath);

        /// <summary>
        /// حجم الملف بالبايت
        /// </summary>
        public long FileSize { get; set; }

        /// <summary>
        /// بصمة SHA256
        /// </summary>
        public string? Sha256Hash { get; set; }

        /// <summary>
        /// بصمة MD5
        /// </summary>
        public string? Md5Hash { get; set; }

        /// <summary>
        /// معلومات PE (null إذا لم يكن ملف PE)
        /// </summary>
        public PEFileInfo? PEInfo { get; set; }

        /// <summary>
        /// اسم الناشر / الموقّع الرقمي
        /// </summary>
        public string? SignerName { get; set; }

        /// <summary>
        /// هل التوقيع الرقمي صالح
        /// </summary>
        public bool HasValidSignature { get; set; }

        /// <summary>
        /// معرف العملية الأصلية (إن وجد)
        /// </summary>
        public int? OriginProcessId { get; set; }

        /// <summary>
        /// مسار العملية الأصلية (إن وجد)
        /// </summary>
        public string? OriginProcessPath { get; set; }

        /// <summary>
        /// مسار العملية الأب (إن وجد)
        /// </summary>
        public string? ParentProcessPath { get; set; }

        /// <summary>
        /// سطر الأوامر للعملية الأصلية
        /// </summary>
        public string? CommandLine { get; set; }

        /// <summary>
        /// امتداد الملف
        /// </summary>
        public string Extension => Path.GetExtension(FilePath).ToLowerInvariant();

        /// <summary>
        /// مجلد الملف
        /// </summary>
        public string? Directory => Path.GetDirectoryName(FilePath);

        /// <summary>
        /// تاريخ إنشاء الملف
        /// </summary>
        public DateTime CreationTime { get; set; }

        /// <summary>
        /// تاريخ آخر تعديل
        /// </summary>
        public DateTime LastWriteTime { get; set; }

        /// <summary>
        /// عدد مرات مشاهدة الملف محلياً
        /// </summary>
        public int LocalSeenCount { get; set; }

        /// <summary>
        /// آخر وقت رؤية للملف
        /// </summary>
        public DateTime LastSeenTime { get; set; }

        /// <summary>
        /// هل الملف من Temp أو AppData
        /// </summary>
        public bool IsFromTempOrAppData { get; set; }

        /// <summary>
        /// هل الملف في مسارات بدء التشغيل
        /// </summary>
        public bool IsStartupLocation { get; set; }

        /// <summary>
        /// هل الناشر غير موقع أو غير موثوق
        /// </summary>
        public bool IsUnsignedOrUntrustedPublisher { get; set; }

        /// <summary>
        /// إنشاء سياق من مسار ملف
        /// </summary>
        public static ThreatScanContext FromFile(string filePath)
        {
            var fileInfo = new FileInfo(filePath);
            var fullPath = Path.GetFullPath(filePath);
            var tempPath = Path.GetFullPath(Path.GetTempPath());
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            var isFromTempOrAppData = fullPath.StartsWith(tempPath, StringComparison.OrdinalIgnoreCase)
                                     || (!string.IsNullOrWhiteSpace(appData) &&
                                         fullPath.StartsWith(Path.GetFullPath(appData), StringComparison.OrdinalIgnoreCase))
                                     || (!string.IsNullOrWhiteSpace(localAppData) &&
                                         fullPath.StartsWith(Path.GetFullPath(localAppData), StringComparison.OrdinalIgnoreCase));
            var isStartupLocation = !string.IsNullOrWhiteSpace(startup)
                                    && fullPath.StartsWith(Path.GetFullPath(startup), StringComparison.OrdinalIgnoreCase);
            return new ThreatScanContext
            {
                FilePath = filePath,
                FileSize = fileInfo.Exists ? fileInfo.Length : 0,
                CreationTime = fileInfo.Exists ? fileInfo.CreationTime : DateTime.MinValue,
                LastWriteTime = fileInfo.Exists ? fileInfo.LastWriteTime : DateTime.MinValue,
                IsFromTempOrAppData = isFromTempOrAppData,
                IsStartupLocation = isStartupLocation
            };
        }
    }
}
