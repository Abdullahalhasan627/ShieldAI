// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/Services/DialogService.cs
// خدمة الحوارات
// =====================================================

using System.Windows;
using Microsoft.Win32;

namespace ShieldAI.UI.Services
{
    /// <summary>
    /// خدمة الحوارات - تدير عرض مربعات الحوار
    /// </summary>
    public interface IDialogService
    {
        /// <summary>
        /// عرض رسالة معلومات
        /// </summary>
        void ShowInfo(string message, string title = "معلومات");

        /// <summary>
        /// عرض تحذير
        /// </summary>
        void ShowWarning(string message, string title = "تحذير");

        /// <summary>
        /// عرض خطأ
        /// </summary>
        void ShowError(string message, string title = "خطأ");

        /// <summary>
        /// عرض سؤال تأكيد
        /// </summary>
        bool ShowConfirm(string message, string title = "تأكيد");

        /// <summary>
        /// فتح حوار اختيار ملف
        /// </summary>
        string? ShowOpenFileDialog(string filter = "All Files|*.*", string title = "اختر ملف");

        /// <summary>
        /// فتح حوار اختيار مجلد
        /// </summary>
        string? ShowFolderBrowserDialog(string title = "اختر مجلد");

        /// <summary>
        /// فتح حوار حفظ ملف
        /// </summary>
        string? ShowSaveFileDialog(string defaultName = "", string filter = "All Files|*.*", string title = "حفظ كـ");
    }

    /// <summary>
    /// تنفيذ خدمة الحوارات
    /// </summary>
    public class DialogService : IDialogService
    {
        public void ShowInfo(string message, string title = "معلومات")
        {
            MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Information);
        }

        public void ShowWarning(string message, string title = "تحذير")
        {
            MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        public void ShowError(string message, string title = "خطأ")
        {
            MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Error);
        }

        public bool ShowConfirm(string message, string title = "تأكيد")
        {
            var result = MessageBox.Show(message, title, MessageBoxButton.YesNo, MessageBoxImage.Question);
            return result == MessageBoxResult.Yes;
        }

        public string? ShowOpenFileDialog(string filter = "All Files|*.*", string title = "اختر ملف")
        {
            var dialog = new OpenFileDialog
            {
                Filter = filter,
                Title = title,
                CheckFileExists = true
            };

            return dialog.ShowDialog() == true ? dialog.FileName : null;
        }

        public string? ShowFolderBrowserDialog(string title = "اختر مجلد")
        {
            var dialog = new OpenFolderDialog
            {
                Title = title
            };

            return dialog.ShowDialog() == true ? dialog.FolderName : null;
        }

        public string? ShowSaveFileDialog(string defaultName = "", string filter = "All Files|*.*", string title = "حفظ كـ")
        {
            var dialog = new SaveFileDialog
            {
                FileName = defaultName,
                Filter = filter,
                Title = title
            };

            return dialog.ShowDialog() == true ? dialog.FileName : null;
        }
    }
}
