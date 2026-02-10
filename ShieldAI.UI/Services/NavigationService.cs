// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/Services/NavigationService.cs
// خدمة التنقل بين الصفحات
// =====================================================

using System.Windows.Controls;

namespace ShieldAI.UI.Services
{
    /// <summary>
    /// خدمة التنقل - تدير التنقل بين صفحات التطبيق
    /// </summary>
    public interface INavigationService
    {
        /// <summary>
        /// الصفحة الحالية
        /// </summary>
        string CurrentPage { get; }

        /// <summary>
        /// حدث عند تغيير الصفحة
        /// </summary>
        event EventHandler<string>? PageChanged;

        /// <summary>
        /// الانتقال إلى صفحة
        /// </summary>
        void NavigateTo(string pageName);

        /// <summary>
        /// يمكن الرجوع
        /// </summary>
        bool CanGoBack { get; }

        /// <summary>
        /// الرجوع
        /// </summary>
        void GoBack();
    }

    /// <summary>
    /// تنفيذ خدمة التنقل
    /// </summary>
    public class NavigationService : INavigationService
    {
        private readonly Stack<string> _navigationStack;
        private string _currentPage;

        public string CurrentPage => _currentPage;
        public bool CanGoBack => _navigationStack.Count > 0;

        public event EventHandler<string>? PageChanged;

        public NavigationService()
        {
            _navigationStack = new Stack<string>();
            _currentPage = "Dashboard";
        }

        public void NavigateTo(string pageName)
        {
            if (string.IsNullOrEmpty(pageName) || pageName == _currentPage)
                return;

            // إضافة الصفحة الحالية للمكدس
            if (!string.IsNullOrEmpty(_currentPage))
            {
                _navigationStack.Push(_currentPage);
            }

            _currentPage = pageName;
            PageChanged?.Invoke(this, pageName);
        }

        public void GoBack()
        {
            if (_navigationStack.Count > 0)
            {
                _currentPage = _navigationStack.Pop();
                PageChanged?.Invoke(this, _currentPage);
            }
        }
    }

    /// <summary>
    /// أسماء الصفحات
    /// </summary>
    public static class PageNames
    {
        public const string Dashboard = "Dashboard";
        public const string Scan = "Scan";
        public const string Quarantine = "Quarantine";
        public const string Processes = "Processes";
        public const string History = "History";
        public const string Settings = "Settings";
        public const string Logs = "Logs";
    }
}
