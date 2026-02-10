// =====================================================
// ShieldAI - AI-Powered Antivirus Solution
// UI/Services/NotificationService.cs
// إشعارات النظام (Tray/Toast)
// =====================================================

using System.Windows;
using System.Windows.Forms;

namespace ShieldAI.UI.Services
{
    public class NotificationService
    {
        private readonly NotifyIcon _notifyIcon;
        private Action? _onThreatClick;

        public NotificationService(NotifyIcon notifyIcon)
        {
            _notifyIcon = notifyIcon;
        }

        public void ShowThreatNotification(string title, string message, Action? onClick = null)
        {
            _onThreatClick = onClick;
            _notifyIcon.BalloonTipTitle = title;
            _notifyIcon.BalloonTipText = message;
            _notifyIcon.BalloonTipIcon = ToolTipIcon.Warning;
            _notifyIcon.ShowBalloonTip(5000);
        }

        public void WireClickHandler()
        {
            _notifyIcon.BalloonTipClicked += (_, _) => _onThreatClick?.Invoke();
        }

        public void ShowInfo(string title, string message)
        {
            _notifyIcon.BalloonTipTitle = title;
            _notifyIcon.BalloonTipText = message;
            _notifyIcon.BalloonTipIcon = ToolTipIcon.Info;
            _notifyIcon.ShowBalloonTip(3000);
        }
    }
}
