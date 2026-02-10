using System.Windows;
using System.Windows.Forms;
using ShieldAI.UI.Services;

namespace ShieldAI.UI;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    private NotifyIcon? _notifyIcon;
    public static NotificationService? Notifications { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        InitializeTray();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _notifyIcon?.Dispose();
        base.OnExit(e);
    }

    private void InitializeTray()
    {
        _notifyIcon = new NotifyIcon
        {
            Text = "ShieldAI",
            Icon = System.Drawing.SystemIcons.Shield,
            Visible = true,
            ContextMenuStrip = new ContextMenuStrip()
        };

        _notifyIcon.ContextMenuStrip.Items.Add("إظهار", null, (_, _) => ShowMainWindow());
        _notifyIcon.ContextMenuStrip.Items.Add("خروج", null, (_, _) => Shutdown());

        _notifyIcon.DoubleClick += (_, _) => ShowMainWindow();
        Notifications = new NotificationService(_notifyIcon);
        Notifications.WireClickHandler();
    }

    private void ShowMainWindow()
    {
        if (MainWindow == null)
        {
            MainWindow = new MainWindow();
        }

        MainWindow.Show();
        MainWindow.WindowState = WindowState.Normal;
        MainWindow.Activate();
    }
}

