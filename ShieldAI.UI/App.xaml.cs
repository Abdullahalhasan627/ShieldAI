using System.Runtime.InteropServices;
using System.Security.Principal;
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
    
    // Mutex لمنع تشغيل أكثر من نسخة
    private static Mutex? _mutex;
    private const string MutexName = "ShieldAI_SingleInstance_Mutex_v1.0";
    
    // رسالة Windows لإظهار النافذة من النسخة الأخرى
    private const int WM_SHOWWINDOW = 0x0400 + 1;

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    private static extern bool IsIconic(IntPtr hWnd);

    private const int SW_RESTORE = 9;

    protected override void OnStartup(StartupEventArgs e)
    {
        // 1. التحقق من صلاحيات المسؤول
        if (!IsRunningAsAdministrator())
        {
            MessageBox.Show(
                "يجب تشغيل ShieldAI كمسؤول (Administrator).\n\n" +
                "انقر بزر الماوس الأيمن على التطبيق واختر 'تشغيل كمسؤول' (Run as administrator)",
                "صلاحيات غير كافية",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            Shutdown();
            return;
        }

        // 2. التحقق من عدم وجود نسخة أخرى تعمل
        _mutex = new Mutex(true, MutexName, out bool createdNew);
        
        if (!createdNew)
        {
            // هناك نسخة أخرى تعمل - إظهار رسالة وإحضار النافذة للمقدمة
            MessageBox.Show(
                "التطبيق يعمل بالفعل!",
                "ShieldAI",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            
            // محاولة إظهار نافذة النسخة الأخرى
            BringExistingWindowToFront();
            
            _mutex.Close();
            Shutdown();
            return;
        }

        base.OnStartup(e);
        InitializeTray();
        
        // إنشاء النافذة الرئيسية يدوياً
        MainWindow = new MainWindow();
        MainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _notifyIcon?.Dispose();
        _mutex?.ReleaseMutex();
        _mutex?.Close();
        base.OnExit(e);
    }

    /// <summary>
    /// التحقق مما إذا كان التطبيق يعمل كمسؤول
    /// </summary>
    private static bool IsRunningAsAdministrator()
    {
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    /// <summary>
    /// إحضار نافذة النسخة الأخرى للمقدمة
    /// </summary>
    private void BringExistingWindowToFront()
    {
        try
        {
            // البحث عن نافذة ShieldAI المفتوحة
            var currentProcess = System.Diagnostics.Process.GetCurrentProcess();
            var processes = System.Diagnostics.Process.GetProcessesByName(currentProcess.ProcessName);
            
            foreach (var process in processes)
            {
                if (process.Id != currentProcess.Id && process.MainWindowHandle != IntPtr.Zero)
                {
                    // إذا كانت النافذة مصغرة، استعادتها
                    if (IsIconic(process.MainWindowHandle))
                    {
                        ShowWindow(process.MainWindowHandle, SW_RESTORE);
                    }
                    
                    // إحضارها للمقدمة
                    SetForegroundWindow(process.MainWindowHandle);
                    break;
                }
            }
        }
        catch { }
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
        MainWindow.Topmost = true;
        MainWindow.Topmost = false;
    }
}
