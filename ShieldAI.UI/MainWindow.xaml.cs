using System.Windows;
using System.Windows.Input;

namespace ShieldAI.UI;

/// <summary>
/// النافذة الرئيسية للتطبيق
/// </summary>
public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = new ViewModels.MainViewModel();
    }

    // سحب النافذة من شريط العنوان
    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            ToggleMaximize();
        }
        else
        {
            DragMove();
        }
    }

    private void MinimizeButton_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void MaximizeButton_Click(object sender, RoutedEventArgs e)
    {
        ToggleMaximize();
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        // إيقاف المراقبة قبل الإغلاق
        if (DataContext is ViewModels.MainViewModel vm)
        {
            vm.StopMonitoring();
        }
        Close();
    }

    private void ToggleMaximize()
    {
        WindowState = WindowState == WindowState.Maximized 
            ? WindowState.Normal 
            : WindowState.Maximized;
    }
}