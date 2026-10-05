using System.Windows;
using System.Windows.Controls;

namespace Zion.Views.Controls;

public partial class WindowButtons : UserControl
{
    public WindowButtons()
    {
        InitializeComponent();
    }

    private void Minimize_Click(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is { } window) window.WindowState = WindowState.Minimized;
    }

    // Closing only hides the window: Zion keeps running in the tray (exit is in the tray menu)
    private void Hide_Click(object sender, RoutedEventArgs e) => Window.GetWindow(this)?.Hide();
}
