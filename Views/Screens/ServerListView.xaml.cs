using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Zion.Models;
using Zion.ViewModels;

namespace Zion.Views.Screens;

public partial class ServerListView : UserControl
{
    public ServerListView()
    {
        InitializeComponent();
    }

    private MainViewModel? Vm => DataContext as MainViewModel;

    private static ProxyItem? ProxyOf(object sender) => (sender as FrameworkElement)?.DataContext as ProxyItem;

    private void Card_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (Vm is not { } vm || ProxyOf(sender) is not { } proxy) return;
        vm.SelectProxy(proxy);
        vm.CurrentScreen = AppScreen.Dashboard;
    }

    // The row actions sit on the card: each one marks the click handled, so the card is not picked too

    private void BtnFavorite_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        e.Handled = true;
        if (ProxyOf(sender) is { } proxy) Vm?.ServerListVm.ToggleFavoriteCommand.Execute(proxy);
    }

    private void BtnEditServer_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        e.Handled = true;
        if (ProxyOf(sender) is { } proxy) Vm?.OpenEditor(proxy);
    }

    private void BtnDeleteServer_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        e.Handled = true;
        if (ProxyOf(sender) is { } proxy) Vm?.ServerListVm.DeleteProxy(proxy);
    }
}
