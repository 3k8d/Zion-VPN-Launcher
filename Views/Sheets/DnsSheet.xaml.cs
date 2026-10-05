using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Zion.ViewModels;

namespace Zion.Views.Sheets;

public partial class DnsSheet : UserControl
{
    public DnsSheet()
    {
        InitializeComponent();
    }

    private MainViewModel? Vm => DataContext as MainViewModel;

    // A click next to the sheet closes it; a click on the sheet stays there (and does not drag the window)
    private void Backdrop_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (Vm is { } vm) vm.IsDnsModalOpen = false;
    }

    private void Card_MouseDown(object sender, MouseButtonEventArgs e) => e.Handled = true;

    private void DnsOption_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is DnsOptionItem item)
        {
            Vm?.SelectDnsCommand.Execute(item.Provider);
        }
    }
}
