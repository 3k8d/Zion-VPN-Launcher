using System.Windows.Controls;
using System.Windows.Input;
using Zion.ViewModels;

namespace Zion.Views.Sheets;

public partial class DeleteAllSheet : UserControl
{
    public DeleteAllSheet()
    {
        InitializeComponent();
    }

    // A click next to the sheet means "never mind"
    private void Backdrop_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is MainViewModel vm) vm.ServerListVm.IsDeleteAllConfirmOpen = false;
    }

    private void Card_MouseDown(object sender, MouseButtonEventArgs e) => e.Handled = true;
}
