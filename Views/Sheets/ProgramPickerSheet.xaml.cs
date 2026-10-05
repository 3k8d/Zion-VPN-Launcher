using System.Windows.Controls;
using System.Windows.Input;
using Zion.ViewModels;

namespace Zion.Views.Sheets;

public partial class ProgramPickerSheet : UserControl
{
    public ProgramPickerSheet()
    {
        InitializeComponent();
    }

    // A click next to the sheet closes it without adding anything
    private void Backdrop_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is MainViewModel vm) vm.ExcludedAppsVm.IsPickerOpen = false;
    }

    private void Card_MouseDown(object sender, MouseButtonEventArgs e) => e.Handled = true;
}
