using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using System.Windows.Media;
using Zion.Models;
using Zion.Services;

namespace Zion.ViewModels;

/// <summary>The "Программы мимо VPN" screen and its picker.</summary>
public class ExcludedAppsViewModel : INotifyPropertyChanged
{
    private readonly MainViewModel _main;
    private List<AppCandidate> _allRunning = new();

    public ObservableCollection<ExcludedAppRow> Rows { get; } = new();
    public ObservableCollection<PickerItem> PickerItems { get; } = new();

    public ExcludedAppsViewModel(MainViewModel main)
    {
        _main = main;
        OpenPickerCommand = new RelayCommand(async _ => await OpenPickerAsync());
        ClosePickerCommand = new RelayCommand(_ => IsPickerOpen = false);
        PickCommand = new RelayCommand(p => { if (p is PickerItem item && !item.IsAdded) { IsPickerOpen = false; Add(item.Path); } });
        BrowseCommand = new RelayCommand(_ => Browse());
        BackCommand = new RelayCommand(_ => _main.CurrentScreen = AppScreen.Settings);

        foreach (var app in _main.Config.DirectApps) Rows.Add(new ExcludedAppRow(this, app));
    }

    public ICommand OpenPickerCommand { get; }
    public ICommand ClosePickerCommand { get; }
    public ICommand PickCommand { get; }
    public ICommand BrowseCommand { get; }
    public ICommand BackCommand { get; }

    public bool IsEmpty => Rows.Count == 0;
    public int Count => Rows.Count;

    /// <summary>One line for the settings screen: "Steam, Discord и ещё 2" or "Не выбраны".</summary>
    public string Summary
    {
        get
        {
            if (Rows.Count == 0) return "Не выбраны";
            var names = Rows.Take(2).Select(r => r.DisplayName).ToList();
            string text = string.Join(", ", names);
            return Rows.Count > 2 ? $"{text} и ещё {Rows.Count - 2}" : text;
        }
    }

    private string _status = "";
    public string Status
    {
        get => _status;
        private set { if (SetField(ref _status, value)) OnPropertyChanged(nameof(HasStatus)); }
    }
    public bool HasStatus => Status.Length > 0;

    private bool _isPickerOpen;
    public bool IsPickerOpen
    {
        get => _isPickerOpen;
        set => SetField(ref _isPickerOpen, value);
    }

    private bool _isLoadingPicker;
    public bool IsLoadingPicker
    {
        get => _isLoadingPicker;
        private set
        {
            if (SetField(ref _isLoadingPicker, value)) OnPropertyChanged(nameof(PickerIsEmpty));
        }
    }

    private string _search = "";
    public string Search
    {
        get => _search;
        set { if (SetField(ref _search, value ?? "")) FillPicker(); }
    }

    private async Task OpenPickerAsync()
    {
        Status = "";
        Search = "";
        PickerItems.Clear();
        IsPickerOpen = true;
        IsLoadingPicker = true;
        try
        {
            _allRunning = await Task.Run(AppInfoService.RunningPrograms);
            FillPicker();
        }
        finally
        {
            IsLoadingPicker = false;
        }
    }

    private void FillPicker()
    {
        PickerItems.Clear();
        string q = Search.Trim();
        foreach (var app in _allRunning)
        {
            if (q.Length > 0 &&
                app.DisplayName.IndexOf(q, StringComparison.CurrentCultureIgnoreCase) < 0 &&
                app.ProcessName.IndexOf(q, StringComparison.OrdinalIgnoreCase) < 0) continue;

            bool added = Rows.Any(r => r.ProcessName.Equals(app.ProcessName, StringComparison.OrdinalIgnoreCase));
            PickerItems.Add(new PickerItem(app.Path, app.ProcessName, app.DisplayName, added));
        }
        OnPropertyChanged(nameof(PickerIsEmpty));
    }

    public bool PickerIsEmpty => !IsLoadingPicker && PickerItems.Count == 0;

    private void Browse()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Выберите программу, которая будет работать мимо VPN",
            Filter = "Программы (*.exe)|*.exe",
            CheckFileExists = true
        };
        if (dialog.ShowDialog() == true)
        {
            IsPickerOpen = false;
            Add(dialog.FileName);
        }
    }

    public void Add(string path)
    {
        string exe = Path.GetFileName(path);
        if (TunRoutingEngine.SanitizeDirectApps(new[] { exe }).Count == 0)
        {
            Status = exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? "Сам Zion и его ядро исключать нельзя."
                : "Нужен exe-файл программы.";
            return;
        }
        if (Rows.Any(r => r.ProcessName.Equals(exe, StringComparison.OrdinalIgnoreCase)))
        {
            Status = $"{exe} уже в списке.";
            return;
        }

        var app = new ExcludedApp { ProcessName = exe, Path = path, DisplayName = AppInfoService.ReadableName(path, exe) };
        _main.Config.DirectApps.Add(app);
        Rows.Add(new ExcludedAppRow(this, app));
        Status = _main.IsConnected
            ? $"Программа «{app.DisplayName}» добавлена. Туннель перезапустится через пару секунд."
            : $"Программа «{app.DisplayName}» добавлена.";
        Changed();
    }

    internal void Remove(ExcludedAppRow row)
    {
        _main.Config.DirectApps.Remove(row.App);
        Rows.Remove(row);
        Status = $"Программа «{row.DisplayName}» снова идёт через VPN.";
        Changed();
    }

    private void Changed()
    {
        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(Count));
        OnPropertyChanged(nameof(Summary));
        _main.ApplyRoutingExceptions();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    protected bool SetField<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }
}

/// <summary>An excluded program in the list.</summary>
public class ExcludedAppRow
{
    private readonly ExcludedAppsViewModel _owner;
    public ExcludedApp App { get; }

    public ExcludedAppRow(ExcludedAppsViewModel owner, ExcludedApp app)
    {
        _owner = owner;
        App = app;
        RemoveCommand = new RelayCommand(_ => _owner.Remove(this));
    }

    public string ProcessName => App.ProcessName;
    public string DisplayName => string.IsNullOrWhiteSpace(App.DisplayName) ? Path.GetFileNameWithoutExtension(App.ProcessName) : App.DisplayName;
    public ImageSource? Icon => AppInfoService.Icon(App.Path);
    public ICommand RemoveCommand { get; }
}

/// <summary>A running program offered in the picker.</summary>
public class PickerItem
{
    public PickerItem(string path, string processName, string displayName, bool isAdded)
    {
        Path = path;
        ProcessName = processName;
        DisplayName = displayName;
        IsAdded = isAdded;
    }

    public string Path { get; }
    public string ProcessName { get; }
    public string DisplayName { get; }
    public bool IsAdded { get; }
    public ImageSource? Icon => AppInfoService.Icon(Path);
}
