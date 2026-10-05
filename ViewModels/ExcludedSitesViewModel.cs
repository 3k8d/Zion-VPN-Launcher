using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using Zion.Models;
using Zion.Services;

namespace Zion.ViewModels;

/// <summary>The "Сайты мимо VPN" screen: sites (with subdomains) that always go directly.</summary>
public class ExcludedSitesViewModel : INotifyPropertyChanged
{
    private readonly MainViewModel _main;

    public ObservableCollection<ExcludedSiteRow> Rows { get; } = new();

    public ExcludedSitesViewModel(MainViewModel main)
    {
        _main = main;
        AddCommand = new RelayCommand(_ => Add());
        BackCommand = new RelayCommand(_ => _main.CurrentScreen = AppScreen.Settings);

        foreach (string d in DirectSites.Sanitize(_main.Config.DirectSites)) Rows.Add(new ExcludedSiteRow(this, d));
    }

    public ICommand AddCommand { get; }
    public ICommand BackCommand { get; }

    public bool IsEmpty => Rows.Count == 0;
    public int Count => Rows.Count;

    /// <summary>One line for the settings screen: "kinopoisk.ru, sberbank.ru и ещё 2" or "Не выбраны".</summary>
    public string Summary
    {
        get
        {
            if (Rows.Count == 0) return "Не выбраны";
            string text = string.Join(", ", Rows.Take(2).Select(r => r.DisplayName));
            return Rows.Count > 2 ? $"{text} и ещё {Rows.Count - 2}" : text;
        }
    }

    private string _newSite = "";
    public string NewSite
    {
        get => _newSite;
        set
        {
            if (SetField(ref _newSite, value ?? ""))
            {
                OnPropertyChanged(nameof(HasNewSite));
                Status = "";
            }
        }
    }

    public bool HasNewSite => !string.IsNullOrWhiteSpace(NewSite);

    private string _status = "";
    public string Status
    {
        get => _status;
        private set { if (SetField(ref _status, value)) OnPropertyChanged(nameof(HasStatus)); }
    }
    public bool HasStatus => Status.Length > 0;

    private bool _statusIsError;
    public bool StatusIsError
    {
        get => _statusIsError;
        private set => SetField(ref _statusIsError, value);
    }

    /// <summary>Adds what is typed; with an empty field, takes the address from the clipboard.</summary>
    private void Add()
    {
        if (!HasNewSite)
        {
            try { if (Clipboard.ContainsText()) NewSite = Clipboard.GetText().Trim(); } catch { }
        }

        string? domain = DirectSites.Normalize(NewSite, out string error);
        if (domain == null)
        {
            ShowStatus(error, true);
            return;
        }
        if (Rows.Any(r => r.Domain == domain))
        {
            ShowStatus($"{DirectSites.Display(domain)} уже в списке", true);
            return;
        }

        _main.Config.DirectSites.Add(domain);
        Rows.Insert(0, new ExcludedSiteRow(this, domain));
        NewSite = "";
        ShowStatus(_main.IsConnected
            ? $"{DirectSites.Display(domain)} добавлен. Туннель перезапустится через пару секунд."
            : $"{DirectSites.Display(domain)} добавлен", false);
        Changed();
    }

    internal void Remove(ExcludedSiteRow row)
    {
        _main.Config.DirectSites.RemoveAll(d => string.Equals(d, row.Domain, StringComparison.OrdinalIgnoreCase));
        Rows.Remove(row);
        ShowStatus($"{row.DisplayName} снова идёт через VPN", false);
        Changed();
    }

    private void ShowStatus(string text, bool isError)
    {
        StatusIsError = isError;
        Status = text;
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

/// <summary>A site in the list.</summary>
public class ExcludedSiteRow
{
    private readonly ExcludedSitesViewModel _owner;

    public ExcludedSiteRow(ExcludedSitesViewModel owner, string domain)
    {
        _owner = owner;
        Domain = domain;
        RemoveCommand = new RelayCommand(_ => _owner.Remove(this));
    }

    /// <summary>As stored and matched (punycode for non-Latin names).</summary>
    public string Domain { get; }

    /// <summary>As shown ("кинопоиск.рф" rather than "xn--...").</summary>
    public string DisplayName => DirectSites.Display(Domain);

    public ICommand RemoveCommand { get; }
}
