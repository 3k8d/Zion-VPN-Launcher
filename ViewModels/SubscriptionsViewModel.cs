using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using Zion.Models;
using Zion.Services;

namespace Zion.ViewModels;

/// <summary>The "Подписки" screen: any number of subscription links, each with its status and plan.</summary>
public class SubscriptionsViewModel : INotifyPropertyChanged
{
    private readonly MainViewModel _main;
    private DispatcherTimer? _undoTimer;
    private Action? _undoAction;

    public ObservableCollection<SubscriptionRow> Rows { get; } = new();

    public SubscriptionsViewModel(MainViewModel main)
    {
        _main = main;

        AddCommand = new RelayCommand(async _ => await AddAsync(), _ => !IsAdding);
        RefreshAllCommand = new RelayCommand(async _ => await _main.RefreshAllSubscriptionsAsync(), _ => Rows.Count > 0);
        UndoCommand = new RelayCommand(_ => ExecuteUndo());
        BackCommand = new RelayCommand(_ => _main.CurrentScreen = AppScreen.ServerList);

        _main.SubscriptionsChanged += Sync;
        _main.Proxies.CollectionChanged += (_, _) => Sync();
        Sync();
    }

    public ICommand AddCommand { get; }
    public ICommand RefreshAllCommand { get; }
    public ICommand UndoCommand { get; }
    public ICommand BackCommand { get; }

    public int Count => Rows.Count;
    public bool IsEmpty => Rows.Count == 0;

    private string _newUrl = "";
    public string NewUrl
    {
        get => _newUrl;
        set
        {
            if (SetField(ref _newUrl, value ?? ""))
            {
                OnPropertyChanged(nameof(HasNewUrl));
                if (!IsAdding) Status = "";
            }
        }
    }

    public bool HasNewUrl => !string.IsNullOrWhiteSpace(NewUrl);

    private bool _isAdding;
    public bool IsAdding
    {
        get => _isAdding;
        private set => SetField(ref _isAdding, value);
    }

    // One status line under the input: progress, result, or the reason it failed
    private string _status = "";
    public string Status
    {
        get => _status;
        private set
        {
            if (SetField(ref _status, value)) OnPropertyChanged(nameof(HasStatus));
        }
    }
    public bool HasStatus => !string.IsNullOrEmpty(Status);

    private bool _statusIsError;
    public bool StatusIsError
    {
        get => _statusIsError;
        private set => SetField(ref _statusIsError, value);
    }

    private bool _isUndoVisible;
    public bool IsUndoVisible
    {
        get => _isUndoVisible;
        private set => SetField(ref _isUndoVisible, value);
    }

    private string _undoMessage = "";
    public string UndoMessage
    {
        get => _undoMessage;
        private set => SetField(ref _undoMessage, value);
    }

    private void PasteFromClipboard()
    {
        try
        {
            if (Clipboard.ContainsText()) NewUrl = Clipboard.GetText().Trim();
        }
        catch { }
    }

    private async Task AddAsync()
    {
        if (!HasNewUrl) PasteFromClipboard();

        string url = ProxyParser.ExtractActualSubscriptionUrl(NewUrl);
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            ShowStatus("Это не похоже на ссылку подписки: она должна начинаться с https://", true);
            return;
        }

        bool known = SubscriptionService.Find(_main.Config, url) != null;
        IsAdding = true;
        ShowStatus(known ? "Эта подписка уже есть, обновляю…" : "Загружаю подписку…", false);
        try
        {
            var result = await _main.UpdateSubscriptionAsync(url);
            if (result.Ok)
            {
                NewUrl = "";
                ShowStatus(known
                    ? $"Подписка обновлена: {Servers(result.Total)}."
                    : $"Подписка добавлена: {Servers(result.Total)}.", false);
            }
            else
            {
                ShowStatus($"Не получилось: {result.Error}.", true);
            }
        }
        finally
        {
            IsAdding = false;
        }
    }

    internal async Task RefreshAsync(SubscriptionRow row)
    {
        var result = await _main.UpdateSubscriptionAsync(row.Entry.Url);
        if (!result.Ok && result.Error != "Уже обновляется")
            ShowStatus($"«{row.Title}» не обновилась: {result.Error}.", true);
    }

    internal void Remove(SubscriptionRow row)
    {
        var removed = _main.RemoveSubscription(row.Entry);
        ShowUndo($"Подписка «{row.Title}» удалена, серверов: {removed.RemovedCount}", () => _main.RestoreSubscription(removed));
    }

    private void ShowStatus(string text, bool isError)
    {
        StatusIsError = isError;
        Status = text;
    }

    private void ShowUndo(string message, Action undo)
    {
        _undoAction = undo;
        UndoMessage = message;
        IsUndoVisible = true;

        _undoTimer?.Stop();
        _undoTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(10) };
        _undoTimer.Tick += (_, _) =>
        {
            _undoTimer?.Stop();
            IsUndoVisible = false;
            _undoAction = null;
        };
        _undoTimer.Start();
    }

    private void ExecuteUndo()
    {
        var undo = _undoAction;
        _undoAction = null;
        _undoTimer?.Stop();
        IsUndoVisible = false;
        undo?.Invoke();
    }

    /// <summary>Brings the rows in line with the saved subscriptions without recreating the ones that stay.</summary>
    public void Sync()
    {
        var entries = _main.Config.Subscriptions.ToList();

        for (int i = Rows.Count - 1; i >= 0; i--)
        {
            if (!entries.Contains(Rows[i].Entry)) Rows.RemoveAt(i);
        }

        for (int i = 0; i < entries.Count; i++)
        {
            var row = Rows.FirstOrDefault(r => r.Entry == entries[i]);
            if (row == null)
            {
                row = new SubscriptionRow(this, entries[i]);
                Rows.Insert(Math.Min(i, Rows.Count), row);
            }
            row.Refresh(
                _main.Proxies.Count(p => p.IsFromSubscription && SubscriptionService.SameUrl(p.SubscriptionUrl, entries[i].Url)),
                _main.IsSubscriptionUpdating(entries[i].Url));
        }

        OnPropertyChanged(nameof(Count));
        OnPropertyChanged(nameof(IsEmpty));
    }

    // ------------------------------------------------------------------ formatting

    private static readonly CultureInfo Ru = CultureInfo.GetCultureInfo("ru-RU");

    public static string Plural(int n, string one, string few, string many)
    {
        int n10 = n % 10, n100 = n % 100;
        if (n10 == 1 && n100 != 11) return one;
        if (n10 is >= 2 and <= 4 && (n100 < 10 || n100 >= 20)) return few;
        return many;
    }

    public static string Servers(int n) => $"{n} {Plural(n, "сервер", "сервера", "серверов")}";

    public static string When(DateTime time, DateTime now)
    {
        if (time.Date == now.Date) return $"сегодня в {time:HH:mm}";
        if (time.Date == now.Date.AddDays(-1)) return $"вчера в {time:HH:mm}";
        return time.Year == now.Year ? time.ToString("d MMMM в HH:mm", Ru) : time.ToString("d MMMM yyyy", Ru);
    }

    public static string Size(long bytes)
    {
        double gb = bytes / (1024.0 * 1024 * 1024);
        if (gb >= 100) return gb.ToString("0", Ru) + " ГБ";
        if (gb >= 1) return gb.ToString("0.#", Ru) + " ГБ";
        return (bytes / (1024.0 * 1024)).ToString("0", Ru) + " МБ";
    }

    /// <summary>"Осталось 87,4 ГБ из 100 ГБ · до 15 ноября" and the used share for the bar (0..1).</summary>
    public static (string Text, double UsedFraction, bool IsWarning) Plan(SubscriptionEntry e, DateTime now)
    {
        var parts = new List<string>();
        double used = 0;
        bool warning = false;
        long spent = e.Upload + e.Download;

        if (e.Total > 0)
        {
            long left = Math.Max(0, e.Total - spent);
            used = Math.Clamp((double)spent / e.Total, 0, 1);
            parts.Add($"Осталось {Size(left)} из {Size(e.Total)}");
            if (used >= 0.9) warning = true;
        }
        else if (spent > 0)
        {
            parts.Add($"Израсходовано {Size(spent)} · без лимита");
        }

        if (e.Expire.HasValue)
        {
            var end = e.Expire.Value;
            if (end <= now)
            {
                parts.Add($"истекла {end.ToString("d MMMM", Ru)}");
                warning = true;
            }
            else
            {
                int days = (int)Math.Ceiling((end - now).TotalDays);
                parts.Add(days <= 7
                    ? $"ещё {days} {Plural(days, "день", "дня", "дней")}"
                    : "до " + end.ToString(end.Year == now.Year ? "d MMMM" : "d MMMM yyyy", Ru));
                if (days <= 3) warning = true;
            }
        }

        return (string.Join(" · ", parts), used, warning);
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

/// <summary>One card on the subscriptions screen.</summary>
public class SubscriptionRow : INotifyPropertyChanged
{
    private readonly SubscriptionsViewModel _owner;
    private DispatcherTimer? _disarmTimer;

    public SubscriptionEntry Entry { get; }

    public SubscriptionRow(SubscriptionsViewModel owner, SubscriptionEntry entry)
    {
        _owner = owner;
        Entry = entry;
        RefreshCommand = new RelayCommand(async _ => await _owner.RefreshAsync(this), _ => !IsUpdating);
        DeleteCommand = new RelayCommand(_ => DeleteClicked());
    }

    public ICommand RefreshCommand { get; }
    public ICommand DeleteCommand { get; }

    public string Title => MainViewModel.SubscriptionDisplayName(Entry.Title, Entry.Url);

    /// <summary>Host only: the rest of the link usually contains a personal token.</summary>
    public string Host => Uri.TryCreate(Entry.Url, UriKind.Absolute, out var uri) ? uri.Host : "";

    private string _statusText = "";
    public string StatusText { get => _statusText; private set => SetField(ref _statusText, value); }

    private bool _hasError;
    public bool HasError { get => _hasError; private set => SetField(ref _hasError, value); }

    private string _planText = "";
    public string PlanText { get => _planText; private set => SetField(ref _planText, value); }

    private bool _hasPlan;
    public bool HasPlan { get => _hasPlan; private set => SetField(ref _hasPlan, value); }

    private bool _hasQuota;
    public bool HasQuota { get => _hasQuota; private set => SetField(ref _hasQuota, value); }

    private double _usedFraction;
    public double UsedFraction { get => _usedFraction; private set => SetField(ref _usedFraction, value); }

    private bool _planWarning;
    public bool PlanWarning { get => _planWarning; private set => SetField(ref _planWarning, value); }

    private bool _isUpdating;
    public bool IsUpdating { get => _isUpdating; private set => SetField(ref _isUpdating, value); }

    /// <summary>First click on delete arms it for a few seconds; only a second click removes.</summary>
    private bool _isDeleteArmed;
    public bool IsDeleteArmed { get => _isDeleteArmed; private set => SetField(ref _isDeleteArmed, value); }

    public void Refresh(int serverCount, bool updating)
    {
        var now = DateTime.Now;
        IsUpdating = updating;
        OnPropertyChanged(nameof(Title));

        string servers = SubscriptionsViewModel.Servers(serverCount);
        if (updating)
        {
            StatusText = $"{servers} · обновляется…";
            HasError = false;
        }
        else if (!string.IsNullOrEmpty(Entry.LastError))
        {
            StatusText = $"{servers} · не обновилась: {Entry.LastError}";
            HasError = true;
        }
        else
        {
            StatusText = Entry.LastUpdate.HasValue
                ? $"{servers} · обновлено {SubscriptionsViewModel.When(Entry.LastUpdate.Value, now)}"
                : servers;
            HasError = false;
        }

        var plan = SubscriptionsViewModel.Plan(Entry, now);
        PlanText = plan.Text;
        HasPlan = plan.Text.Length > 0;
        HasQuota = Entry.Total > 0;
        UsedFraction = plan.UsedFraction;
        PlanWarning = plan.IsWarning;
    }

    private void DeleteClicked()
    {
        if (!IsDeleteArmed)
        {
            IsDeleteArmed = true;
            _disarmTimer?.Stop();
            _disarmTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
            _disarmTimer.Tick += (_, _) => { _disarmTimer?.Stop(); IsDeleteArmed = false; };
            _disarmTimer.Start();
            return;
        }

        _disarmTimer?.Stop();
        IsDeleteArmed = false;
        _owner.Remove(this);
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
