using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using System.Windows.Threading;
using Zion.Models;
using Zion.Services;

namespace Zion.ViewModels;

public class ServerListViewModel : INotifyPropertyChanged
{
    private readonly MainViewModel _mainVm;
    private string _undoMessage = "";
    private bool _isUndoVisible;
    private Action? _undoAction;
    private DispatcherTimer? _undoTimer;

    public ObservableCollection<ProxyItem> Proxies => _mainVm.Proxies;

    /// <summary>
    /// What the list shows: servers (ProxyItem) mixed with section titles (ServerGroupHeader) and
    /// provider dividers (ServerSubHeader). Favourites first, then each subscription, then manual servers.
    /// </summary>
    public ObservableCollection<object> ListItems { get; } = new();

    // Section titles are kept and reused, so re-ordering moves them instead of recreating them
    private readonly Dictionary<string, ServerGroupHeader> _headers = new();
    private readonly Dictionary<ProxyItem, ServerSubHeader> _subHeaders = new();

    public ICommand ToggleFavoriteCommand { get; }

    private int _serverCount;
    /// <summary>Real servers in the list (provider dividers are not counted).</summary>
    public int ServerCount
    {
        get => _serverCount;
        private set => SetField(ref _serverCount, value);
    }

    public string UndoMessage
    {
        get => _undoMessage;
        set => SetField(ref _undoMessage, value);
    }

    public bool IsUndoVisible
    {
        get => _isUndoVisible;
        set => SetField(ref _isUndoVisible, value);
    }

    public ICommand RefreshSubscriptionCommand { get; }
    public ICommand UndoDeleteCommand { get; }

    private bool _isRefreshingSub = false;

    public ServerListViewModel(MainViewModel mainVm)
    {
        _mainVm = mainVm;

        RefreshSubscriptionCommand = new RelayCommand(async _ => await RefreshSubscriptionAsync(), _ => !_isRefreshingSub);
        UndoDeleteCommand = new RelayCommand(_ => ExecuteUndo());
        AskDeleteAllCommand = new RelayCommand(_ => AskDeleteAll(), _ => _mainVm.DeletableProxyCount > 0);
        CancelDeleteAllCommand = new RelayCommand(_ => IsDeleteAllConfirmOpen = false);
        ConfirmDeleteAllCommand = new RelayCommand(_ => ConfirmDeleteAll());
        ToggleFavoriteCommand = new RelayCommand(p =>
        {
            if (p is not ProxyItem proxy) return;
            proxy.IsFavorite = !proxy.IsFavorite; // the list re-orders itself via the property change
            _mainVm.SaveConfig();
        });

        // Keep the shown order in step with the real list and with every star change
        Proxies.CollectionChanged += (_, e) =>
        {
            if (e.OldItems != null) foreach (ProxyItem p in e.OldItems) p.PropertyChanged -= OnProxyChanged;
            if (e.NewItems != null) foreach (ProxyItem p in e.NewItems) p.PropertyChanged += OnProxyChanged;
            if (e.Action == System.Collections.Specialized.NotifyCollectionChangedAction.Reset)
                foreach (var p in Proxies) { p.PropertyChanged -= OnProxyChanged; p.PropertyChanged += OnProxyChanged; }
            SyncOrder();
        };
        foreach (var p in Proxies) p.PropertyChanged += OnProxyChanged;
        _mainVm.SubscriptionsChanged += SyncOrder; // titles and counts of subscription sections
        SyncOrder();
    }

    private void OnProxyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(ProxyItem.IsFavorite) or nameof(ProxyItem.Name) or nameof(ProxyItem.IsFromSubscription)) SyncOrder();
    }

    /// <summary>Favourites first, then the rest; inside each group the saved order is kept.</summary>
    public static List<ProxyItem> FavoritesFirst(IEnumerable<ProxyItem> proxies)
    {
        var list = proxies.ToList();
        return list.Where(p => p.IsFavorite).Concat(list.Where(p => !p.IsFavorite)).ToList();
    }

    /// <summary>One section of the list: its key, title and members in the saved order.</summary>
    public sealed record ServerSection(string Key, string Title, List<ProxyItem> Members);

    /// <summary>
    /// Splits the list into sections: "Избранное", one per subscription (in the subscriptions' order),
    /// then "Добавлены вручную". A favourite appears only under "Избранное". Empty sections are dropped.
    /// </summary>
    public static List<ServerSection> BuildSections(IEnumerable<ProxyItem> proxies, IEnumerable<SubscriptionEntry> subscriptions)
    {
        var all = proxies.ToList();
        var sections = new List<ServerSection>();

        sections.Add(new ServerSection("fav", "Избранное", all.Where(p => p.IsFavorite && !p.IsDivider).ToList()));

        var rest = all.Where(p => !(p.IsFavorite && !p.IsDivider)).ToList();
        var placed = new HashSet<ProxyItem>();
        foreach (var sub in subscriptions)
        {
            var members = rest.Where(p => p.IsFromSubscription && SubscriptionService.SameUrl(p.SubscriptionUrl, sub.Url)).ToList();
            members.ForEach(p => placed.Add(p));
            sections.Add(new ServerSection("sub:" + sub.Id, MainViewModel.SubscriptionDisplayName(sub.Title, sub.Url), members));
        }

        // Subscription servers whose link is no longer in the list, then manual ones
        var orphans = rest.Where(p => p.IsFromSubscription && !placed.Contains(p)).ToList();
        sections.Add(new ServerSection("orphan", "Из подписки", orphans));
        sections.Add(new ServerSection("manual", "Добавлены вручную", rest.Where(p => !p.IsFromSubscription).ToList()));

        return sections.Where(s => s.Members.Any(p => !p.IsDivider)).ToList();
    }

    /// <summary>Moves items instead of rebuilding, so the list does not jump or lose its scroll position.</summary>
    private void SyncOrder()
    {
        var sections = BuildSections(Proxies, _mainVm.Config.Subscriptions);
        bool showTitles = sections.Count > 1; // a single section needs no title

        var target = new List<object>();
        var usedHeaders = new HashSet<string>();
        var usedSubs = new HashSet<ProxyItem>();
        foreach (var s in sections)
        {
            if (showTitles)
            {
                if (!_headers.TryGetValue(s.Key, out var header)) _headers[s.Key] = header = new ServerGroupHeader();
                header.Title = s.Title;
                header.Count = s.Members.Count(p => !p.IsDivider);
                target.Add(header);
                usedHeaders.Add(s.Key);
            }

            foreach (var p in s.Members)
            {
                if (!p.IsDivider) { target.Add(p); continue; }
                if (!_subHeaders.TryGetValue(p, out var sub)) _subHeaders[p] = sub = new ServerSubHeader(p);
                target.Add(sub);
                usedSubs.Add(p);
            }
        }

        ServerCount = Proxies.Count(p => !p.IsDivider);

        foreach (var key in _headers.Keys.Where(k => !usedHeaders.Contains(k)).ToList()) _headers.Remove(key);
        foreach (var p in _subHeaders.Keys.Where(k => !usedSubs.Contains(k)).ToList()) _subHeaders.Remove(p);

        for (int i = ListItems.Count - 1; i >= 0; i--)
        {
            if (!target.Contains(ListItems[i])) ListItems.RemoveAt(i);
        }

        for (int i = 0; i < target.Count; i++)
        {
            int at = ListItems.IndexOf(target[i]);
            if (at < 0) ListItems.Insert(i, target[i]);
            else if (at != i) ListItems.Move(at, i);
        }
    }


    public async Task RefreshSubscriptionAsync()
    {
        _isRefreshingSub = true;
        try
        {
            await _mainVm.RefreshSubscriptionAsync();
        }
        finally
        {
            _isRefreshingSub = false;
        }
    }

    public void DeleteProxy(ProxyItem proxy)
    {
        if (Proxies.Count <= 1) return;

        int index = Proxies.IndexOf(proxy);
        _mainVm.DeleteProxy(proxy);

        ShowUndo($"Сервер {MainViewModel.FormatCountryAndCity(proxy.Country)} удалён", TimeSpan.FromSeconds(6), () =>
        {
            if (index >= 0 && index <= Proxies.Count) Proxies.Insert(index, proxy);
            else Proxies.Add(proxy);
            _mainVm.SaveConfig();
        });
    }

    // ---- Delete all: a confirmation sheet first, then an undo bar as a second safety net ----

    private bool _isDeleteAllConfirmOpen;
    public bool IsDeleteAllConfirmOpen
    {
        get => _isDeleteAllConfirmOpen;
        set => SetField(ref _isDeleteAllConfirmOpen, value);
    }

    private string _deleteAllConfirmText = "";
    public string DeleteAllConfirmText
    {
        get => _deleteAllConfirmText;
        private set => SetField(ref _deleteAllConfirmText, value);
    }

    public ICommand AskDeleteAllCommand { get; }
    public ICommand CancelDeleteAllCommand { get; }
    public ICommand ConfirmDeleteAllCommand { get; }

    private void AskDeleteAll()
    {
        int count = _mainVm.DeletableProxyCount;
        if (count == 0) return;

        var inUse = _mainVm.ServerInUse;
        string text = inUse == null
            ? $"Из списка будут удалены все серверы ({count})."
            : $"Будут удалены серверы ({count}). «{inUse.CleanName}» останется: вы сейчас через него подключены.";
        if (_mainVm.Config.Subscriptions.Count > 0)
            text += " Подписки сохранятся: кнопка обновления вернёт их серверы.";

        DeleteAllConfirmText = text;
        IsDeleteAllConfirmOpen = true;
    }

    private void ConfirmDeleteAll()
    {
        IsDeleteAllConfirmOpen = false;
        if (_mainVm.DeletableProxyCount == 0) return;

        var snapshot = _mainVm.DeleteAllProxies();
        ShowUndo($"Удалено серверов: {snapshot.RemovedCount}", TimeSpan.FromSeconds(10), () => _mainVm.RestoreProxies(snapshot));
    }

    private void ShowUndo(string message, TimeSpan duration, Action undo)
    {
        _undoAction = undo;
        UndoMessage = message;
        IsUndoVisible = true;

        _undoTimer?.Stop();
        _undoTimer = new DispatcherTimer { Interval = duration };
        _undoTimer.Tick += (s, e) =>
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

/// <summary>A section title in the server list: "Избранное · 2", a subscription's name, "Добавлены вручную".</summary>
public class ServerGroupHeader : INotifyPropertyChanged
{
    private string _title = "";
    public string Title
    {
        get => _title;
        set
        {
            if (_title == value) return;
            _title = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Title)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Caption)));
        }
    }

    /// <summary>Upper-case, like the section titles in settings.</summary>
    public string Caption => Title.ToUpper(System.Globalization.CultureInfo.CurrentCulture);

    private int _count;
    public int Count
    {
        get => _count;
        set { if (_count != value) { _count = value; PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Count))); } }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

/// <summary>A provider's divider entry ("❗️Белые списки ниже") shown as a small title, not as a server.</summary>
public class ServerSubHeader
{
    public ServerSubHeader(ProxyItem source) => Source = source;
    public ProxyItem Source { get; }
    public string Title => Source.DividerTitle;
}
