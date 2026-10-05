using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using System.Windows.Threading;
using Zion.Models;

namespace Zion.ViewModels;

public class ServerListViewModel : INotifyPropertyChanged
{
    private readonly MainViewModel _mainVm;
    private string _undoMessage = "";
    private bool _isUndoVisible;
    private Action? _undoAction;
    private DispatcherTimer? _undoTimer;

    public ObservableCollection<ProxyItem> Proxies => _mainVm.Proxies;

    /// <summary>What the list shows: favourites first, then everything else, each in the saved order.</summary>
    public ObservableCollection<ProxyItem> OrderedProxies { get; } = new();

    public ICommand ToggleFavoriteCommand { get; }

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
        SyncOrder();
    }

    private void OnProxyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ProxyItem.IsFavorite)) SyncOrder();
    }

    /// <summary>Favourites first, then the rest; inside each group the saved order is kept.</summary>
    public static List<ProxyItem> FavoritesFirst(IEnumerable<ProxyItem> proxies)
    {
        var list = proxies.ToList();
        return list.Where(p => p.IsFavorite).Concat(list.Where(p => !p.IsFavorite)).ToList();
    }

    /// <summary>Moves items instead of rebuilding, so the list does not jump or lose its scroll position.</summary>
    private void SyncOrder()
    {
        var target = FavoritesFirst(Proxies);

        for (int i = OrderedProxies.Count - 1; i >= 0; i--)
        {
            if (!target.Contains(OrderedProxies[i])) OrderedProxies.RemoveAt(i);
        }

        for (int i = 0; i < target.Count; i++)
        {
            int at = OrderedProxies.IndexOf(target[i]);
            if (at < 0) OrderedProxies.Insert(i, target[i]);
            else if (at != i) OrderedProxies.Move(at, i);
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
            : $"Будут удалены серверы ({count}). «{inUse.DisplayName}» останется: вы сейчас через него подключены.";
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

