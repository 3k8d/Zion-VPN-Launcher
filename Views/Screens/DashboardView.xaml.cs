using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media.Animation;

namespace Zion.Views.Screens;

/// <summary>
/// Main screen. Its only logic is the breathing ring around the power button: it means "connected",
/// so it runs only while the VPN is up and somebody can actually see it (screen shown, window open,
/// not minimized, in front). Every other moment it is paused or stopped: the window is layered, so
/// each animation frame repaints all of it, and a ring breathing in the background is pure battery drain.
/// </summary>
public partial class DashboardView : UserControl
{
    public static readonly DependencyProperty IsConnectedProperty = DependencyProperty.Register(
        nameof(IsConnected), typeof(bool), typeof(DashboardView),
        new PropertyMetadata(false, (d, _) => ((DashboardView)d).UpdateBreathing()));

    /// <summary>Bound to the view model's IsConnected.</summary>
    public bool IsConnected
    {
        get => (bool)GetValue(IsConnectedProperty);
        set => SetValue(IsConnectedProperty, value);
    }

    private enum Breathing { Stopped, Running, Paused }

    private readonly Storyboard _breathing;
    private Breathing _state = Breathing.Stopped;
    private Window? _window;

    public DashboardView()
    {
        InitializeComponent();
        _breathing = (Storyboard)Resources["Breathing"];
        SetBinding(IsConnectedProperty, new Binding("IsConnected"));

        IsVisibleChanged += (_, _) => UpdateBreathing();
        Loaded += (_, _) => AttachWindow(Window.GetWindow(this));
        Unloaded += (_, _) => AttachWindow(null);
    }

    private void AttachWindow(Window? window)
    {
        if (_window != null)
        {
            _window.Activated -= OnWindowChanged;
            _window.Deactivated -= OnWindowChanged;
            _window.StateChanged -= OnWindowChanged;
        }

        _window = window;

        if (_window != null)
        {
            _window.Activated += OnWindowChanged;
            _window.Deactivated += OnWindowChanged;
            _window.StateChanged += OnWindowChanged;
        }
        UpdateBreathing();
    }

    private void OnWindowChanged(object? sender, EventArgs e) => UpdateBreathing();

    private void UpdateBreathing()
    {
        if (!IsConnected)
        {
            // Not connected: the ring rests at its normal size
            if (_state != Breathing.Stopped) _breathing.Stop(this);
            _state = Breathing.Stopped;
            return;
        }

        bool seen = IsVisible && _window is { IsActive: true } window && window.WindowState != WindowState.Minimized;
        if (seen)
        {
            if (_state == Breathing.Stopped) _breathing.Begin(this, isControllable: true);
            else if (_state == Breathing.Paused) _breathing.Resume(this);
            _state = Breathing.Running;
        }
        else if (_state == Breathing.Running)
        {
            // Out of sight: freeze where it is, so it continues smoothly when the window comes back
            _breathing.Pause(this);
            _state = Breathing.Paused;
        }
    }
}
