using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;
using Zion.Models;

namespace Zion.Views;

public partial class FlagBadge : UserControl
{
    private static readonly Dictionary<string, BitmapImage> _cache = new(StringComparer.OrdinalIgnoreCase);

    public static readonly DependencyProperty CountryProperty =
        DependencyProperty.Register(
            nameof(Country),
            typeof(string),
            typeof(FlagBadge),
            new PropertyMetadata("", OnCountryChanged));

    public string Country
    {
        get => (string)GetValue(CountryProperty);
        set => SetValue(CountryProperty, value);
    }

    public FlagBadge()
    {
        InitializeComponent();
    }

    private static void OnCountryChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is FlagBadge badge)
        {
            badge.RenderFlag(e.NewValue as string);
        }
    }

    public void RenderFlag(string? countryText)
    {
        string code = ProxyItem.ResolveIsoCode(countryText);

        if (code == "auto")
        {
            FlagImage.Visibility = Visibility.Collapsed;
            GlobeFallback.Text = "🚀";
            GlobeFallback.Visibility = Visibility.Visible;
            return;
        }

        if (string.IsNullOrEmpty(code) || code == "un")
        {
            FlagImage.Visibility = Visibility.Collapsed;
            GlobeFallback.Text = "🌐";
            GlobeFallback.Visibility = Visibility.Visible;
            return;
        }

        lock (_cache)
        {
            if (_cache.TryGetValue(code, out var cachedImg))
            {
                FlagImage.Source = cachedImg;
                FlagImage.Visibility = Visibility.Visible;
                GlobeFallback.Visibility = Visibility.Collapsed;
                return;
            }
        }

        try
        {
            var uri = new Uri($"pack://application:,,,/Resources/Flags/{code}.png", UriKind.Absolute);
            var bmp = new BitmapImage();
            bmp.BeginInit();
            bmp.UriSource = uri;
            bmp.CacheOption = BitmapCacheOption.OnLoad;
            bmp.EndInit();
            bmp.Freeze();

            lock (_cache)
            {
                _cache[code] = bmp;
            }

            FlagImage.Source = bmp;
            FlagImage.Visibility = Visibility.Visible;
            GlobeFallback.Visibility = Visibility.Collapsed;
        }
        catch
        {
            FlagImage.Visibility = Visibility.Collapsed;
            GlobeFallback.Text = "🌐";
            GlobeFallback.Visibility = Visibility.Visible;
        }
    }
}

