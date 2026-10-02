using System.Globalization;
using System.Windows.Data;
using System.Windows.Media.Imaging;
using Zion.Models;

namespace Zion.Views.Converters;

public class FlagPathConverter : IValueConverter
{
    private static readonly Dictionary<string, BitmapImage> _cachedImages = new(StringComparer.OrdinalIgnoreCase);

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        string? text = value as string;
        string code = ProxyItem.ResolveIsoCode(text);

        if (string.IsNullOrEmpty(code))
            return null;

        lock (_cachedImages)
        {
            if (_cachedImages.TryGetValue(code, out var img))
                return img;
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

            lock (_cachedImages)
            {
                _cachedImages[code] = bmp;
            }

            return bmp;
        }
        catch
        {
            return null;
        }
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotImplementedException();
}

