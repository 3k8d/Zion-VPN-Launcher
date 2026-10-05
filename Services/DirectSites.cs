using System.Globalization;
using System.Net;

namespace Zion.Services;

/// <summary>
/// Sites the user sends around the VPN. A site always includes its subdomains
/// ("yandex.ru" also covers "music.yandex.ru"); matching is by whole name parts, so it never catches
/// an unrelated site with a similar ending.
/// </summary>
public static class DirectSites
{
    private static readonly IdnMapping Idn = new();

    /// <summary>
    /// Turns whatever the user pasted ("https://www.kinopoisk.ru/film/1", "КИНОПОИСК.РФ", "*.vk.com")
    /// into the bare site name the core compares against ("kinopoisk.ru", "xn--h1aafkeagik.xn--p1ai", "vk.com").
    /// Returns null and a reason when it is not a site address.
    /// </summary>
    public static string? Normalize(string? input, out string error)
    {
        error = "";
        string s = (input ?? "").Trim();
        if (s.Length == 0) { error = "Введите адрес сайта"; return null; }

        // Full links: keep only the host
        if (s.Contains("://") && Uri.TryCreate(s, UriKind.Absolute, out var uri)) s = uri.Host;

        // Bare "site.com/path?x" or "site.com:8080"
        int cut = s.IndexOfAny(new[] { '/', '?', '#', ' ' });
        if (cut >= 0) s = s[..cut];
        int colon = s.LastIndexOf(':');
        if (colon > 0 && s.IndexOf(':') == colon) s = s[..colon];

        s = s.Trim().TrimEnd('.').ToLowerInvariant();
        while (s.StartsWith("*.") || s.StartsWith(".")) s = s.TrimStart('*').TrimStart('.');
        if (s.StartsWith("www.")) s = s[4..]; // subdomains are included anyway

        if (IPAddress.TryParse(s, out _)) { error = "Нужен адрес сайта, а не IP"; return null; }

        try { s = Idn.GetAscii(s); } // кинопоиск.рф -> xn--...
        catch { error = "Это не похоже на адрес сайта"; return null; }

        string[] labels = s.Split('.');
        bool valid = labels.Length >= 2 && s.Length <= 253 && labels.All(IsLabel) && !labels[^1].All(char.IsDigit);
        if (!valid) { error = "Это не похоже на адрес сайта"; return null; }
        return s;
    }

    /// <summary>Readable form for the list: punycode back to letters ("xn--p1ai" -> "рф").</summary>
    public static string Display(string domain)
    {
        try { return Idn.GetUnicode(domain); }
        catch { return domain; }
    }

    /// <summary>Clean, de-duplicated list for the routing rule; anything invalid is dropped.</summary>
    public static List<string> Sanitize(IEnumerable<string>? domains)
    {
        var result = new List<string>();
        if (domains == null) return result;
        foreach (string d in domains)
        {
            string? n = Normalize(d, out _);
            if (n != null && !result.Contains(n)) result.Add(n);
        }
        return result;
    }

    private static bool IsLabel(string l) =>
        l.Length is > 0 and <= 63 && !l.StartsWith('-') && !l.EndsWith('-') && l.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');
}
