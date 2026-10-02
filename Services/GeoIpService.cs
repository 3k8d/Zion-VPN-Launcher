using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Zion.Services;

public static class GeoIpService
{
    private static readonly HttpClient _httpClient = new() { Timeout = TimeSpan.FromSeconds(4.0) };
    private static readonly Dictionary<string, string> _cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly SemaphoreSlim _throttle = new(2, 2);

    public static async Task<string> ResolveCountryForHostAsync(string host)
    {
        if (string.IsNullOrWhiteSpace(host)) return "";
        
        string cleanHost = host.Trim();
        if (cleanHost.Contains(':'))
            cleanHost = cleanHost.Split(':')[0];

        lock (_cache)
        {
            if (_cache.TryGetValue(cleanHost, out var cached))
                return cached;
        }

        await _throttle.WaitAsync();
        try
        {
            // 1. Try ipwho.is with hostname or IP
            try
            {
                string targetQuery = cleanHost;
                if (!IPAddress.TryParse(cleanHost, out _))
                {
                    try
                    {
                        var addrs = await Dns.GetHostAddressesAsync(cleanHost);
                        var v4 = addrs.FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                        if (v4 != null) targetQuery = v4.ToString();
                    }
                    catch { }
                }

                string url = $"https://ipwho.is/{targetQuery}";
                var resp = await _httpClient.GetStringAsync(url);
                using var doc = JsonDocument.Parse(resp);
                var root = doc.RootElement;

                if (root.TryGetProperty("success", out var s) && s.GetBoolean())
                {
                    string country = root.TryGetProperty("country", out var c) ? c.GetString() ?? "" : "";
                    string city = root.TryGetProperty("city", out var ct) ? ct.GetString() ?? "" : "";

                    string result = !string.IsNullOrEmpty(city) ? $"{country}, {city}" : country;
                    result = NormalizeLocation(result);
                    if (!string.IsNullOrWhiteSpace(result))
                    {
                        lock (_cache) { _cache[cleanHost] = result; }
                        return result;
                    }
                }
            }
            catch { }

            // 2. Fallback: freeipapi.com (HTTPS-only)
            try
            {
                string url = $"https://freeipapi.com/api/json/{cleanHost}";
                var resp = await _httpClient.GetStringAsync(url);
                using var doc = JsonDocument.Parse(resp);
                var root = doc.RootElement;

                string country = root.TryGetProperty("countryName", out var c) ? c.GetString() ?? "" : "";
                string city = root.TryGetProperty("cityName", out var ct) ? ct.GetString() ?? "" : "";

                if (!string.IsNullOrEmpty(country))
                {
                    string result = !string.IsNullOrEmpty(city) ? $"{country}, {city}" : country;
                    result = NormalizeLocation(result);
                    if (!string.IsNullOrWhiteSpace(result))
                    {
                        lock (_cache) { _cache[cleanHost] = result; }
                        return result;
                    }
                }
            }
            catch { }
        }
        finally
        {
            await Task.Delay(100);
            _throttle.Release();
        }

        return "";
    }

    public static string NormalizeLocation(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return raw;
        string s = raw.Trim();

        // 1. Clean river and geographic suffixes in city names
        s = Regex.Replace(s, @"\s+am Main\b", "", RegexOptions.IgnoreCase);
        s = Regex.Replace(s, @"\s+an der Oder\b", "", RegexOptions.IgnoreCase);
        s = Regex.Replace(s, @"\s+an der Donau\b", "", RegexOptions.IgnoreCase);
        s = Regex.Replace(s, @"\bSaint Petersburg\b", "St. Petersburg", RegexOptions.IgnoreCase);

        // 2. Clean long official country names to clean short standards
        s = Regex.Replace(s, @"\bUnited States of America\b", "USA", RegexOptions.IgnoreCase);
        s = Regex.Replace(s, @"\bUnited States\b", "USA", RegexOptions.IgnoreCase);
        s = Regex.Replace(s, @"\bUnited Kingdom of Great Britain and Northern Ireland\b", "UK", RegexOptions.IgnoreCase);
        s = Regex.Replace(s, @"\bUnited Kingdom\b", "UK", RegexOptions.IgnoreCase);
        s = Regex.Replace(s, @"\bRussian Federation\b", "Russia", RegexOptions.IgnoreCase);
        s = Regex.Replace(s, @"\bThe Netherlands\b", "Netherlands", RegexOptions.IgnoreCase);
        s = Regex.Replace(s, @"\bUnited Arab Emirates\b", "UAE", RegexOptions.IgnoreCase);

        return s.Trim();
    }
}

