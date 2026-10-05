using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Zion.Models;

public class ProxyItem : INotifyPropertyChanged
{
    private Guid _id = Guid.NewGuid();
    private string _name = "Прокси";
    private string _host = "";
    private int _port = 8080;
    private ProxyProtocol _protocol = ProxyProtocol.Vless;
    private string _username = "";
    private string _password = "";
    private ProxyStatus _status = ProxyStatus.Unknown;
    private int _pingMs = -1;
    private string _country = "";
    private DateTime? _lastChecked;
    private bool _isSelected;
    private bool _isFromSubscription;
    private string _subscriptionUrl = "";

    public Guid Id
    {
        get => _id;
        set => SetField(ref _id, value);
    }

    public string Name
    {
        get => _name;
        set => SetField(ref _name, value);
    }

    public string Host
    {
        get => _host;
        set
        {
            if (SetField(ref _host, value))
            {
                OnPropertyChanged(nameof(CleanHost));
                OnPropertyChanged(nameof(DisplayAddress));
            }
        }
    }

    public int Port
    {
        get => _port;
        set
        {
            if (SetField(ref _port, value))
            {
                OnPropertyChanged(nameof(DisplayAddress));
            }
        }
    }

    public ProxyProtocol Protocol
    {
        get => _protocol;
        set
        {
            if (SetField(ref _protocol, value))
            {
                OnPropertyChanged(nameof(ProtocolBadge));
            }
        }
    }

    public string Username
    {
        get => _username;
        set
        {
            if (SetField(ref _username, value))
            {
                OnPropertyChanged(nameof(HasAuth));
            }
        }
    }

    public string Password
    {
        get => _password;
        set => SetField(ref _password, value);
    }

    public ProxyStatus Status
    {
        get => _status;
        set
        {
            if (SetField(ref _status, value))
            {
                OnPropertyChanged(nameof(StatusText));
            }
        }
    }

    public int PingMs
    {
        get => _pingMs;
        set
        {
            if (SetField(ref _pingMs, value))
            {
                OnPropertyChanged(nameof(PingDisplay));
            }
        }
    }

    public string Country
    {
        get => _country;
        set
        {
            if (SetField(ref _country, value))
            {
                OnPropertyChanged(nameof(CleanCountryName));
                OnPropertyChanged(nameof(CountryCode));
                OnPropertyChanged(nameof(LocationShort));
            }
        }
    }

    public DateTime? LastChecked
    {
        get => _lastChecked;
        set => SetField(ref _lastChecked, value);
    }

    public bool IsFromSubscription
    {
        get => _isFromSubscription;
        set => SetField(ref _isFromSubscription, value);
    }

    public string SubscriptionUrl
    {
        get => _subscriptionUrl;
        set => SetField(ref _subscriptionUrl, value);
    }


    // Extended Proxy & Protocol properties
    private string _uuid = "";
    private string _flow = "";
    private string _security = "reality";
    private string _sni = "";
    private string _fingerprint = "chrome";
    private string _publicKey = "";
    private string _shortId = "";
    private string _spiderX = "";
    private string _transportType = "tcp";
    private string _wsPath = "";
    private string _wsHost = "";
    private string _grpcServiceName = "";
    private string _alpn = "";
    private string _rawLink = "";
    private int _alterId = 0;

    public string Uuid { get => _uuid; set => SetField(ref _uuid, value); }
    public string Flow { get => _flow; set => SetField(ref _flow, value); }
    public string Security
    {
        get => _security;
        set
        {
            if (SetField(ref _security, value))
            {
                OnPropertyChanged(nameof(ProtocolBadge));
            }
        }
    }
    public string Sni { get => _sni; set => SetField(ref _sni, value); }
    public string Fingerprint { get => _fingerprint; set => SetField(ref _fingerprint, value); }
    public string PublicKey { get => _publicKey; set => SetField(ref _publicKey, value); }
    public string ShortId { get => _shortId; set => SetField(ref _shortId, value); }
    public string SpiderX { get => _spiderX; set => SetField(ref _spiderX, value); }
    public string TransportType
    {
        get => _transportType;
        set
        {
            if (SetField(ref _transportType, value))
            {
                OnPropertyChanged(nameof(ProtocolBadge));
            }
        }
    }
    public string WsPath { get => _wsPath; set => SetField(ref _wsPath, value); }
    public string WsHost { get => _wsHost; set => SetField(ref _wsHost, value); }
    public string GrpcServiceName { get => _grpcServiceName; set => SetField(ref _grpcServiceName, value); }
    public string Alpn { get => _alpn; set => SetField(ref _alpn, value); }
    public string RawLink { get => _rawLink; set => SetField(ref _rawLink, value); }
    public int AlterId { get => _alterId; set => SetField(ref _alterId, value); }

    [JsonIgnore]
    public bool IsSelected
    {
        get => _isSelected;
        set => SetField(ref _isSelected, value);
    }

    private bool _isFavorite;
    /// <summary>Marked with a star by the user: shown first in the list and tried first on failover.</summary>
    public bool IsFavorite
    {
        get => _isFavorite;
        set => SetField(ref _isFavorite, value);
    }

    [JsonIgnore]
    public string DisplayName => !string.IsNullOrWhiteSpace(Name) ? Name : CleanCountryName;

    [JsonIgnore]
    public string CleanHost
    {
        get
        {
            string h = Host?.Trim() ?? "";
            if (h.Contains(':'))
            {
                return h.Split(':')[0];
            }
            return h;
        }
    }

    [JsonIgnore]
    public bool HasAuth => !string.IsNullOrEmpty(Username) || !string.IsNullOrEmpty(Password);

    [JsonIgnore]
    public string DisplayAddress => $"{CleanHost}:{Port}";

    [JsonIgnore]
    public string ProtocolBadge
    {
        get
        {
            string transport = !string.IsNullOrEmpty(TransportType) ? TransportType.Trim().ToLowerInvariant() : "tcp";
            return Protocol switch
            {
                ProxyProtocol.Vless => transport switch
                {
                    "grpc" => "VLESS / gRPC",
                    "ws" => "VLESS / WS",
                    "http" or "h2" => "VLESS / H2",
                    "httpupgrade" => "VLESS / HTTPUpgrade",
                    _ => "VLESS / TCP"
                },
                ProxyProtocol.Trojan => transport switch
                {
                    "grpc" => "Trojan / gRPC",
                    "ws" => "Trojan / WS",
                    _ => "Trojan"
                },
                ProxyProtocol.Shadowsocks => !string.IsNullOrEmpty(Security) && Security != "none" ? $"SS / {Security}" : "Shadowsocks",
                ProxyProtocol.Vmess => transport switch
                {
                    "ws" => "VMess / WS",
                    "grpc" => "VMess / gRPC",
                    _ => "VMess"
                },
                ProxyProtocol.Socks5 => "SOCKS5",
                _ => "HTTP"
            };
        }
    }

    [JsonIgnore]
    public string PingDisplay => PingMs >= 0 ? $"{PingMs} ms" : "—";

    [JsonIgnore]
    public string StatusText => Status switch
    {
        ProxyStatus.Online => "Онлайн",
        ProxyStatus.Offline => "Недоступен",
        ProxyStatus.AuthError => "Ошибка входа",
        ProxyStatus.Testing => "Проверка...",
        _ => "Не проверен"
    };

    [JsonIgnore]
    public string CleanCountryName
    {
        get
        {
            if (IsAutoRoutingNode)
                return "Автоматический выбор";

            if (!string.IsNullOrWhiteSpace(Country) && Country.Contains(','))
                return Country;

            string iso = ResolveIsoCode(Name, Country, CleanHost);
            if (!string.IsNullOrEmpty(iso) && iso != "un" && iso != "auto")
            {
                return GetCountryNameRu(iso);
            }

            if (!string.IsNullOrWhiteSpace(Country))
            {
                string c = Country.Trim();
                while (c.Length > 0 && (char.IsSurrogatePair(c, 0) || c.StartsWith("🌐")))
                {
                    if (char.IsSurrogatePair(c, 0)) c = c.Length >= 2 ? c.Substring(2).Trim() : "";
                    else c = c.Substring(1).Trim();
                }
                return string.IsNullOrWhiteSpace(c) ? Country : c;
            }

            return "Локация не определена";
        }
    }

    [JsonIgnore]
    public bool IsAutoRoutingNode =>
        (!string.IsNullOrEmpty(Name) && (Name.Contains("Авто выбор", StringComparison.OrdinalIgnoreCase) ||
                                         Name.Contains("Автовыбор", StringComparison.OrdinalIgnoreCase) ||
                                         Name.Contains("Auto", StringComparison.OrdinalIgnoreCase))) ||
        (!string.IsNullOrEmpty(CleanHost) && CleanHost.StartsWith("auto.", StringComparison.OrdinalIgnoreCase));

    [JsonIgnore]
    public string CountryCode => ResolveIsoCode(Name, Country, CleanHost);

    [JsonIgnore]
    public string LocationShort => CleanCountryName;

    public static string? ExtractEmojiFlag(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;

        for (int i = 0; i < text.Length - 1; i++)
        {
            int cp1 = char.ConvertToUtf32(text, i);
            if (cp1 >= 0x1F1E6 && cp1 <= 0x1F1FF)
            {
                int charCount = char.IsSurrogatePair(text, i) ? 2 : 1;
                int nextIndex = i + charCount;
                if (nextIndex < text.Length)
                {
                    int cp2 = char.ConvertToUtf32(text, nextIndex);
                    if (cp2 >= 0x1F1E6 && cp2 <= 0x1F1FF)
                    {
                        char c1 = (char)(cp1 - 0x1F1E6 + 'a');
                        char c2 = (char)(cp2 - 0x1F1E6 + 'a');
                        return $"{c1}{c2}";
                    }
                }
            }
            if (char.IsSurrogatePair(text, i)) i++;
        }
        return null;
    }

    public static string MatchHostPattern(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return "un";
        string clean = host.Trim().ToLowerInvariant();
        if (clean.Contains(':')) clean = clean.Split(':')[0];

        // 1. Prefix checks (e.g. pt-nl.example.net, al-n1, de-n3, en-n1)
        if (clean.StartsWith("pt-") || clean.StartsWith("pt.") || clean.StartsWith("pt_")) return "pt";
        if (clean.StartsWith("al-") || clean.StartsWith("al.") || clean.StartsWith("al_")) return "al";
        if (clean.StartsWith("rm-") || clean.StartsWith("ro-") || clean.StartsWith("ro.") || clean.StartsWith("ro_")) return "ro";
        if (clean.StartsWith("de-") || clean.StartsWith("de.") || clean.StartsWith("de_")) return "de";
        if (clean.StartsWith("nl-") || clean.StartsWith("nl.") || clean.StartsWith("nl_")) return "nl";
        if (clean.StartsWith("en-") || clean.StartsWith("uk-") || clean.StartsWith("gb-") || clean.StartsWith("gb.") || clean.StartsWith("gb_")) return "gb";
        if (clean.StartsWith("cz-") || clean.StartsWith("cz.") || clean.StartsWith("cz_")) return "cz";
        if (clean.StartsWith("au-") || clean.StartsWith("at-") || clean.StartsWith("at.") || clean.StartsWith("at_")) return "at";
        if (clean.StartsWith("si-") || clean.StartsWith("ch-") || clean.StartsWith("ch.") || clean.StartsWith("ch_")) return "ch";
        if (clean.StartsWith("sw-") || clean.StartsWith("se-") || clean.StartsWith("se.") || clean.StartsWith("se_")) return "se";
        if (clean.StartsWith("li-") || clean.StartsWith("lt-") || clean.StartsWith("lt.") || clean.StartsWith("lt_")) return "lt";
        if (clean.StartsWith("fr-") || clean.StartsWith("fr.") || clean.StartsWith("fr_")) return "fr";
        if (clean.StartsWith("pl-") || clean.StartsWith("pl.") || clean.StartsWith("pl_")) return "pl";
        if (clean.StartsWith("kz-") || clean.StartsWith("kz.") || clean.StartsWith("kz_")) return "kz";
        if (clean.StartsWith("sp-") || clean.StartsWith("es-") || clean.StartsWith("es.") || clean.StartsWith("es_")) return "es";
        if (clean.StartsWith("us-") || clean.StartsWith("us.") || clean.StartsWith("us_")) return "us";
        if (clean.StartsWith("tr-") || clean.StartsWith("tr.") || clean.StartsWith("tr_")) return "tr";
        if (clean.StartsWith("id-") || clean.StartsWith("id.") || clean.StartsWith("in-") || clean.StartsWith("in.") || clean.StartsWith("in_")) return "in";
        if (clean.StartsWith("jp-") || clean.StartsWith("jp.")) return "jp";
        if (clean.StartsWith("sg-") || clean.StartsWith("sg.")) return "sg";
        if (clean.StartsWith("ru-") || clean.StartsWith("ru.")) return "ru";

        // Universal prefix token check (e.g. fi-hel1.example.com -> fi)
        var tokens = clean.Split(new[] { '-', '.', '_' }, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length > 0 && tokens[0].Length == 2 && char.IsLetter(tokens[0][0]) && char.IsLetter(tokens[0][1]))
        {
            string t0 = tokens[0];
            string ru = GetCountryNameRu(t0);
            if (!string.Equals(ru, t0, StringComparison.OrdinalIgnoreCase))
            {
                return t0 == "uk" ? "gb" : t0;
            }
        }

        // 2. Domain extension / TLD checks
        if (clean.EndsWith(".nl")) return "nl";
        if (clean.EndsWith(".de")) return "de";
        if (clean.EndsWith(".fi")) return "fi";
        if (clean.EndsWith(".se")) return "se";
        if (clean.EndsWith(".pl")) return "pl";
        if (clean.EndsWith(".ru") || clean.EndsWith(".su")) return "ru";
        if (clean.EndsWith(".fr")) return "fr";
        if (clean.EndsWith(".uk") || clean.EndsWith(".co.uk")) return "gb";
        if (clean.EndsWith(".ch")) return "ch";
        if (clean.EndsWith(".at")) return "at";
        if (clean.EndsWith(".cz")) return "cz";
        if (clean.EndsWith(".es")) return "es";
        if (clean.EndsWith(".it")) return "it";
        if (clean.EndsWith(".jp")) return "jp";
        if (clean.EndsWith(".sg")) return "sg";
        if (clean.EndsWith(".hk")) return "hk";
        if (clean.EndsWith(".ca")) return "ca";
        if (clean.EndsWith(".ae")) return "ae";
        if (clean.EndsWith(".kz")) return "kz";
        if (clean.EndsWith(".ua")) return "ua";
        if (clean.EndsWith(".tr")) return "tr";
        if (clean.EndsWith(".no")) return "no";
        if (clean.EndsWith(".dk")) return "dk";
        if (clean.EndsWith(".be")) return "be";
        if (clean.EndsWith(".ee")) return "ee";
        if (clean.EndsWith(".lv")) return "lv";
        if (clean.EndsWith(".lt")) return "lt";
        if (clean.EndsWith(".pt")) return "pt";
        if (clean.EndsWith(".al")) return "al";
        if (clean.EndsWith(".ro")) return "ro";
        if (clean.EndsWith(".in")) return "in";
        if (clean.EndsWith(".us")) return "us";

        return "un";
    }

    public static string MatchSemanticKeyword(string text)
    {
        string lower = text.ToLowerInvariant();
        if (lower.Contains("netherlands") || lower.Contains("нидерланд") || lower.Contains("голланди") || lower.Contains("amsterdam") || lower.Contains("амстердам") || lower.Contains("rotterdam")) return "nl";
        if (lower.Contains("germany") || lower.Contains("германи") || lower.Contains("deutschland") || lower.Contains("frankfurt") || lower.Contains("франкфурт") || lower.Contains("berlin") || lower.Contains("берлин") || lower.Contains("munich") || lower.Contains("мюнхен")) return "de";
        if (lower.Contains("united states") || lower.Contains("usa") || lower.Contains("сша") || lower.Contains("america") || lower.Contains("америк") || lower.Contains("new york") || lower.Contains("нью-йорк") || lower.Contains("los angeles") || lower.Contains("miami") || lower.Contains("dallas") || lower.Contains("даллас")) return "us";
        if (lower.Contains("finland") || lower.Contains("финлянд") || lower.Contains("helsinki") || lower.Contains("хельсинки")) return "fi";
        if (lower.Contains("sweden") || lower.Contains("швеци") || lower.Contains("stockholm") || lower.Contains("стокгольм")) return "se";
        if (lower.Contains("poland") || lower.Contains("польш") || lower.Contains("warsaw") || lower.Contains("варшава") || lower.Contains("krakow")) return "pl";
        if (lower.Contains("russia") || lower.Contains("росси") || lower.Contains("moscow") || lower.Contains("москва") || lower.Contains("petersburg") || lower.Contains("петербург") || lower.Contains("спб")) return "ru";
        if (lower.Contains("united kingdom") || lower.Contains("великобритан") || lower.Contains("england") || lower.Contains("англи") || lower.Contains("london") || lower.Contains("лондон") || lower.Contains("uk")) return "gb";
        if (lower.Contains("france") || lower.Contains("франци") || lower.Contains("paris") || lower.Contains("париж")) return "fr";
        if (lower.Contains("turkey") || lower.Contains("турци") || lower.Contains("istanbul") || lower.Contains("стамбул") || lower.Contains("ankara")) return "tr";
        if (lower.Contains("kazakhstan") || lower.Contains("казахстан") || lower.Contains("almaty") || lower.Contains("astana") || lower.Contains("алматы") || lower.Contains("астана")) return "kz";
        if (lower.Contains("switzerland") || lower.Contains("швейцари") || lower.Contains("zurich") || lower.Contains("цюрих") || lower.Contains("geneva")) return "ch";
        if (lower.Contains("austria") || lower.Contains("австри") || lower.Contains("vienna") || lower.Contains("вена")) return "at";
        if (lower.Contains("czech") || lower.Contains("чехи") || lower.Contains("prague") || lower.Contains("прага")) return "cz";
        if (lower.Contains("spain") || lower.Contains("испани") || lower.Contains("madrid") || lower.Contains("мадрид") || lower.Contains("barcelona")) return "es";
        if (lower.Contains("italy") || lower.Contains("итали") || lower.Contains("rome") || lower.Contains("рим") || lower.Contains("milan") || lower.Contains("милан")) return "it";
        if (lower.Contains("japan") || lower.Contains("япони") || lower.Contains("tokyo") || lower.Contains("токио") || lower.Contains("osaka")) return "jp";
        if (lower.Contains("singapore") || lower.Contains("сингапур")) return "sg";
        if (lower.Contains("hong kong") || lower.Contains("гонконг") || lower.Contains("hkg")) return "hk";
        if (lower.Contains("canada") || lower.Contains("канада") || lower.Contains("toronto") || lower.Contains("торонто") || lower.Contains("montreal")) return "ca";
        if (lower.Contains("united arab") || lower.Contains("emirates") || lower.Contains("оаэ") || lower.Contains("dubai") || lower.Contains("дубай") || lower.Contains("abu dhabi")) return "ae";
        if (lower.Contains("portugal") || lower.Contains("португали") || lower.Contains("lisbon") || lower.Contains("лиссабон")) return "pt";
        if (lower.Contains("albania") || lower.Contains("албани") || lower.Contains("tirana") || lower.Contains("тирана")) return "al";
        if (lower.Contains("romania") || lower.Contains("румыни") || lower.Contains("bucharest") || lower.Contains("бухарест")) return "ro";
        if (lower.Contains("india") || lower.Contains("инди") || lower.Contains("mumbai") || lower.Contains("мумбаи") || lower.Contains("delhi") || lower.Contains("дели")) return "in";
        if (lower.Contains("moldova") || lower.Contains("молдов") || lower.Contains("chisinau") || lower.Contains("кишинев") || lower.Contains("кишинёв")) return "md";
        if (lower.Contains("bulgaria") || lower.Contains("болгари") || lower.Contains("sofia") || lower.Contains("софия")) return "bg";
        if (lower.Contains("cyprus") || lower.Contains("кипр") || lower.Contains("nicosia")) return "cy";
        if (lower.Contains("serbia") || lower.Contains("серби") || lower.Contains("belgrade") || lower.Contains("белград")) return "rs";
        if (lower.Contains("hungary") || lower.Contains("венгри") || lower.Contains("budapest") || lower.Contains("будапешт")) return "hu";
        if (lower.Contains("greece") || lower.Contains("греци") || lower.Contains("athens") || lower.Contains("афины")) return "gr";
        if (lower.Contains("ireland") || lower.Contains("ирланди") || lower.Contains("dublin") || lower.Contains("дублин")) return "ie";
        if (lower.Contains("south korea") || lower.Contains("корея") || lower.Contains("korea") || lower.Contains("seoul") || lower.Contains("сеул")) return "kr";
        if (lower.Contains("brazil") || lower.Contains("бразили") || lower.Contains("sao paulo")) return "br";
        if (lower.Contains("slovakia") || lower.Contains("словаки") || lower.Contains("bratislava")) return "sk";
        if (lower.Contains("slovenia") || lower.Contains("словени") || lower.Contains("ljubljana")) return "si";
        if (lower.Contains("croatia") || lower.Contains("хорвати") || lower.Contains("zagreb")) return "hr";
        if (lower.Contains("iceland") || lower.Contains("исланди") || lower.Contains("reykjavik")) return "is";
        if (lower.Contains("luxembourg") || lower.Contains("люксембург")) return "lu";
        if (lower.Contains("taiwan") || lower.Contains("тайван") || lower.Contains("taipei")) return "tw";
        if (lower.Contains("latvia") || lower.Contains("латви") || lower.Contains("riga") || lower.Contains("рига")) return "lv";
        if (lower.Contains("lithuania") || lower.Contains("литва") || lower.Contains("vilnius") || lower.Contains("вильнюс")) return "lt";
        if (lower.Contains("estonia") || lower.Contains("эстони") || lower.Contains("tallinn") || lower.Contains("таллин")) return "ee";
        if (lower.Contains("norway") || lower.Contains("норвеги") || lower.Contains("oslo") || lower.Contains("осло")) return "no";
        if (lower.Contains("denmark") || lower.Contains("дани") || lower.Contains("copenhagen")) return "dk";
        if (lower.Contains("belgium") || lower.Contains("бельги") || lower.Contains("brussels")) return "be";
        if (lower.Contains("ukraine") || lower.Contains("украин") || lower.Contains("kyiv") || lower.Contains("киев")) return "ua";
        if (lower.Contains("georgia") || lower.Contains("грузи") || lower.Contains("tbilisi")) return "ge";
        if (lower.Contains("armenia") || lower.Contains("армени") || lower.Contains("yerevan")) return "am";
        if (lower.Contains("israel") || lower.Contains("израиль") || lower.Contains("tel aviv")) return "il";
        if (lower.Contains("australia") || lower.Contains("австрали") || lower.Contains("sydney")) return "au";
        if (lower.Contains("azerbaijan") || lower.Contains("азербайджан") || lower.Contains("baku")) return "az";
        if (lower.Contains("uzbekistan") || lower.Contains("узбекистан") || lower.Contains("tashkent")) return "uz";
        if (lower.Contains("kyrgyzstan") || lower.Contains("киргизи") || lower.Contains("кыргызстан")) return "kg";
        if (lower.Contains("tajikistan") || lower.Contains("таджикистан")) return "tj";
        if (lower.Contains("belarus") || lower.Contains("беларус") || lower.Contains("белорусси") || lower.Contains("minsk")) return "by";
        if (lower.Contains("argentina") || lower.Contains("аргентин")) return "ar";
        if (lower.Contains("chile") || lower.Contains("чили")) return "cl";
        if (lower.Contains("south africa") || lower.Contains("юар")) return "za";
        if (lower.Contains("thailand") || lower.Contains("таиланд") || lower.Contains("тайланд") || lower.Contains("bangkok")) return "th";
        if (lower.Contains("vietnam") || lower.Contains("вьетнам")) return "vn";
        if (lower.Contains("indonesia") || lower.Contains("индонези") || lower.Contains("jakarta")) return "id";
        if (lower.Contains("malaysia") || lower.Contains("малайзи")) return "my";
        if (lower.Contains("philippines") || lower.Contains("филиппин")) return "ph";
        if (lower.Contains("new zealand") || lower.Contains("новая зеланди")) return "nz";
        if (lower.Contains("mexico") || lower.Contains("мексик")) return "mx";
        if (lower.Contains("egypt") || lower.Contains("египет")) return "eg";
        if (lower.Contains("saudi") || lower.Contains("саудовск")) return "sa";

        return "un";
    }

    public static string ResolveIsoCode(string? text)
    {
        return ResolveIsoCode(text, null, null);
    }

    public static string ResolveIsoCode(string? name, string? country, string? host)
    {
        // 0. Auto-Routing Check
        if ((!string.IsNullOrWhiteSpace(name) && (name.Contains("Авто выбор", StringComparison.OrdinalIgnoreCase) ||
                                                  name.Contains("Автовыбор", StringComparison.OrdinalIgnoreCase) ||
                                                  name.Contains("Auto", StringComparison.OrdinalIgnoreCase))) ||
            (!string.IsNullOrWhiteSpace(host) && host.Trim().StartsWith("auto.", StringComparison.OrdinalIgnoreCase)))
        {
            return "auto";
        }

        // Tier 1: Check name for native Emoji Flag
        if (!string.IsNullOrWhiteSpace(name))
        {
            var emojiIso = ExtractEmojiFlag(name);
            if (!string.IsNullOrEmpty(emojiIso)) return emojiIso;

            var semIso = MatchSemanticKeyword(name);
            if (semIso != "un") return semIso;
        }

        // Tier 2: Check country for native Emoji Flag or semantic keyword
        if (!string.IsNullOrWhiteSpace(country))
        {
            var emojiIso = ExtractEmojiFlag(country);
            if (!string.IsNullOrEmpty(emojiIso)) return emojiIso;

            var semIso = MatchSemanticKeyword(country);
            if (semIso != "un") return semIso;

            string trimmedC = country.Trim().ToLowerInvariant();
            if (trimmedC.Length == 2 && char.IsLetter(trimmedC[0]) && char.IsLetter(trimmedC[1]))
                return trimmedC == "uk" ? "gb" : trimmedC;
        }

        // Tier 3: Check host pattern
        if (!string.IsNullOrWhiteSpace(host))
        {
            var hostIso = MatchHostPattern(host);
            if (hostIso != "un") return hostIso;
        }

        // Tier 4: Check if name was a raw 2-letter ISO code
        if (!string.IsNullOrWhiteSpace(name))
        {
            string trimmedN = name.Trim().ToLowerInvariant();
            if (trimmedN.Length == 2 && char.IsLetter(trimmedN[0]) && char.IsLetter(trimmedN[1]))
                return trimmedN == "uk" ? "gb" : trimmedN;
        }

        return "";
    }

    public static string GetCountryNameRu(string iso)
    {
        return iso.ToLowerInvariant() switch
        {
            "nl" => "Нидерланды",
            "de" => "Германия",
            "us" => "США",
            "fi" => "Финляндия",
            "se" => "Швеция",
            "pl" => "Польша",
            "ru" => "Россия",
            "gb" or "uk" => "Великобритания",
            "fr" => "Франция",
            "tr" => "Турция",
            "kz" => "Казахстан",
            "ch" => "Швейцария",
            "at" => "Австрия",
            "cz" => "Чехия",
            "es" => "Испания",
            "it" => "Италия",
            "jp" => "Япония",
            "sg" => "Сингапур",
            "hk" => "Гонконг",
            "ca" => "Канада",
            "ae" => "ОАЭ",
            "md" => "Молдова",
            "ro" => "Румыния",
            "bg" => "Болгария",
            "cy" => "Кипр",
            "rs" => "Сербия",
            "hu" => "Венгрия",
            "gr" => "Греция",
            "ie" => "Ирландия",
            "pt" => "Португалия",
            "al" => "Албания",
            "kr" => "Южная Корея",
            "in" => "Индия",
            "br" => "Бразилия",
            "sk" => "Словакия",
            "si" => "Словения",
            "hr" => "Хорватия",
            "is" => "Исландия",
            "lu" => "Люксембург",
            "tw" => "Тайвань",
            "lv" => "Латвия",
            "lt" => "Литва",
            "ee" => "Эстония",
            "no" => "Норвегия",
            "dk" => "Дания",
            "be" => "Бельгия",
            "ua" => "Украина",
            "ge" => "Грузия",
            "am" => "Армения",
            "il" => "Израиль",
            "au" => "Австралия",
            "az" => "Азербайджан",
            "uz" => "Узбекистан",
            "kg" => "Кыргызстан",
            "tj" => "Таджикистан",
            "by" => "Беларусь",
            "ar" => "Аргентина",
            "cl" => "Чили",
            "za" => "ЮАР",
            "th" => "Таиланд",
            "vn" => "Вьетнам",
            "id" => "Индонезия",
            "my" => "Малайзия",
            "ph" => "Филиппины",
            "nz" => "Новая Зеландия",
            "mx" => "Мексика",
            "eg" => "Египет",
            "sa" => "Саудовская Аравия",
            "cn" => "Китай",
            "auto" => "Авто выбор",
            _ => iso.ToUpperInvariant()
        };
    }

    public void AutoEnrichCountryIfMissing()
    {
        if (IsAutoRoutingNode)
        {
            if (string.IsNullOrWhiteSpace(Country) || Country == "Локация не определена")
                Country = "Автоматический выбор";
            return;
        }

        if (string.IsNullOrWhiteSpace(Country) || Country == "Локация не определена" || Country.Length == 2)
        {
            string iso = ResolveIsoCode(Name, Country, CleanHost);
            if (!string.IsNullOrEmpty(iso) && iso != "un")
            {
                Country = GetCountryNameRu(iso);
            }
        }
    }

    public string ToShareableUrl()
    {
        if (Protocol == ProxyProtocol.Vless)
        {
            var q = new List<string>();
            if (!string.IsNullOrEmpty(TransportType)) q.Add($"type={Uri.EscapeDataString(TransportType.ToLowerInvariant())}");
            if (!string.IsNullOrEmpty(Security)) q.Add($"security={Uri.EscapeDataString(Security.ToLowerInvariant())}");
            if (!string.IsNullOrEmpty(PublicKey)) q.Add($"pbk={Uri.EscapeDataString(PublicKey)}");
            if (!string.IsNullOrEmpty(Fingerprint)) q.Add($"fp={Uri.EscapeDataString(Fingerprint.ToLowerInvariant())}");
            if (!string.IsNullOrEmpty(Sni)) q.Add($"sni={Uri.EscapeDataString(Sni)}");
            if (!string.IsNullOrEmpty(GrpcServiceName))
            {
                q.Add($"serviceName={Uri.EscapeDataString(GrpcServiceName)}");
            }
            else if (!string.IsNullOrEmpty(WsPath))
            {
                q.Add($"path={Uri.EscapeDataString(WsPath)}");
            }
            string query = q.Count > 0 ? "?" + string.Join("&", q) : "";
            string tag = !string.IsNullOrEmpty(Name) ? "#" + Uri.EscapeDataString(Name) : "";
            return $"vless://{Uuid}@{CleanHost}:{Port}{query}{tag}";
        }
        else if (Protocol == ProxyProtocol.Trojan)
        {
            var q = new List<string>();
            if (!string.IsNullOrEmpty(TransportType)) q.Add($"type={Uri.EscapeDataString(TransportType.ToLowerInvariant())}");
            if (!string.IsNullOrEmpty(Sni)) q.Add($"sni={Uri.EscapeDataString(Sni)}");
            if (!string.IsNullOrEmpty(GrpcServiceName)) q.Add($"serviceName={Uri.EscapeDataString(GrpcServiceName)}");
            else if (!string.IsNullOrEmpty(WsPath)) q.Add($"path={Uri.EscapeDataString(WsPath)}");
            string query = q.Count > 0 ? "?" + string.Join("&", q) : "";
            string tag = !string.IsNullOrEmpty(Name) ? "#" + Uri.EscapeDataString(Name) : "";
            string pass = !string.IsNullOrEmpty(Password) ? Password : Uuid;
            return $"trojan://{Uri.EscapeDataString(pass)}@{CleanHost}:{Port}{query}{tag}";
        }
        else if (Protocol == ProxyProtocol.Shadowsocks)
        {
            string method = !string.IsNullOrEmpty(Security) && Security != "none" ? Security : "aes-256-gcm";
            string pass = !string.IsNullOrEmpty(Password) ? Password : Uuid;
            string userInfo = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{method}:{pass}"));
            string tag = !string.IsNullOrEmpty(Name) ? "#" + Uri.EscapeDataString(Name) : "";
            return $"ss://{userInfo}@{CleanHost}:{Port}{tag}";
        }
        else if (Protocol == ProxyProtocol.Vmess)
        {
            var vmessObj = new JsonObject
            {
                ["v"] = "2",
                ["ps"] = Name,
                ["add"] = CleanHost,
                ["port"] = Port,
                ["id"] = Uuid,
                ["aid"] = AlterId,
                ["scy"] = !string.IsNullOrEmpty(Security) && Security != "tls" ? Security : "auto",
                ["net"] = !string.IsNullOrEmpty(TransportType) ? TransportType : "tcp",
                ["type"] = "none",
                ["host"] = WsHost,
                ["path"] = !string.IsNullOrEmpty(GrpcServiceName) ? GrpcServiceName : WsPath,
                ["tls"] = Security == "tls" || !string.IsNullOrEmpty(Sni) ? "tls" : "none",
                ["sni"] = Sni
            };
            string jsonStr = vmessObj.ToJsonString();
            string base64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(jsonStr));
            return $"vmess://{base64}";
        }
        else if (Protocol == ProxyProtocol.Socks5)
        {
            string auth = !string.IsNullOrEmpty(Username) ? $"{Uri.EscapeDataString(Username)}:{Uri.EscapeDataString(Password)}@" : "";
            string tag = !string.IsNullOrEmpty(Name) ? "#" + Uri.EscapeDataString(Name) : "";
            return $"socks5://{auth}{CleanHost}:{Port}{tag}";
        }
        else
        {
            string auth = !string.IsNullOrEmpty(Username) ? $"{Uri.EscapeDataString(Username)}:{Uri.EscapeDataString(Password)}@" : "";
            string tag = !string.IsNullOrEmpty(Name) ? "#" + Uri.EscapeDataString(Name) : "";
            return $"http://{auth}{CleanHost}:{Port}{tag}";
        }
    }

    public string GetFingerprint()
    {
        return Protocol switch
        {
            ProxyProtocol.Vless => $"vless://{Uuid.Trim().ToLowerInvariant()}@{CleanHost.Trim().ToLowerInvariant()}:{Port}?type={TransportType.Trim().ToLowerInvariant()}&security={Security.Trim().ToLowerInvariant()}&sni={Sni.Trim().ToLowerInvariant()}&pbk={PublicKey.Trim()}&sid={ShortId.Trim()}&fp={Fingerprint.Trim().ToLowerInvariant()}&path={WsPath.Trim()}&serviceName={GrpcServiceName.Trim()}",
            ProxyProtocol.Trojan => $"trojan://{Password.Trim()}@{CleanHost.Trim().ToLowerInvariant()}:{Port}?type={TransportType.Trim().ToLowerInvariant()}&sni={Sni.Trim().ToLowerInvariant()}&path={WsPath.Trim()}&serviceName={GrpcServiceName.Trim()}",
            ProxyProtocol.Shadowsocks => $"ss://{Security.Trim().ToLowerInvariant()}:{Password.Trim()}@{CleanHost.Trim().ToLowerInvariant()}:{Port}",
            ProxyProtocol.Vmess => $"vmess://{Uuid.Trim().ToLowerInvariant()}@{CleanHost.Trim().ToLowerInvariant()}:{Port}?net={TransportType.Trim().ToLowerInvariant()}&type={WsPath.Trim()}&tls={Security.Trim().ToLowerInvariant()}&sni={Sni.Trim().ToLowerInvariant()}",
            _ => $"{Protocol}://{Username.Trim().ToLowerInvariant()}@{CleanHost.Trim().ToLowerInvariant()}:{Port}"
        };
    }

    public static Guid ComputeDeterministicGuid(string input)
    {
        byte[] hash = System.Security.Cryptography.MD5.HashData(System.Text.Encoding.UTF8.GetBytes(input));
        return new Guid(hash);
    }

    public void EnsureDeterministicId()
    {
        if (IsFromSubscription)
        {
            Id = ComputeDeterministicGuid(GetFingerprint());
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    protected bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }
}
