namespace Zion.Models;

/// <summary>A program whose traffic always goes around the VPN (matched by its exe file name).</summary>
public class ExcludedApp
{
    /// <summary>Exe file name exactly as on disk, e.g. "steam.exe". This is what the routing rule matches.</summary>
    public string ProcessName { get; set; } = "";

    /// <summary>Where it was picked from; used for the icon and the readable name only.</summary>
    public string Path { get; set; } = "";

    /// <summary>Readable name from the file's description, e.g. "Steam".</summary>
    public string DisplayName { get; set; } = "";
}
