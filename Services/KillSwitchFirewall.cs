using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace Zion.Services;

/// <summary>
/// Kill Switch built on the Windows Filtering Platform (the same mechanism WireGuard and
/// other VPN clients use). While armed, only this is allowed to reach the network:
///   - Zion itself and sing-box.exe (they have to reach the VPN server),
///   - anything that leaves through the tunnel adapter,
///   - loopback and the local network (router, printers, DHCP).
/// Everything else is blocked, so when the tunnel is down nothing leaks past it.
///
/// The filters live in a DYNAMIC session: Windows removes them by itself the moment this
/// process ends, even if it crashes. The switch can therefore never leave the machine
/// permanently offline.
/// </summary>
public static class KillSwitchFirewall
{
    // The tunnel subnets configured in TunRoutingEngine (tun inbound "address").
    private const string TunnelV4 = "172.19.0.0/30";
    private const string TunnelV6 = "fdfe:dcba:9876::/126";

    private static readonly object _lock = new();
    private static IntPtr _engine = IntPtr.Zero;

    public static string LastError { get; private set; } = "";

    public static bool IsArmed
    {
        get { lock (_lock) { return _engine != IntPtr.Zero; } }
    }

    /// <summary>Apps that must stay online while the switch is armed.</summary>
    public static IReadOnlyList<string> DefaultPermittedApps()
    {
        var list = new List<string>();
        string? self = Environment.ProcessPath;
        if (!string.IsNullOrEmpty(self)) list.Add(self);
        list.Add(TunRoutingEngine.SingBoxExePath);
        return list;
    }

    public static bool Arm() => Arm(DefaultPermittedApps(), permitTunnel: true);

    public static bool Arm(IEnumerable<string> permittedApps, bool permitTunnel)
    {
        lock (_lock)
        {
            if (_engine != IntPtr.Zero) return true;
            LastError = "";

            var owned = new List<IntPtr>();   // HGlobal blocks we allocated
            var appIds = new List<IntPtr>();  // blobs allocated by WFP
            IntPtr engine = IntPtr.Zero;
            bool inTxn = false;

            try
            {
                var session = new Native.Session
                {
                    displayData = Display("Zion Kill Switch", owned),
                    flags = Native.FWPM_SESSION_FLAG_DYNAMIC,
                    txnWaitTimeoutInMSec = 5000
                };
                Check(Native.FwpmEngineOpen0(null, Native.RPC_C_AUTHN_WINNT, IntPtr.Zero, ref session, out engine), "открыть фильтр пакетов");
                Check(Native.FwpmTransactionBegin0(engine, 0), "начать транзакцию");
                inTxn = true;

                Guid subLayerKey = Guid.NewGuid();
                var subLayer = new Native.SubLayer
                {
                    subLayerKey = subLayerKey,
                    displayData = Display("Zion Kill Switch", owned),
                    weight = 0xFFFF
                };
                Check(Native.FwpmSubLayerAdd0(engine, ref subLayer, IntPtr.Zero), "добавить слой");

                foreach (string app in permittedApps.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    if (!File.Exists(app)) continue;
                    if (Native.FwpmGetAppIdFromFileName0(app, out IntPtr blob) == 0 && blob != IntPtr.Zero)
                        appIds.Add(blob);
                }

                foreach (bool v6 in new[] { false, true })
                {
                    Guid[] layers = v6
                        ? new[] { Native.LayerConnectV6, Native.LayerRecvAcceptV6 }
                        : new[] { Native.LayerConnectV4, Native.LayerRecvAcceptV4 };

                    foreach (Guid layer in layers)
                    {
                        // Highest priority: loopback and the permitted programs
                        AddFilter(engine, layer, subLayerKey, 15, Native.FWP_ACTION_PERMIT, owned,
                            Cond(Native.CondFlags, Native.FWP_MATCH_FLAGS_ALL_SET, Native.FWP_UINT32, Native.FWP_CONDITION_FLAG_IS_LOOPBACK));

                        foreach (IntPtr appId in appIds)
                        {
                            AddFilter(engine, layer, subLayerKey, 15, Native.FWP_ACTION_PERMIT, owned,
                                Cond(Native.CondAppId, Native.FWP_MATCH_EQUAL, Native.FWP_BYTE_BLOB_TYPE, (ulong)appId.ToInt64()));
                        }

                        // Traffic that leaves through the tunnel adapter
                        if (permitTunnel)
                        {
                            AddFilter(engine, layer, subLayerKey, 14, Native.FWP_ACTION_PERMIT, owned,
                                AddressCond(Native.CondLocalAddress, v6 ? TunnelV6 : TunnelV4, owned));
                        }

                        // DNS outside the tunnel is closed even towards the router, otherwise the
                        // Windows DNS service would keep telling the provider which sites are opened.
                        // (Outgoing layers only. Zion and sing-box do their own lookups and are permitted above.)
                        if (layer == Native.LayerConnectV4 || layer == Native.LayerConnectV6)
                        {
                            foreach (byte protocol in new byte[] { Native.IPPROTO_TCP, Native.IPPROTO_UDP })
                            {
                                AddFilter(engine, layer, subLayerKey, 13, Native.FWP_ACTION_BLOCK, owned,
                                    Cond(Native.CondProtocol, Native.FWP_MATCH_EQUAL, Native.FWP_UINT8, protocol),
                                    Cond(Native.CondRemotePort, Native.FWP_MATCH_EQUAL, Native.FWP_UINT16, 53));
                            }
                        }

                        // Local network stays reachable
                        string[] lan = v6
                            ? new[] { "fe80::/10", "ff00::/8", "fc00::/7" }
                            : new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32" };
                        foreach (string range in lan)
                        {
                            AddFilter(engine, layer, subLayerKey, 12, Native.FWP_ACTION_PERMIT, owned,
                                AddressCond(Native.CondRemoteAddress, range, owned));
                        }

                        // Everything else is blocked
                        AddFilter(engine, layer, subLayerKey, 0, Native.FWP_ACTION_BLOCK, owned);
                    }
                }

                Check(Native.FwpmTransactionCommit0(engine), "применить правила");
                inTxn = false;

                _engine = engine;
                engine = IntPtr.Zero;
                return true;
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                Debug.WriteLine($"[KillSwitch] Arm failed: {ex.Message}");
                return false;
            }
            finally
            {
                if (engine != IntPtr.Zero)
                {
                    if (inTxn) Native.FwpmTransactionAbort0(engine);
                    Native.FwpmEngineClose0(engine);
                }
                foreach (IntPtr blob in appIds) { IntPtr p = blob; Native.FwpmFreeMemory0(ref p); }
                foreach (IntPtr p in owned) Marshal.FreeHGlobal(p);
            }
        }
    }

    /// <summary>Removes every filter. Closing a dynamic session deletes all of its objects.</summary>
    public static void Disarm()
    {
        lock (_lock)
        {
            if (_engine == IntPtr.Zero) return;
            try { Native.FwpmEngineClose0(_engine); } catch { }
            _engine = IntPtr.Zero;
        }
    }

    // ------------------------------------------------------------------ helpers

    private static void Check(uint code, string what)
    {
        if (code == 0) return;
        string hint = code == 5 ? " (нужны права администратора)" : "";
        throw new InvalidOperationException($"Kill Switch: не удалось {what}, код 0x{code:X8}{hint}");
    }

    private static Native.DisplayData Display(string name, List<IntPtr> owned)
    {
        IntPtr p = Marshal.StringToHGlobalUni(name);
        owned.Add(p);
        return new Native.DisplayData { name = p, description = IntPtr.Zero };
    }

    private static Native.Condition Cond(Guid field, uint match, uint type, ulong value) => new()
    {
        fieldKey = field,
        matchType = match,
        conditionValue = new Native.Value { type = type, value = value }
    };

    /// <summary>Builds "address is inside this CIDR range" for either address family.</summary>
    private static Native.Condition AddressCond(Guid field, string cidr, List<IntPtr> owned)
    {
        var (address, prefix) = ParseCidr(cidr);
        byte[] bytes = address.GetAddressBytes();

        if (bytes.Length == 4)
        {
            // FWP_V4_ADDR_AND_MASK: both fields in host byte order
            uint addr = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
            uint mask = prefix == 0 ? 0 : 0xFFFFFFFF << (32 - prefix);
            IntPtr p = Marshal.AllocHGlobal(8);
            owned.Add(p);
            Marshal.WriteInt32(p, 0, unchecked((int)(addr & mask)));
            Marshal.WriteInt32(p, 4, unchecked((int)mask));
            return Cond(field, Native.FWP_MATCH_EQUAL, Native.FWP_V4_ADDR_MASK, (ulong)p.ToInt64());
        }
        else
        {
            // FWP_V6_ADDR_AND_MASK: 16 address bytes followed by the prefix length
            IntPtr p = Marshal.AllocHGlobal(17);
            owned.Add(p);
            Marshal.Copy(bytes, 0, p, 16);
            Marshal.WriteByte(p, 16, (byte)prefix);
            return Cond(field, Native.FWP_MATCH_EQUAL, Native.FWP_V6_ADDR_MASK, (ulong)p.ToInt64());
        }
    }

    internal static (IPAddress Address, int Prefix) ParseCidr(string cidr)
    {
        string[] parts = cidr.Split('/');
        return (IPAddress.Parse(parts[0]), int.Parse(parts[1]));
    }

    private static void AddFilter(IntPtr engine, Guid layer, Guid subLayer, byte weight, uint action, List<IntPtr> owned, params Native.Condition[] conditions)
    {
        IntPtr condPtr = IntPtr.Zero;
        if (conditions.Length > 0)
        {
            int size = Marshal.SizeOf<Native.Condition>();
            condPtr = Marshal.AllocHGlobal(size * conditions.Length);
            owned.Add(condPtr);
            for (int i = 0; i < conditions.Length; i++)
                Marshal.StructureToPtr(conditions[i], condPtr + i * size, false);
        }

        var filter = new Native.Filter
        {
            filterKey = Guid.NewGuid(),
            displayData = Display("Zion Kill Switch", owned),
            layerKey = layer,
            subLayerKey = subLayer,
            weight = new Native.Value { type = Native.FWP_UINT8, value = weight },
            numFilterConditions = (uint)conditions.Length,
            filterCondition = condPtr,
            action = new Native.Action { type = action }
        };

        Check(Native.FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out _), "добавить правило");
    }

    // ------------------------------------------------------------------ self-test

    /// <summary>
    /// Arms the switch for a couple of seconds and checks that it really blocks.
    /// Run with: Zion.exe --killswitch-selftest [report path]
    /// The test does not permit Zion itself, so this process stands in for "any other program".
    /// The tunnel stays permitted, so an already running VPN session is not interrupted.
    /// </summary>
    public static (bool Passed, string Report) SelfTest()
    {
        var sb = new StringBuilder();
        bool passed = true;
        void Line(string s) => sb.AppendLine(s);

        Line($"Zion Kill Switch self-test  {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        Line($"Struct sizes: filter={Marshal.SizeOf<Native.Filter>()} (expected 200), condition={Marshal.SizeOf<Native.Condition>()} (expected 40), session={Marshal.SizeOf<Native.Session>()} (expected 72)");

        IPAddress? physical = InternetProbe.FindPhysicalAddress();
        bool tunnelUp = InternetProbe.IsTunnelUp();
        Line($"Physical adapter address: {physical?.ToString() ?? "not found"}   VPN tunnel active: {tunnelUp}");

        using var loopListener = new TcpListener(IPAddress.Loopback, 0);
        loopListener.Start();
        int loopPort = ((IPEndPoint)loopListener.LocalEndpoint).Port;

        var targets = new[] { new IPEndPoint(IPAddress.Parse("1.1.1.1"), 443), new IPEndPoint(IPAddress.Parse("8.8.8.8"), 443) };

        var dnsServers = DirectDns.SystemDnsServers();
        Line($"System DNS servers: {(dnsServers.Count > 0 ? string.Join(", ", dnsServers) : "none found")}");

        // 1. Baseline: can this process reach the internet past the tunnel right now?
        bool baseline = targets.Any(t => TryConnect(t, physical));
        bool dnsBaseline = TryDirectDns(dnsServers);
        Line($"1. Before arming: direct connection works: {baseline}, direct DNS query works: {dnsBaseline}");

        // 2. Arm without permitting ourselves: this process plays "any other program"
        bool armed = Arm(new[] { TunRoutingEngine.SingBoxExePath }, permitTunnel: true);
        Line($"2. Armed (this process NOT on the permit list): {armed}{(armed ? "" : "  error: " + LastError)}");
        if (!armed) return (false, sb.ToString());

        try
        {
            bool direct = targets.Any(t => TryConnect(t, physical));
            Line($"3. While armed, direct connection works: {direct}   (must be False)");
            if (direct) passed = false;

            bool dns = TryDirectDns(dnsServers);
            Line($"4. While armed, direct DNS query works: {dns}   (must be False)");
            if (dns) passed = false;

            bool loop = TryConnect(new IPEndPoint(IPAddress.Loopback, loopPort), null);
            Line($"5. While armed, loopback works: {loop}   (must be True)");
            if (!loop) passed = false;

            if (tunnelUp)
            {
                bool viaTunnel = targets.Any(t => TryConnect(t, null));
                Line($"6. While armed, connection through the tunnel works: {viaTunnel}   (must be True)");
                if (!viaTunnel) passed = false;
            }
            else
            {
                Line("6. Tunnel check skipped (no VPN session is running)");
            }
        }
        finally
        {
            Disarm();
        }

        Thread.Sleep(300);
        bool after = targets.Any(t => TryConnect(t, physical));
        Line($"7. After disarming, direct connection works: {after}   (must match step 1: {baseline})");
        if (after != baseline) passed = false;

        // 8. Arm the way the app does it: this process IS permitted, exactly like Zion and sing-box
        //    have to be in order to reach the VPN server while everything else is blocked.
        bool armedPermitted = Arm();
        Line($"8. Armed (this process on the permit list): {armedPermitted}{(armedPermitted ? "" : "  error: " + LastError)}");
        if (!armedPermitted)
        {
            passed = false;
        }
        else
        {
            try
            {
                bool direct = targets.Any(t => TryConnect(t, physical));
                Line($"9. Permitted program reaches the internet: {direct}   (must match step 1: {baseline})");
                if (direct != baseline) passed = false;

                bool dns = TryDirectDns(dnsServers);
                Line($"10. Permitted program can do its own DNS query: {dns}   (must match step 1: {dnsBaseline})");
                if (dns != dnsBaseline) passed = false;
            }
            finally
            {
                Disarm();
            }
        }

        if (!baseline)
        {
            Line("NOTE: there was no direct connectivity to begin with, so step 3 proves nothing. Re-run with internet available.");
            passed = false;
        }
        if (!dnsBaseline)
        {
            Line("NOTE: the direct DNS query did not work even before arming, so step 4 proves nothing.");
        }

        Line(passed ? "RESULT: PASSED" : "RESULT: FAILED");
        return (passed, sb.ToString());
    }

    /// <summary>TCP connect with a short timeout; optionally bound to a specific local address.</summary>
    private static bool TryConnect(IPEndPoint target, IPAddress? bindTo)
    {
        try
        {
            using var socket = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            if (bindTo != null) socket.Bind(new IPEndPoint(bindTo, 0));
            var task = socket.ConnectAsync(target);
            return task.Wait(2000) && socket.Connected;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Real DNS query sent from this process straight to the system DNS servers.</summary>
    private static bool TryDirectDns(List<IPAddress> servers)
    {
        foreach (IPAddress server in servers)
        {
            try
            {
                var task = DirectDns.QueryServerAsync(server, "example.com");
                if (task.Wait(2500) && task.Result.Length > 0) return true;
            }
            catch { }
        }
        return false;
    }

    // ------------------------------------------------------------------ interop

    internal static class Native
    {
        public const uint RPC_C_AUTHN_WINNT = 10;
        public const uint FWPM_SESSION_FLAG_DYNAMIC = 0x1;

        public const uint FWP_ACTION_BLOCK = 0x1001;
        public const uint FWP_ACTION_PERMIT = 0x1002;

        public const uint FWP_MATCH_EQUAL = 0;
        public const uint FWP_MATCH_FLAGS_ALL_SET = 6;

        public const uint FWP_UINT8 = 1;
        public const uint FWP_UINT16 = 2;
        public const uint FWP_UINT32 = 3;
        public const uint FWP_BYTE_BLOB_TYPE = 12;
        public const uint FWP_V4_ADDR_MASK = 0x100;
        public const uint FWP_V6_ADDR_MASK = 0x101;

        public const ulong FWP_CONDITION_FLAG_IS_LOOPBACK = 0x1;

        public const byte IPPROTO_TCP = 6;
        public const byte IPPROTO_UDP = 17;

        public static readonly Guid LayerConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        public static readonly Guid LayerConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        public static readonly Guid LayerRecvAcceptV4 = new("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
        public static readonly Guid LayerRecvAcceptV6 = new("a3b42c97-9f04-4672-b87e-cee9c483257f");

        public static readonly Guid CondAppId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
        public static readonly Guid CondLocalAddress = new("d9ee00de-c1ef-4617-bfe3-ffd8f5a08957");
        public static readonly Guid CondRemoteAddress = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
        public static readonly Guid CondFlags = new("632ce23b-5167-435c-86d7-e903684aa80c");
        public static readonly Guid CondProtocol = new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
        public static readonly Guid CondRemotePort = new("c35a604d-d22b-4e1a-91b4-68f674ee674b");

        [StructLayout(LayoutKind.Sequential)]
        public struct DisplayData { public IntPtr name; public IntPtr description; }

        [StructLayout(LayoutKind.Sequential)]
        public struct ByteBlob { public uint size; public IntPtr data; }

        // FWP_VALUE0 / FWP_CONDITION_VALUE0: a type tag plus an 8-byte union
        [StructLayout(LayoutKind.Sequential)]
        public struct Value { public uint type; public ulong value; }

        [StructLayout(LayoutKind.Sequential)]
        public struct Session
        {
            public Guid sessionKey;
            public DisplayData displayData;
            public uint flags;
            public uint txnWaitTimeoutInMSec;
            public uint processId;
            public IntPtr sid;
            public IntPtr username;
            public int kernelMode;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SubLayer
        {
            public Guid subLayerKey;
            public DisplayData displayData;
            public uint flags;
            public IntPtr providerKey;
            public ByteBlob providerData;
            public ushort weight;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct Condition
        {
            public Guid fieldKey;
            public uint matchType;
            public Value conditionValue;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct Action { public uint type; public Guid filterType; }

        [StructLayout(LayoutKind.Sequential)]
        public struct Filter
        {
            public Guid filterKey;
            public DisplayData displayData;
            public uint flags;
            public IntPtr providerKey;
            public ByteBlob providerData;
            public Guid layerKey;
            public Guid subLayerKey;
            public Value weight;
            public uint numFilterConditions;
            public IntPtr filterCondition;
            public Action action;
            public ulong rawContext;      // union { UINT64 rawContext; GUID providerContextKey; }
            public ulong contextReserved;
            public IntPtr reserved;
            public ulong filterId;
            public Value effectiveWeight;
        }

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
        public static extern uint FwpmEngineOpen0(string? serverName, uint authnService, IntPtr authIdentity, ref Session session, out IntPtr engineHandle);

        [DllImport("fwpuclnt.dll")]
        public static extern uint FwpmEngineClose0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll")]
        public static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

        [DllImport("fwpuclnt.dll")]
        public static extern uint FwpmTransactionCommit0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll")]
        public static extern uint FwpmTransactionAbort0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll")]
        public static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, ref SubLayer subLayer, IntPtr sd);

        [DllImport("fwpuclnt.dll")]
        public static extern uint FwpmFilterAdd0(IntPtr engineHandle, ref Filter filter, IntPtr sd, out ulong id);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
        public static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);

        [DllImport("fwpuclnt.dll")]
        public static extern void FwpmFreeMemory0(ref IntPtr p);
    }
}
