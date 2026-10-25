using System.Net;
using System.Text.Json;
using NetMog.Core;
using NetMog.Models;

namespace NetMog;

public sealed class DeviceManager : IDisposable
{
    private const int AutoScanSeconds = 15;
    private const int OfflineAfterSeconds = 45;
    private const int NetLockGraceScans = 3;
    private const int PruneAfterHours = 24;

    // Devices are keyed by MAC: an IP address is only a lease, a MAC is the
    // hardware. Kills, names, limits and history all follow the MAC, so a DHCP
    // change can neither hide a cut device nor "forget" a restored one.
    private readonly Dictionary<string, DeviceInfo> _devices = new(StringComparer.OrdinalIgnoreCase);

    // Approved hardware. netLock only cuts devices that are not in here.
    private readonly HashSet<string> _trustedMacs = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _trustedNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _deviceNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _limits = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _everSeen = new(StringComparer.OrdinalIgnoreCase);
    // Name lookups that keep failing are not retried forever.
    private readonly Dictionary<string, int> _nameAttempts = new(StringComparer.OrdinalIgnoreCase);

    private readonly NetworkInfo _net;
    private readonly string _namesFile;
    private readonly string _trustedFile;
    private readonly string _limitsFile;
    private readonly string _pendingFile;
    private readonly string _seenFile;
    private readonly object _lock = new();

    private int _scanCount;
    private volatile bool _scanning;
    private volatile bool _resolving;
    private volatile bool _netLock;
    private volatile bool _disposed;
    private Thread? _autoScan;

    public ArpPoisoner Poisoner { get; }
    public TrafficMeter Meter { get; }
    public EventLog Events { get; }

    private readonly ArpScanner _scanner;

    public bool Scanning => _scanning;
    public int ScanCount => _scanCount;
    public string? MeteredIp => Meter.MeteredIp;
    public bool NetLock => _netLock;

    public DeviceManager(NetworkInfo net)
    {
        _net = net;

        // State lives in %LOCALAPPDATA%\NetMog, never next to the executable:
        // the install directory is read-only for a normal user.
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetMog");
        try { Directory.CreateDirectory(dir); } catch { }

        _namesFile = Path.Combine(dir, "device-names.json");
        _trustedFile = Path.Combine(dir, "trusted-devices.json");
        _limitsFile = Path.Combine(dir, "limits.json");
        _pendingFile = Path.Combine(dir, "pending-restores.json");
        _seenFile = Path.Combine(dir, "seen-devices.json");

        Events = new EventLog(Path.Combine(dir, "history.jsonl"));

        LoadDeviceNames();
        LoadTrusted();
        LoadLimits();
        LoadSeen();

        Poisoner = new ArpPoisoner(net);
        Meter = new TrafficMeter(net, Poisoner, Snapshot);
        _scanner = new ArpScanner(net);
        Meter.OnSample += (dev, down, up) =>
        {
            dev.DownKbps = down;
            dev.UpKbps = up;
        };
    }

    public void Start()
    {
        Poisoner.Start();
        RestorePending();
        Events.Add("app", _net.LocalIpString, _net.LocalMacString, "",
            $"NetMog started on {_net.AdapterDescription} (gateway {_net.GatewayIpString})");
        _autoScan = new Thread(AutoScanLoop) { IsBackground = true, Name = "auto-scan" };
        _autoScan.Start();
    }

    private void AutoScanLoop()
    {
        while (!_disposed)
        {
            Thread.Sleep(TimeSpan.FromSeconds(AutoScanSeconds));
            if (_disposed) break;
            if (!_scanning) StartScan();
        }
    }

    // Anything still cut when the process died is restored on the next start,
    // so a crash can never leave a device poisoned indefinitely.
    private void RestorePending()
    {
        try
        {
            if (!File.Exists(_pendingFile)) return;
            var saved = JsonSerializer.Deserialize<List<SavedKill>>(File.ReadAllText(_pendingFile));
            if (saved == null || saved.Count == 0)
            {
                File.Delete(_pendingFile);
                return;
            }
            if (_net.GatewayMac == null)
            {
                var gw = ArpWinApi.ResolveMac(_net.GatewayIp);
                if (gw != null) _net.GatewayMac = NetworkInfo.ParseMac(gw);
            }
            foreach (var entry in saved)
            {
                if (string.IsNullOrEmpty(entry.Ip) || string.IsNullOrEmpty(entry.Mac)) continue;
                Poisoner.Restore(new DeviceInfo { Ip = entry.Ip, Mac = entry.Mac });
                Events.Add("restored", entry.Ip, entry.Mac, "",
                    "restored — was left cut by the previous session");
            }
            File.Delete(_pendingFile);
        }
        catch
        {
        }
    }

    private void SavePending()
    {
        try
        {
            var killed = Poisoner.KilledList();
            if (killed.Count == 0)
            {
                if (File.Exists(_pendingFile)) File.Delete(_pendingFile);
                return;
            }
            var payload = killed.Select(k => new SavedKill { Ip = k.Ip, Mac = k.Mac }).ToList();
            File.WriteAllText(_pendingFile, JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch
        {
        }
    }

    private sealed class SavedKill
    {
        public string Ip { get; set; } = "";
        public string Mac { get; set; } = "";
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { StopMeter(); } catch { }
        try { Poisoner.Dispose(); } catch { }
        try { Meter.Dispose(); } catch { }
        SavePending();
    }

    // ======== persisted state ========

    private static T? ReadJson<T>(string file) where T : class
    {
        try
        {
            if (!File.Exists(file)) return null;
            return JsonSerializer.Deserialize<T>(File.ReadAllText(file));
        }
        catch
        {
            return null;
        }
    }

    private static void WriteJson(string file, object value)
    {
        try
        {
            File.WriteAllText(file, JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch
        {
        }
    }

    private void LoadDeviceNames()
    {
        var dict = ReadJson<Dictionary<string, string>>(_namesFile);
        if (dict == null) return;
        foreach (var kv in dict) _deviceNames[kv.Key] = kv.Value;
    }

    private void LoadSeen()
    {
        var list = ReadJson<List<string>>(_seenFile);
        if (list == null) return;
        foreach (var mac in list) _everSeen.Add(mac);
    }

    private void LoadLimits()
    {
        var dict = ReadJson<Dictionary<string, int>>(_limitsFile);
        if (dict == null) return;
        foreach (var kv in dict) _limits[kv.Key] = kv.Value;
    }

    private void LoadTrusted()
    {
        var saved = ReadJson<TrustedState>(_trustedFile);
        if (saved == null) return;
        foreach (var mac in saved.Macs) _trustedMacs.Add(mac);
        foreach (var name in saved.Names) _trustedNames.Add(name);
        // An armed netLock stays armed across restarts, otherwise a reboot would
        // silently unlock the network.
        _netLock = saved.Armed;
    }

    private void SaveTrusted()
    {
        lock (_lock)
        {
            WriteJson(_trustedFile, new TrustedState
            {
                Armed = _netLock,
                Macs = _trustedMacs.ToList(),
                Names = _trustedNames.ToList(),
            });
        }
    }

    private void SaveSeen()
    {
        lock (_lock) WriteJson(_seenFile, _everSeen.ToList());
    }

    private sealed class TrustedState
    {
        public bool Armed { get; set; }
        public List<string> Macs { get; set; } = new();
        public List<string> Names { get; set; } = new();
    }

    /// <summary>
    /// Sets or clears the label of a device. A label is only a display name: it
    /// does NOT approve the device. Trust stays explicit (arming netLock, or
    /// restoring a device you cut), so renaming something can never quietly put
    /// it on the allowed list.
    /// </summary>
    public void SetDeviceName(string mac, string name)
    {
        lock (_lock)
        {
            if (string.IsNullOrWhiteSpace(name))
                _deviceNames.Remove(mac);
            else
                _deviceNames[mac] = name.Trim();
            WriteJson(_namesFile, _deviceNames);
        }
    }

    /// <summary>
    /// Best name for a device: your label, then the name it reports, then its
    /// address. Used for log entries so they read "Moti · cut access".
    /// </summary>
    private string Label(DeviceInfo dev)
    {
        var custom = "";
        lock (_lock)
        {
            if (!string.IsNullOrEmpty(dev.Mac) && _deviceNames.TryGetValue(dev.Mac, out var stored))
                custom = stored;
        }
        if (!string.IsNullOrWhiteSpace(custom)) return custom;
        return string.IsNullOrEmpty(dev.HostName) ? dev.Ip : dev.HostName;
    }

    // ======== netLock ========

    public void SetNetLock(bool on)
    {
        lock (_lock)
        {
            _netLock = on;
            if (on)
            {
                // Everything present when you arm it becomes the baseline, and
                // that baseline survives restarts.
                foreach (var d in _devices.Values)
                {
                    _trustedMacs.Add(d.Mac);
                    if (!string.IsNullOrEmpty(d.HostName)) _trustedNames.Add(d.HostName);
                }
            }
        }
        SaveTrusted();
        Events.Add("netlock", "", "", "", on
            ? $"netLock armed — {TrustedCount()} devices trusted, new ones will be cut"
            : "netLock disarmed");
    }

    private int TrustedCount()
    {
        lock (_lock) return _trustedMacs.Count;
    }

    private bool IsTrustedLocked(DeviceInfo dev) =>
        _trustedMacs.Contains(dev.Mac) ||
        (!string.IsNullOrEmpty(dev.HostName) && _trustedNames.Contains(dev.HostName));

    // ======== scanning ========

    public List<DeviceInfo> Snapshot()
    {
        lock (_lock)
        {
            var list = _devices.Values
                .OrderBy(d => d.Ip, new IpComparer())
                .ToList();
            var now = DateTime.UtcNow;
            foreach (var d in list)
            {
                // Always read it back: a cleared name must not linger on the object.
                d.CustomName = _deviceNames.TryGetValue(d.Mac, out var custom) ? custom : "";
                d.Online = d.IsSelf || (now - d.LastSeen).TotalSeconds < OfflineAfterSeconds;
            }
            return list;
        }
    }

    public void StartScan()
    {
        if (_scanning) return;
        _scanning = true;
        ThreadPool.QueueUserWorkItem(_ =>
        {
            try
            {
                ScanOnce();
            }
            catch
            {
            }
            finally
            {
                _scanning = false;
            }
        });
    }

    private void ScanOnce()
    {
        var found = _scanner.Scan();
        var now = DateTime.UtcNow;

        var joined = new List<DeviceInfo>();
        var returned = new List<DeviceInfo>();
        var left = new List<DeviceInfo>();
        var blocked = new List<DeviceInfo>();

        lock (_lock)
        {
            UpsertSelfLocked(now);

            foreach (var kv in found)
            {
                var ip = kv.Key;
                var mac = NormalizeMac(kv.Value);
                if (mac.Length == 0) continue;

                if (!_devices.TryGetValue(mac, out var dev))
                {
                    dev = new DeviceInfo { Ip = ip, Mac = mac, FirstSeen = now };
                    dev.RandomizedMac = MacVendor.IsRandomized(mac);
                    if (!dev.RandomizedMac) dev.Vendor = MacVendor.Lookup(mac) ?? "";
                    if (_limits.TryGetValue(mac, out var limit)) dev.LimitKbps = limit;
                    _devices[mac] = dev;
                    joined.Add(dev);
                }
                else if (!string.Equals(dev.Ip, ip, StringComparison.Ordinal))
                {
                    // Same hardware, new DHCP lease. State, name and limit follow it.
                    dev.Ip = ip;
                    if (dev.Online) returned.Add(dev);
                }

                dev.LastSeen = now;
                dev.SeenScans++;

                if (ip == _net.LocalIpString)
                {
                    dev.IsSelf = true;
                    dev.HostName = Environment.MachineName;
                }
                if (ip == _net.GatewayIpString)
                {
                    dev.IsGateway = true;
                    _net.GatewayMac ??= NetworkInfo.ParseMac(mac);
                }
                if (!dev.RandomizedMac && string.IsNullOrEmpty(dev.Vendor))
                    dev.Vendor = MacVendor.Lookup(mac) ?? "";
            }

            foreach (var dev in _devices.Values)
            {
                var online = dev.IsSelf || (now - dev.LastSeen).TotalSeconds < OfflineAfterSeconds;
                if (!dev.IsSelf && dev.Online && !online) left.Add(dev);
                // A device that comes back gets a fresh set of name lookups.
                if (!dev.Online && online) _nameAttempts.Remove(dev.Mac);
                dev.Online = online;
            }

            // netLock: cut hardware we have never approved. Privacy MACs are
            // exempt — they cannot be identified reliably, and auto-cutting them
            // is what turned a phone's normal MAC rotation into a disconnection.
            if (_netLock)
            {
                foreach (var dev in _devices.Values)
                {
                    if (dev.IsSelf || dev.IsGateway || dev.State == DeviceState.Cut) continue;
                    if (dev.RandomizedMac || dev.SeenScans < NetLockGraceScans) continue;
                    if (IsTrustedLocked(dev)) continue;
                    Poisoner.Kill(dev);
                    dev.State = DeviceState.Cut;
                    blocked.Add(dev);
                }
            }

            // Drop stale entries we have no reason to remember.
            var cutoff = now.AddHours(-PruneAfterHours);
            foreach (var stale in _devices.Values
                         .Where(d => !d.IsSelf && !d.IsGateway && d.State == DeviceState.Online && d.LastSeen < cutoff)
                         .ToList())
            {
                _devices.Remove(stale.Mac);
            }

            _scanCount++;
        }

        foreach (var dev in joined)
        {
            var first = !_everSeen.Contains(dev.Mac);
            _everSeen.Add(dev.Mac);
            if (!first || dev.IsSelf || dev.IsGateway) continue;
            var tag = dev.RandomizedMac ? " (privacy MAC)" : "";
            Events.Add("device-new", dev.Ip, dev.Mac, Label(dev), $"joined{tag}");
        }
        if (joined.Count > 0) SaveSeen();

        foreach (var dev in returned)
            Events.Add("device-new", dev.Ip, dev.Mac, Label(dev), "came back on a new lease");

        foreach (var dev in left)
        {
            if (dev.IsGateway) continue;
            Events.Add("device-left", dev.Ip, dev.Mac, Label(dev), "went offline");
        }

        if (blocked.Count > 0)
        {
            SavePending();
            foreach (var dev in blocked)
                Events.Add("netlock", dev.Ip, dev.Mac, Label(dev), "cut by netLock — unknown device");
        }

        // Name lookups can take seconds on a slow LAN, so they never hold up
        // the scan (and never make the UI look busy).
        QueueHostnameResolution();
    }

    private void QueueHostnameResolution()
    {
        if (_resolving) return;
        _resolving = true;
        ThreadPool.QueueUserWorkItem(_ =>
        {
            try
            {
                ResolveHostnames();
            }
            catch
            {
            }
            finally
            {
                _resolving = false;
            }
        });
    }

    private void UpsertSelfLocked(DateTime now)
    {
        var mac = NormalizeMac(_net.LocalMacString);
        if (!_devices.TryGetValue(mac, out var self))
        {
            self = new DeviceInfo
            {
                Ip = _net.LocalIpString,
                Mac = mac,
                IsSelf = true,
                HostName = Environment.MachineName,
                FirstSeen = now,
            };
            _devices[mac] = self;
        }
        self.Ip = _net.LocalIpString;
        self.IsSelf = true;
        self.IsGateway = false;
        self.State = DeviceState.Online;
        self.LastSeen = now;
        self.Online = true;
        self.HostName = Environment.MachineName;
    }

    private void ResolveHostnames()
    {
        List<DeviceInfo> pending;
        lock (_lock)
        {
            var cutoff = DateTime.UtcNow.AddSeconds(-OfflineAfterSeconds);
            pending = _devices.Values
                .Where(d => !d.IsSelf && d.Online && d.LastSeen >= cutoff && string.IsNullOrEmpty(d.HostName))
                .Where(d => _nameAttempts.TryGetValue(d.Mac, out var tries) ? tries < 6 : true)
                .ToList();
            foreach (var d in pending)
                _nameAttempts[d.Mac] = (_nameAttempts.TryGetValue(d.Mac, out var n) ? n : 0) + 1;
        }
        if (pending.Count == 0) return;

        Parallel.ForEach(pending, new ParallelOptions { MaxDegreeOfParallelism = 10 }, d =>
        {
            string? name = null;
            try
            {
                // The Windows resolver (DNS + LLMNR + mDNS) answers in ~1.5s when it
                // can and needs ~5s to give up; cutting it short lost real names.
                var lookup = Dns.GetHostEntryAsync(d.Ip).WaitAsync(TimeSpan.FromMilliseconds(6000));
                lookup.Wait();
                var resolved = lookup.Result.HostName;
                if (resolved.Length > 0 &&
                    !resolved.StartsWith("unknown", StringComparison.OrdinalIgnoreCase) &&
                    resolved != d.Ip)
                    name = resolved;
            }
            catch
            {
            }
            if (name == null)
            {
                try { name = NetbiosResolver.Resolve(IPAddress.Parse(d.Ip), 1200); } catch { }
            }
            if (name == null)
            {
                try { name = MdnsResolver.Resolve(IPAddress.Parse(d.Ip), 1200); } catch { }
            }
            if (string.IsNullOrWhiteSpace(name)) return;

            var trimmed = MdnsResolver.CleanName(name);
            if (trimmed.Length == 0) return;
            lock (_lock)
            {
                if (!_devices.TryGetValue(d.Mac, out var dev) || !string.IsNullOrEmpty(dev.HostName)) return;
                dev.HostName = trimmed;
                // A device that reappears with a rotated MAC is the same phone:
                // remember its hostname so netLock can recognise it next time.
                if (_trustedMacs.Contains(dev.Mac)) _trustedNames.Add(trimmed);
            }
        });
    }

    // ======== device actions ========

    public bool Kill(string ip)
    {
        lock (_lock)
        {
            var dev = FindByIpLocked(ip);
            if (dev == null)
            {
                // Not in the list yet (e.g. clicked right after app start): resolve on the fly.
                var mac = ArpWinApi.ResolveMac(IPAddress.Parse(ip));
                if (mac == null) return false;
                dev = new DeviceInfo
                {
                    Ip = ip,
                    Mac = NormalizeMac(mac),
                    LastSeen = DateTime.UtcNow,
                };
                dev.RandomizedMac = MacVendor.IsRandomized(dev.Mac);
                if (!dev.RandomizedMac) dev.Vendor = MacVendor.Lookup(dev.Mac) ?? "";
                _devices[dev.Mac] = dev;
            }
            if (dev.IsSelf || dev.IsGateway) return false;
            if (dev.State == DeviceState.Monitoring) StopMeterLocked();
            Poisoner.Kill(dev);
            dev.State = DeviceState.Cut;
            SavePending();
            Events.Add("killed", dev.Ip, dev.Mac, Label(dev), "cut access");
            return true;
        }
    }

    public bool Restore(string ip)
    {
        lock (_lock)
        {
            var dev = FindByIpLocked(ip);
            if (dev == null) return false;
            Poisoner.Restore(dev);
            dev.State = DeviceState.Online;
            dev.DownKbps = dev.UpKbps = 0;
            // Restoring is an explicit allow: netLock must not cut it again.
            _trustedMacs.Add(dev.Mac);
            if (!string.IsNullOrEmpty(dev.HostName)) _trustedNames.Add(dev.HostName);
            SavePending();
            SaveTrusted();
            Events.Add("restored", dev.Ip, dev.Mac, Label(dev), "restored");
            return true;
        }
    }

    public int KillAll()
    {
        lock (_lock)
        {
            int n = 0;
            foreach (var dev in _devices.Values)
            {
                if (dev.IsSelf || dev.IsGateway || !dev.Online) continue;
                if (dev.State == DeviceState.Monitoring) StopMeterLocked();
                Poisoner.Kill(dev);
                dev.State = DeviceState.Cut;
                n++;
            }
            SavePending();
            if (n > 0) Events.Add("killed", "", "", "", n == 1 ? "cut access to 1 device" : $"cut access to {n} devices");
            return n;
        }
    }

    public int RestoreAll()
    {
        StopMeter();
        lock (_lock)
        {
            int n = 0;
            foreach (var dev in _devices.Values)
            {
                if (dev.State == DeviceState.Online) continue;
                Poisoner.Restore(dev);
                dev.State = DeviceState.Online;
                dev.DownKbps = dev.UpKbps = 0;
                n++;
            }
            SavePending();
            if (n > 0) Events.Add("restored", "", "", "", n == 1 ? "restored 1 device" : $"restored {n} devices");
            return n;
        }
    }

    private DeviceInfo? FindByIpLocked(string ip) =>
        _devices.Values.FirstOrDefault(d => string.Equals(d.Ip, ip, StringComparison.Ordinal))
        ?? _devices.Values.FirstOrDefault(d => string.Equals(d.Ip, ip, StringComparison.OrdinalIgnoreCase));

    // ======== bandwidth meter + limits ========

    public bool ToggleMonitor(string ip)
    {
        lock (_lock)
        {
            if (MeteredIp == ip)
            {
                StopMeterLocked();
                return false;
            }
            var dev = FindByIpLocked(ip);
            if (dev == null || dev.IsSelf) return false;
            if (_net.GatewayMac == null) return false;

            if (MeteredIp != null) StopMeterLocked();
            if (dev.State == DeviceState.Cut) Poisoner.Restore(dev);
            Meter.LimitKbps = dev.LimitKbps;
            if (!Meter.Start(dev)) return false;
            dev.State = DeviceState.Monitoring;
            return true;
        }
    }

    public bool SetLimit(string ip, int kbps)
    {
        kbps = Math.Clamp(kbps, 0, 1_000_000);
        DeviceInfo? dev;
        lock (_lock)
        {
            dev = FindByIpLocked(ip);
            if (dev == null) return false;
            dev.LimitKbps = kbps;
            if (kbps > 0) _limits[dev.Mac] = kbps;
            else _limits.Remove(dev.Mac);
            WriteJson(_limitsFile, _limits);
            if (MeteredIp == dev.Ip) Meter.LimitKbps = kbps;
        }
        Events.Add("limit", dev.Ip, dev.Mac, Label(dev), kbps > 0
            ? $"limited to {kbps} kbps"
            : "limit removed");
        return true;
    }

    public void StopMeter()
    {
        lock (_lock) StopMeterLocked();
    }

    private void StopMeterLocked()
    {
        var dev = _devices.Values.FirstOrDefault(d => d.State == DeviceState.Monitoring);
        Meter.Stop();
        Meter.LimitKbps = 0;
        if (dev != null)
        {
            dev.State = DeviceState.Online;
            dev.DownKbps = dev.UpKbps = 0;
        }
    }

    private static string NormalizeMac(string mac)
    {
        if (string.IsNullOrWhiteSpace(mac)) return "";
        try { return NetworkInfo.FormatMac(NetworkInfo.ParseMac(mac)); }
        catch { return mac.ToUpperInvariant(); }
    }

    private sealed class IpComparer : IComparer<string>
    {
        public int Compare(string? a, string? b)
        {
            if (a == null || b == null) return string.CompareOrdinal(a, b);
            var pa = IPAddress.TryParse(a, out var ia) ? ia.GetAddressBytes() : null;
            var pb = IPAddress.TryParse(b, out var ib) ? ib.GetAddressBytes() : null;
            if (pa == null || pb == null) return string.CompareOrdinal(a, b);
            for (int i = 0; i < 4; i++)
            {
                if (pa[i] != pb[i]) return pa[i].CompareTo(pb[i]);
            }
            return 0;
        }
    }
}
