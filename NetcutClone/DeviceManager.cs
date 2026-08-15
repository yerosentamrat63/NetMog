using System.Net;
using NetcutClone.Core;
using NetcutClone.Models;

namespace NetcutClone;

public sealed class DeviceManager
{
    private readonly NetworkInfo _net;
    private readonly Dictionary<string, DeviceInfo> _devices = new();
    private readonly HashSet<string> _knownMacs = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private int _scanCount;
    private volatile bool _scanning;
    private volatile bool _netLock;

    public ArpPoisoner Poisoner { get; }
    public TrafficMeter Meter { get; }
    public ArpScanner Scanner { get; }
    public bool Scanning => _scanning;
    public int ScanCount => _scanCount;
    public string? MeteredIp => Meter.MeteredIp;
    public bool NetLock => _netLock;

    public void SetNetLock(bool on)
    {
        lock (_lock)
        {
            _netLock = on;
            if (on)
            {
                foreach (var d in _devices.Values) _knownMacs.Add(d.Mac);
            }
        }
    }

    public DeviceManager(NetworkInfo net)
    {
        _net = net;
        Poisoner = new ArpPoisoner(net);
        Meter = new TrafficMeter(net, Poisoner, Snapshot);
        Scanner = new ArpScanner(net);
        Meter.OnSample += (dev, down, up) =>
        {
            dev.DownKbps = down;
            dev.UpKbps = up;
        };
    }

    public void Start() => Poisoner.Start();

    public List<DeviceInfo> Snapshot()
    {
        lock (_lock)
        {
            return _devices.Values
                .OrderBy(d => d.Ip, new IpComparer())
                .ToList();
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
                Dictionary<string, string> found;
                using (var scanner = Scanner)
                {
                    found = scanner.Scan();
                }

                var now = DateTime.UtcNow;
                lock (_lock)
                {
                    // Always surface our own machine in the device list.
                    if (!_devices.TryGetValue(_net.LocalIpString, out var self))
                    {
                        self = new DeviceInfo
                        {
                            Ip = _net.LocalIpString,
                            Mac = _net.LocalMacString,
                            IsSelf = true,
                            HostName = Environment.MachineName,
                        };
                        _devices[_net.LocalIpString] = self;
                    }
                    self.LastSeen = now;

                    foreach (var kv in found)
                    {
                        var isSelf = kv.Key == _net.LocalIpString;
                        var isGateway = kv.Key == _net.GatewayIpString;
                        if (_devices.TryGetValue(kv.Key, out var existing))
                        {
                            existing.Mac = kv.Value;
                            existing.LastSeen = now;
                            if (isGateway) existing.IsGateway = true;
                            if (string.IsNullOrEmpty(existing.Vendor) && !MacVendor.IsRandomized(kv.Value))
                                existing.Vendor = MacVendor.Lookup(kv.Value) ?? "";
                        }
                        else
                        {
                            _devices[kv.Key] = new DeviceInfo
                            {
                                Ip = kv.Key,
                                Mac = kv.Value,
                                IsSelf = isSelf,
                                IsGateway = isGateway,
                                HostName = isSelf ? Environment.MachineName : "",
                                Vendor = MacVendor.Lookup(kv.Value) ?? "",
                                RandomizedMac = MacVendor.IsRandomized(kv.Value),
                            };
                        }
                    }

                    if (_net.GatewayMac == null)
                    {
                        foreach (var kv in found)
                        {
                            if (kv.Key == _net.GatewayIpString)
                            {
                                _net.GatewayMac = NetworkInfo.ParseMac(kv.Value);
                                break;
                            }
                        }
                    }

                    // netLock: cut any device we have never seen before.
                    if (_netLock)
                    {
                        foreach (var kv in found)
                        {
                            if (kv.Key == _net.LocalIpString || kv.Key == _net.GatewayIpString) continue;
                            if (!_knownMacs.Contains(kv.Value) &&
                                _devices.TryGetValue(kv.Key, out var newcomer) &&
                                newcomer.State != DeviceState.Cut)
                            {
                                _knownMacs.Add(kv.Value);
                                Poisoner.Kill(newcomer);
                            }
                        }
                    }

                    _scanCount++;
                }

                ResolveHostnames();
            }
            finally
            {
                _scanning = false;
            }
        });
    }

    public bool Kill(string ip)
    {
        lock (_lock)
        {
            if (!_devices.TryGetValue(ip, out var dev))
            {
                // Not in the list yet (e.g. clicked right after app start): resolve on the fly.
                var mac = ArpWinApi.ResolveMac(IPAddress.Parse(ip));
                if (mac == null) return false;
                dev = new DeviceInfo
                {
                    Ip = ip,
                    Mac = mac,
                    LastSeen = DateTime.UtcNow,
                };
                _devices[ip] = dev;
            }
            if (dev.IsSelf || dev.IsGateway) return false;
            if (dev.State == DeviceState.Monitoring) StopMeterLocked();
            Poisoner.Kill(dev);
            dev.State = DeviceState.Cut;
            return true;
        }
    }

    public bool Restore(string ip)
    {
        lock (_lock)
        {
            if (!_devices.TryGetValue(ip, out var dev)) return false;
            Poisoner.Restore(dev);
            dev.State = DeviceState.Online;
            dev.DownKbps = dev.UpKbps = 0;
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
                if (dev.IsSelf || dev.IsGateway) continue;
                if (dev.State == DeviceState.Monitoring) StopMeterLocked();
                Poisoner.Kill(dev);
                dev.State = DeviceState.Cut;
                n++;
            }
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
            return n;
        }
    }

    public bool ToggleMonitor(string ip, string mode = "")
    {
        lock (_lock)
        {
            if (MeteredIp == ip)
            {
                StopMeterLocked();
                return false;
            }
            if (!_devices.TryGetValue(ip, out var dev)) return false;
            if (dev.IsSelf) return false;
            if (_net.GatewayMac == null) return false;

            if (MeteredIp != null) StopMeterLocked();
            if (dev.State == DeviceState.Cut) Poisoner.Restore(dev);
            if (!Meter.Start(dev)) return false;
            dev.State = DeviceState.Monitoring;
            return true;
        }
    }

    public void StopMeter()
    {
        lock (_lock) StopMeterLocked();
    }

    private void StopMeterLocked()
    {
        var dev = _devices.Values.FirstOrDefault(d => d.State == DeviceState.Monitoring);
        Meter.Stop();
        if (dev != null)
        {
            dev.State = DeviceState.Online;
            dev.DownKbps = dev.UpKbps = 0;
        }
    }

    private void ResolveHostnames()
    {
        List<DeviceInfo> fresh;
        lock (_lock) fresh = _devices.Values.Where(d => !d.IsSelf).ToList();

        using var gate = new SemaphoreSlim(10);
        Parallel.ForEach(fresh, new ParallelOptions { MaxDegreeOfParallelism = 10 }, d =>
        {
            gate.Wait();
            try
            {
                string? name = null;
                try
                {
                    var t = Dns.GetHostEntryAsync(d.Ip).WaitAsync(TimeSpan.FromMilliseconds(1200));
                    t.Wait();
                    if (t.Result.HostName.Length > 0 &&
                        !t.Result.HostName.StartsWith("unknown", StringComparison.OrdinalIgnoreCase) &&
                        t.Result.HostName != d.Ip)
                        name = t.Result.HostName;
                }
                catch
                {
                }
                if (name == null)
                {
                    try
                    {
                        name = NetbiosResolver.Resolve(IPAddress.Parse(d.Ip), 1200);
                    }
                    catch
                    {
                    }
                }
                if (name == null)
                {
                    try
                    {
                        name = MdnsResolver.Resolve(IPAddress.Parse(d.Ip), 1200);
                    }
                    catch
                    {
                    }
                }
                if (!string.IsNullOrWhiteSpace(name))
                {
                    lock (_lock)
                    {
                        if (_devices.TryGetValue(d.Ip, out var dev) && string.IsNullOrEmpty(dev.HostName))
                            dev.HostName = name.Trim();
                    }
                }
            }
            finally
            {
                gate.Release();
            }
        });
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