using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using SharpPcap;
using SharpPcap.LibPcap;

namespace NetMog.Core;

public sealed class NetworkInfo
{
    public required string AdapterName { get; set; }
    public required string AdapterDescription { get; init; }
    public required IPAddress LocalIp { get; init; }
    public required IPAddress GatewayIp { get; init; }
    public required PhysicalAddress LocalMac { get; init; }
    public required uint NetworkAddr { get; init; }
    public required uint BroadcastAddr { get; init; }

    public PhysicalAddress? GatewayMac { get; set; }
    public string LocalIpString => LocalIp.ToString();
    public string GatewayIpString => GatewayIp.ToString();
    public string LocalMacString => FormatMac(LocalMac);
    public string GatewayMacString => GatewayMac == null ? "?" : FormatMac(GatewayMac);

    public static NetworkInfo? Discover()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

            var props = nic.GetIPProperties();
            var gw = props.GatewayAddresses
                .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
            if (gw == null) continue;

            var unicast = props.UnicastAddresses
                .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
            if (unicast == null || unicast.PrefixLength == 0) continue;

            var ip = unicast.Address;
            var prefix = unicast.PrefixLength;
            var mask = PrefixToMask(prefix);
            var network = ipUint(ip) & mask;
            var broadcast = network | ~mask;

            return new NetworkInfo
            {
                AdapterName = nic.Name,
                AdapterDescription = nic.Description,
                LocalIp = ip,
                GatewayIp = gw.Address,
                LocalMac = nic.GetPhysicalAddress(),
                NetworkAddr = network,
                BroadcastAddr = broadcast,
            };
        }
        return null;
    }

    public IEnumerable<IPAddress> EnumerateHosts()
    {
        for (uint h = NetworkAddr + 1; h < BroadcastAddr; h++)
            yield return UintToIp(h);
    }

    public static uint ipUint(IPAddress a) =>
        BitConverter.ToUInt32(a.GetAddressBytes().Reverse().ToArray(), 0);

    public static IPAddress UintToIp(uint v) =>
        new(BitConverter.GetBytes(v).Reverse().ToArray());

    public static uint PrefixToMask(int prefix) =>
        prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix);

    public static string FormatMac(PhysicalAddress mac)
    {
        var b = mac.GetAddressBytes();
        return string.Join(":", b.Select(x => x.ToString("X2")));
    }

    public static PhysicalAddress ParseMac(string mac) => PhysicalAddress.Parse(mac.Replace(":", "-"));

    /// <summary>Parses a MAC, or returns null when it is not a usable address.</summary>
    public static PhysicalAddress? ParseMacSafe(string mac)
    {
        if (string.IsNullOrWhiteSpace(mac)) return null;
        try
        {
            var parsed = ParseMac(mac);
            return parsed.GetAddressBytes().Length == 6 ? parsed : null;
        }
        catch
        {
            return null;
        }
    }

    public LibPcapLiveDevice CreateDevice()
    {
        // CaptureDeviceList caches device objects; each engine must get its own
        // handle so scanner/poisoner/meter can all be open simultaneously.
        var cached = CaptureDeviceList.Instance
            .OfType<LibPcapLiveDevice>()
            .FirstOrDefault(d => d.Name == AdapterName);
        if (cached?.Interface == null)
            throw new InvalidOperationException($"pcap device '{AdapterName}' is not available");
        return new LibPcapLiveDevice(cached.Interface);
    }
}
