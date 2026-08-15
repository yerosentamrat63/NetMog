using System.Net;
using System.Net.Sockets;

namespace NetMog.Core;

/// <summary>
/// Scans the subnet using the Windows OS ARP stack (SendARP + neighbor table),
/// which works reliably on Wi-Fi adapters where raw Npcap injection is dropped.
/// </summary>
public sealed class ArpScanner : IDisposable
{
    private readonly NetworkInfo _net;

    public long Probed { get; private set; }
    public long Found { get; private set; }

    public ArpScanner(NetworkInfo net) => _net = net;

    public Dictionary<string, string> Scan(int waitMs = 2000)
    {
        var hosts = new HashSet<IPAddress>(_net.EnumerateHosts());
        hosts.Add(_net.GatewayIp);
        hosts.Add(_net.LocalIp);
        var inSubnet = new Func<IPAddress, bool>(ip => hosts.Contains(ip));

        var result = ArpWinApi.ReadNeighborTable()
            .Where(kv => inSubnet(IPAddress.Parse(kv.Key)))
            .ToDictionary(kv => kv.Key, kv => kv.Value);

        // Trigger OS ARP resolution for every host by sending a tiny UDP probe;
        // the OS resolves the MAC in the background and caches it.
        using var udp = new UdpClient();
        foreach (var ip in _net.EnumerateHosts())
        {
            var key = ip.ToString();
            if (result.ContainsKey(key)) continue;
            try
            {
                udp.Send(new byte[1], 1, new IPEndPoint(ip, 9));
                Probed++;
            }
            catch
            {
            }
        }

        Thread.Sleep(waitMs);

        foreach (var kv in ArpWinApi.ReadNeighborTable())
        {
            if (!inSubnet(IPAddress.Parse(kv.Key))) continue;
            result[kv.Key] = kv.Value;
        }

        // Gateway + self, authoritatively.
        var gw = ArpWinApi.ResolveMac(_net.GatewayIp);
        if (gw != null) result[_net.GatewayIpString] = gw;
        var self = ArpWinApi.ResolveMac(_net.LocalIp);
        if (self != null) result[_net.LocalIpString] = self;

        Found = result.Count;
        return result;
    }

    public void Dispose()
    {
    }
}