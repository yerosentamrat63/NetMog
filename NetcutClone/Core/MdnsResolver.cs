using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NetcutClone.Core;

/// <summary>
/// mDNS (Bonjour) reverse-PTR resolver. Phones, TVs and smart-home devices
/// don't answer NetBIOS, but most respond to multicast DNS on UDP 5353.
/// </summary>
public static class MdnsResolver
{
    private const string MulticastAddr = "224.0.0.251";
    private const int Port = 5353;

    public static string? Resolve(IPAddress ip, int timeoutMs = 1200)
    {
        try
        {
            using var udp = new UdpClient();
            udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
            udp.Client.ReceiveTimeout = timeoutMs;
            udp.JoinMulticastGroup(IPAddress.Parse(MulticastAddr));
            udp.MulticastLoopback = false;
            udp.Ttl = 4;

            var query = BuildReversePtrQuery(ip);
            udp.Send(query, query.Length, new IPEndPoint(IPAddress.Parse(MulticastAddr), Port));

            var remote = new IPEndPoint(IPAddress.Any, 0);
            var deadline = Environment.TickCount64 + timeoutMs;
            while (Environment.TickCount64 < deadline)
            {
                try
                {
                    var resp = udp.Receive(ref remote);
                    var name = ParsePtrAnswer(resp);
                    if (!string.IsNullOrEmpty(name)) return name;
                }
                catch (SocketException)
                {
                    break;
                }
                catch
                {
                    break;
                }
            }
        }
        catch
        {
        }
        return null;
    }

    private static byte[] BuildReversePtrQuery(IPAddress ip)
    {
        var octets = ip.GetAddressBytes();
        var parts = new[]
        {
            octets[3].ToString(), octets[2].ToString(),
            octets[1].ToString(), octets[0].ToString(),
            "in-addr", "arpa",
        };

        var ms = new MemoryStream();
        ms.Write(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 0, 12);
        foreach (var p in parts)
        {
            ms.WriteByte((byte)p.Length);
            ms.Write(Encoding.ASCII.GetBytes(p), 0, p.Length);
        }
        ms.WriteByte(0);
        ms.Write(new byte[] { 0x00, 0x0C, 0x80, 0x01 }, 0, 4); // QTYPE=PTR, QCLASS=QU(unicast-response)|IN
        return ms.ToArray();
    }

    private static string? ParsePtrAnswer(byte[] resp)
    {
        if (resp.Length < 12) return null;
        int qdcount = (resp[4] << 8) | resp[5];
        int ancount = (resp[6] << 8) | resp[7];
        if (ancount == 0) return null;

        int pos = 12;
        for (int i = 0; i < qdcount; i++)
        {
            pos = SkipName(resp, pos);
            if (pos < 0 || pos + 4 > resp.Length) return null;
            pos += 4;
        }

        for (int i = 0; i < ancount; i++)
        {
            pos = SkipName(resp, pos);
            if (pos < 0 || pos + 10 > resp.Length) return null;
            int type = (resp[pos] << 8) | resp[pos + 1];
            int rdlen = (resp[pos + 8] << 8) | resp[pos + 9];
            int data = pos + 10;
            if (data + rdlen > resp.Length) return null;

            if (type == 12 && rdlen > 0)
            {
                var name = ReadName(resp, data, out _);
                if (!string.IsNullOrEmpty(name))
                {
                    if (name.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
                        name = name[..^6];
                    return name;
                }
            }
            pos = data + rdlen;
        }
        return null;
    }

    private static int SkipName(byte[] resp, int pos)
    {
        while (pos < resp.Length)
        {
            int len = resp[pos];
            if (len == 0) return pos + 1;
            if ((len & 0xC0) == 0xC0) return pos + 2;
            pos += len + 1;
        }
        return -1;
    }

    private static string? ReadName(byte[] resp, int pos, out int nextPos)
    {
        var sb = new StringBuilder();
        int p = pos;
        int jumps = 0;
        nextPos = -1;
        while (true)
        {
            if (p >= resp.Length) return null;
            int len = resp[p];
            if ((len & 0xC0) == 0xC0)
            {
                if (p + 1 >= resp.Length) return null;
                int ptr = ((len & 0x3F) << 8) | resp[p + 1];
                if (jumps == 0) nextPos = p + 2;
                p = ptr;
                if (++jumps > 8) return null;
                continue;
            }
            if (len == 0)
            {
                if (jumps == 0) nextPos = p + 1;
                return sb.ToString();
            }
            p++;
            if (p + len > resp.Length) return null;
            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.ASCII.GetString(resp, p, len));
            p += len;
        }
    }
}