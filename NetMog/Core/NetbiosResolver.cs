using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NetMog.Core;

public static class NetbiosResolver
{
    public static string? Resolve(IPAddress ip, int timeoutMs = 1500)
    {
        try
        {
            using var udp = new UdpClient();
            udp.Client.ReceiveTimeout = timeoutMs;
            var query = BuildNbstatQuery();
            udp.Send(query, query.Length, new IPEndPoint(ip, 137));
            var remote = new IPEndPoint(IPAddress.Any, 0);
            var resp = udp.Receive(ref remote);
            return ParseNbstat(resp);
        }
        catch
        {
            return null;
        }
    }

    private static byte[] BuildNbstatQuery()
    {
        // NetBIOS NBSTAT query for the wildcard name (like "nbtstat -A ip").
        var b = new byte[48];
        b[0] = 0x12; b[1] = 0x34;          // transaction id
        b[2] = 0x00; b[3] = 0x10;          // flags: recursion desired
        b[4] = 0x00; b[5] = 0x01;          // QDCOUNT = 1
        for (int i = 12; i < 27; i++) b[i] = 0x2A;  // 15 x '*' 
        // byte 27 = 0x00 (end of name), bytes 28..43 = 0x00 (16-byte suffix)
        b[44] = 0x00; b[45] = 0x21;        // type: NBSTAT
        b[46] = 0x00; b[47] = 0x01;        // class: IN
        return b;
    }

    private static string? ParseNbstat(byte[] resp)
    {
        if (resp.Length < 57) return null;
        // Skip the 12-byte header and the answer record's NAME field.
        // NAME may be a 2-byte compression pointer (0xC0 0x0C) or a full label list.
        int pos = 12;
        if (pos >= resp.Length) return null;
        if (resp[pos] == 0xC0)
        {
            pos += 2;
        }
        else
        {
            while (pos < resp.Length)
            {
                int len = resp[pos];
                if (len == 0) { pos++; break; }
                if ((len & 0xC0) == 0xC0) { pos += 2; break; }
                pos += len + 1;
            }
        }
        pos += 2 + 2 + 4 + 2; // type, class, ttl, rdlength
        if (pos >= resp.Length) return null;
        int count = resp[pos];
        pos++;
        for (int i = 0; i < count && pos + 18 <= resp.Length; i++)
        {
            int type = resp[pos + 15];
            var name = Encoding.ASCII.GetString(resp, pos, 15)
                .TrimEnd(' ', '\0', '\x1a');
            pos += 18;
            if (type == 0x00 || type == 0x20)
            {
                if (name.Length > 0) return name;
            }
        }
        return null;
    }
}
