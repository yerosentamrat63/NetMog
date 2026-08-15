using System.Net;
using System.Runtime.InteropServices;

namespace NetcutClone.Core;

/// <summary>
/// OS-based ARP resolution via the Windows IP Helper API.
/// Avoids Npcap injection entirely, which some Wi-Fi drivers drop silently.
/// </summary>
public static class ArpWinApi
{
    private const uint NO_ERROR = 0;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;

    [DllImport("iphlpapi.dll")]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] mac, ref uint macLen);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetIpNetTable(IntPtr table, ref uint size, bool sort);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibIpNetRow
    {
        public uint Index;
        public uint PhysAddrLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] PhysAddr;
        public uint Addr;
        public uint Type;
    }

    public static string? ResolveMac(IPAddress ip)
    {
        try
        {
            var bytes = ip.GetAddressBytes();
            uint dest = BitConverter.ToUInt32(bytes.Reverse().ToArray(), 0);
            byte[] mac = new byte[6];
            uint len = 6;
            if (SendARP(dest, 0, mac, ref len) == NO_ERROR && len >= 6)
            {
                bool allZero = true;
                foreach (var b in mac)
                {
                    if (b != 0) { allZero = false; break; }
                }
                if (allZero) return null;
                return string.Join(":", mac.Select(b => b.ToString("X2")));
            }
        }
        catch
        {
        }
        return null;
    }

    public static Dictionary<string, string> ReadNeighborTable()
    {
        var result = new Dictionary<string, string>();
        try
        {
            uint size = 0;
            if (GetIpNetTable(IntPtr.Zero, ref size, false) != ERROR_INSUFFICIENT_BUFFER) return result;

            IntPtr table = Marshal.AllocHGlobal((int)size);
            try
            {
                if (GetIpNetTable(table, ref size, false) != NO_ERROR) return result;

                int rows = Marshal.ReadInt32(table);
                IntPtr rowPtr = table + 4;
                for (int i = 0; i < rows; i++)
                {
                    var row = Marshal.PtrToStructure<MibIpNetRow>(rowPtr);
                    rowPtr += Marshal.SizeOf<MibIpNetRow>();
                    if (row.Type is 3 or 4) // dynamic / static
                    {
                        var ip = new IPAddress(row.Addr);
                        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            var mac = string.Join(":", row.PhysAddr.Take(6).Select(b => b.ToString("X2")));
                            result[ip.ToString()] = mac;
                        }
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(table);
            }
        }
        catch
        {
        }
        return result;
    }
}