using System.Net.NetworkInformation;

namespace NetMog.Core;

/// <summary>
/// Best-effort MAC OUI vendor identification.
/// Uses the full IEEE MA-L registry (39k+ entries, generated from the
/// Wireshark manuf database). Randomized (privacy) MACs are detected and
/// flagged instead of guessed.
/// </summary>
public static class MacVendor
{
    public static bool IsRandomized(string mac)
    {
        if (!TryParseMac(mac, out var bytes)) return false;
        // Second-least-significant bit of the first octet = locally administered.
        return (bytes[0] & 0x02) != 0;
    }

    public static string? Lookup(string mac)
    {
        if (!TryParseMac(mac, out var bytes)) return null;
        var key = $"{bytes[0]:x2}{bytes[1]:x2}{bytes[2]:x2}";
        return OuiData.Lookup(key);
    }

    private static bool TryParseMac(string mac, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(mac)) return false;
        try
        {
            bytes = PhysicalAddress.Parse(mac).GetAddressBytes();
            return bytes.Length == 6 && bytes.Any(b => b != 0);
        }
        catch
        {
            return false;
        }
    }
}