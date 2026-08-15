using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using NetcutClone.Core;
using SharpPcap;

namespace NetcutClone;

static class Program
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);

    private static readonly ManualResetEventSlim _exit = new();

    [STAThread]
    static void Main()
    {
        if (!IsAdministrator())
        {
            Msg("NetcutClone must run as Administrator to inject raw ARP packets.",
                "Administrator required");
            return;
        }

        var npcapDll = Path.Combine(Environment.SystemDirectory, "Npcap", "wpcap.dll");
        var winpcapDll = Path.Combine(Environment.SystemDirectory, "wpcap.dll");
        if (!File.Exists(npcapDll) && !File.Exists(winpcapDll))
        {
            Msg("WinPcap 4.1.3 or Npcap (WinPcap API-compatible mode) is not installed.\n\n" +
                "Install WinPcap 4.1.3, or download Npcap from https://npcap.com\n" +
                "and install it with the 'WinPcap API-compatible Mode' checkbox checked.",
                "pcap library missing");
            return;
        }

        var net = NetworkInfo.Discover();
        if (net == null)
        {
            Msg("No active network adapter with a gateway was found.", "No network");
            return;
        }

        if (!MatchPcapAdapter(net))
        {
            Msg("No Npcap device matches the active network adapter.", "Npcap device not found");
            return;
        }

        var dm = new DeviceManager(net);
        dm.Start();

        var port = PickPort();
        if (port == 0)
        {
            Msg("Could not find a free local port for the web UI.", "Server error");
            return;
        }

        var server = new WebServer(dm, net, port);
        try
        {
            server.Start();
        }
        catch (Exception ex)
        {
            Msg($"Could not start the local web server: {ex.Message}", "Server error");
            return;
        }

        OpenBrowser(port);
        server.WaitForExit();
    }

    private static bool MatchPcapAdapter(NetworkInfo net)
    {
        foreach (var dev in CaptureDeviceList.Instance)
        {
            bool match = false;
            try
            {
                match = dev.MacAddress != null && dev.MacAddress.Equals(net.LocalMac);
            }
            catch
            {
            }
            if (!match)
                match = dev.Description?.Contains(net.AdapterDescription, StringComparison.OrdinalIgnoreCase) == true;
            if (match)
            {
                net.AdapterName = dev.Name;
                return true;
            }
        }
        return false;
    }

    private static int PickPort()
    {
        for (int p = 8899; p <= 8918; p++)
        {
            try
            {
                using var probe = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, p);
                probe.Start();
                probe.Stop();
                return p;
            }
            catch
            {
            }
        }
        return 0;
    }

    private static void OpenBrowser(int port)
    {
        try
        {
            Process.Start(new ProcessStartInfo($"http://127.0.0.1:{port}/")
            {
                UseShellExecute = true,
            });
        }
        catch
        {
        }
    }

    private static bool IsAdministrator() =>
        new WindowsPrincipal(WindowsIdentity.GetCurrent())
            .IsInRole(WindowsBuiltInRole.Administrator);

    private static void Msg(string text, string caption) =>
        MessageBoxW(IntPtr.Zero, text, caption, 0x10);
}