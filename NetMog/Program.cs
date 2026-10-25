using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using NetMog.Core;
using SharpPcap;

namespace NetMog;

static class Program
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);

    private const string MutexName = @"Global\NetMog_SingleInstance_Mutex";
    private static readonly string PortFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetMog", "port.txt");

    [STAThread]
    static void Main()
    {
        using var mutex = new Mutex(true, MutexName, out bool createdNew);
        if (!createdNew)
        {
            // Single-instance: NetMog is already running in background.
            // Open the browser to the existing server instance and exit.
            int runningPort = ReadSavedPort();
            OpenBrowser(runningPort > 0 ? runningPort : 8899);
            return;
        }

        if (!IsAdministrator())
        {
            Msg("NetMog must run as Administrator to inject raw ARP packets.",
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
            Msg("No pcap device matches the active network adapter.", "pcap device not found");
            return;
        }

        DeviceManager? dm = null;
        AppDomain.CurrentDomain.ProcessExit += (_, _) => dm?.Dispose();
        AppDomain.CurrentDomain.UnhandledException += (_, _) => dm?.Dispose();
        try
        {
            dm = new DeviceManager(net);
            dm.Start();

            var port = PickPort();
            if (port == 0)
            {
                Msg("Could not find a free local port for the web UI.", "Server error");
                return;
            }

            SavePort(port);

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

            dm.StartScan();

            OpenBrowser(port);
            server.WaitForExit();
        }
        finally
        {
            // Always undo our ARP poisoning, whatever way we exit.
            dm?.Dispose();
        }
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

    private static void SavePort(int port)
    {
        try
        {
            var dir = Path.GetDirectoryName(PortFilePath);
            if (dir != null && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(PortFilePath, port.ToString());
        }
        catch { }
    }

    private static int ReadSavedPort()
    {
        try
        {
            if (File.Exists(PortFilePath) && int.TryParse(File.ReadAllText(PortFilePath).Trim(), out int port))
                return port;
        }
        catch { }
        return 0;
    }

    private static bool IsAdministrator() =>
        new WindowsPrincipal(WindowsIdentity.GetCurrent())
            .IsInRole(WindowsBuiltInRole.Administrator);

    private static void Msg(string text, string caption) =>
        MessageBoxW(IntPtr.Zero, text, caption, 0x10);
}