using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Xml;
using NetcutClone.Core;
using SharpPcap;

namespace NetcutClone;

public sealed class WebServer
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    private readonly HttpListener _listener = new();
    private readonly DeviceManager _dm;
    private readonly NetworkInfo _net;
    private readonly int _port;
    private Thread? _thread;
    private readonly ManualResetEventSlim _exit = new();

    public WebServer(DeviceManager dm, NetworkInfo net, int port)
    {
        _dm = dm;
        _net = net;
        _port = port;
    }

    public int Port => _port;

    public void Start()
    {
        _listener.Prefixes.Add($"http://127.0.0.1:{_port}/");
        _listener.Start();
        _thread = new Thread(Loop) { IsBackground = true, Name = "http" };
        _thread.Start();
    }

    private void Loop()
    {
        while (_listener.IsListening)
        {
            try
            {
                var ctx = _listener.GetContext();
                _ = Task.Run(() => Handle(ctx));
            }
            catch
            {
                break;
            }
        }
    }

    private async Task Handle(HttpListenerContext ctx)
    {
        try
        {
            var path = ctx.Request.Url?.AbsolutePath ?? "/";
            var method = ctx.Request.HttpMethod;

            switch ($"{method} {path}")
            {
                case "GET /":
                case "GET /index.html":
                    await ServeStatic(ctx, "index.html");
                    return;

                case "GET /app.js":
                    await ServeStatic(ctx, "app.js");
                    return;

                case "GET /style.css":
                    await ServeStatic(ctx, "style.css");
                    return;

                case "GET /api/info":
                    await Json(ctx, new
                    {
                        adapter = _net.AdapterDescription,
                        localIp = _net.LocalIpString,
                        gateway = _net.GatewayIpString,
                        localMac = _net.LocalMacString,
                        gatewayMac = _net.GatewayMacString,
                        version = "1.0.0",
                    });
                    return;

                case "GET /api/devices":
                    await Json(ctx, new
                    {
                        scanning = _dm.Scanning,
                        scanCount = _dm.ScanCount,
                        killed = _dm.Poisoner.KilledCount,
                        packets = _dm.Poisoner.PacketsSent,
                        meteringIp = _dm.MeteredIp,
                        defender = _dm.Poisoner.DefenderOn,
                        netLock = _dm.NetLock,
                        devices = _dm.Snapshot(),
                    });
                    return;

                case "POST /api/scan":
                    _dm.StartScan();
                    await Json(ctx, new { ok = true });
                    return;

                case "POST /api/kill":
                    await Json(ctx, new { ok = _dm.Kill(GetIp(ctx)) });
                    return;

                case "POST /api/restore":
                    await Json(ctx, new { ok = _dm.Restore(GetIp(ctx)) });
                    return;

                case "POST /api/killall":
                    await Json(ctx, new { ok = true, count = _dm.KillAll() });
                    return;

                case "POST /api/restoreall":
                    await Json(ctx, new { ok = true, count = _dm.RestoreAll() });
                    return;

                case "POST /api/monitor":
                    await Json(ctx, new { ok = _dm.ToggleMonitor(GetIp(ctx), GetMode(ctx)), metering = _dm.MeteredIp });
                    return;

                case "POST /api/defender":
                    _dm.Poisoner.SetDefender(GetBool(ctx, "on", true));
                    await Json(ctx, new { ok = true, on = _dm.Poisoner.DefenderOn });
                    return;

                case "POST /api/netlock":
                    _dm.SetNetLock(GetBool(ctx, "on", true));
                    await Json(ctx, new { ok = true, on = _dm.NetLock });
                    return;

                case "POST /api/monitorstop":
                    _dm.StopMeter();
                    await Json(ctx, new { ok = true });
                    return;

                case "POST /api/shutdown":
                    await Json(ctx, new { ok = true });
                    ThreadPool.QueueUserWorkItem(_ =>
                    {
                        Thread.Sleep(300);
                        _exit.Set();
                    });
                    return;

                case "GET /api/debug":
                    await Json(ctx, new
                    {
                        selectedAdapter = _net.AdapterName,
                        adapterDescription = _net.AdapterDescription,
                        devices = CaptureDeviceList.Instance.Select(d =>
                        {
                            string mac;
                            try
                            {
                                mac = d.MacAddress?.ToString() ?? "null";
                            }
                            catch (Exception ex)
                            {
                                mac = "ERR:" + ex.Message;
                            }
                            return new { d.Name, d.Description, mac };
                        }).ToList(),
                        scanner = new
                        {
                            probed = _dm.Scanner.Probed,
                            found = _dm.Scanner.Found,
                        },
                        poisoner = new
                        {
                            started = _dm.Poisoner.IsStarted,
                            threadAlive = _dm.Poisoner.IsThreadAlive,
                            deviceOpen = _dm.Poisoner.IsDeviceOpen,
                            gatewayMac = _net.GatewayMacString,
                            packets = _dm.Poisoner.PacketsSent,
                            killed = _dm.Poisoner.KilledCount,
                            loopCount = _dm.Poisoner.LoopCount,
                            lastSendError = _dm.Poisoner.LastSendError,
                            poisonMode = _dm.Poisoner.PoisonMode,
                        },
                    });
                    return;

                case "GET /api/debug/probe":
                    var target = ctx.Request.QueryString["ip"] ?? _net.GatewayIpString;
                    var mode = ctx.Request.QueryString["mode"] ?? "";
                    var secs = ctx.Request.QueryString["secs"] ?? "20";
                    await Json(ctx, await ProbeArp(_net, target, mode, secs));
                    return;

                case "GET /api/debug/meter":
                    await Json(ctx, new
                    {
                        metering = _dm.MeteredIp,
                        running = _dm.Meter.IsMetering,
                        mode = "netcut-style",
                        rxFrames = _dm.Meter.RxFrames,
                        rxIPv4 = _dm.Meter.RxIPv4,
                        relayedUp = _dm.Meter.RelayedUp,
                        relayedDown = _dm.Meter.RelayedDown,
                        victimSrcSeen = _dm.Meter.VictimSrcSeen,
                        victimDstSeen = _dm.Meter.VictimDstSeen,
                        pairsTop = _dm.Meter.PairsTop,
                        recent = _dm.Meter.Recent,
                        targetDesc = _dm.Meter.TargetDesc,
                        lastError = _dm.Meter.LastError,
                    });
                    return;

                case "GET /api/debug/upnp":
                    await Json(ctx, await ProbeUpnp());
                    return;

                case "GET /api/debug/snmp":
                    await Json(ctx, await ProbeSnmp(_net));
                    return;

                default:
                    ctx.Response.StatusCode = 404;
                    await Json(ctx, new { error = "Not found" });
                    return;
            }
        }
        catch (Exception ex)
        {
            try
            {
                ctx.Response.StatusCode = 500;
                await Json(ctx, new { error = ex.Message });
            }
            catch
            {
            }
        }
        finally
        {
            try
            {
                ctx.Response.Close();
            }
            catch
            {
            }
        }
    }

    private static string GetIp(HttpListenerContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.InputStream);
        var body = reader.ReadToEnd();
        if (string.IsNullOrWhiteSpace(body)) return "";
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("ip", out var p) ? p.GetString() ?? "" : "";
        }
        catch
        {
            return "";
        }
    }

    private static string GetMode(HttpListenerContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.InputStream);
        var body = reader.ReadToEnd();
        if (string.IsNullOrWhiteSpace(body)) return "";
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("mode", out var p) ? p.GetString() ?? "" : "";
        }
        catch
        {
            return "";
        }
    }

    private static bool GetBool(HttpListenerContext ctx, string name, bool def)
    {
        using var reader = new StreamReader(ctx.Request.InputStream);
        var body = reader.ReadToEnd();
        if (string.IsNullOrWhiteSpace(body)) return def;
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty(name, out var p) ? p.GetBoolean() : def;
        }
        catch
        {
            return def;
        }
    }

    private static async Task<object> ProbeSnmp(NetworkInfo net)
    {
        byte[] pkt =
        {
            0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63,
            0xA0, 0x1C, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
            0x05, 0x00
        };
        try
        {
            using var c = new System.Net.Sockets.UdpClient();
            c.Client.ReceiveTimeout = 2000;
            await c.SendAsync(pkt, pkt.Length, new IPEndPoint(IPAddress.Parse(net.GatewayIpString), 161));
            var resp = await c.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(2.5));
            byte[] oid = { 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00 };
            var data = resp.Buffer;
            string sysDescr = "";
            for (int i = 0; i + oid.Length <= data.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < oid.Length; j++)
                    if (data[i + j] != oid[j]) { match = false; break; }
                if (!match) continue;
                int p = i + oid.Length;
                if (p + 2 <= data.Length && data[p] == 0x04)
                {
                    int len = data[p + 1];
                    if (p + 2 + len <= data.Length)
                        sysDescr = System.Text.Encoding.ASCII.GetString(data, p + 2, len);
                }
                break;
            }
            return new { ok = true, snmp = true, sysDescr };
        }
        catch
        {
            return new { ok = true, snmp = false, sysDescr = "" };
        }
    }

    private static async Task<object> ProbeUpnp()
    {
        var msg = "M-SEARCH * HTTP/1.1\r\n" +
                  "HOST: 239.255.255.250:1900\r\n" +
                  "MAN: \"ssdp:discover\"\r\n" +
                  "MX: 2\r\n" +
                  "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
        var locations = new List<string>();
        try
        {
            using var c = new System.Net.Sockets.UdpClient();
            c.Client.ReceiveTimeout = 3000;
            var bytes = System.Text.Encoding.ASCII.GetBytes(msg);
            await c.SendAsync(bytes, bytes.Length, new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900));
            var sw = System.Diagnostics.Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < 3500)
            {
                try
                {
                    var resp = await c.ReceiveAsync().WaitAsync(TimeSpan.FromMilliseconds(1200));
                    var text = System.Text.Encoding.ASCII.GetString(resp.Buffer);
                    foreach (var line in text.Split('\n'))
                    {
                        if (line.StartsWith("LOCATION:", StringComparison.OrdinalIgnoreCase))
                        {
                            var url = line[(line.IndexOf(':') + 1)..].Trim();
                            if (url.StartsWith("http", StringComparison.OrdinalIgnoreCase) && !locations.Contains(url))
                                locations.Add(url);
                        }
                    }
                }
                catch
                {
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            return new { error = ex.Message, locations = locations.ToList() };
        }

        var results = new List<object>();
        foreach (var loc in locations.Take(4))
        {
            try
            {
                using var hc = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
                var xml = await hc.GetStringAsync(loc);
                var doc = new XmlDocument();
                doc.LoadXml(xml);
                string friendly = "";
                string model = "";
                try { friendly = doc.GetElementsByTagName("friendlyName")[0]?.InnerText ?? ""; } catch { }
                try { model = doc.GetElementsByTagName("modelName")[0]?.InnerText ?? ""; } catch { }
                var services = new List<object>();
                try
                {
                    foreach (XmlNode svc in doc.GetElementsByTagName("service"))
                    {
                        string st = "", ctl = "", scpd = "";
                        foreach (XmlNode child in svc.ChildNodes)
                        {
                            if (child.Name == "serviceType") st = child.InnerText;
                            else if (child.Name == "controlURL") ctl = child.InnerText;
                            else if (child.Name == "SCPDURL") scpd = child.InnerText;
                        }
                        if (st.Length > 0)
                            services.Add(new { serviceType = st, controlUrl = ctl, scpdUrl = scpd });
                    }
                }
                catch { }
                results.Add(new { location = loc, friendlyName = friendly, modelName = model, services });
            }
            catch (Exception ex)
            {
                results.Add(new { location = loc, error = ex.Message });
            }
        }
        return new { locations = locations.ToList(), results };
    }

    private static async Task Json(HttpListenerContext ctx, object payload)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOpts);
        ctx.Response.ContentType = "application/json; charset=utf-8";
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes);
    }

    private static async Task ServeStatic(HttpListenerContext ctx, string name)
    {
        var asm = Assembly.GetExecutingAssembly();
        using var stream = asm.GetManifestResourceStream($"NetcutClone.web.{name}");
        if (stream == null)
        {
            ctx.Response.StatusCode = 404;
            return;
        }

        var bytes = new byte[stream.Length];
        await stream.ReadAsync(bytes);
        ctx.Response.ContentType = name switch
        {
            "index.html" => "text/html; charset=utf-8",
            "app.js" => "application/javascript; charset=utf-8",
            "style.css" => "text/css; charset=utf-8",
            _ => "application/octet-stream",
        };
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes);
    }

    public void WaitForExit() => _exit.Wait();

    private static async Task<object> ProbeArp(NetworkInfo net, string targetIp, string mode, string secs)
    {
        var dev = net.CreateDevice();
        dev.Open(DeviceModes.Promiscuous, 200);

        var events = new List<string>();
        var frames = new List<string>();
        var sw = System.Diagnostics.Stopwatch.StartNew();

        PacketArrivalEventHandler handler = (s, e) =>
        {
            if (e.Data.Length < 42) return;
            try
            {
                var raw = e.Data.ToArray();
                var pkt = PacketDotNet.Packet.ParsePacket(PacketDotNet.LinkLayers.Ethernet, raw);
                if (pkt is PacketDotNet.EthernetPacket eth && eth.PayloadPacket is PacketDotNet.ArpPacket arp)
                {
                    events.Add($"{sw.ElapsedMilliseconds}ms len={raw.Length} op={(int)arp.Operation} sender={arp.SenderProtocolAddress} ({arp.SenderHardwareAddress}) target={arp.TargetProtocolAddress}");
                    if (mode == "frames")
                        frames.Add($"arp\t{sw.ElapsedMilliseconds}\t{(int)arp.Operation}\t{arp.SenderProtocolAddress}\t{arp.SenderHardwareAddress}\t{arp.TargetProtocolAddress}");
                }
                else if (mode == "frames" && pkt is PacketDotNet.EthernetPacket eth2 && eth2.PayloadPacket is PacketDotNet.IPv4Packet ip)
                {
                    frames.Add($"ip\t{sw.ElapsedMilliseconds}\t{eth2.SourceHardwareAddress}\t{eth2.DestinationHardwareAddress}\t{ip.SourceAddress}\t{ip.DestinationAddress}\t{(int)ip.Protocol}\t{ip.TimeToLive}");
                }
            }
            catch
            {
            }
        };
        dev.OnPacketArrival += handler;
        dev.StartCapture();

        if (mode == "frames")
        {
            var secsNum = 20;
            try { secsNum = Math.Clamp(int.Parse(secs), 3, 120); } catch { }
            Thread.Sleep(secsNum * 1000);
            sw.Stop();
            dev.StopCapture();
            dev.OnPacketArrival -= handler;
            dev.Close();
            return new { targetIp, elapsedMs = sw.ElapsedMilliseconds, frames, count = frames.Count };
        }

        if (mode == "passive")
        {
            // Capture-only: open the device, never inject. Verifies whether
            // merely opening the adapter disturbs ARP on this Wi-Fi card.
            Thread.Sleep(6000);
            sw.Stop();
            dev.StopCapture();
            dev.OnPacketArrival -= handler;
            dev.Close();
            return new { targetIp, elapsedMs = sw.ElapsedMilliseconds, events };
        }

        var injectCount = mode == "min" ? 1 : 5;
        var zeros = System.Net.NetworkInformation.PhysicalAddress.Parse("00-00-00-00-00-00");
        var bcast = System.Net.NetworkInformation.PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF");
        var target = IPAddress.Parse(targetIp);

        // Phase 1 (0-1.5s): passive
        Thread.Sleep(1500);

        // Phase 2 (1.5-3.5s): inject raw ARP requests
        for (int i = 0; i < injectCount; i++)
        {
            var arp = new PacketDotNet.ArpPacket(PacketDotNet.ArpOperation.Request, zeros, target,
                net.LocalMac, net.LocalIp);
            var eth = new PacketDotNet.EthernetPacket(net.LocalMac, bcast, PacketDotNet.EthernetType.Arp)
            {
                PayloadPacket = arp
            };
            dev.SendPacket(eth);
            Thread.Sleep(400);
        }

        // Phase 3 (3.5-5.5s): OS-native SendARP (ground truth: does the gateway reply at all?)
        for (int i = 0; i < 3; i++)
        {
            var mac = ArpWinApi.ResolveMac(target);
            events.Add($"{sw.ElapsedMilliseconds}ms SendARP -> {(mac ?? "no-reply")}");
            Thread.Sleep(400);
        }
        Thread.Sleep(500);
        sw.Stop();

        dev.StopCapture();
        dev.OnPacketArrival -= handler;
        dev.Close();

        return new
        {
            targetIp,
            elapsedMs = sw.ElapsedMilliseconds,
            events,
        };
    }
}