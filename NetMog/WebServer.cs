using System.Net;
using System.Reflection;
using System.Text.Json;
using NetMog.Core;

namespace NetMog;

public sealed class WebServer
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    // Comes from <Version> in NetMog.csproj, so the UI, the exe and the
    // installer can never disagree about what is running.
    private static readonly string AppVersion =
        typeof(WebServer).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion.Split('+')[0]
        ?? "0.0.0";

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

            // Only mutations coming from our own page are accepted. Without this,
            // any website the user visits could POST text/plain JSON to
            // /api/killall and cut the whole LAN (classic CSRF against localhost).
            if (method == "POST" && !TrustedMutation(ctx))
            {
                ctx.Response.StatusCode = 403;
                await Json(ctx, new { error = "Forbidden" });
                return;
            }

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
                        version = AppVersion,
                    });
                    return;

                case "GET /api/devices":
                    await Json(ctx, new
                    {
                        scanning = _dm.Scanning,
                        scanCount = _dm.ScanCount,
                        killed = _dm.Poisoner.KilledCount,
                        meteringIp = _dm.MeteredIp,
                        meteringLimit = _dm.Meter.LimitKbps,
                        defender = _dm.Poisoner.DefenderOn,
                        netLock = _dm.NetLock,
                        events = _dm.Events.Recent(30),
                        devices = _dm.Snapshot(),
                    });
                    return;

                case "GET /api/history":
                    await Json(ctx, new { events = _dm.Events.Recent(GetLimit(ctx)) });
                    return;

                case "POST /api/limit":
                    GetIp(ctx, out var limitIp, out var limitKbps);
                    await Json(ctx, new { ok = _dm.SetLimit(limitIp, limitKbps) });
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
                    await Json(ctx, new { ok = _dm.ToggleMonitor(GetIp(ctx)), metering = _dm.MeteredIp });
                    return;

                case "POST /api/defender":
                    _dm.Poisoner.SetDefender(GetBool(ctx, "on", true));
                    await Json(ctx, new { ok = true, on = _dm.Poisoner.DefenderOn });
                    return;

                case "POST /api/netlock":
                    _dm.SetNetLock(GetBool(ctx, "on", true));
                    await Json(ctx, new { ok = true, on = _dm.NetLock });
                    return;

                case "POST /api/rename":
                    GetMacName(ctx, out var renameMac, out var renameName);
                    if (!string.IsNullOrEmpty(renameMac))
                        _dm.SetDeviceName(renameMac, renameName);
                    await Json(ctx, new { ok = true });
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

    private bool TrustedMutation(HttpListenerContext ctx)
    {
        var origin = ctx.Request.Headers["Origin"];
        if (!string.IsNullOrEmpty(origin) &&
            !string.Equals(origin, $"http://127.0.0.1:{_port}", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(origin, $"http://localhost:{_port}", StringComparison.OrdinalIgnoreCase))
            return false;

        var contentType = ctx.Request.ContentType ?? "";
        return contentType.StartsWith("application/json", StringComparison.OrdinalIgnoreCase);
    }

    private static string GetIp(HttpListenerContext ctx)
    {
        GetIp(ctx, out var ip, out _);
        return ip;
    }

    private static void GetIp(HttpListenerContext ctx, out string ip, out int kbps)
    {
        ip = "";
        kbps = 0;
        using var reader = new StreamReader(ctx.Request.InputStream);
        var body = reader.ReadToEnd();
        if (string.IsNullOrWhiteSpace(body)) return;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("ip", out var p)) ip = p.GetString() ?? "";
            if (doc.RootElement.TryGetProperty("kbps", out var k) && k.TryGetInt32(out var value)) kbps = value;
        }
        catch
        {
        }
    }

    private static int GetLimit(HttpListenerContext ctx)
    {
        var raw = ctx.Request.QueryString["limit"];
        return int.TryParse(raw, out var limit) ? limit : 100;
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

    private static void GetMacName(HttpListenerContext ctx, out string mac, out string name)
    {
        mac = "";
        name = "";
        using var reader = new StreamReader(ctx.Request.InputStream);
        var body = reader.ReadToEnd();
        if (string.IsNullOrWhiteSpace(body)) return;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("mac", out var m)) mac = m.GetString() ?? "";
            if (doc.RootElement.TryGetProperty("name", out var n)) name = n.GetString() ?? "";
        }
        catch
        {
        }
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
        using var stream = asm.GetManifestResourceStream($"NetMog.web.{name}");
        if (stream == null)
        {
            ctx.Response.StatusCode = 404;
            return;
        }

        ctx.Response.ContentType = name switch
        {
            "index.html" => "text/html; charset=utf-8",
            "app.js" => "application/javascript; charset=utf-8",
            "style.css" => "text/css; charset=utf-8",
            _ => "application/octet-stream",
        };
        ctx.Response.ContentLength64 = stream.Length;
        await stream.CopyToAsync(ctx.Response.OutputStream);
    }

    public void WaitForExit() => _exit.Wait();
}