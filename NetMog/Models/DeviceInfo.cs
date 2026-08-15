namespace NetMog.Models;

public enum DeviceState
{
    Online,
    Cut,
    Monitoring
}

public sealed class DeviceInfo
{
    public required string Ip { get; init; }
    public string Mac { get; set; } = "";
    public string HostName { get; set; } = "";
    public string Vendor { get; set; } = "";
    public bool RandomizedMac { get; set; }
    public DeviceState State { get; set; } = DeviceState.Online;
    public bool IsSelf { get; set; }
    public bool IsGateway { get; set; }
    public long BytesDown { get; set; }
    public long BytesUp { get; set; }
    public double DownKbps { get; set; }
    public double UpKbps { get; set; }
    public DateTime LastSeen { get; set; } = DateTime.UtcNow;
    public string CustomName { get; set; } = "";
}