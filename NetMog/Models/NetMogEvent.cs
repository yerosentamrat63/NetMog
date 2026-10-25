namespace NetMog.Models;

/// <summary>One entry in the network activity log.</summary>
public sealed class NetMogEvent
{
    public long Seq { get; set; }
    public DateTime At { get; set; }
    public string Kind { get; set; } = "";
    public string Ip { get; set; } = "";
    public string Mac { get; set; } = "";
    /// <summary>Device name at the time of the event (empty for app-level events).</summary>
    public string Name { get; set; } = "";
    public string Message { get; set; } = "";
}
