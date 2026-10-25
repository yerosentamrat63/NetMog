using System.Text;
using System.Text.Json;
using NetMog.Models;

namespace NetMog.Core;

/// <summary>
/// Ring buffer plus an append-only JSONL file of network events, so what
/// happened on the LAN (joins, leaves, cuts, restores) is still readable after
/// the process restarts. The file is compacted once it grows past 1 MiB.
/// </summary>
public sealed class EventLog
{
    private const int Capacity = 500;
    private const long FileSizeLimit = 1_048_576;

    private readonly string _file;
    private readonly List<NetMogEvent> _events = new();
    private readonly object _lock = new();
    private long _seq;

    public EventLog(string file)
    {
        _file = file;
        Load();
    }

    public NetMogEvent Add(string kind, string ip, string mac, string name, string message)
    {
        lock (_lock)
        {
            var entry = new NetMogEvent
            {
                Seq = ++_seq,
                At = DateTime.UtcNow,
                Kind = kind,
                Ip = ip ?? "",
                Mac = mac ?? "",
                Name = name ?? "",
                Message = message ?? "",
            };
            _events.Add(entry);
            if (_events.Count > Capacity) _events.RemoveRange(0, _events.Count - Capacity);
            AppendLocked(entry);
            return entry;
        }
    }

    /// <summary>Newest last.</summary>
    public List<NetMogEvent> Recent(int limit)
    {
        lock (_lock)
        {
            var take = Math.Clamp(limit, 1, Capacity);
            return _events.Skip(Math.Max(0, _events.Count - take)).ToList();
        }
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_file)) return;
            foreach (var line in File.ReadLines(_file))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                NetMogEvent? entry;
                try { entry = JsonSerializer.Deserialize<NetMogEvent>(line); }
                catch { continue; }
                if (entry == null) continue;
                _events.Add(entry);
                if (entry.Seq > _seq) _seq = entry.Seq;
            }
            if (_events.Count > Capacity) _events.RemoveRange(0, _events.Count - Capacity);
        }
        catch
        {
        }
    }

    private void AppendLocked(NetMogEvent entry)
    {
        try
        {
            var info = new FileInfo(_file);
            if (info.Exists && info.Length > FileSizeLimit) CompactLocked();
            File.AppendAllText(_file, JsonSerializer.Serialize(entry) + Environment.NewLine, Encoding.UTF8);
        }
        catch
        {
        }
    }

    private void CompactLocked()
    {
        try
        {
            var text = string.Join(Environment.NewLine, _events.Select(e => JsonSerializer.Serialize(e)));
            File.WriteAllText(_file, text + Environment.NewLine, Encoding.UTF8);
        }
        catch
        {
        }
    }
}
