using KapeAnalyser.WPF.Models;

namespace KapeAnalyser.WPF.Core;

/// <summary>One inbound logon pattern (aggregated), used for Logons.csv and lateral movement.</summary>
public sealed class LogonRecord
{
    public string User { get; set; } = "";
    public string LogonType { get; set; } = "";
    public string SourceHost { get; set; } = "";
    public string SourceIp { get; set; } = "";
    public string Via { get; set; } = "";      // "4624", "RDP 1149", "RDP 21/25"
    public int Count { get; set; }
    public DateTime? First { get; set; }
    public DateTime? Last { get; set; }
}

/// <summary>
/// One logon session: start from 4624 (or RDP LocalSessionManager 21), end
/// from the matching 4634/4647 (same logon ID) or RDP 23/24 (same session).
/// No end means the session was still open at collection, or the log rolled.
/// </summary>
public sealed class LogonSession
{
    public string User { get; set; } = "";
    public string LogonType { get; set; } = "";
    public string SourceHost { get; set; } = "";
    public string SourceIp { get; set; } = "";
    /// <summary>TargetLogonId (4624) or RDP session ID.</summary>
    public string Id { get; set; } = "";
    public DateTime? Start { get; set; }
    public DateTime? End { get; set; }
    /// <summary>"4634", "4647", "RDP 23 logoff", "RDP 24 disconnect".</summary>
    public string EndedBy { get; set; } = "";
    public string Via { get; set; } = "";
    public TimeSpan? Duration => Start.HasValue && End.HasValue && End >= Start ? End - Start : null;
    public bool IsRdp => LogonType == "RemoteInteractive" || Via.StartsWith("RDP", StringComparison.Ordinal);
}

/// <summary>Per-source coverage: which KAPE outputs were read and what time span they hold.</summary>
public sealed class SourceCoverage
{
    public string Source { get; init; } = "";
    public List<string> Files { get; } = new();
    public long Rows { get; set; }
    public DateTime? First { get; set; }
    public DateTime? Last { get; set; }

    public void See(DateTime? t)
    {
        if (!t.HasValue) return;
        if (First == null || t < First) First = t;
        if (Last == null || t > Last) Last = t;
    }
}

/// <summary>State shared by all analysers while one host is processed.</summary>
public sealed class AnalysisContext
{
    public AnalyserConfig Config { get; }
    public DetectionRules Rules { get; }
    public Action<string> Log { get; }
    public CancellationToken Cancel { get; }
    public string HostFolder { get; }

    public List<Finding> Findings { get; } = new();
    public Dictionary<string, SourceCoverage> Coverage { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Hostname votes (EvtxECmd Computer column, registry ComputerName).</summary>
    public Dictionary<string, long> HostnameVotes { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, LogonRecord> Logons { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<LogonSession> Sessions { get; } = new();
    public HashSet<string> HostIps { get; } = new(StringComparer.OrdinalIgnoreCase);

    public AnalysisContext(AnalyserConfig config, string hostFolder, Action<string> log, CancellationToken ct)
    {
        Config = config;
        Rules = new DetectionRules(config);
        HostFolder = hostFolder;
        Log = log;
        Cancel = ct;
    }

    public SourceCoverage CoverageFor(string source)
    {
        if (!Coverage.TryGetValue(source, out var c))
            Coverage[source] = c = new SourceCoverage { Source = source };
        return c;
    }

    public bool InDateRange(DateTime? t)
    {
        if (!t.HasValue) return true;
        if (Config.FilterFrom.HasValue && t.Value < Config.FilterFrom.Value.Date) return false;
        if (Config.FilterTo.HasValue && t.Value >= Config.FilterTo.Value.Date.AddDays(1)) return false;
        return true;
    }

    public void Add(Finding f)
    {
        if (InDateRange(f.TimeUtc) || InDateRange(f.LastUtc)) Findings.Add(f);
    }

    public void AddRange(IEnumerable<Finding> fs) { foreach (var f in fs) Add(f); }

    public void VoteHostname(string? name, long weight = 1)
    {
        if (string.IsNullOrWhiteSpace(name)) return;
        var n = name.Trim();
        int dot = n.IndexOf('.');
        if (dot > 0) n = n[..dot];
        n = n.ToUpperInvariant();
        if (n is "-" or "LOCALHOST" or "MINWINPC") return;
        HostnameVotes[n] = HostnameVotes.GetValueOrDefault(n) + weight;
    }

    public void RecordLogon(string user, string type, string srcHost, string srcIp, string via, DateTime? t)
    {
        srcHost = string.IsNullOrWhiteSpace(srcHost) || srcHost == "-" ? "" : srcHost.Trim().ToUpperInvariant();
        srcIp = DetectionRules.IsUsableIp(srcIp) ? srcIp.Trim() : "";
        if (srcHost.Length == 0 && srcIp.Length == 0) return;
        var key = $"{user}|{type}|{srcHost}|{srcIp}|{via}";
        if (!Logons.TryGetValue(key, out var r))
            Logons[key] = r = new LogonRecord { User = user, LogonType = type, SourceHost = srcHost, SourceIp = srcIp, Via = via };
        r.Count++;
        if (t.HasValue)
        {
            if (r.First == null || t < r.First) r.First = t;
            if (r.Last == null || t > r.Last) r.Last = t;
        }
    }
}

/// <summary>
/// One KAPE module output type (EvtxECmd, PECmd, …). An instance is created
/// per host, so analysers can keep state across files and emit aggregated
/// findings in <see cref="Complete"/>.
/// </summary>
public interface IArtifactAnalyser
{
    /// <summary>Short tag used in findings and QuickWins section headers.</summary>
    string Source { get; }
    /// <summary>KAPE module / tool name shown in COVERAGE.</summary>
    string Module { get; }
    bool Enabled(AnalyserConfig config);
    /// <summary>True when this analyser reads the given CSV (by file name).</summary>
    bool Accepts(string fileName);
    void Analyse(string csvPath, AnalysisContext ctx);
    void Complete(AnalysisContext ctx);
}

/// <summary>
/// An analyser that reads raw files collected from the host (PowerShell
/// history, web server logs) instead of EZ Tools CSVs. The engine lists the
/// host's KAPE output folder and its matching extracted collection in
/// Decompressed\ once, and hands every file this analyser accepts to
/// <see cref="IArtifactAnalyser.Analyse"/>. <see cref="IArtifactAnalyser.Accepts"/> is false for every CSV.
/// </summary>
public interface IRawFileAnalyser : IArtifactAnalyser
{
    /// <summary>True when this analyser reads the given file (full path, so parent folders can be checked).</summary>
    bool AcceptsRaw(string path);
}
