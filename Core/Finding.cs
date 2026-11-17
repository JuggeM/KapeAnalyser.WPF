namespace KapeAnalyser.WPF.Core;

public enum Severity { Critical = 0, High = 1, Medium = 2, Suspicious = 3 }

/// <summary>
/// One analyst-facing finding. Repeated events (e.g. 300 failed logons from
/// one IP) are collapsed by the analyser into a single finding with a count
/// and a first/last time, so QuickWins stays readable.
/// </summary>
public sealed class Finding
{
    public Severity Severity { get; init; }
    public DateTime? TimeUtc { get; init; }
    public DateTime? LastUtc { get; init; }
    public int Count { get; init; } = 1;
    /// <summary>Short source tag: EVTX, PREFETCH, AMCACHE, SHIMCACHE, REGISTRY, LNK, JUMPLIST, MFT, USNJRNL, RECYCLEBIN, SHELLBAGS.</summary>
    public string Source { get; init; } = "";
    /// <summary>Pattern label used for PATTERN COUNTS, e.g. "Service installed".</summary>
    public string Category { get; init; } = "";
    public string Text { get; init; } = "";
    /// <summary>Supporting detail (command line, path, hash) — kept out of the one-line text.</summary>
    public string Detail { get; init; } = "";
    /// <summary>Artifact the finding came from (source file / log channel).</summary>
    public string Artifact { get; init; } = "";

    public static string SeverityLabel(Severity s) => s switch
    {
        Severity.Critical => "CRITICAL",
        Severity.High => "HIGH",
        Severity.Medium => "MEDIUM",
        _ => "SUSPICIOUS",
    };

    public string SeverityText => SeverityLabel(Severity);

    public string TimeText => TimeUtc.HasValue ? TimeUtc.Value.ToString("yyyy-MM-dd HH:mm:ss") : "(no time)          ";

    /// <summary>"[SEVERITY] [time UTC] text" — same shape as CsirtParser's finding lines.</summary>
    public string ToLine()
    {
        var span = Count > 1 && LastUtc.HasValue && TimeUtc.HasValue && LastUtc.Value != TimeUtc.Value
            ? $" (x{Count}, last {LastUtc.Value:yyyy-MM-dd HH:mm:ss})"
            : Count > 1 ? $" (x{Count})" : "";
        var when = TimeUtc.HasValue ? $"[{TimeUtc.Value:yyyy-MM-dd HH:mm:ss} UTC]" : "[no-timestamp]";
        return $"[{SeverityText}] {when} {Text}{span}";
    }
}

/// <summary>
/// Collapses repeated events into one finding per key: counts them and keeps
/// the first/last time and the first sample's text and detail.
/// </summary>
public sealed class FindingAggregator
{
    private sealed class Bucket
    {
        public Severity Severity;
        public DateTime? First, Last;
        public int Count;
        public string Source = "", Category = "", Text = "", Detail = "", Artifact = "";
        public HashSet<string>? Extras;
    }

    private readonly Dictionary<string, Bucket> _buckets = new(StringComparer.OrdinalIgnoreCase);

    public void Add(string key, Severity sev, DateTime? time, string source, string category,
                    string text, string detail = "", string artifact = "", string? extra = null)
    {
        if (!_buckets.TryGetValue(key, out var b))
        {
            b = new Bucket { Severity = sev, Source = source, Category = category, Text = text, Detail = detail, Artifact = artifact };
            _buckets[key] = b;
        }
        b.Count++;
        if (sev < b.Severity) b.Severity = sev;
        if (time.HasValue)
        {
            if (b.First == null || time < b.First) b.First = time;
            if (b.Last == null || time > b.Last) b.Last = time;
        }
        if (!string.IsNullOrEmpty(extra))
        {
            b.Extras ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (b.Extras.Count < 20) b.Extras.Add(extra);
        }
    }

    public int Count => _buckets.Count;

    public IEnumerable<Finding> Flush(Func<string, int, IReadOnlyCollection<string>, string>? textFor = null)
    {
        foreach (var (key, b) in _buckets)
        {
            var extras = (IReadOnlyCollection<string>?)b.Extras ?? Array.Empty<string>();
            yield return new Finding
            {
                Severity = b.Severity,
                TimeUtc = b.First,
                LastUtc = b.Last,
                Count = b.Count,
                Source = b.Source,
                Category = b.Category,
                Text = textFor != null ? textFor(b.Text, b.Count, extras) : b.Text,
                Detail = extras.Count > 0 && string.IsNullOrEmpty(b.Detail) ? string.Join("; ", extras) : b.Detail,
                Artifact = b.Artifact,
            };
        }
        _buckets.Clear();
    }
}
