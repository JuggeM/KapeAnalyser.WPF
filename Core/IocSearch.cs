using System.Text.RegularExpressions;

namespace KapeAnalyser.WPF.Core;

public sealed class IocHit
{
    public Ioc Ioc { get; init; } = null!;
    public int Count { get; set; }
    public DateTime? First { get; set; }
    public DateTime? Last { get; set; }
    public HashSet<string> Sources { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string Sample { get; set; } = "";
}

/// <summary>
/// Searches every KAPE module CSV of a host for the case IOCs (raw lines, so
/// it also covers columns no analyser looks at). Matching is exact on token
/// boundaries: 1.2.3.4 does not hit 11.2.3.45; a domain also matches its
/// subdomains; Amcache's "0000"-padded SHA1 values match.
/// </summary>
public static class IocSearch
{
    private static readonly Regex TimeRx = new(@"\b(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})", RegexOptions.Compiled);

    public static List<IocHit> SearchHost(string kapeRoot, List<Ioc> iocs, Action<string> log, CancellationToken ct)
    {
        var hits = new Dictionary<Ioc, IocHit>();
        if (iocs.Count == 0 || !Directory.Exists(kapeRoot)) return new List<IocHit>();

        // One combined regex, one named group per IOC
        var parts = iocs.Select((ioc, i) => $"(?<i{i}>{PatternFor(ioc)})");
        var rx = new Regex(string.Join("|", parts), RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);
        var groupNames = iocs.Select((_, i) => "i" + i).ToArray();

        var files = Directory.EnumerateFiles(kapeRoot, "*.csv", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true })
            .Where(f => KapeDiscovery.IsKnownCsv(Path.GetFileName(f))).ToList();

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var source = SourceLabel(Path.GetFileName(file));
            long n = 0;
            foreach (var line in File.ReadLines(file))
            {
                if ((++n & 0x3FFF) == 0) ct.ThrowIfCancellationRequested();
                var m = rx.Match(line);
                while (m.Success)
                {
                    for (int g = 0; g < groupNames.Length; g++)
                    {
                        if (!m.Groups[groupNames[g]].Success) continue;
                        var ioc = iocs[g];
                        if (!hits.TryGetValue(ioc, out var h)) hits[ioc] = h = new IocHit { Ioc = ioc, Sample = Trim(line) };
                        h.Count++;
                        h.Sources.Add(source);
                        var tm = TimeRx.Match(line);
                        if (tm.Success && CsvReader.ParseTime(tm.Groups[1].Value) is { } t)
                        {
                            if (h.First == null || t < h.First) h.First = t;
                            if (h.Last == null || t > h.Last) h.Last = t;
                        }
                        break;
                    }
                    m = m.NextMatch();
                }
            }
        }
        return hits.Values.OrderBy(h => h.First ?? DateTime.MaxValue).ToList();
    }

    private static string PatternFor(Ioc ioc)
    {
        var v = Regex.Escape(ioc.Value);
        return ioc.Type switch
        {
            "IP" => $@"(?<![\w.]){v}(?![\w]|\.\d)",
            "DOMAIN" => $@"(?<![\w-]){v}(?![\w-]|\.[a-z0-9])",
            "SHA1" or "SHA256" or "MD5" => $@"(?:(?<![0-9a-f])|(?<=(?<![0-9a-f])0000)){v}(?![0-9a-f])",
            "USER" => $@"(?<![\w.-]){v}(?![\w.-])",
            "FILE" => $@"(?<![\w.-]){v}(?![\w.-])",
            _ => v,  // URL, PATH: literal
        };
    }

    private static string SourceLabel(string file)
    {
        foreach (var a in Analysers.AnalyserRegistry.CreateAll())
            if (a.Accepts(file)) return a.Source;
        return "CSV";
    }

    private static string Trim(string s)
    {
        s = s.Replace('\t', ' ');
        return s.Length > 300 ? s[..300] + "…" : s;
    }
}
