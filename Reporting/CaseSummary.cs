using System.Globalization;
using System.Text;
using KapeAnalyser.WPF.Core;

namespace KapeAnalyser.WPF.Reporting;

/// <summary>
/// Case-wide view built only from processed output (so it also covers hosts
/// processed in earlier runs): hosts ranked by severity, lateral movement
/// between case hosts, sources that logged on to several hosts, IOC hits,
/// IOCs across hosts, a case timeline and the top findings per host.
/// Writes Processed\CaseSummary.txt and Processed\CaseFindings.csv. The
/// loaders are shared with the case report.
/// </summary>
public static class CaseSummary
{
    public const string FileName = "CaseSummary.txt";
    public const string MergedFindingsFile = "CaseFindings.csv";
    private const int MaxIocs = 30;
    private const int TopPerHost = 8;

    /// <summary>One row of a host's Findings.csv.</summary>
    public sealed record CaseFinding(DateTime? TimeUtc, DateTime? LastUtc, string Host, string Severity, int Rank,
                                     string Source, string Category, int Count, string Text, string Detail, string Artifact, string[] Raw);

    public sealed class HostData
    {
        public string Dir = "", Hostname = "", Collection = "";
        public List<string> Ips = new();
        public List<CaseFinding> Findings = new();
        public List<string[]> Logons = new();   // Host,User,LogonType,SourceHost,SourceIp,Via,Count,First,Last
        public List<string[]> IocHits = new();  // Host,Type,Ioc,Comment,Hits,First,Last,Sources,Sample
        public bool IocSearched;
    }

    /// <summary>A link from one case host to another, with the strongest evidence.</summary>
    public sealed record LateralLink(string From, string To, LinkEvidence Evidence)
    {
        public DateTime? TimeUtc => Evidence.TimeUtc;
    }

    /// <summary>What shows the link: a logon record or a finding that names the other host's address.</summary>
    public sealed record LinkEvidence(string Text, DateTime? TimeUtc, string Source);

    public static int RankOf(string sev) => sev switch { "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, _ => 3 };

    public static List<HostData> LoadHosts(string processedRoot)
    {
        if (!Directory.Exists(processedRoot)) return new();
        return Directory.GetDirectories(processedRoot)
            .Where(d => File.Exists(Path.Combine(d, HostReport.HostInfoFile)))
            .Select(Load).OrderBy(h => h.Hostname, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static string? Write(string processedRoot, string caseName, string analyst)
    {
        var hosts = LoadHosts(processedRoot);
        if (hosts.Count == 0) return null;
        var lateral = FindLateral(hosts);
        var iocHosts = IocsAcrossHosts(hosts);
        var ipOwner = IpOwners(hosts);

        var sb = new StringBuilder();
        sb.AppendLine("==========================================================================");
        sb.AppendLine(" KAPE Analyser — Case summary");
        sb.AppendLine($" Case: {caseName}   Analyst: {analyst}   Hosts: {hosts.Count}");
        sb.AppendLine($" Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC   All times UTC");
        sb.AppendLine("==========================================================================");
        sb.AppendLine();

        // Hosts ranked
        sb.AppendLine("########## HOSTS (ranked by critical, high, medium) ##########");
        sb.AppendLine($"  {"Host",-18} {"Crit",4} {"High",5} {"Med",5} {"IOC",4}  {"IPs",-24} Top finding");
        foreach (var h in Ranked(hosts))
        {
            var top = h.Findings.OrderBy(f => f.Rank).ThenBy(f => f.TimeUtc ?? DateTime.MaxValue).FirstOrDefault();
            sb.AppendLine($"  {h.Hostname,-18} {Count(h, 0),4} {Count(h, 1),5} {Count(h, 2),5} {h.IocHits.Count,4}  {Trunc(string.Join(",", h.Ips), 24),-24} " +
                          (top != null ? $"[{top.Severity}] {Trunc(top.Text, 90)}" : "-"));
        }
        sb.AppendLine();

        // Lateral movement between case hosts
        sb.AppendLine("########## LATERAL MOVEMENT (logons between case hosts, host IPs in other hosts' findings) ##########");
        if (lateral.Count == 0) sb.AppendLine("  No links between case hosts found (logon source name/IP, or a host's IP in another host's findings).");
        foreach (var l in lateral)
            sb.AppendLine($"  {(l.TimeUtc.HasValue ? l.TimeUtc.Value.ToString("yyyy-MM-dd HH:mm:ss") : "(no time)"),-19}  {l.From,-16} → {l.To,-16} [{l.Evidence.Source}] {Trunc(l.Evidence.Text, 140)}");
        sb.AppendLine();

        // Sources seen on several hosts
        sb.AppendLine("########## SOURCES LOGGING ON TO SEVERAL HOSTS ##########");
        var byName = hosts.ToDictionary(h => h.Hostname, StringComparer.OrdinalIgnoreCase);
        var multi = hosts.SelectMany(h => h.Logons.Select(l => (Src: l[4].Length > 0 ? l[4] : l[3], Host: h.Hostname, User: l[1], First: l[7])))
            .Where(x => x.Src.Length > 0 && !byName.ContainsKey(x.Src) && !ipOwner.ContainsKey(x.Src))
            .GroupBy(x => x.Src, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Select(x => x.Host).Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1)
            .OrderByDescending(g => DetectionRules.IsExternalIp(g.Key)).ThenByDescending(g => g.Select(x => x.Host).Distinct().Count())
            .ToList();
        if (multi.Count == 0) sb.AppendLine("  None.");
        foreach (var g in multi.Take(40))
            sb.AppendLine($"  {g.Key,-22}{(DetectionRules.IsExternalIp(g.Key) ? " EXTERNAL" : "         ")}  → {string.Join(", ", g.Select(x => x.Host).Distinct(StringComparer.OrdinalIgnoreCase))}" +
                          $"   users: {Trunc(string.Join(", ", g.Select(x => x.User).Distinct(StringComparer.OrdinalIgnoreCase)), 80)}   first {g.Min(x => x.First)}");
        sb.AppendLine();

        // IOC hits
        var iocHostsHit = hosts.Where(h => h.IocHits.Count > 0).ToList();
        if (iocHostsHit.Count > 0)
        {
            sb.AppendLine("########## CASE IOC HITS (host × IOC) ##########");
            foreach (var g in iocHostsHit.SelectMany(h => h.IocHits.Select(r => (Host: h.Hostname, Type: r[1], Ioc: r[2], Hits: r[4], First: r[5])))
                                         .GroupBy(x => (x.Type, x.Ioc)).OrderBy(g => g.Min(x => x.First)))
                sb.AppendLine($"  {g.Key.Type,-7} {g.Key.Ioc,-40} first {g.Min(x => x.First),-19}  on {string.Join(", ", g.Select(x => $"{x.Host} ({x.Hits})"))}");
            sb.AppendLine();
        }

        // IOCs across hosts (from findings, like CsirtParser)
        sb.AppendLine("########## IOCs ACROSS HOSTS ##########");
        if (iocHosts.Count == 0) sb.AppendLine("  No IOCs extracted.");
        else
        {
            int shared = iocHosts.Count(k => k.Value.Hosts.Count > 1);
            sb.AppendLine($"  {shared} IOC(s) seen on more than one host — likely the same actor or campaign.");
            foreach (var kv in iocHosts.OrderByDescending(k => k.Value.Hosts.Count)
                         .ThenBy(k => FindingIndicators.KindOrder(k.Key.Kind))
                         .ThenBy(k => k.Key.Value, StringComparer.OrdinalIgnoreCase)
                         .Take(MaxIocs))
            {
                var note = kv.Key.Kind == "IP" && ipOwner.TryGetValue(kv.Key.Value, out var owner)
                    ? $"   ← this is host {owner} (internal / lateral movement)" : "";
                sb.AppendLine($"  {kv.Key.Kind,-8} {kv.Key.Value,-40} {kv.Value.Hosts.Count} host(s): {string.Join(", ", kv.Value.Hosts.OrderBy(x => x))}{note}");
            }
            if (iocHosts.Count > MaxIocs) sb.AppendLine($"  … {iocHosts.Count - MaxIocs} more");
        }
        sb.AppendLine();

        // Case timeline
        sb.AppendLine("########## CASE TIMELINE (critical/high, all hosts) ##########");
        var timeline = hosts.SelectMany(h => h.Findings.Where(f => f.Rank <= 1).Select(f => (Host: h.Hostname, F: f)))
            .OrderBy(x => x.F.TimeUtc ?? DateTime.MaxValue).ToList();
        if (timeline.Count == 0) sb.AppendLine("  No CRITICAL or HIGH findings.");
        foreach (var (host, f) in timeline.Take(200))
            sb.AppendLine($"  {(f.TimeUtc.HasValue ? f.TimeUtc.Value.ToString("yyyy-MM-dd HH:mm:ss") : "(no time)"),-19}  {host,-16} {f.Severity,-9} [{f.Source}] {Trunc(f.Text, 140)}");
        if (timeline.Count > 200) sb.AppendLine($"  … {timeline.Count - 200} more in {MergedFindingsFile}");
        sb.AppendLine();

        // Top findings per host
        sb.AppendLine("########## TOP FINDINGS PER HOST ##########");
        foreach (var h in Ranked(hosts))
        {
            sb.AppendLine($"  ── {h.Hostname} ({h.Collection}) — {Count(h, 0)} critical, {Count(h, 1)} high");
            var top = h.Findings.Where(f => f.Rank <= 1).OrderBy(f => f.Rank).ThenBy(f => f.TimeUtc ?? DateTime.MaxValue).Take(TopPerHost).ToList();
            if (top.Count == 0) sb.AppendLine("     No critical or high findings.");
            foreach (var f in top)
                sb.AppendLine($"     {f.Severity,-8} {(f.TimeUtc.HasValue ? f.TimeUtc.Value.ToString("yyyy-MM-dd HH:mm:ss") : "(no time)          ")}  [{f.Source}] {Trunc(f.Text, 150)}");
            sb.AppendLine($"     → full detail: {h.Collection}\\{HostReport.QuickWinsFile}");
            sb.AppendLine();
        }

        var path = Path.Combine(processedRoot, FileName);
        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));

        // Merged findings for Timeline Explorer
        using (var w = new StreamWriter(Path.Combine(processedRoot, MergedFindingsFile), false, new UTF8Encoding(false)))
        {
            w.WriteLine(string.Join(",", HostReport.FindingsHeader));
            foreach (var f in hosts.SelectMany(h => h.Findings).OrderBy(f => f.TimeUtc ?? DateTime.MaxValue))
                w.WriteLine(Csv.Row(f.Raw));
        }
        return path;
    }

    // ── Shared with the case report ──────────────────────────────────
    /// <summary>Which case host owns which address.</summary>
    public static Dictionary<string, string> IpOwners(IEnumerable<HostData> hosts)
    {
        var owner = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in hosts)
            foreach (var ip in h.Ips) owner.TryAdd(ip, h.Hostname);
        return owner;
    }

    /// <summary>Indicator (kind, value) → hosts whose findings mention it and the sources it came from.</summary>
    public static Dictionary<(string Kind, string Value), (HashSet<string> Hosts, HashSet<string> Sources)> IocsAcrossHosts(IEnumerable<HostData> hosts)
    {
        var result = new Dictionary<(string Kind, string Value), (HashSet<string> Hosts, HashSet<string> Sources)>();
        var canon = new Dictionary<string, (string, string)>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in hosts)
            foreach (var kv in FindingIndicators.Extract(h.Findings.Select(f => (f.Source, f.Text, f.Detail))))
            {
                var key = canon.TryGetValue(kv.Key.Kind + "|" + kv.Key.Value, out var c) ? c : canon[kv.Key.Kind + "|" + kv.Key.Value] = kv.Key;
                if (!result.TryGetValue(key, out var e))
                    result[key] = e = (new HashSet<string>(StringComparer.OrdinalIgnoreCase), new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                e.Hosts.Add(h.Hostname);
                e.Sources.UnionWith(kv.Value);
            }
        return result;
    }

    /// <summary>
    /// Links between case hosts: inbound logons whose source workstation or IP
    /// is another case host, and a case host's IP showing up in another
    /// host's findings (e.g. rclone copying from \\10.10.1.30\Finance).
    /// </summary>
    public static List<LateralLink> FindLateral(List<HostData> hosts)
    {
        var byName = hosts.ToDictionary(h => h.Hostname, StringComparer.OrdinalIgnoreCase);
        var ipOwner = IpOwners(hosts);
        var links = new List<LateralLink>();

        foreach (var dest in hosts)
            foreach (var l in dest.Logons)
            {
                string? src = l[3].Length > 0 && byName.ContainsKey(l[3]) ? byName[l[3]].Hostname
                            : l[4].Length > 0 && ipOwner.TryGetValue(l[4], out var o) ? o : null;
                if (src == null || src.Equals(dest.Hostname, StringComparison.OrdinalIgnoreCase)) continue;
                links.Add(new LateralLink(src, dest.Hostname, new LinkEvidence(
                    $"{l[2]} logon as {l[1]} x{l[6]}, last {l[8]} [{l[5]}]", ParseTime(l[7]), "EVTX")));
            }

        foreach (var h in hosts)
            foreach (var (ip, owner) in ipOwner)
            {
                if (owner.Equals(h.Hostname, StringComparison.OrdinalIgnoreCase)) continue;
                var ev = h.Findings.Where(f => ContainsIp(f.Text + " " + f.Detail, ip))
                                   .OrderBy(f => f.Rank).ThenBy(f => f.TimeUtc ?? DateTime.MaxValue).FirstOrDefault();
                if (ev == null) continue;
                // Already explained by a logon between the two hosts (the IP is then the logon source)
                if (links.Any(x => (x.From.Equals(owner, StringComparison.OrdinalIgnoreCase) && x.To.Equals(h.Hostname, StringComparison.OrdinalIgnoreCase))
                                || (x.From.Equals(h.Hostname, StringComparison.OrdinalIgnoreCase) && x.To.Equals(owner, StringComparison.OrdinalIgnoreCase)))) continue;
                // Otherwise h's findings name owner's address: h reached out to owner (e.g. \\10.10.1.30\share)
                links.Add(new LateralLink(h.Hostname, owner, new LinkEvidence(ev.Text, ev.TimeUtc, ev.Source)));
            }

        return links.OrderBy(l => l.TimeUtc ?? DateTime.MaxValue).ThenBy(l => l.From).ToList();
    }

    public static bool ContainsIp(string text, string ip)
    {
        int i = 0;
        while ((i = text.IndexOf(ip, i, StringComparison.Ordinal)) >= 0)
        {
            bool before = i == 0 || !(char.IsDigit(text[i - 1]) || text[i - 1] == '.');
            int end = i + ip.Length;
            bool after = end >= text.Length || !(char.IsDigit(text[end]) || (text[end] == '.' && end + 1 < text.Length && char.IsDigit(text[end + 1])));
            if (before && after) return true;
            i = end;
        }
        return false;
    }

    private static IEnumerable<HostData> Ranked(List<HostData> hosts) =>
        hosts.OrderByDescending(h => Count(h, 0)).ThenByDescending(h => Count(h, 1)).ThenByDescending(h => Count(h, 2));

    private static HostData Load(string dir)
    {
        var h = new HostData { Dir = dir, Collection = Path.GetFileName(dir) };
        foreach (var line in File.ReadAllLines(Path.Combine(dir, HostReport.HostInfoFile)))
        {
            int eq = line.IndexOf('=');
            if (eq < 0) continue;
            var (k, v) = (line[..eq], line[(eq + 1)..]);
            if (k == "Hostname") h.Hostname = v;
            else if (k == "IPs") h.Ips = v.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList();
        }
        if (h.Hostname.Length == 0) h.Hostname = h.Collection;
        // TimeUtc,LastUtc,Host,Severity,Source,Category,Count,Text,Detail,Artifact
        h.Findings = ReadCsv(Path.Combine(dir, HostReport.FindingsFile), 10)
            .Select(r => new CaseFinding(ParseTime(r[0]), ParseTime(r[1]), h.Hostname, r[3], RankOf(r[3]), r[4], r[5],
                int.TryParse(r[6], out var n) ? n : 1, r[7], r[8], r[9], r))
            .ToList();
        h.Logons = ReadCsv(Path.Combine(dir, HostReport.LogonsFile), 9);
        var hitsFile = Path.Combine(dir, HostReport.IocHitsFile);
        h.IocSearched = File.Exists(hitsFile);
        h.IocHits = ReadCsv(hitsFile, 9);
        return h;
    }

    public static DateTime? ParseTime(string s) =>
        DateTime.TryParseExact(s, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t) ? t : null;

    private static List<string[]> ReadCsv(string path, int cols)
    {
        var rows = new List<string[]>();
        if (!File.Exists(path)) return rows;
        using var csv = new CsvReader(path);
        while (csv.Read()) rows.Add(Enumerable.Range(0, cols).Select(i => csv[i]).ToArray());
        return rows;
    }

    private static int Count(HostData h, int rank) => h.Findings.Count(f => f.Rank == rank);
    private static string Trunc(string s, int n) => s.Length <= n ? s : s[..(n - 1)] + "…";
}
