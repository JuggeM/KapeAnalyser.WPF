using System.Text;
using KapeAnalyser.WPF.Core;

namespace KapeAnalyser.WPF.Reporting;

/// <summary>
/// Case-wide view built only from processed output (so it also covers hosts
/// processed in earlier runs): hosts ranked by severity, lateral movement
/// between case hosts, a case timeline of critical/high findings, sources
/// that logged on to several hosts, and IOC hits per host.
/// Writes Processed\CaseSummary.txt and Processed\CaseFindings.csv.
/// </summary>
public static class CaseSummary
{
    public const string FileName = "CaseSummary.txt";
    public const string MergedFindingsFile = "CaseFindings.csv";

    private sealed class HostData
    {
        public string Dir = "", Hostname = "", Collection = "";
        public List<string> Ips = new();
        public List<string[]> Findings = new();  // FindingsHeader columns
        public List<string[]> Logons = new();
        public List<string[]> IocHits = new();
    }

    public static string? Write(string processedRoot, string caseName, string analyst)
    {
        if (!Directory.Exists(processedRoot)) return null;
        var hosts = Directory.GetDirectories(processedRoot)
            .Where(d => File.Exists(Path.Combine(d, HostReport.HostInfoFile)))
            .Select(Load).OrderBy(h => h.Hostname, StringComparer.OrdinalIgnoreCase).ToList();
        if (hosts.Count == 0) return null;

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
        foreach (var h in hosts.OrderByDescending(h => Count(h, "CRITICAL")).ThenByDescending(h => Count(h, "HIGH")).ThenByDescending(h => Count(h, "MEDIUM")))
        {
            var top = h.Findings.OrderBy(f => Rank(f[3])).ThenBy(f => f[0]).FirstOrDefault();
            sb.AppendLine($"  {h.Hostname,-18} {Count(h, "CRITICAL"),4} {Count(h, "HIGH"),5} {Count(h, "MEDIUM"),5} {h.IocHits.Count,4}  {Trunc(string.Join(",", h.Ips), 24),-24} " +
                          (top != null ? $"[{top[3]}] {Trunc(top[7], 90)}" : "-"));
        }
        sb.AppendLine();

        // Lateral movement between case hosts
        sb.AppendLine("########## LATERAL MOVEMENT (logons between case hosts) ##########");
        var byName = hosts.ToDictionary(h => h.Hostname, StringComparer.OrdinalIgnoreCase);
        var byIp = hosts.SelectMany(h => h.Ips.Select(ip => (ip, h))).GroupBy(x => x.ip).ToDictionary(g => g.Key, g => g.First().h);
        var edges = new List<string>();
        foreach (var dest in hosts)
            foreach (var l in dest.Logons) // Host,User,LogonType,SourceHost,SourceIp,Via,Count,First,Last
            {
                HostData? src = null;
                if (l[3].Length > 0 && byName.TryGetValue(l[3], out var s1)) src = s1;
                else if (l[4].Length > 0 && byIp.TryGetValue(l[4], out var s2)) src = s2;
                if (src == null || ReferenceEquals(src, dest)) continue;
                edges.Add($"  {l[7],-19}  {src.Hostname,-16} → {dest.Hostname,-16} {l[2],-17} {l[1],-26} x{l[6],-5} last {l[8]}  [{l[5]}]");
            }
        if (edges.Count == 0) sb.AppendLine("  No logons from one case host to another found (source workstation name or host IP).");
        else foreach (var e in edges.OrderBy(e => e)) sb.AppendLine(e);
        sb.AppendLine();

        // Sources seen on several hosts
        sb.AppendLine("########## SOURCES LOGGING ON TO SEVERAL HOSTS ##########");
        var multi = hosts.SelectMany(h => h.Logons.Select(l => (Src: l[4].Length > 0 ? l[4] : l[3], Host: h.Hostname, User: l[1], First: l[7])))
            .Where(x => x.Src.Length > 0 && !byName.ContainsKey(x.Src) && !byIp.ContainsKey(x.Src))
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
        var iocHosts = hosts.Where(h => h.IocHits.Count > 0).ToList();
        if (iocHosts.Count > 0)
        {
            sb.AppendLine("########## CASE IOC HITS (host × IOC) ##########");
            foreach (var g in iocHosts.SelectMany(h => h.IocHits.Select(r => (Host: h.Hostname, Type: r[1], Ioc: r[2], Hits: r[4], First: r[5])))
                                      .GroupBy(x => (x.Type, x.Ioc)).OrderBy(g => g.Min(x => x.First)))
                sb.AppendLine($"  {g.Key.Type,-7} {g.Key.Ioc,-40} first {g.Min(x => x.First),-19}  on {string.Join(", ", g.Select(x => $"{x.Host} ({x.Hits})"))}");
            sb.AppendLine();
        }

        // Case timeline
        sb.AppendLine("########## CASE TIMELINE (critical/high, all hosts) ##########");
        var timeline = hosts.SelectMany(h => h.Findings.Where(f => Rank(f[3]) <= 1).Select(f => (Host: h.Hostname, F: f)))
            .OrderBy(x => x.F[0].Length == 0 ? "9999" : x.F[0]).ToList();
        if (timeline.Count == 0) sb.AppendLine("  No CRITICAL or HIGH findings.");
        foreach (var (host, f) in timeline.Take(200))
            sb.AppendLine($"  {(f[0].Length > 0 ? f[0] : "(no time)"),-19}  {host,-16} {f[3],-9} [{f[4]}] {Trunc(f[7], 140)}");
        if (timeline.Count > 200) sb.AppendLine($"  … {timeline.Count - 200} more in {MergedFindingsFile}");

        var path = Path.Combine(processedRoot, FileName);
        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));

        // Merged findings for Timeline Explorer
        using (var w = new StreamWriter(Path.Combine(processedRoot, MergedFindingsFile), false, new UTF8Encoding(false)))
        {
            w.WriteLine(string.Join(",", HostReport.FindingsHeader));
            foreach (var f in hosts.SelectMany(h => h.Findings).OrderBy(f => f[0].Length == 0 ? "9999" : f[0]))
                w.WriteLine(Csv.Row(f));
        }
        return path;
    }

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
        h.Findings = ReadCsv(Path.Combine(dir, HostReport.FindingsFile), 10);
        h.Logons = ReadCsv(Path.Combine(dir, HostReport.LogonsFile), 9);
        h.IocHits = ReadCsv(Path.Combine(dir, HostReport.IocHitsFile), 9);
        return h;
    }

    private static List<string[]> ReadCsv(string path, int cols)
    {
        var rows = new List<string[]>();
        if (!File.Exists(path)) return rows;
        using var csv = new CsvReader(path);
        while (csv.Read()) rows.Add(Enumerable.Range(0, cols).Select(i => csv[i]).ToArray());
        return rows;
    }

    private static int Count(HostData h, string sev) => h.Findings.Count(f => f[3] == sev);
    private static int Rank(string sev) => sev switch { "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, _ => 3 };
    private static string Trunc(string s, int n) => s.Length <= n ? s : s[..(n - 1)] + "…";
}
