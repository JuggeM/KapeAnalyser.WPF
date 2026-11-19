using System.Globalization;
using System.Text;
using KapeAnalyser.WPF.Core;

namespace KapeAnalyser.WPF.Reporting;

/// <summary>Writes one host's output: QuickWins.txt, Findings.csv, Logons.csv and host.txt.</summary>
public static class HostReport
{
    public const string QuickWinsFile = "QuickWins.txt";
    public const string FindingsFile = "Findings.csv";
    public const string LogonsFile = "Logons.csv";
    public const string SessionsFile = "Sessions.csv";
    public const int MaxSessions = 30;
    public const string HostInfoFile = "host.txt";
    public const string IocHitsFile = "IocHits.csv";
    public const int MaxPerSection = 300;
    public const int MaxKeyFindings = 30;

    private static readonly UTF8Encoding Utf8 = new(false);

    public sealed record HostInfo(string Hostname, string Collection, string KapeRoot, IReadOnlyCollection<string> Ips);

    public static void Write(string outDir, HostInfo host, AnalysisContext ctx,
                             IReadOnlyList<(string Source, string Module, bool Enabled)> modules,
                             string caseName, string analyst)
    {
        Directory.CreateDirectory(outDir);
        var findings = ctx.Findings
            .OrderBy(f => f.Severity).ThenBy(f => f.TimeUtc ?? DateTime.MaxValue).ToList();

        File.WriteAllText(Path.Combine(outDir, HostInfoFile),
            $"Hostname={host.Hostname}\nCollection={host.Collection}\nKapeRoot={host.KapeRoot}\nIPs={string.Join(",", host.Ips)}\n", Utf8);

        WriteFindingsCsv(Path.Combine(outDir, FindingsFile), host.Hostname, findings);
        WriteLogonsCsv(Path.Combine(outDir, LogonsFile), host.Hostname, ctx.Logons.Values);
        WriteSessionsCsv(Path.Combine(outDir, SessionsFile), host.Hostname, ctx.Sessions);
        File.WriteAllText(Path.Combine(outDir, QuickWinsFile), BuildQuickWins(host, ctx, findings, modules, caseName, analyst), Utf8);
    }

    // ── QuickWins.txt ────────────────────────────────────────────────
    private static string BuildQuickWins(HostInfo host, AnalysisContext ctx, List<Finding> findings,
        IReadOnlyList<(string Source, string Module, bool Enabled)> modules, string caseName, string analyst)
    {
        // Same sections and line formats as CsirtParser's QuickWins.txt, so both
        // tools read alike and QuickWinsRtf can lay the file out as tables.
        var sb = new StringBuilder();
        sb.AppendLine("##########################################");
        sb.AppendLine("# Quick Wins - KAPE Analyser");
        sb.AppendLine($"# Generated on {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine("##########################################");

        // Timeline Coverage: the event log span when there are event logs, else every source
        var spanSources = ctx.Coverage.Values.Where(c => c.Source == "EVTX" && c.First.HasValue).ToList();
        if (spanSources.Count == 0) spanSources = ctx.Coverage.Values.Where(c => c.First.HasValue).ToList();
        Header(sb, "Timeline Coverage");
        sb.AppendLine($"First Log Entry: {(spanSources.Count > 0 ? Fmt(spanSources.Min(c => c.First)) + " UTC" : "-")}");
        sb.AppendLine($"Last Log Entry:  {(spanSources.Count > 0 ? Fmt(spanSources.Max(c => c.Last)) + " UTC" : "-")}");
        sb.AppendLine();

        // HOST
        Header(sb, "HOST");
        sb.AppendLine($"  Host:       {host.Hostname}");
        sb.AppendLine($"  Collection: {host.Collection}");
        sb.AppendLine($"  IP:         {(host.Ips.Count > 0 ? string.Join(", ", host.Ips) : "unknown (not found in the registry)")}");
        sb.AppendLine("  Timezone:   all times UTC (EZ Tools output)");
        if (ctx.Config.FilterFrom.HasValue || ctx.Config.FilterTo.HasValue)
            sb.AppendLine($"  Date filter: findings from {ctx.Config.FilterFrom:yyyy-MM-dd} to {ctx.Config.FilterTo:yyyy-MM-dd}");
        if (caseName.Length > 0) sb.AppendLine($"  Case:       {caseName}");
        if (analyst.Length > 0) sb.AppendLine($"  Analyst:    {analyst}");
        sb.AppendLine($"  KAPE output: {host.KapeRoot}");
        sb.AppendLine();

        // KEY FINDINGS
        Header(sb, "KEY FINDINGS (critical/high, all sources)");
        var key = findings.Where(f => f.Severity <= Severity.High).ToList();
        if (key.Count == 0) sb.AppendLine("  No CRITICAL or HIGH findings.");
        else
        {
            sb.AppendLine($"  {key.Count(f => f.Severity == Severity.Critical)} critical, {key.Count(f => f.Severity == Severity.High)} high " +
                          $"across {key.Select(f => f.Source).Distinct().Count()} source(s)" +
                          (key.Count > MaxKeyFindings ? $" — top {MaxKeyFindings} shown, rest in the sections below" : ""));
            sb.AppendLine();
            foreach (var f in key.Take(MaxKeyFindings))
                sb.AppendLine($"  {f.SeverityText,-8} {f.TimeText}  [{f.Source}] {f.Text}{CountSuffix(f)}");
        }
        sb.AppendLine();

        // IOCs seen in findings
        Header(sb, "IOCs (indicators seen in findings)");
        var iocs = FindingIndicators.Extract(findings.Select(f => (f.Source, f.Text, f.Detail)), host.Ips);
        if (iocs.Count == 0) sb.AppendLine("  No IOCs extracted from findings.");
        else
        {
            sb.AppendLine("  Values pulled from findings; more sources = stronger link. Verify before blocking.");
            sb.AppendLine();
            foreach (var kv in iocs.OrderByDescending(k => k.Value.Count).ThenBy(k => FindingIndicators.KindOrder(k.Key.Kind))
                                   .ThenBy(k => k.Key.Value, StringComparer.OrdinalIgnoreCase).Take(MaxIocs))
                sb.AppendLine($"  {kv.Key.Kind,-8} {kv.Key.Value,-42} {kv.Value.Count} source(s): {string.Join(", ", kv.Value.OrderBy(s => s))}");
            if (iocs.Count > MaxIocs) sb.AppendLine($"  … {iocs.Count - MaxIocs} more");
        }
        sb.AppendLine();

        // COVERAGE (CsirtParser's CoverageTable layout)
        Header(sb, "COVERAGE (what was checked)");
        sb.AppendLine($"  {"Source",-14} {"Files",5}  {"Time range (UTC)",-35}  {"Crit",4} {"High",4} {"Med",4}  Status");
        sb.AppendLine($"  {new string('-', 14)} {new string('-', 5)}  {new string('-', 35)}  {new string('-', 4)} {new string('-', 4)} {new string('-', 4)}  {new string('-', 12)}");
        var missing = new List<string>();
        foreach (var (source, module, enabled) in modules)
        {
            if (!enabled) { missing.Add($"  {source,-14} {"-",5}  {"",-35}  {"",4} {"",4} {"",4}  disabled"); continue; }
            if (!ctx.Coverage.TryGetValue(source, out var c) || c.Files.Count == 0)
            {
                missing.Add($"  {source,-14} {"-",5}  {"",-35}  {"",4} {"",4} {"",4}  not found ({module})");
                continue;
            }
            var mine = findings.Where(f => f.Source == source).ToList();
            int crit = mine.Count(f => f.Severity == Severity.Critical), high = mine.Count(f => f.Severity == Severity.High),
                med = mine.Count(f => f.Severity >= Severity.Medium);
            var range = c.First.HasValue ? $"{c.First:yyyy-MM-dd HH:mm} → {c.Last:yyyy-MM-dd HH:mm}" : "(no timestamps)";
            var status = crit + high > 0 ? "REVIEW" : med > 0 ? "minor" : "clean";
            sb.AppendLine($"  {source,-14} {c.Files.Count,5}  {range,-35}  {crit,4} {high,4} {med,4}  {status}");
        }
        foreach (var m in missing) sb.AppendLine(m);
        sb.AppendLine();

        // LOGONS
        var logons = ctx.Logons.Values.OrderByDescending(l => DetectionRules.IsExternalIp(l.SourceIp)).ThenByDescending(l => l.Count).ToList();
        if (logons.Count > 0)
        {
            Header(sb, "INBOUND LOGONS (network, RDP, admin shares — by source)");
            foreach (var l in logons.Take(40))
            {
                var src = string.Join(" ", new[] { l.SourceHost, l.SourceIp.Length > 0 ? $"({l.SourceIp})" : "" }.Where(s => s.Length > 0));
                var ext = DetectionRules.IsExternalIp(l.SourceIp) ? " EXTERNAL" : "";
                sb.AppendLine($"  {l.LogonType,-20}  {l.User,-28} from {src,-34} x{l.Count,-5} {Fmt(l.First)} → {Fmt(l.Last)}  [{l.Via}]{ext}");
            }
            if (logons.Count > 40) sb.AppendLine($"  … {logons.Count - 40} more in {LogonsFile}");
            sb.AppendLine();
        }

        // LOGON SESSIONS: who had a desktop, from where, and for how long (network logons are in Sessions.csv)
        var desk = ctx.Sessions.Where(s => s.LogonType is "Interactive" or "RemoteInteractive" or "CachedInteractive" or "Unlock")
            .OrderByDescending(s => DetectionRules.IsExternalIp(s.SourceIp)).ThenByDescending(s => s.Duration ?? TimeSpan.MaxValue)
            .ToList();
        if (desk.Count > 0)
        {
            Header(sb, "LOGON SESSIONS (interactive and RDP — all sessions in Sessions.csv)");
            foreach (var s in desk.Take(MaxSessions))
            {
                var src = string.Join(" ", new[] { s.SourceHost, s.SourceIp.Length > 0 ? $"({s.SourceIp})" : "" }.Where(x => x.Length > 0));
                if (src.Length == 0) src = "local";
                var ext = DetectionRules.IsExternalIp(s.SourceIp) ? " EXTERNAL" : "";
                var dur = s.Duration is TimeSpan d ? Analysers.EventLogAnalyser.Dur(d) : "open";
                sb.AppendLine($"  {s.LogonType,-20}  {s.User,-28} from {src,-34} {Fmt(s.Start)} → {(s.End.HasValue ? Fmt(s.End) : "-")}  {dur,8}  [{s.Via}{(s.EndedBy.Length > 0 ? " / " + s.EndedBy : "")}]{ext}");
            }
            if (desk.Count > MaxSessions) sb.AppendLine($"  … {desk.Count - MaxSessions} more in {SessionsFile}");
            sb.AppendLine();
        }

        // Per-source sections: "  <artifact>: [SEV] [time UTC] text", detail indented below
        foreach (var (source, _, _) in modules)
        {
            var list = findings.Where(f => f.Source == source).ToList();
            if (list.Count == 0) continue;
            int files = Math.Max(1, list.Select(f => f.Artifact).Where(a => a.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).Count());
            sb.AppendLine($"########## [{source}] — {list.Count} finding(s) across {files} file(s) ##########");
            foreach (var f in list.Take(MaxPerSection))
            {
                var artifact = f.Artifact.Replace(": ", " ").Trim();
                sb.AppendLine(artifact.Length > 0 ? $"  {artifact}: {f.ToLine()}" : $"  {f.ToLine()}");
                if (f.Detail.Length > 0) sb.AppendLine($"      {OneLine(f.Detail, 400)}");
            }
            if (list.Count > MaxPerSection) sb.AppendLine($"  … {list.Count - MaxPerSection} more (lower severity) in {FindingsFile}");
            sb.AppendLine();
        }

        // PATTERN COUNTS: one line per source, like CsirtParser
        Header(sb, "PATTERN COUNTS (all sources)");
        foreach (var g in findings.GroupBy(f => f.Source).OrderBy(g => g.Key))
            sb.AppendLine($"  [{g.Key}] " + string.Join(", ", g.GroupBy(f => f.Category)
                .OrderByDescending(c => c.Count()).ThenBy(c => c.Key).Select(c => $"{c.Key} x{c.Count()}")));
        return sb.ToString();
    }

    public const int MaxIocs = 25;

    private static void Header(StringBuilder sb, string title) => sb.AppendLine($"########## {title} ##########");

    private static string CountSuffix(Finding f) => f.Count > 1 ? $" (x{f.Count}{(f.LastUtc.HasValue && f.LastUtc != f.TimeUtc ? $", last {f.LastUtc:yyyy-MM-dd HH:mm:ss}" : "")})" : "";

    internal static string Fmt(DateTime? t) => t.HasValue ? t.Value.ToString("yyyy-MM-dd HH:mm:ss") : "-";

    private static string OneLine(string s, int max)
    {
        s = s.Replace("\r", " ").Replace("\n", " ").Replace("\t", " ");
        return s.Length > max ? s[..max] + "…" : s;
    }

    // ── CSV outputs ──────────────────────────────────────────────────
    public static readonly string[] FindingsHeader =
        { "TimeUtc", "LastUtc", "Host", "Severity", "Source", "Category", "Count", "Text", "Detail", "Artifact" };

    private static void WriteFindingsCsv(string path, string host, List<Finding> findings)
    {
        using var w = new StreamWriter(path, false, Utf8);
        w.WriteLine(string.Join(",", FindingsHeader));
        foreach (var f in findings.OrderBy(f => f.TimeUtc ?? DateTime.MaxValue))
            w.WriteLine(Csv.Row(Iso(f.TimeUtc), Iso(f.LastUtc), host, f.SeverityText, f.Source, f.Category,
                f.Count.ToString(CultureInfo.InvariantCulture), f.Text, f.Detail, f.Artifact));
    }

    private static void WriteLogonsCsv(string path, string host, IEnumerable<LogonRecord> logons)
    {
        using var w = new StreamWriter(path, false, Utf8);
        w.WriteLine("Host,User,LogonType,SourceHost,SourceIp,Via,Count,First,Last");
        foreach (var l in logons.OrderBy(l => l.First ?? DateTime.MaxValue))
            w.WriteLine(Csv.Row(host, l.User, l.LogonType, l.SourceHost, l.SourceIp, l.Via,
                l.Count.ToString(CultureInfo.InvariantCulture), Iso(l.First), Iso(l.Last)));
    }

    private static void WriteSessionsCsv(string path, string host, IEnumerable<LogonSession> sessions)
    {
        using var w = new StreamWriter(path, false, Utf8);
        w.WriteLine("Host,User,LogonType,SourceHost,SourceIp,Start,End,DurationMinutes,EndedBy,Id,Via");
        foreach (var s in sessions.OrderBy(s => s.Start ?? DateTime.MaxValue))
            w.WriteLine(Csv.Row(host, s.User, s.LogonType, s.SourceHost, s.SourceIp, Iso(s.Start), Iso(s.End),
                s.Duration is TimeSpan d ? Math.Round(d.TotalMinutes, 1).ToString(CultureInfo.InvariantCulture) : "",
                s.EndedBy, s.Id, s.Via));
    }

    internal static string Iso(DateTime? t) => t.HasValue ? t.Value.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) : "";

    // ── IOC hits block (inserted after the banner, replaced on re-search) ──
    public const string IocSectionTitle = "CASE IOC HITS (analyst IOC list, iocs.txt)";

    public static void WriteIocHits(string outDir, string host, List<IocHit> hits, int iocCount)
    {
        var csvPath = Path.Combine(outDir, IocHitsFile);
        using (var w = new StreamWriter(csvPath, false, Utf8))
        {
            w.WriteLine("Host,Type,Ioc,Comment,Hits,First,Last,Sources,Sample");
            foreach (var h in hits)
                w.WriteLine(Csv.Row(host, h.Ioc.Type, h.Ioc.Value, h.Ioc.Comment, h.Count.ToString(CultureInfo.InvariantCulture),
                    Iso(h.First), Iso(h.Last), string.Join(" ", h.Sources), h.Sample));
        }

        var qw = Path.Combine(outDir, QuickWinsFile);
        if (!File.Exists(qw)) return;
        var lines = File.ReadAllLines(qw).ToList();

        // Remove an earlier IOC block
        int start = lines.FindIndex(l => l.StartsWith("########## CASE IOC HITS", StringComparison.Ordinal));
        if (start >= 0)
        {
            int end = lines.FindIndex(start + 1, l => l.StartsWith("##########", StringComparison.Ordinal));
            lines.RemoveRange(start, (end < 0 ? lines.Count : end) - start);
        }

        var block = new List<string> { $"########## {IocSectionTitle} ##########" };
        if (hits.Count == 0) block.Add($"  None of the {iocCount} case IOC(s) seen on this host.");
        else
        {
            block.Add($"  {hits.Count} of {iocCount} case IOC(s) seen on this host — treat as CRITICAL until explained.");
            foreach (var h in hits)
                block.Add($"  [CRITICAL] {h.Ioc.Type,-7} {h.Ioc.Value,-40} {h.Count,5} hit(s)  {Fmt(h.First)} → {Fmt(h.Last)}  in {string.Join(", ", h.Sources)}" +
                          (h.Ioc.Comment.Length > 0 ? $"  # {h.Ioc.Comment}" : ""));
        }
        block.Add("");

        int insertAt = lines.FindIndex(l => l.StartsWith("########## HOST", StringComparison.Ordinal));
        lines.InsertRange(insertAt < 0 ? 0 : insertAt, block);
        File.WriteAllLines(qw, lines, Utf8);
    }
}

public static class Csv
{
    public static string Row(params string[] cols) => string.Join(",", cols.Select(Escape));

    public static string Escape(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.IndexOfAny(new[] { ',', '"', '\r', '\n' }) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    }
}
