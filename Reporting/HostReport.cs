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
        File.WriteAllText(Path.Combine(outDir, QuickWinsFile), BuildQuickWins(host, ctx, findings, modules, caseName, analyst), Utf8);
    }

    // ── QuickWins.txt ────────────────────────────────────────────────
    private static string BuildQuickWins(HostInfo host, AnalysisContext ctx, List<Finding> findings,
        IReadOnlyList<(string Source, string Module, bool Enabled)> modules, string caseName, string analyst)
    {
        var sb = new StringBuilder();
        sb.AppendLine("==========================================================================");
        sb.AppendLine(" KAPE Analyser — QuickWins");
        sb.AppendLine($" Host: {host.Hostname}   Collection: {host.Collection}");
        if (caseName.Length > 0 || analyst.Length > 0) sb.AppendLine($" Case: {caseName}   Analyst: {analyst}");
        sb.AppendLine($" Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine("==========================================================================");
        sb.AppendLine();

        // HOST
        Header(sb, "HOST");
        sb.AppendLine($"  Host: {host.Hostname}   IP(s): {(host.Ips.Count > 0 ? string.Join(", ", host.Ips) : "not found in registry")}");
        sb.AppendLine($"  KAPE output: {host.KapeRoot}");
        var first = ctx.Coverage.Values.Where(c => c.Source == "EVTX").Select(c => c.First).FirstOrDefault()
                    ?? ctx.Coverage.Values.Min(c => c.First);
        var last = ctx.Coverage.Values.Max(c => c.Last);
        sb.AppendLine($"  Event log span: {Fmt(first)} → {Fmt(last)}   All times UTC (EZ Tools output)");
        if (ctx.Config.FilterFrom.HasValue || ctx.Config.FilterTo.HasValue)
            sb.AppendLine($"  Date filter: findings from {ctx.Config.FilterFrom:yyyy-MM-dd} to {ctx.Config.FilterTo:yyyy-MM-dd}");
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
                sb.AppendLine($"  {f.SeverityText,-10} {f.TimeText}  [{f.Source}] {f.Text}{CountSuffix(f)}");
        }
        sb.AppendLine();

        // COVERAGE
        Header(sb, "COVERAGE (what was checked)");
        sb.AppendLine($"  {"Source",-11} {"Module",-22} {"Files",5} {"Rows",12}  {"First",-19}   {"Last",-19}  Findings");
        foreach (var (source, module, enabled) in modules)
        {
            int n = findings.Count(f => f.Source == source);
            if (!enabled) { sb.AppendLine($"  {source,-11} {module,-22} (disabled)"); continue; }
            if (!ctx.Coverage.TryGetValue(source, out var c) || c.Files.Count == 0)
            {
                sb.AppendLine($"  {source,-11} {module,-22} not found — module not run or no output");
                continue;
            }
            sb.AppendLine($"  {source,-11} {module,-22} {c.Files.Count,5} {c.Rows,12:N0}  {Fmt(c.First),-19} → {Fmt(c.Last),-19}  {n}");
        }
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
                sb.AppendLine($"  {l.LogonType,-17} {l.User,-28} from {src,-34} x{l.Count,-5} {Fmt(l.First)} → {Fmt(l.Last)}  [{l.Via}]{ext}");
            }
            if (logons.Count > 40) sb.AppendLine($"  … {logons.Count - 40} more in {LogonsFile}");
            sb.AppendLine();
        }

        // Per-source sections
        foreach (var (source, _, _) in modules)
        {
            var list = findings.Where(f => f.Source == source).ToList();
            if (list.Count == 0) continue;
            sb.AppendLine($"########## [{source}] — {list.Count} finding(s) ##########");
            foreach (var f in list.Take(MaxPerSection))
            {
                sb.AppendLine($"  {f.ToLine()}");
                if (f.Detail.Length > 0) sb.AppendLine($"      {OneLine(f.Detail, 400)}");
            }
            if (list.Count > MaxPerSection) sb.AppendLine($"  … {list.Count - MaxPerSection} more (lower severity) in {FindingsFile}");
            sb.AppendLine();
        }

        // PATTERN COUNTS
        Header(sb, "PATTERN COUNTS (all sources)");
        foreach (var g in findings.GroupBy(f => (f.Source, f.Category)).OrderBy(g => g.Min(f => f.Severity)).ThenByDescending(g => g.Count()))
            sb.AppendLine($"  {g.Key.Source,-11} {g.Key.Category,-50} {g.Count(),5}");
        return sb.ToString();
    }

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
