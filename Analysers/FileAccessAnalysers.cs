using System.Text.RegularExpressions;
using KapeAnalyser.WPF.Core;
using KapeAnalyser.WPF.Models;

namespace KapeAnalyser.WPF.Analysers;

/// <summary>
/// Shared logic for LECmd (.lnk) and JLECmd (jump lists): what a user opened.
/// Flags targets that are tools or sit in staging folders, LNK arguments with
/// attack techniques (malicious shortcuts), admin-share paths, and files
/// opened from removable media (grouped per volume).
/// </summary>
public abstract class LinkAnalyserBase : IArtifactAnalyser
{
    public abstract string Source { get; }
    public abstract string Module { get; }
    public abstract bool Enabled(AnalyserConfig c);
    public abstract bool Accepts(string f);

    private static readonly Regex AdminShare = new(@"^\\\\[^\\]+\\(ADMIN|[A-Z])\$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private readonly FindingAggregator _agg = new();

    public void Analyse(string csvPath, AnalysisContext ctx)
    {
        using var csv = new CsvReader(csvPath);
        int cSrc = csv.Col("SourceFile"), cCreated = csv.Col("SourceCreated"), cModified = csv.Col("LastModified", "SourceModified"),
            cLocal = csv.Col("LocalPath"), cPath = csv.Col("Path"), cNet = csv.Col("NetworkPath"), cCommon = csv.Col("CommonPath"),
            cAbs = csv.Col("TargetIDAbsolutePath"), cArgs = csv.Col("Arguments"), cDrive = csv.Col("DriveType"),
            cLabel = csv.Col("VolumeLabel"), cSerial = csv.Col("VolumeSerialNumber"), cApp = csv.Col("AppIdDescription");
        if (cSrc < 0) return;
        var cov = ctx.CoverageFor(Source);
        cov.Files.Add(csvPath);

        while (csv.Read())
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            cov.Rows++;
            var opened = CsvReader.ParseTime(csv[cModified]) ?? CsvReader.ParseTime(csv[cCreated]);
            cov.See(opened);

            var net = csv[cNet];
            var target = First(csv[cLocal], csv[cPath], net.Length > 0 ? (net.TrimEnd('\\') + "\\" + csv[cCommon]).TrimEnd('\\') : "", csv[cAbs]);
            if (target.Length == 0) continue;
            var args = csv[cArgs];
            var user = UserOf(csv[cSrc]);
            var app = csv[cApp];
            var artifact = DetectionRules.FileNameOf(csv[cSrc]);

            var hits = ctx.Rules.MatchCommandLine(args);
            if (hits.Count > 0)
            {
                _agg.Add($"args|{target}|{args}", (Severity)Math.Min((int)hits.Min(h => h.Severity), (int)Severity.High), opened, Source,
                    "Shortcut with malicious arguments",
                    $"Shortcut {artifact} ({user}) runs {DetectionRules.FileNameOf(target)} with: {string.Join(", ", hits.Select(h => h.Label).Distinct())}",
                    EventLogAnalyser.Trunc($"{target} {args}", 1000), artifact);
                continue;
            }

            var score = ctx.Rules.ScoreBinaryPath(target);
            if (score != null)
            {
                _agg.Add($"tgt|{target}", score.Value.Sev, opened, Source, score.Value.Reason,
                    $"Opened by {user}: {DetectionRules.FileNameOf(target)} — {score.Value.Reason}", target, artifact);
                continue;
            }

            if (AdminShare.IsMatch(target))
            {
                var host = target.Split('\\', StringSplitOptions.RemoveEmptyEntries)[0];
                _agg.Add($"share|{user}|{host}", Severity.Medium, opened, Source, "Admin share browsed",
                    $"{user} opened files on admin share of {host}", "", artifact, extra: target);
                continue;
            }

            if (csv[cDrive].Contains("Removable", StringComparison.OrdinalIgnoreCase))
            {
                var vol = First(csv[cLabel], csv[cSerial], "unknown volume");
                _agg.Add($"usb|{user}|{vol}", Severity.Suspicious, opened, Source, "File opened from removable media",
                    $"{user} opened file(s) from removable media '{vol}'{(app.Length > 0 ? $" ({app})" : "")}", "", artifact, extra: target);
                continue;
            }

            if (DetectionRules.IsArchive(target) && ctx.Rules.StagingDir(target) is { } dir)
                _agg.Add($"arch|{target}", Severity.Suspicious, opened, Source, "Archive in staging folder opened",
                    $"{user} opened archive {DetectionRules.FileNameOf(target)} in {dir}", target, artifact);
        }
    }

    private static string First(params string[] v) => v.FirstOrDefault(s => !string.IsNullOrWhiteSpace(s))?.Trim() ?? "";

    private static string UserOf(string path)
    {
        var m = Regex.Match(path ?? "", @"\\Users\\([^\\]+)\\", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value : "unknown user";
    }

    public void Complete(AnalysisContext ctx) => ctx.AddRange(_agg.Flush((text, n, extras) => n > 1 ? $"{text} — {n} item(s)" : text));
}

public sealed class LnkAnalyser : LinkAnalyserBase
{
    public override string Source => "LNK";
    public override string Module => "LECmd";
    public override bool Enabled(AnalyserConfig c) => c.AnalyseLnk;
    public override bool Accepts(string f) => f.EndsWith("_LECmd_Output.csv", StringComparison.OrdinalIgnoreCase);
}

public sealed class JumpListAnalyser : LinkAnalyserBase
{
    public override string Source => "JUMPLIST";
    public override string Module => "JLECmd";
    public override bool Enabled(AnalyserConfig c) => c.AnalyseJumpLists;
    public override bool Accepts(string f) =>
        f.EndsWith("_AutomaticDestinations.csv", StringComparison.OrdinalIgnoreCase)
        || f.EndsWith("_CustomDestinations.csv", StringComparison.OrdinalIgnoreCase);
}

/// <summary>SBECmd output: folders a user browsed (shellbags), including folders since deleted.</summary>
public sealed class ShellbagsAnalyser : IArtifactAnalyser
{
    public string Source => "SHELLBAGS";
    public string Module => "SBECmd";
    public bool Enabled(AnalyserConfig c) => c.AnalyseShellbags;
    public bool Accepts(string f) =>
        f.EndsWith(".csv", StringComparison.OrdinalIgnoreCase)
        && (f.Contains("UsrClass", StringComparison.OrdinalIgnoreCase) || f.Contains("NTUSER", StringComparison.OrdinalIgnoreCase)
            || f.Equals("Deduplicated.csv", StringComparison.OrdinalIgnoreCase) || f.Contains("SBECmd", StringComparison.OrdinalIgnoreCase))
        && !f.Contains("RECmd", StringComparison.OrdinalIgnoreCase);

    private static readonly Regex Interesting = new(
        @"\b(mimikatz|rclone|exfil|loot|dump|dumps|hashes|creds|passwords?|sharphound|bloodhound|lazagne|procdump|psexec|cobalt|beacon|tools?|hack|payloads?|ransom|staging)\b|\\\\[^\\]+\\(ADMIN|[A-Z])\$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly FindingAggregator _agg = new();

    public void Analyse(string csvPath, AnalysisContext ctx)
    {
        using var csv = new CsvReader(csvPath);
        int cPath = csv.Col("AbsolutePath"), cTime = csv.Col("LastInteracted", "LastWriteTime", "AccessedOn");
        if (cPath < 0) return; // not shellbags output
        var cov = ctx.CoverageFor(Source);
        cov.Files.Add(csvPath);
        var user = Regex.Match(Path.GetFileName(csvPath), @"Users_([^_]+)_", RegexOptions.IgnoreCase) is { Success: true } m ? m.Groups[1].Value : "user";

        while (csv.Read())
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            cov.Rows++;
            var t = CsvReader.ParseTime(csv[cTime]);
            cov.See(t);
            var path = csv[cPath];
            var mm = Interesting.Match(path);
            var tool = ctx.Rules.MatchTool(path.TrimEnd('\\') + ".exe"); // folder named after a tool
            if (!mm.Success && tool == null) continue;
            var sev = tool != null ? (Severity)Math.Max((int)tool.Severity, (int)Severity.Medium) : Severity.Suspicious;
            _agg.Add($"sb|{path}", sev, t, Source, "Folder browsed",
                $"Folder browsed by {user}: {EventLogAnalyser.Trunc(path, 160)}" + (tool != null ? $" — {tool.Category}" : $" ('{mm.Value}')"),
                path, DetectionRules.FileNameOf(csvPath));
        }
    }

    public void Complete(AnalysisContext ctx) => ctx.AddRange(_agg.Flush());
}
