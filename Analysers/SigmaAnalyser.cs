using KapeAnalyser.WPF.Core;
using KapeAnalyser.WPF.Models;

namespace KapeAnalyser.WPF.Analysers;

/// <summary>
/// Sigma detections from Hayabusa (dfir-timeline / csv-timeline CSV) or
/// Chainsaw (hunt --csv). Put the CSV in the host's folder under Processed\
/// with "hayabusa" or "chainsaw" in the file name (Chainsaw's own sigma.csv
/// works too). Columns are found by name, so any Hayabusa output profile and
/// both tools' layouts are read; informational hits are counted, not reported.
/// Each rule (per computer) becomes one finding with a count and first/last time.
/// </summary>
public sealed class SigmaAnalyser : IArtifactAnalyser
{
    public string Source => "SIGMA";
    public string Module => "Hayabusa / Chainsaw";
    public bool Enabled(AnalyserConfig c) => c.AnalyseSigma;
    public bool Accepts(string f) =>
        f.EndsWith(".csv", StringComparison.OrdinalIgnoreCase)
        && (f.Contains("hayabusa", StringComparison.OrdinalIgnoreCase) || f.Contains("chainsaw", StringComparison.OrdinalIgnoreCase)
            || f.Equals("sigma.csv", StringComparison.OrdinalIgnoreCase));

    private readonly FindingAggregator _agg = new();
    private int _info;

    public void Analyse(string csvPath, AnalysisContext ctx)
    {
        using var csv = new CsvReader(csvPath);
        int cTitle = csv.Col("RuleTitle", "Rule Title", "detections", "Detection", "rule", "name");
        int cTime = csv.Col("Timestamp", "timestamp", "Time", "system_time", "datetime");
        if (cTitle < 0 || cTime < 0)
        {
            ctx.Log($"[WARN] {Path.GetFileName(csvPath)}: not Hayabusa or Chainsaw output (no rule title / timestamp column) — skipped.");
            return;
        }
        int cLevel = csv.Col("Level", "Rule Level", "rule_level", "severity");
        int cComp = csv.Col("Computer", "Event.System.Computer", "computer", "hostname");
        int cEid = csv.Col("EventID", "Event ID", "EventId", "event_id", "Event.System.EventID");
        int cChan = csv.Col("Channel", "Event.System.Channel", "Event.System.Provider", "Provider");
        int cDet = csv.Col("Details", "Event Data", "details", "ExtraFieldInfo");
        var tool = Path.GetFileName(csvPath).Contains("chainsaw", StringComparison.OrdinalIgnoreCase)
                   || (cTitle >= 0 && csv.Col("detections") == cTitle) ? "Chainsaw" : "Hayabusa";

        var cov = ctx.CoverageFor(Source);
        cov.Files.Add(csvPath);

        while (csv.Read())
        {
            if ((csv.RowNumber & 0x3FFF) == 0) ctx.Cancel.ThrowIfCancellationRequested();
            cov.Rows++;
            var time = CsvReader.ParseTime(csv[cTime]);
            cov.See(time);

            Severity? sev = cLevel < 0 ? Severity.Medium : LevelOf(csv[cLevel]);
            if (sev == null) { _info++; continue; }

            var computer = cComp >= 0 ? csv[cComp].Trim() : "";
            var eid = cEid >= 0 ? csv[cEid].Trim() : "";
            var chan = cChan >= 0 ? csv[cChan].Trim() : "";
            var detail = cDet >= 0 ? EventLogAnalyser.Trunc(csv[cDet].Replace("\r", " ").Replace("\n", " "), 600) : "";

            // Chainsaw can list several rules for one event
            foreach (var title in Titles(csv[cTitle]))
            {
                var where = (computer.Length > 0 ? $" on {computer}" : "") +
                            (eid.Length > 0 ? $" (event {eid}{(chan.Length > 0 ? ", " + chan : "")})" : "");
                _agg.Add($"sigma|{title}|{computer}", sev.Value, time, Source, title,
                    $"Sigma ({tool}): {title}{where}", detail, Path.GetFileName(csvPath));
            }
        }
    }

    public void Complete(AnalysisContext ctx)
    {
        if (_info > 0) ctx.Log($"[{Source}] {_info} informational / low-level hit(s) not reported (they stay in the Hayabusa/Chainsaw CSV).");
        ctx.AddRange(_agg.Flush());
    }

    /// <summary>Hayabusa writes crit/high/med/low/info (or the full words with -b); Chainsaw may write the rule level.</summary>
    internal static Severity? LevelOf(string level) => level.Trim().ToLowerInvariant() switch
    {
        "crit" or "critical" or "emer" or "emergency" => Severity.Critical,
        "high" => Severity.High,
        "med" or "medium" => Severity.Medium,
        "low" => Severity.Suspicious,
        "" => Severity.Medium,
        _ => null,   // info, informational, undef
    };

    private static IEnumerable<string> Titles(string cell) =>
        cell.Split(new[] { '\n', '\r', ';', '|' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(t => t.Trim().TrimStart('+', '-', '*', ' ').Trim())
            .Where(t => t.Length > 0)
            .DefaultIfEmpty("(unnamed rule)");
}
