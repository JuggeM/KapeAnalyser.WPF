using KapeAnalyser.WPF.Core;
using KapeAnalyser.WPF.Models;

namespace KapeAnalyser.WPF.Analysers;

/// <summary>PECmd output (*_PECmd_Output.csv): programs that ran, with run count and last 8 run times.</summary>
public sealed class PrefetchAnalyser : IArtifactAnalyser
{
    public string Source => "PREFETCH";
    public string Module => "PECmd";
    public bool Enabled(AnalyserConfig c) => c.AnalysePrefetch;
    public bool Accepts(string f) => f.EndsWith("_PECmd_Output.csv", StringComparison.OrdinalIgnoreCase);

    private readonly FindingAggregator _agg = new();

    public void Analyse(string csvPath, AnalysisContext ctx)
    {
        using var csv = new CsvReader(csvPath);
        int cExe = csv.Col("ExecutableName"), cLast = csv.Col("LastRun"), cCount = csv.Col("RunCount"),
            cFiles = csv.Col("FilesLoaded"), cSrc = csv.Col("SourceFilename"), cCreated = csv.Col("SourceCreated");
        if (cExe < 0) return;
        var prev = Enumerable.Range(0, 7).Select(i => csv.Col($"PreviousRun{i}")).Where(i => i >= 0).ToArray();

        var cov = ctx.CoverageFor(Source);
        cov.Files.Add(csvPath);

        while (csv.Read())
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            cov.Rows++;
            var exe = csv[cExe];
            var last = CsvReader.ParseTime(csv[cLast]);
            var runs = prev.Select(i => CsvReader.ParseTime(csv[i])).Append(last).Where(t => t.HasValue).ToList();
            var first = runs.Count > 0 ? runs.Min() : CsvReader.ParseTime(csv[cCreated]);
            cov.See(first); cov.See(last);

            var full = FullPath(exe, csv[cFiles]);
            var score = ctx.Rules.ScoreBinaryPath(full.Length > 0 ? full : exe);
            if (score == null) continue;

            _agg.Add($"pf|{full}|{exe}", score.Value.Sev, first, Source, score.Value.Reason,
                $"Executed: {exe} — {score.Value.Reason} (run count {csv[cCount]})",
                full.Length > 0 ? full : DetectionRules.FileNameOf(csv[cSrc]), DetectionRules.FileNameOf(csv[cSrc]));
            if (last.HasValue && last != first)
                _agg.Add($"pf|{full}|{exe}", score.Value.Sev, last, Source, score.Value.Reason, "");
        }
    }

    /// <summary>The executable's own path from the FilesLoaded list ("\VOLUME{…}\USERS\…\X.EXE").</summary>
    private static string FullPath(string exe, string filesLoaded)
    {
        if (string.IsNullOrEmpty(exe) || string.IsNullOrEmpty(filesLoaded)) return string.Empty;
        foreach (var f in filesLoaded.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            if (f.EndsWith("\\" + exe, StringComparison.OrdinalIgnoreCase)) return f;
        return string.Empty;
    }

    public void Complete(AnalysisContext ctx) => ctx.AddRange(_agg.Flush());
}

/// <summary>AmcacheParser output (*_Amcache_*FileEntries.csv): binaries present/run, with SHA1.</summary>
public sealed class AmcacheAnalyser : IArtifactAnalyser
{
    public string Source => "AMCACHE";
    public string Module => "AmcacheParser";
    public bool Enabled(AnalyserConfig c) => c.AnalyseAmcache;
    public bool Accepts(string f) =>
        f.EndsWith("_Amcache_UnassociatedFileEntries.csv", StringComparison.OrdinalIgnoreCase)
        || f.EndsWith("_Amcache_AssociatedFileEntries.csv", StringComparison.OrdinalIgnoreCase);

    private readonly FindingAggregator _agg = new();

    public void Analyse(string csvPath, AnalysisContext ctx)
    {
        using var csv = new CsvReader(csvPath);
        int cPath = csv.Col("FullPath"), cSha = csv.Col("SHA1"), cTime = csv.Col("FileKeyLastWriteTimestamp"),
            cOs = csv.Col("IsOsComponent"), cProduct = csv.Col("ProductName"), cLink = csv.Col("LinkDate");
        if (cPath < 0) return;
        var cov = ctx.CoverageFor(Source);
        cov.Files.Add(csvPath);

        while (csv.Read())
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            cov.Rows++;
            var t = CsvReader.ParseTime(csv[cTime]);
            cov.See(t);
            if (csv[cOs].Equals("True", StringComparison.OrdinalIgnoreCase)) continue;

            var path = csv[cPath];
            var score = ctx.Rules.ScoreBinaryPath(path);
            if (score == null) continue;
            var sha = csv[cSha].Trim();
            if (sha.Length == 44 && sha.StartsWith("0000")) sha = sha[4..]; // Amcache pads SHA1 with 0000
            var product = csv[cProduct];
            _agg.Add($"am|{path}|{sha}", score.Value.Sev, t, Source, score.Value.Reason,
                $"Seen: {DetectionRules.FileNameOf(path)} — {score.Value.Reason}" + (product.Length > 0 ? $" [{product}]" : ""),
                $"{path}  SHA1 {sha}  (compiled {csv[cLink]})", DetectionRules.FileNameOf(csvPath));
        }
    }

    public void Complete(AnalysisContext ctx) => ctx.AddRange(_agg.Flush());
}

/// <summary>AppCompatCacheParser output (*AppCompatCache*.csv). Times are file modification times, not run times.</summary>
public sealed class ShimcacheAnalyser : IArtifactAnalyser
{
    public string Source => "SHIMCACHE";
    public string Module => "AppCompatCacheParser";
    public bool Enabled(AnalyserConfig c) => c.AnalyseShimcache;
    public bool Accepts(string f) => f.Contains("AppCompatCache", StringComparison.OrdinalIgnoreCase)
                                    && f.EndsWith(".csv", StringComparison.OrdinalIgnoreCase);

    private readonly FindingAggregator _agg = new();

    public void Analyse(string csvPath, AnalysisContext ctx)
    {
        using var csv = new CsvReader(csvPath);
        int cPath = csv.Col("Path"), cTime = csv.Col("LastModifiedTimeUTC"), cExec = csv.Col("Executed"), cDup = csv.Col("Duplicate");
        if (cPath < 0) return;
        var cov = ctx.CoverageFor(Source);
        cov.Files.Add(csvPath);

        while (csv.Read())
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            cov.Rows++;
            if (csv[cDup].Equals("True", StringComparison.OrdinalIgnoreCase)) continue;
            var t = CsvReader.ParseTime(csv[cTime]);
            cov.See(t);
            var path = csv[cPath];
            var score = ctx.Rules.ScoreBinaryPath(path);
            if (score == null) continue;
            var exec = csv[cExec].Equals("Yes", StringComparison.OrdinalIgnoreCase) || csv[cExec].Equals("True", StringComparison.OrdinalIgnoreCase);
            _agg.Add($"shim|{path}", score.Value.Sev, t, Source, score.Value.Reason,
                $"{(exec ? "Executed" : "Present")}: {DetectionRules.FileNameOf(path)} — {score.Value.Reason} (time = file last modified)",
                path, DetectionRules.FileNameOf(csvPath));
        }
    }

    public void Complete(AnalysisContext ctx) => ctx.AddRange(_agg.Flush());
}
