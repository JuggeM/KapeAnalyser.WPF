using System.Diagnostics;
using KapeAnalyser.WPF.Analysers;
using KapeAnalyser.WPF.Core;
using KapeAnalyser.WPF.Models;
using KapeAnalyser.WPF.Reporting;

namespace KapeAnalyser.WPF.Services;

/// <summary>
/// Runs every enabled analyser over each host's KAPE module output and writes
/// Processed\&lt;host&gt;\…, then the case-wide steps (IOC search, case summary).
/// A host is processed once: delete its Processed folder (or .processed) to redo it.
/// </summary>
public sealed class AnalysisEngine
{
    public const string ProcessedMarkerFile = ".processed";

    private readonly AnalyserConfig _config;
    private readonly Action<string> _log;

    public AnalysisEngine(AnalyserConfig config, Action<string> log)
    {
        _config = config;
        _log = log;
    }

    public static bool IsProcessed(string outputBase, string collection) =>
        File.Exists(Path.Combine(outputBase, collection, ProcessedMarkerFile));

    public void RunAll(CancellationToken ct, IProgress<double>? progress = null)
    {
        var outputBase = _config.ResolveOutputPath();
        Directory.CreateDirectory(outputBase);
        _log($"Output: {outputBase}");

        var hosts = KapeDiscovery.Find(_config.CaseFolderPath, outputBase);
        if (hosts.Count == 0)
        {
            _log("[WARN] No KAPE module output found in the case folder (looked for EZ Tools CSVs such as *_EvtxECmd_Output.csv).");
            return;
        }

        for (int i = 0; i < hosts.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var h = hosts[i];
            var outDir = Path.Combine(outputBase, h.Name);

            if (IsProcessed(outputBase, h.Name))
            {
                _log($"===== Skipping {h.Name}: already processed ({outDir}) =====");
                progress?.Report((double)(i + 1) / hosts.Count);
                continue;
            }
            if (Directory.Exists(outDir) && Directory.EnumerateFileSystemEntries(outDir).Any())
            {
                _log($"[WARN] [{h.Name}] Incomplete output from an earlier run — clearing and reprocessing.");
                Directory.Delete(outDir, recursive: true);
            }

            ProcessHost(h, outDir, ct, p => progress?.Report((i + p) / hosts.Count));
            File.WriteAllText(Path.Combine(outDir, ProcessedMarkerFile), $"Processed {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z{Environment.NewLine}");
            progress?.Report((double)(i + 1) / hosts.Count);
        }

        FinishCase(_config.CaseFolderPath, outputBase, _config.CaseName, _config.AnalystName, _config.SearchIocs, _log, ct);
    }

    private void ProcessHost(KapeHost host, string outDir, CancellationToken ct, Action<double> progress)
    {
        _log($"===== Host folder: {host.Name} ({host.CsvCount} module CSV file(s)) =====");
        var sw = Stopwatch.StartNew();
        var ctx = new AnalysisContext(_config, host.RootPath, _log, ct);
        var analysers = AnalyserRegistry.CreateAll();

        // Assign each CSV to the first analyser that claims it
        var work = new List<(IArtifactAnalyser A, string File, long Size)>();
        foreach (var file in Directory.EnumerateFiles(host.RootPath, "*.csv",
                     new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }))
        {
            var name = Path.GetFileName(file);
            var a = analysers.FirstOrDefault(x => x.Accepts(name));
            if (a == null) continue;
            if (!a.Enabled(_config)) continue;
            work.Add((a, file, new FileInfo(file).Length));
        }

        long total = Math.Max(1, work.Sum(w => w.Size)), done = 0;
        foreach (var (a, file, size) in work.OrderBy(w => Array.IndexOf(analysers, w.A)))
        {
            ct.ThrowIfCancellationRequested();
            _log($"[{host.Name}] {a.Source}: {Path.GetRelativePath(host.RootPath, file)} ({size / 1024.0 / 1024.0:N1} MB)");
            try { a.Analyse(file, ctx); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { _log($"[ERROR] [{host.Name}] {a.Source} {Path.GetFileName(file)}: {ex.Message}"); }
            done += size;
            progress((double)done / total);
        }

        foreach (var a in analysers.Where(a => a.Enabled(_config)))
        {
            try { a.Complete(ctx); }
            catch (Exception ex) { _log($"[ERROR] [{host.Name}] {a.Source} summary: {ex.Message}"); }
        }

        var hostname = ctx.HostnameVotes.OrderByDescending(kv => kv.Value).Select(kv => kv.Key).FirstOrDefault()
                       ?? KapeDiscovery.HostFromFolderName(host.Name) ?? host.Name.ToUpperInvariant();
        _log($"[{host.Name}] Hostname: {hostname}" + (ctx.HostIps.Count > 0 ? $"   IP(s): {string.Join(", ", ctx.HostIps)}" : ""));

        var modules = analysers.Select(a => (a.Source, a.Module, a.Enabled(_config))).ToList();
        HostReport.Write(outDir, new HostReport.HostInfo(hostname, host.Name, host.RootPath, ctx.HostIps), ctx, modules,
            _config.CaseName, _config.AnalystName);

        int crit = ctx.Findings.Count(f => f.Severity == Severity.Critical), high = ctx.Findings.Count(f => f.Severity == Severity.High);
        _log($"[{host.Name}] {ctx.Findings.Count} finding(s): {crit} critical, {high} high — {sw.Elapsed:mm\\:ss}. QuickWins: {Path.Combine(outDir, HostReport.QuickWinsFile)}");
        try { QuickWinsRtf.Convert(outDir); }
        catch (Exception ex) { _log($"[WARN] [{host.Name}] RTF conversion failed: {ex.Message} — QuickWins.txt is still available."); }
    }

    /// <summary>
    /// Case-wide steps that only read processed output, so they also run on
    /// their own ("Search IOCs" in the IOC panel) without re-analysing.
    /// </summary>
    public static void FinishCase(string caseFolder, string outputBase, string caseName, string analyst,
                                  bool searchIocs, Action<string> log, CancellationToken ct)
    {
        if (searchIocs)
        {
            var iocs = CaseIocs.Load(caseFolder);
            if (iocs.Count > 0)
            {
                log($"IOC search: {iocs.Count} case IOC(s) across processed hosts…");
                foreach (var dir in Directory.GetDirectories(outputBase))
                {
                    ct.ThrowIfCancellationRequested();
                    var info = Path.Combine(dir, HostReport.HostInfoFile);
                    if (!File.Exists(info)) continue;
                    var kv = File.ReadAllLines(info).Select(l => l.Split('=', 2)).Where(p => p.Length == 2).ToDictionary(p => p[0], p => p[1]);
                    var root = kv.GetValueOrDefault("KapeRoot", "");
                    var host = kv.GetValueOrDefault("Hostname", Path.GetFileName(dir));
                    if (!Directory.Exists(root)) { log($"[WARN] {host}: KAPE output folder no longer exists ({root}) — IOC search skipped."); continue; }
                    try
                    {
                        var hits = IocSearch.SearchHost(root, iocs, log, ct);
                        HostReport.WriteIocHits(dir, host, hits, iocs.Count);
                        try { QuickWinsRtf.Convert(dir); } catch { /* .txt is still correct */ }
                        log(hits.Count > 0 ? $"[WARN] {host}: {hits.Count} of {iocs.Count} case IOC(s) seen." : $"{host}: no case IOC hits.");
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex) { log($"[WARN] {host}: IOC search failed: {ex.Message}"); }
                }
            }
        }

        try
        {
            var p = CaseSummary.Write(outputBase, caseName, analyst);
            if (p != null) log($"Case summary written: {p}");
        }
        catch (Exception ex) { log($"[WARN] Case summary failed: {ex.Message}"); }
    }
}
