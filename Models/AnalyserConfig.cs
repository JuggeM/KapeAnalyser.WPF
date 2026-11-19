using System.Collections.ObjectModel;

namespace KapeAnalyser.WPF.Models;

/// <summary>
/// All analyst-configurable settings, bound to the UI and passed to the
/// analysis engine at run time.
/// </summary>
public class AnalyserConfig
{
    // ── Case ─────────────────────────────────────────────────────────
    public string CaseName { get; set; } = string.Empty;
    public string AnalystName { get; set; } = string.Empty;
    public string CaseFolderPath { get; set; } = string.Empty;
    /// <summary>
    /// Case layout: Uploads\ (ORC archives) → Decompressed\ (extracted) → KAPE
    /// writes its module output to Processed\ → this tool reads Processed\ and
    /// writes its results to Processed\Level2\.
    /// </summary>
    public const string KapeOutputFolder = "Processed";
    public const string ResultsFolder = "Level2";
    public static readonly string DefaultOutputPath = Path.Combine(KapeOutputFolder, ResultsFolder);

    public string OutputPath { get; set; } = DefaultOutputPath;

    /// <summary>
    /// Folder results are written to. A relative OutputPath is resolved
    /// against the case folder. The case root (evidence) and the KAPE output
    /// root (Processed\) are never used, so results never mix with their
    /// input; both fall back to &lt;case&gt;\Processed\Level2.
    /// </summary>
    public string ResolveOutputPath()
    {
        string caseDir = string.IsNullOrWhiteSpace(CaseFolderPath) ? string.Empty : Path.GetFullPath(CaseFolderPath);
        string defaultOut = Path.Combine(caseDir, DefaultOutputPath);
        if (string.IsNullOrWhiteSpace(OutputPath)) return defaultOut;

        string resolved = Path.IsPathRooted(OutputPath)
            ? Path.GetFullPath(OutputPath)
            : Path.GetFullPath(Path.Combine(caseDir, OutputPath));

        static bool Same(string a, string b) =>
            string.Equals(a.TrimEnd('\\', '/'), b.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase);
        if (caseDir.Length > 0 && (Same(resolved, caseDir) || Same(resolved, Path.Combine(caseDir, KapeOutputFolder))))
            return defaultOut;
        return resolved;
    }

    /// <summary>Optional date filter on finding times (UTC dates, inclusive).</summary>
    public DateTime? FilterFrom { get; set; }
    public DateTime? FilterTo { get; set; }

    // ── Module toggles ───────────────────────────────────────────────
    public bool AnalyseEventLogs { get; set; } = true;
    public bool AnalysePrefetch { get; set; } = true;
    public bool AnalyseAmcache { get; set; } = true;
    public bool AnalyseShimcache { get; set; } = true;
    public bool AnalyseRegistry { get; set; } = true;
    public bool AnalyseLnk { get; set; } = true;
    public bool AnalyseJumpLists { get; set; } = true;
    public bool AnalyseMft { get; set; } = true;
    public bool AnalyseUsnJournal { get; set; } = true;
    public bool AnalyseRecycleBin { get; set; } = true;
    public bool AnalyseShellbags { get; set; } = true;
    public bool AnalyseSrum { get; set; } = true;

    // ── Detection ────────────────────────────────────────────────────
    /// <summary>Detection rules file; empty = rules.json next to the exe.</summary>
    public string RulesPath { get; set; } = string.Empty;

    public string ResolveRulesPath() =>
        string.IsNullOrWhiteSpace(RulesPath) ? Core.RuleSet.DefaultPath : Path.GetFullPath(RulesPath);

    /// <summary>Failed logons from one source before it is flagged as brute force.</summary>
    public int BruteForceThreshold { get; set; } = 10;

    /// <summary>$MFT / $J: only flag files created within this many days of the newest event (0 = no limit).</summary>
    public int FileSystemRecencyDays { get; set; } = 0;

    /// <summary>Extra names/strings flagged HIGH wherever seen in a path or command line.</summary>
    public ObservableCollection<string> ExtraKeywords { get; set; } = new();

    /// <summary>Path fragments never flagged (e.g. your EDR or deployment tool).</summary>
    public ObservableCollection<string> WhitelistPaths { get; set; } = new(new[]
    {
        @"\Windows\WinSxS\", @"\Windows\SoftwareDistribution\", @"\Windows Defender\",
        @"\Microsoft\Windows Defender\", @"\CrowdStrike\",
    });

    // ── Output ───────────────────────────────────────────────────────
    public bool SearchIocs { get; set; } = true;
}
