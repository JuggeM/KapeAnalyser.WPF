using System.Text.RegularExpressions;
using KapeAnalyser.WPF.Core;
using KapeAnalyser.WPF.Models;

namespace KapeAnalyser.WPF.Analysers;

/// <summary>
/// PSReadLine history: ...\Users\&lt;user&gt;\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
/// (and the other hosts' *_history.txt next to it). Every command typed in an
/// interactive PowerShell session, oldest first, with no timestamps; the file's
/// last write time is roughly when the last command was typed. Commands are
/// checked against the command-line rules, known tools and staging folders.
/// </summary>
public sealed class PowerShellHistoryAnalyser : IRawFileAnalyser
{
    public string Source => "PSHISTORY";
    public string Module => "ConsoleHost_history.txt";
    public bool Enabled(AnalyserConfig c) => c.AnalysePowerShellHistory;
    public bool Accepts(string fileName) => false;

    public bool AcceptsRaw(string path) =>
        path.EndsWith("_history.txt", StringComparison.OrdinalIgnoreCase)
        && string.Equals(Path.GetFileName(Path.GetDirectoryName(path)), "PSReadLine", StringComparison.OrdinalIgnoreCase);

    private static readonly Regex UserInPath = new(@"[\\/]Users[\\/](?<u>[^\\/]+)[\\/]AppData[\\/]", RegexOptions.IgnoreCase | RegexOptions.RightToLeft | RegexOptions.Compiled);
    // Command starts: first word of the line and after | ; & ( {
    private static readonly Regex CommandWord = new(@"(?:^|[|;&({])\s*(?:&\s*|\.\s+)?[""']?(?<w>[^\s""'|;&(){}]+)", RegexOptions.Compiled);
    private static readonly Regex PathToken = new(@"(?:[A-Za-z]:|\\\\|\.)[\\/][^\s""'|;&]+", RegexOptions.Compiled);

    private readonly FindingAggregator _agg = new();

    public void Analyse(string path, AnalysisContext ctx)
    {
        var cov = ctx.CoverageFor(Source);
        cov.Files.Add(path);
        var written = File.GetLastWriteTimeUtc(path);
        cov.See(written);

        var um = UserInPath.Match(path);
        var user = um.Success ? um.Groups["u"].Value : "unknown user";
        var file = Path.GetFileName(path);
        var artifact = $"{file} ({user}, last written {written:yyyy-MM-dd HH:mm} UTC)";

        int lineNo = 0;
        foreach (var raw in File.ReadLines(path))
        {
            lineNo++;
            cov.Rows++;
            var line = raw.Trim();
            if (line.Length == 0) continue;
            var sample = $"#{lineNo}: {Shorten(line, 300)}";

            foreach (var hit in ctx.Rules.MatchCommandLine(line))
                _agg.Add($"cmd|{user}|{hit.Label}", hit.Severity, null, Source, hit.Label,
                    $"PowerShell history ({user}): {hit.Label}", "", artifact, sample);

            // Tools by name: the command word, and any path in the line
            var names = CommandWord.Matches(line).Select(m => m.Groups["w"].Value)
                .Concat(PathToken.Matches(line).Select(m => m.Value))
                .Distinct(StringComparer.OrdinalIgnoreCase);
            foreach (var name in names)
            {
                var score = ctx.Rules.ScoreBinaryPath(name);
                if (score == null) continue;
                var exe = DetectionRules.FileNameOf(name);
                _agg.Add($"tool|{user}|{exe}", score.Value.Sev, null, Source, score.Value.Reason,
                    $"PowerShell history ({user}): {exe} — {score.Value.Reason}", "", artifact, sample);
            }
        }
    }

    public void Complete(AnalysisContext ctx) => ctx.AddRange(_agg.Flush());

    private static string Shorten(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}
