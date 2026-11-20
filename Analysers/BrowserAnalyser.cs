using System.Text.RegularExpressions;
using KapeAnalyser.WPF.Core;
using KapeAnalyser.WPF.Models;

namespace KapeAnalyser.WPF.Analysers;

/// <summary>
/// Browser history and downloads from SQLECmd (KAPE module SQLECmd, output
/// &lt;time&gt;_&lt;prefix&gt;_&lt;map&gt;_&lt;guid&gt;.csv with a SourceFile column):
///   *_ChromiumBrowser_HistoryVisits_*.csv   Chrome, Edge and other Chromium browsers
///   *_ChromiumBrowser_Downloads_*.csv
///   *_Firefox_History_*.csv
///   *_Firefox_Downloads*.csv                (moz_annos rows from places.sqlite)
/// Reports visits to sites on the suspicious-domain list in rules.json (file
/// sharing, paste, tunnels, remote-access tools) and to raw external IP
/// addresses, and downloads of known tools, of files into staging folders,
/// and of executables or archives from a raw IP or a listed domain. All
/// times are UTC; the user comes from the profile path in SourceFile.
/// </summary>
public sealed class BrowserAnalyser : IArtifactAnalyser
{
    public string Source => "BROWSER";
    public string Module => "SQLECmd";
    public bool Enabled(AnalyserConfig c) => c.AnalyseBrowser;

    public bool Accepts(string f) =>
        f.EndsWith(".csv", StringComparison.OrdinalIgnoreCase)
        && (f.Contains("_ChromiumBrowser_HistoryVisits_", StringComparison.OrdinalIgnoreCase)
            || f.Contains("_ChromiumBrowser_Downloads_", StringComparison.OrdinalIgnoreCase)
            || f.Contains("_Firefox_History_", StringComparison.OrdinalIgnoreCase)
            || f.Contains("_Firefox_Downloads", StringComparison.OrdinalIgnoreCase));

    private static readonly Regex UserInPath = new(@"[\\/]Users[\\/](?<u>[^\\/]+)[\\/]AppData[\\/]", RegexOptions.IgnoreCase | RegexOptions.RightToLeft | RegexOptions.Compiled);
    private static readonly Regex Payload = new(@"\.(?:exe|dll|msi|ps1|bat|cmd|vbs|js|hta|scr|jar|lnk|iso|img|zip|7z|rar)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly FindingAggregator _agg = new();

    public void Analyse(string csvPath, AnalysisContext ctx)
    {
        var name = Path.GetFileName(csvPath);
        using var csv = new CsvReader(csvPath);
        var cov = ctx.CoverageFor(Source);
        cov.Files.Add(csvPath);
        int cSrc = csv.Col("SourceFile");

        if (name.Contains("_ChromiumBrowser_HistoryVisits_", StringComparison.OrdinalIgnoreCase))
            Visits(csv, ctx, cov, cSrc, csv.Col("URL"), csv.Col("VisitTime (UTC)", "VisitTime"), "Chromium");
        else if (name.Contains("_Firefox_History_", StringComparison.OrdinalIgnoreCase))
            Visits(csv, ctx, cov, cSrc, csv.Col("URL"), csv.Col("VisitDate"), "Firefox");
        else if (name.Contains("_ChromiumBrowser_Downloads_", StringComparison.OrdinalIgnoreCase))
        {
            int cTarget = csv.Col("TargetPath", "CurrentPath"), cUrl = csv.Col("DownloadURL", "TabURL", "SiteURL"), cStart = csv.Col("StartTime");
            int cBytes = csv.Col("ReceivedBytes", "TotalBytes");
            while (csv.Read())
            {
                cov.Rows++;
                var t = CsvReader.ParseTime(csv[cStart]);
                cov.See(t);
                Download(ctx, csv[cTarget], csv[cUrl], t, Browser(csv[cSrc], "Chromium"), User(csv[cSrc]), csv[cBytes], name);
            }
        }
        else
        {
            // Firefox moz_annos: one row per annotation; the download URL repeats on each
            int cUrl = csv.Col("URL"), cContent = csv.Col("Content"), cType = csv.Col("Type"), cTime = csv.Col("DateAdded");
            while (csv.Read())
            {
                cov.Rows++;
                var t = CsvReader.ParseTime(csv[cTime]);
                cov.See(t);
                var content = csv[cContent];
                if (!csv[cType].Contains("FileURI", StringComparison.OrdinalIgnoreCase) && !content.StartsWith("file:", StringComparison.OrdinalIgnoreCase)) continue;
                var target = Uri.TryCreate(content, UriKind.Absolute, out var fu) && fu.IsFile ? fu.LocalPath : content;
                Download(ctx, target, csv[cUrl], t, "Firefox", User(csv[cSrc]), "", name);
            }
        }
    }

    public void Complete(AnalysisContext ctx) => ctx.AddRange(_agg.Flush());

    private void Visits(CsvReader csv, AnalysisContext ctx, SourceCoverage cov, int cSrc, int cUrl, int cTime, string fallback)
    {
        if (cUrl < 0) { ctx.Log("[WARN] Browser history CSV without a URL column — skipped."); return; }
        while (csv.Read())
        {
            if ((csv.RowNumber & 0x3FFF) == 0) ctx.Cancel.ThrowIfCancellationRequested();
            cov.Rows++;
            var t = CsvReader.ParseTime(csv[cTime]);
            cov.See(t);
            var url = csv[cUrl];
            if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || (u.Scheme != "http" && u.Scheme != "https")) continue;
            var host = u.IdnHost;
            var (sev, label) = Classify(host, u);
            if (label == null) continue;
            var user = User(csv[cSrc]);
            var browser = Browser(csv[cSrc], fallback);
            _agg.Add($"visit|{user}|{label}|{host}", sev, t, Source, label,
                $"{browser} ({user}): {label}: {host}", "", "Browser history", Shorten(url, 200));
        }
    }

    private void Download(AnalysisContext ctx, string target, string url, DateTime? t, string browser, string user, string bytes, string artifact)
    {
        if (string.IsNullOrWhiteSpace(target)) return;
        var file = DetectionRules.FileNameOf(target);
        Uri.TryCreate(url, UriKind.Absolute, out var u);
        var host = u?.IdnHost ?? "";
        var from = host.Length > 0 ? $" from {host}" : "";
        var size = long.TryParse(bytes, out var b) && b > 0 ? string.Create(System.Globalization.CultureInfo.InvariantCulture, $" ({b / 1024.0 / 1024.0:N1} MB)") : "";

        var score = ctx.Rules.ScoreBinaryPath(target);
        if (score != null)
        {
            _agg.Add($"dl|{target}", score.Value.Sev, t, Source, "Download: " + score.Value.Reason,
                $"{browser} ({user}) downloaded {file}{from}: {score.Value.Reason}{size}", Shorten(url, 300), artifact);
            return;
        }
        if (host.Length == 0 || !Payload.IsMatch(file)) return;
        var (sev, label) = Classify(host, u!);
        if (label == null) return;
        _agg.Add($"dl|{target}", sev < Severity.High ? sev : Severity.High, t, Source, "Download from " + label.ToLowerInvariant(),
            $"{browser} ({user}) downloaded {file}{from} ({label}){size}", $"{Shorten(url, 300)} → {target}", artifact);
    }

    /// <summary>Suspicious-domain rule or raw external IP; label null when the host is not notable.</summary>
    private static (Severity, string?) Classify(string host, Uri u)
    {
        if (DetectionRules.IsIp(host.Trim('[', ']')))
        {
            if (!DetectionRules.IsExternalIp(host.Trim('[', ']'))) return (Severity.Suspicious, null);
            return (Payload.IsMatch(u.AbsolutePath) ? Severity.High : Severity.Medium, "Raw IP address");
        }
        foreach (var d in RuleSet.Active.SuspiciousDomains)
            if (d.Rx.IsMatch(host)) return (d.Severity, d.Label);
        return (Severity.Suspicious, null);
    }

    private static string User(string sourceFile)
    {
        var m = UserInPath.Match(sourceFile ?? "");
        return m.Success ? m.Groups["u"].Value : "unknown user";
    }

    private static string Browser(string sourceFile, string fallback)
    {
        var s = sourceFile ?? "";
        if (s.Contains(@"\Microsoft\Edge\", StringComparison.OrdinalIgnoreCase)) return "Edge";
        if (s.Contains(@"\Google\Chrome\", StringComparison.OrdinalIgnoreCase)) return "Chrome";
        if (s.Contains(@"\BraveSoftware\", StringComparison.OrdinalIgnoreCase)) return "Brave";
        if (s.Contains(@"\Opera", StringComparison.OrdinalIgnoreCase)) return "Opera";
        if (s.Contains(@"\Mozilla\Firefox\", StringComparison.OrdinalIgnoreCase)) return "Firefox";
        return fallback;
    }

    private static string Shorten(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}
