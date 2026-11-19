using System.Text.RegularExpressions;
using KapeAnalyser.WPF.Models;

namespace KapeAnalyser.WPF.Core;

/// <summary>
/// Shared Windows detection logic used by every analyser: attacker and
/// dual-use tools by file name, staging directories, and command-line
/// techniques. One place so prefetch, amcache, shimcache, event logs and the
/// file system all agree on what "suspicious" means. The lists themselves
/// come from rules.json (<see cref="RuleSet"/>); the analyst's extra keywords
/// and whitelist come from the Detection panel.
/// </summary>
public sealed class DetectionRules
{
    public sealed record ToolHit(string Name, string Category, Severity Severity);
    public sealed record CmdHit(string Label, Severity Severity);

    private static readonly Regex DownloadsDir = new(@"\\users\\[^\\]+\\downloads\\", RegexOptions.IgnoreCase | RegexOptions.Compiled);


    private static readonly Regex ExecutableExt = new(@"\.(exe|dll|ps1|psm1|bat|cmd|vbs|vbe|js|jse|hta|scr|sys|msi|cpl|lnk|jar|py)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex ArchiveExt = new(@"\.(7z|zip|rar|tar|gz)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly string[] _extraKeywords;
    private readonly string[] _whitelist;
    private readonly RuleSet _rules;

    public DetectionRules(AnalyserConfig config)
    {
        _extraKeywords = config.ExtraKeywords.Where(k => !string.IsNullOrWhiteSpace(k)).Select(k => k.Trim()).ToArray();
        _rules = RuleSet.Active;
        _whitelist = config.WhitelistPaths.Where(k => !string.IsNullOrWhiteSpace(k)).Select(k => k.Trim()).ToArray();
    }

    public static string FileNameOf(string path)
    {
        if (string.IsNullOrEmpty(path)) return string.Empty;
        var p = path.Trim().Trim('"');
        int i = p.LastIndexOfAny(new[] { '\\', '/' });
        return i >= 0 ? p[(i + 1)..] : p;
    }

    public bool IsWhitelisted(string path) =>
        !string.IsNullOrEmpty(path) && _whitelist.Any(w => path.Contains(w, StringComparison.OrdinalIgnoreCase));

    /// <summary>Known tool by file name (with or without extension, PsExec-style "-64" suffixes stripped).</summary>
    public ToolHit? MatchTool(string pathOrName)
    {
        var name = FileNameOf(pathOrName);
        if (name.Length == 0) return null;
        var stem = Path.GetFileNameWithoutExtension(name).ToLowerInvariant();
        var ext = Path.GetExtension(name).ToLowerInvariant();

        // Only executables, scripts and DLLs count — "nc.txt" or "everything.lnk" are not tools.
        if (ext.Length > 0 && !ExecutableExt.IsMatch(name)) return null;

        if (_rules.ToolIndex.TryGetValue(stem, out var hit)) return new ToolHit(stem, hit.Category, hit.Severity);
        // Prefixed names: "mimikatz_x64", "rclone-v1.65", "AnyDesk (1)"
        foreach (var t in _rules.Tools)
            if (t.Name.Length >= 5 && stem.StartsWith(t.Name, StringComparison.Ordinal))
                return new ToolHit(t.Name, t.Category, t.Severity);

        foreach (var k in _extraKeywords)
            if (name.Contains(k, StringComparison.OrdinalIgnoreCase))
                return new ToolHit(k, "Analyst keyword", Severity.High);
        return null;
    }

    /// <summary>Staging directory label when the path is in one, else null.</summary>
    public string? StagingDir(string path)
    {
        if (string.IsNullOrEmpty(path) || IsWhitelisted(path)) return null;
        foreach (var r in _rules.StagingFolders)
            if (r.Rx.IsMatch(path)) return r.Label;
        return null;
    }

    /// <summary>Staging directory label ignoring the analyst whitelist (for indicator extraction from findings).</summary>
    public static string? StagingDirOf(string path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        foreach (var r in RuleSet.Active.StagingFolders)
            if (r.Rx.IsMatch(path)) return r.Label;
        return null;
    }

    private static readonly Regex PathInText = new(
        @"(?:[A-Za-z]:|%[A-Za-z]+%|\\\\[^\\\s""]+\\[^\\\s""]+)\\[^""|<>*?\r\n]*?\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|scr|jar|py|msi)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Executable/script paths mentioned in free text (registry data, task actions).</summary>
    public static IEnumerable<string> ExtractPaths(string text)
    {
        if (string.IsNullOrEmpty(text)) yield break;
        foreach (Match m in PathInText.Matches(text)) yield return m.Value;
    }

    public static bool IsDownloads(string path) => DownloadsDir.IsMatch(path ?? "");
    public static bool IsExecutable(string path) => ExecutableExt.IsMatch(path ?? "");
    public static bool IsArchive(string path) => ArchiveExt.IsMatch(path ?? "");

    /// <summary>All command-line techniques seen in a command line / script block.</summary>
    public List<CmdHit> MatchCommandLine(string cmd)
    {
        var hits = new List<CmdHit>();
        if (string.IsNullOrWhiteSpace(cmd)) return hits;
        foreach (var r in _rules.CommandLines)
            if (r.Rx.IsMatch(cmd)) hits.Add(new CmdHit(r.Label, r.Severity));
        foreach (var k in _extraKeywords)
            if (cmd.Contains(k, StringComparison.OrdinalIgnoreCase))
                hits.Add(new CmdHit($"Analyst keyword '{k}'", Severity.High));
        return hits;
    }

    /// <summary>
    /// Scores an executed or present binary by its path: known tool, staging
    /// directory, or both. Null when nothing is notable.
    /// </summary>
    public (Severity Sev, string Reason)? ScoreBinaryPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || IsWhitelisted(path)) return null;
        var tool = MatchTool(path);
        var dir = StagingDir(path);

        if (tool != null)
        {
            var sev = tool.Severity;
            // A known tool run from a staging directory is worse than one installed normally
            if (dir != null && sev > Severity.Critical) sev -= 1;
            return (sev, dir != null ? $"{tool.Category} in {dir}" : tool.Category);
        }
        if (dir != null && IsExecutable(path))
            return (Severity.Medium, $"Executable in {dir}");
        return null;
    }

    // ── Network helpers ──────────────────────────────────────────────
    /// <summary>Dotted-quad IPv4 or IPv6 (IPAddress.TryParse alone accepts "10" as 0.0.0.10).</summary>
    public static bool IsIp(string? s) =>
        !string.IsNullOrWhiteSpace(s)
        && (s.Count(c => c == '.') == 3 || s.Contains(':'))
        && System.Net.IPAddress.TryParse(s.Trim(), out _);

    /// <summary>
    /// True for addresses outside private, loopback, link-local, CGNAT and
    /// multicast ranges. Documentation ranges (203.0.113.0/24 etc.) count as
    /// external so test cases behave like real attacker IPs.
    /// </summary>
    public static bool IsExternalIp(string s)
    {
        if (!IsIp(s) || !System.Net.IPAddress.TryParse(s, out var ip)) return false;
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            else return !(ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || System.Net.IPAddress.IsLoopback(ip)
                          || s!.StartsWith("fc", StringComparison.OrdinalIgnoreCase) || s.StartsWith("fd", StringComparison.OrdinalIgnoreCase)
                          || s == "::");
        }
        var b = ip.GetAddressBytes();
        if (b[0] == 10 || b[0] == 127 || b[0] == 0) return false;
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
        if (b[0] == 192 && b[1] == 168) return false;
        if (b[0] == 169 && b[1] == 254) return false;
        if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
        if (b[0] >= 224) return false;
        return true;
    }

    public static bool IsUsableIp(string s) =>
        IsIp(s) && s != "-" && s != "::1" && s != "127.0.0.1" && s != "0.0.0.0" && s != "::";
}
