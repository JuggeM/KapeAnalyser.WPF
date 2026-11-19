using System.Text.RegularExpressions;

namespace KapeAnalyser.WPF.Core;

/// <summary>
/// Pulls indicators out of finding text and detail: IP addresses, URLs,
/// executables in staging folders, accounts that were created or added to a
/// privileged group, and SHA1 hashes. Used for the "IOCs seen in findings"
/// section of QuickWins, IOCs across hosts in the case summary, and
/// corroboration in the case report (same idea as CsirtParser's IOC section).
/// </summary>
public static class FindingIndicators
{
    private static readonly Regex Ipv4Rx = new(
        @"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])", RegexOptions.Compiled);
    private static readonly Regex UrlRx = new(
        @"\b(?:https?|ftp)://[^\s'""|;)<>]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex AccountRx = new(
        @"Account created: (?:[^\\\s]+\\)?(?<u>[A-Za-z0-9._$-]+)|^(?<u>[A-Za-z0-9._$-]+) added to group '",
        RegexOptions.Compiled);
    private static readonly Regex Sha1Rx = new(@"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])", RegexOptions.Compiled);

    public static int KindOrder(string kind) => kind switch { "IP" => 0, "URL" => 1, "File" => 2, "Account" => 3, _ => 4 };

    /// <summary>(kind, value) → sources that mention it.</summary>
    public static Dictionary<(string Kind, string Value), HashSet<string>> Extract(
        IEnumerable<(string Source, string Text, string Detail)> findings, IEnumerable<string>? ownIps = null)
    {
        var own = new HashSet<string>(ownIps ?? Enumerable.Empty<string>(), StringComparer.OrdinalIgnoreCase);
        // Windows paths, accounts and hashes are case-insensitive: merge on that
        var iocs = new Dictionary<(string Kind, string Value), HashSet<string>>(KeyComparer.Instance);
        void Add(string kind, string value, string src)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            if (!iocs.TryGetValue((kind, value), out var set))
                iocs[(kind, value)] = set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            set.Add(src);
        }

        foreach (var (source, text, detail) in findings)
        {
            var all = text + "\n" + detail;
            foreach (Match m in Ipv4Rx.Matches(all))
                if (DetectionRules.IsUsableIp(m.Value) && !own.Contains(m.Value) && !m.Value.StartsWith("255.")) Add("IP", m.Value, source);
            foreach (Match m in UrlRx.Matches(all))
                Add("URL", m.Value.TrimEnd('.', ',', ')', '\''), source);
            foreach (var p in DetectionRules.ExtractPaths(all))
                if (DetectionRules.StagingDirOf(p) != null) Add("File", p.Trim('"'), source);
            foreach (Match m in AccountRx.Matches(text))
                Add("Account", m.Groups["u"].Value, source);
            foreach (Match m in Sha1Rx.Matches(all))
                Add("SHA1", m.Value.ToLowerInvariant(), source);
        }
        return iocs;
    }

    private sealed class KeyComparer : IEqualityComparer<(string Kind, string Value)>
    {
        public static readonly KeyComparer Instance = new();
        public bool Equals((string Kind, string Value) a, (string Kind, string Value) b) =>
            a.Kind == b.Kind && string.Equals(a.Value, b.Value, StringComparison.OrdinalIgnoreCase);
        public int GetHashCode((string Kind, string Value) k) =>
            HashCode.Combine(k.Kind, StringComparer.OrdinalIgnoreCase.GetHashCode(k.Value));
    }
}
