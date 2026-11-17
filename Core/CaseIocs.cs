using System.Text;
using System.Text.RegularExpressions;

namespace KapeAnalyser.WPF.Core;

public sealed record Ioc(string Type, string Value, string Comment);

/// <summary>
/// The case IOC list (&lt;case&gt;\iocs.txt): one or more indicators per line,
/// defanged values fixed (hxxp, [.], (dot), [:], [@]), type detected.
/// Bare user names and file names need a prefix: "user:alice", "file:evil.exe".
/// Text after " #" is a comment.
/// </summary>
public static class CaseIocs
{
    public const string FileName = "iocs.txt";
    public static string PathFor(string caseFolder) => Path.Combine(caseFolder, FileName);

    private static readonly Regex Sha256 = new(@"^[a-f0-9]{64}$", RegexOptions.IgnoreCase);
    private static readonly Regex Sha1 = new(@"^[a-f0-9]{40}$", RegexOptions.IgnoreCase);
    private static readonly Regex Md5 = new(@"^[a-f0-9]{32}$", RegexOptions.IgnoreCase);
    private static readonly Regex Domain = new(@"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", RegexOptions.IgnoreCase);
    private static readonly Regex Url = new(@"^(https?|ftp)://\S+$", RegexOptions.IgnoreCase);
    private static readonly Regex WinPath = new(@"^([a-z]:\\|\\\\|%[a-z]+%\\)\S", RegexOptions.IgnoreCase);
    private static readonly Regex ExeLike = new(@"^[^\\/\s]+\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr|sys|msi|zip|7z|rar|jar|lnk)$", RegexOptions.IgnoreCase);

    public static string Refang(string s) => Regex.Replace(s, @"\[\.\]|\(\.\)|\[dot\]|\(dot\)", ".", RegexOptions.IgnoreCase)
        .Replace("[:]", ":").Replace("[@]", "@").Replace("[at]", "@")
        .Replace("hxxps", "https", StringComparison.OrdinalIgnoreCase).Replace("hxxp", "http", StringComparison.OrdinalIgnoreCase)
        .Replace("fxp", "ftp", StringComparison.OrdinalIgnoreCase);

    public static (List<Ioc> Iocs, List<string> Rejected) Parse(string text)
    {
        var iocs = new List<Ioc>();
        var rejected = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in (text ?? "").Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var comment = "";
            int hash = line.IndexOf(" #", StringComparison.Ordinal);
            if (hash >= 0) { comment = line[(hash + 2)..].Trim(); line = line[..hash].Trim(); }

            bool any = false;
            foreach (var tokRaw in Regex.Split(line, @"[\s,;|""']+").Where(t => t.Length > 0))
            {
                var tok = Refang(tokRaw).Trim('<', '>', '(', ')', '[', ']');
                var ioc = Classify(tok, comment);
                if (ioc == null) continue;
                any = true;
                if (seen.Add(ioc.Type + "|" + ioc.Value)) iocs.Add(ioc);
            }
            // Paths may contain spaces: try the whole line as one value
            if (!any)
            {
                var whole = Classify(Refang(line), comment);
                if (whole != null) { if (seen.Add(whole.Type + "|" + whole.Value)) iocs.Add(whole); }
                else rejected.Add(line);
            }
        }
        return (iocs, rejected);
    }

    private static Ioc? Classify(string t, string comment)
    {
        if (t.StartsWith("user:", StringComparison.OrdinalIgnoreCase) && t.Length > 5) return new("USER", t[5..], comment);
        if (t.StartsWith("file:", StringComparison.OrdinalIgnoreCase) && t.Length > 5) return new("FILE", t[5..], comment);
        if (DetectionRules.IsIp(t) && t.Contains('.')) return new("IP", t, comment);
        if (Sha256.IsMatch(t)) return new("SHA256", t.ToLowerInvariant(), comment);
        if (Sha1.IsMatch(t)) return new("SHA1", t.ToLowerInvariant(), comment);
        if (Md5.IsMatch(t)) return new("MD5", t.ToLowerInvariant(), comment);
        if (Url.IsMatch(t)) return new("URL", t, comment);
        if (WinPath.IsMatch(t)) return new("PATH", t, comment);
        if (ExeLike.IsMatch(t)) return new("FILE", t, comment);
        if (Domain.IsMatch(t)) return new("DOMAIN", t.ToLowerInvariant(), comment);
        return null;
    }

    public static string Summary(List<Ioc> iocs) =>
        $"{iocs.Count} IOC(s): " + string.Join(", ", iocs.GroupBy(i => i.Type).Select(g => $"{g.Count()} {g.Key}"));

    public static string Serialize(List<Ioc> iocs)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Case IOC list — one indicator per line, text after ' #' is a comment.");
        foreach (var g in iocs.GroupBy(i => i.Type))
        {
            sb.AppendLine($"# {g.Key}");
            foreach (var i in g) sb.AppendLine(i.Comment.Length > 0 ? $"{Prefix(i)}{i.Value} # {i.Comment}" : $"{Prefix(i)}{i.Value}");
        }
        return sb.ToString();
    }

    private static string Prefix(Ioc i) => i.Type == "USER" ? "user:" : i.Type == "FILE" && !ExeLike.IsMatch(i.Value) ? "file:" : "";

    public static List<Ioc> Load(string caseFolder)
    {
        var p = PathFor(caseFolder);
        return File.Exists(p) ? Parse(File.ReadAllText(p)).Iocs : new List<Ioc>();
    }
}
