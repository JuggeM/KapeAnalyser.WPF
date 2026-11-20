using System.Globalization;
using System.Text.RegularExpressions;
using KapeAnalyser.WPF.Core;
using KapeAnalyser.WPF.Models;

namespace KapeAnalyser.WPF.Analysers;

/// <summary>
/// Web server access logs collected from the host:
///   IIS     W3SVC*\u_ex*.log (W3C extended, layout from the #Fields: line, times in UTC)
///           and u_nc*.log (NCSA common format)
///   Tomcat  localhost_access_log*.txt (common log format, local time with offset)
/// Each request is URL-decoded twice and classified: webshell use (a known
/// shell name or a script in an upload folder, with or without a command
/// parameter), a script uploaded with PUT, a Tomcat manager deploy, the attack
/// patterns from rules.json (SQL injection, traversal, command injection, XSS,
/// Exchange probes), sensitive file probes and scanner user agents. Findings
/// are grouped per (client IP, type) over all of the host's logs; an attack
/// the server answered with 2xx/3xx is "served" and rated higher. Web login
/// brute force is counted per client IP, as in CsirtParser.
/// </summary>
public sealed class WebLogAnalyser : IRawFileAnalyser
{
    public string Source => "WEBLOG";
    public string Module => "IIS / Tomcat access logs";
    public bool Enabled(AnalyserConfig c) => c.AnalyseWebLogs;
    public bool Accepts(string fileName) => false;

    private static readonly Regex IisName = new(@"^(?:u_)?(?:ex|nc)\d{4,}.*\.log$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex TomcatName = new(@"^localhost_access_log.*\.(?:txt|log)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public bool AcceptsRaw(string path)
    {
        var name = Path.GetFileName(path);
        return IisName.IsMatch(name) || TomcatName.IsMatch(name);
    }

    // ip - user [time] "request" status size ["referer" "agent"]
    private static readonly Regex Clf = new(
        @"^(?<ip>\S+)\s+\S+\s+\S+\s+\[(?<dt>[^\]]+)\]\s+""(?<method>\S+)\s+(?<uri>\S+)(?:\s+[^""]*)?""\s+(?<status>\d{3})\s+(?<size>\d+|-)(?:\s+""(?<ref>[^""]*)""\s+""(?<ua>[^""]*)"")?",
        RegexOptions.Compiled);

    private static readonly Regex PutScript = new(@"\.(?:jspx?|aspx?|ashx|asmx|php\d?|war)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex ManagerDeploy = new(@"^/manager/(?:text/deploy|html/upload)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Brute force (same rules as CsirtParser's WebBruteForceDetector)
    private static readonly Regex LoginPost = new(
        @"/(?:wp-login\.php|xmlrpc\.php|login(?:\.php|\.aspx?)?|signin|sign-in|logon(?:\.aspx)?|auth(?:/login|/session|/token)?|j_security_check|" +
        @"user/login|account/login|admin/login|administrator/index\.php|session|oauth/token|api/(?:v\d+/)?(?:auth|login|token))(?:$|[/?#])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex ProtectedEndpoint = new(
        @"/(?:wp-admin|admin|administrator|manager/(?:html|text|status)|host-manager|phpmyadmin|adminer|webmin|cpanel|webmail|login|signin|api/)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private sealed class Group
    {
        public string Ip = "", Type = "";
        public int Count;
        public DateTime? First, Last;
        public SortedDictionary<int, int> Statuses = new();
        public List<string> Samples = new(), Commands = new();
        public HashSet<string> Files = new(StringComparer.OrdinalIgnoreCase);
        public string? Tool;
        public int Served => Statuses.Where(s => IsServed(s.Key)).Sum(s => s.Value);
    }

    private sealed class Brute
    {
        public int Failures;
        public DateTime? FirstFailure, LastFailure, SuccessAt;
        public HashSet<string> Endpoints = new(StringComparer.OrdinalIgnoreCase);
        public string Agent = "", SuccessPath = "";
        public int SuccessStatus, FailuresBeforeSuccess;
    }

    private readonly Dictionary<(string Ip, string Type), Group> _groups = new();
    private readonly Dictionary<string, Group> _scanners = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Brute> _brute = new(StringComparer.OrdinalIgnoreCase);

    public void Analyse(string path, AnalysisContext ctx)
    {
        var cov = ctx.CoverageFor(Source);
        cov.Files.Add(path);
        var file = Path.GetFileName(path);
        var rules = RuleSet.Active;
        string[]? fields = null;

        foreach (var line in File.ReadLines(path))
        {
            if (line.Length == 0) continue;
            if (line[0] == '#')
            {
                if (line.StartsWith("#Fields:", StringComparison.OrdinalIgnoreCase))
                    fields = line[8..].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                continue;
            }
            if ((cov.Rows & 0x3FFF) == 0) ctx.Cancel.ThrowIfCancellationRequested();
            cov.Rows++;

            var r = fields != null ? ParseW3c(line, fields) : ParseClf(line);
            if (r == null) continue;
            var (ip, method, uri, status, ua, time) = r.Value;
            cov.See(time);
            if (!ctx.InDateRange(time)) continue;

            var decoded = DecodeUri(uri);
            var tool = rules.WebScanners.FirstOrDefault(s => s.Rx.IsMatch(ua))?.Label;
            var type = Classify(rules, uri, decoded, method, status, out var command);

            if (type != null && !(type == "Sensitive file probe" && !IsServed(status) && tool != null))
            {
                var g = Get(_groups, (ip, type), () => new Group { Ip = ip, Type = type });
                Count(g, time, status, file, $"{method} {Shorten(decoded, 140)} → {status}");
                if (command != null && g.Commands.Count < 5 && !g.Commands.Contains(command)) g.Commands.Add(command);
                g.Tool ??= tool;
            }
            if (tool != null)
            {
                if (!_scanners.TryGetValue(ip, out var sg)) _scanners[ip] = sg = new Group { Ip = ip, Type = "Web scanner", Tool = tool };
                Count(sg, time, status, file, type != null ? decoded.Split('?')[0] : null);
                if (!sg.Tool!.Contains(tool)) sg.Tool += "/" + tool;
            }
            TrackBrute(ip, decoded.Split('?')[0], method, status, ua, time, ctx.Config.BruteForceThreshold);
        }
    }

    public void Complete(AnalysisContext ctx)
    {
        foreach (var g in _groups.Values)
        {
            bool shell = IsShellType(g.Type);
            var sev = g.Served > 0 ? (shell ? Severity.Critical : Severity.High) : Severity.Medium;
            var outcome = g.Served == g.Count ? "served" : g.Served == 0 ? "failed/blocked" : $"{g.Served} of {g.Count} served";
            var cmds = g.Commands.Count > 0 ? $" — commands: {string.Join(" ; ", g.Commands.Select(c => Shorten(c, 80)))}" : "";
            ctx.Add(new Finding
            {
                Severity = sev, TimeUtc = g.First, LastUtc = g.Last, Count = g.Count, Source = Source, Category = g.Type,
                Text = $"{g.Type} from {g.Ip}{(g.Tool != null ? $" via {g.Tool}" : "")}: {g.Count} request(s), {outcome} (status {Statuses(g)}){cmds}",
                Detail = "e.g. " + string.Join(" ; ", g.Samples),
                Artifact = string.Join(", ", g.Files.Take(3)) + (g.Files.Count > 3 ? $" (+{g.Files.Count - 3})" : ""),
            });
        }

        foreach (var sg in _scanners.Values)
            ctx.Add(new Finding
            {
                Severity = Severity.Medium, TimeUtc = sg.First, LastUtc = sg.Last, Count = sg.Count, Source = Source, Category = "Web scanner",
                Text = $"Scanner {sg.Tool} from {sg.Ip}: {sg.Count} request(s) (status {Statuses(sg)})",
                Detail = sg.Samples.Count > 0 ? "e.g. " + string.Join(", ", sg.Samples.Distinct()) : "",
                Artifact = string.Join(", ", sg.Files.Take(3)),
            });

        int threshold = Math.Max(1, ctx.Config.BruteForceThreshold);
        foreach (var (ip, b) in _brute.Where(kv => kv.Value.Failures >= threshold))
        {
            var endpoints = string.Join(", ", b.Endpoints.Take(5)) + (b.Endpoints.Count > 5 ? $" (+{b.Endpoints.Count - 5} more)" : "");
            var detail = $"endpoints: {endpoints}" + (b.Agent.Length > 0 ? $" | user agent: {b.Agent}" : "");
            ctx.Add(b.SuccessAt.HasValue
                ? new Finding
                {
                    Severity = Severity.Critical, TimeUtc = b.SuccessAt, Source = Source, Category = "Web login brute force succeeded",
                    Text = $"Web login brute force succeeded: {ip} got {b.SuccessStatus} on {b.SuccessPath} after {b.FailuresBeforeSuccess} failed attempt(s)",
                    Detail = detail,
                }
                : new Finding
                {
                    Severity = Severity.High, TimeUtc = b.FirstFailure, LastUtc = b.LastFailure, Count = b.Failures, Source = Source, Category = "Web login brute force",
                    Text = $"Web login brute force: {ip} made {b.Failures} failed attempt(s), no success seen",
                    Detail = detail,
                });
        }
        _groups.Clear(); _scanners.Clear(); _brute.Clear();
    }

    // ── Classification ───────────────────────────────────────────────
    private static bool IsShellType(string t) => t.StartsWith("Webshell", StringComparison.Ordinal) || t is "Script in upload dir" or "Script uploaded with PUT";

    /// <summary>Attack type for one request, or null. Webshell checks come first.</summary>
    private static string? Classify(RuleSet rules, string rawUri, string decoded, string method, int status, out string? command)
    {
        command = null;
        var path = decoded.Split('?')[0];
        bool shellPath = (rules.WebUploadDirScript?.IsMatch(decoded) ?? false) || (rules.WebShellNames?.IsMatch(decoded) ?? false);
        var cm = rules.WebCommandParam?.Match(decoded);
        if (shellPath && cm is { Success: true })
        {
            command = cm.Groups["cmd"].Value.Trim();
            return "Webshell command";
        }
        if (method.Equals("PUT", StringComparison.OrdinalIgnoreCase) && PutScript.IsMatch(path)) return "Script uploaded with PUT";
        if (shellPath) return method.Equals("POST", StringComparison.OrdinalIgnoreCase) ? "Webshell POST" : "Script in upload dir";
        if (ManagerDeploy.IsMatch(path) && (method is "POST" or "PUT" || path.Contains("/deploy", StringComparison.OrdinalIgnoreCase)))
            return "Tomcat manager deploy";

        foreach (var a in rules.WebAttacks)
            if (a.Rx.IsMatch(decoded)) return a.Label;

        if (rawUri.Contains("%00")) return "Null byte injection";
        if (rules.WebSensitiveProbe?.IsMatch(path) ?? false) return "Sensitive file probe";
        return null;
    }

    private void TrackBrute(string ip, string path, string method, int code, string agent, DateTime? t, int threshold)
    {
        bool isPost = method.Equals("POST", StringComparison.OrdinalIgnoreCase);
        bool loginPost = isPost && LoginPost.IsMatch(path);
        bool isXmlRpc = path.EndsWith("xmlrpc.php", StringComparison.OrdinalIgnoreCase);
        bool protectedHit = ProtectedEndpoint.IsMatch(path);
        if (!loginPost && !protectedHit) return;

        var b = Get(_brute, ip, () => new Brute());
        bool failed = (loginPost && !(code is 301 or 302 or 303) && !(isXmlRpc && code >= 500))
                      || ((code is 401 or 403) && protectedHit);
        if (failed)
        {
            b.Failures++;
            if (b.Endpoints.Count < 50) b.Endpoints.Add(path);
            if (t.HasValue)
            {
                if (b.FirstFailure == null || t < b.FirstFailure) b.FirstFailure = t;
                if (b.LastFailure == null || t > b.LastFailure) b.LastFailure = t;
            }
            if (b.Agent.Length == 0 && agent.Length > 0 && agent != "-") b.Agent = agent;
            return;
        }
        bool success = !isXmlRpc && b.Failures >= Math.Max(1, threshold) && b.SuccessAt == null
                       && ((loginPost && code is 302 or 303) || (code is >= 200 and < 300 && protectedHit && b.Endpoints.Contains(path)));
        if (success)
        {
            b.SuccessAt = t ?? b.LastFailure;
            b.SuccessPath = path;
            b.SuccessStatus = code;
            b.FailuresBeforeSuccess = b.Failures;
        }
    }

    // ── Parsing ──────────────────────────────────────────────────────
    private static (string Ip, string Method, string Uri, int Status, string Ua, DateTime? Time)? ParseW3c(string line, string[] fields)
    {
        var p = line.Split(' ');
        if (p.Length != fields.Length) return null;
        string F(string name) { int i = Array.IndexOf(fields, name); return i >= 0 && p[i] != "-" ? p[i] : ""; }

        var stem = F("cs-uri-stem");
        if (stem.Length == 0) return null;
        var query = F("cs-uri-query");
        DateTime? t = DateTime.TryParseExact($"{F("date")} {F("time")}", "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt) ? dt : null;
        int.TryParse(F("sc-status"), out var status);
        return (F("c-ip"), F("cs-method"), query.Length > 0 ? $"{stem}?{query}" : stem, status, F("cs(User-Agent)").Replace('+', ' '), t);
    }

    private static (string Ip, string Method, string Uri, int Status, string Ua, DateTime? Time)? ParseClf(string line)
    {
        var m = Clf.Match(line);
        if (!m.Success) return null;
        DateTime? t = DateTimeOffset.TryParseExact(m.Groups["dt"].Value, "dd/MMM/yyyy:HH:mm:ss zzz", CultureInfo.InvariantCulture,
            DateTimeStyles.AllowWhiteSpaces, out var dto) ? dto.UtcDateTime : null;
        int.TryParse(m.Groups["status"].Value, out var status);
        return (m.Groups["ip"].Value, m.Groups["method"].Value, m.Groups["uri"].Value, status, m.Groups["ua"].Value, t);
    }

    /// <summary>URL-decodes twice (double encoding) and treats '+' as space.</summary>
    internal static string DecodeUri(string uri)
    {
        var s = uri ?? "";
        for (int i = 0; i < 2; i++)
        {
            string next;
            try { next = Uri.UnescapeDataString(s.Replace('+', ' ')); }
            catch (UriFormatException) { break; }
            if (next == s) break;
            s = next;
        }
        return s;
    }

    // ── Helpers ──────────────────────────────────────────────────────
    private static bool IsServed(int status) => status is >= 200 and < 400;

    private static void Count(Group g, DateTime? t, int status, string file, string? sample)
    {
        g.Count++;
        if (t.HasValue)
        {
            if (g.First == null || t < g.First) g.First = t;
            if (g.Last == null || t > g.Last) g.Last = t;
        }
        g.Statuses[status] = g.Statuses.GetValueOrDefault(status) + 1;
        g.Files.Add(file);
        if (sample != null && g.Samples.Count < 3 && !g.Samples.Contains(sample)) g.Samples.Add(sample);
    }

    private static string Statuses(Group g) => string.Join(", ", g.Statuses.Select(s => $"{s.Key} x{s.Value}"));

    private static TV Get<TK, TV>(Dictionary<TK, TV> d, TK key, Func<TV> make) where TK : notnull
    {
        if (!d.TryGetValue(key, out var v)) d[key] = v = make();
        return v;
    }

    private static string Shorten(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}
