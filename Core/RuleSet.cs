using System.Text.Json;
using System.Text.RegularExpressions;

namespace KapeAnalyser.WPF.Core;

/// <summary>
/// Detection knowledge loaded from rules.json (next to the exe): attacker and
/// dual-use tools by file name, staging folders, command-line techniques and
/// suspicious shellbag folder names. Kept out of the code so analysts can edit
/// it without rebuilding, and so the executable carries no attacker strings
/// (which antivirus otherwise flags as a hack tool).
/// </summary>
public sealed class RuleSet
{
    public const string FileName = "rules.json";

    public sealed record ToolRule(string Name, string Category, Severity Severity);
    public sealed record StagingRule(Regex Rx, string Label);
    public sealed record CommandRule(Regex Rx, string Label, Severity Severity);
    public sealed record LabelRule(Regex Rx, string Label);
    public sealed record DomainRule(Regex Rx, string Label, Severity Severity);

    public string Path { get; }
    public IReadOnlyList<ToolRule> Tools { get; }
    public IReadOnlyDictionary<string, ToolRule> ToolIndex { get; }
    public IReadOnlyList<StagingRule> StagingFolders { get; }
    public IReadOnlyList<CommandRule> CommandLines { get; }
    public Regex? ShellbagFolderNames { get; }

    // Web server logs (IIS, Tomcat)
    public IReadOnlyList<LabelRule> WebAttacks { get; private init; } = Array.Empty<LabelRule>();
    public Regex? WebSensitiveProbe { get; private init; }
    public Regex? WebUploadDirScript { get; private init; }
    public Regex? WebShellNames { get; private init; }
    /// <summary>Command parameter handed to a script; has a "cmd" group.</summary>
    public Regex? WebCommandParam { get; private init; }
    public IReadOnlyList<LabelRule> WebScanners { get; private init; } = Array.Empty<LabelRule>();

    /// <summary>Browser history: file sharing, paste, tunnel and remote-access domains (matched on the host name).</summary>
    public IReadOnlyList<DomainRule> SuspiciousDomains { get; private init; } = Array.Empty<DomainRule>();

    public string Summary =>
        $"{Tools.Count} tools, {StagingFolders.Count} staging folders, {CommandLines.Count} command-line patterns, "
        + $"{WebAttacks.Count + WebScanners.Count} web log patterns, {SuspiciousDomains.Count} domain patterns";

    private RuleSet(string path, List<ToolRule> tools, List<StagingRule> staging, List<CommandRule> commands, Regex? folders)
    {
        Path = path;
        Tools = tools;
        ToolIndex = tools.GroupBy(t => t.Name, StringComparer.OrdinalIgnoreCase)
                         .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        StagingFolders = staging;
        CommandLines = commands;
        ShellbagFolderNames = folders;
    }

    /// <summary>No rules: the analysers still run, but only built-in event logic (logons, services, …) reports anything.</summary>
    public static readonly RuleSet Empty = new("", new(), new(), new(), null);

    // ── Active rule set ──────────────────────────────────────────────
    private static RuleSet? _active;
    private static readonly object Gate = new();

    /// <summary>Last load error (null when the active rules loaded fine).</summary>
    public static string? LoadError { get; private set; }

    public static string DefaultPath => System.IO.Path.Combine(AppContext.BaseDirectory, FileName);

    /// <summary>The rules every analyser uses. Loaded from <see cref="DefaultPath"/> on first use; Empty if that fails.</summary>
    public static RuleSet Active
    {
        get
        {
            if (_active != null) return _active;
            lock (Gate)
            {
                if (_active == null) TryLoad(DefaultPath, out _);
                return _active ?? Empty;
            }
        }
    }

    /// <summary>Loads and activates a rules file. On failure the previous rules stay active and the reason is returned.</summary>
    public static bool TryLoad(string path, out string message)
    {
        try
        {
            var rules = Load(path);
            lock (Gate) { _active = rules; LoadError = null; }
            message = $"{rules.Summary} from {path}";
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or FormatException)
        {
            lock (Gate) { LoadError = ex.Message; }
            message = ex.Message;
            return false;
        }
    }

    // ── File format ──────────────────────────────────────────────────
    private sealed class FileDto
    {
        public int Version { get; set; } = 1;
        public List<ToolDto>? Tools { get; set; }
        public List<StagingDto>? StagingFolders { get; set; }
        public List<CommandDto>? CommandLines { get; set; }
        public string? ShellbagFolderNames { get; set; }
        public List<LabelDto>? WebAttacks { get; set; }
        public string? WebSensitiveProbe { get; set; }
        public string? WebUploadDirScript { get; set; }
        public string? WebShellNames { get; set; }
        public string? WebCommandParam { get; set; }
        public List<ScannerDto>? WebScanners { get; set; }
        public List<CommandDto>? SuspiciousDomains { get; set; }
    }
    private sealed class LabelDto { public string? Pattern { get; set; } public string? Label { get; set; } }
    private sealed class ScannerDto { public string? Pattern { get; set; } public string? Tool { get; set; } }
    private sealed class ToolDto { public string? Name { get; set; } public string? Category { get; set; } public string? Severity { get; set; } public string? Group { get; set; } }
    private sealed class StagingDto { public string? Pattern { get; set; } public string? Label { get; set; } }
    private sealed class CommandDto { public string? Pattern { get; set; } public string? Label { get; set; } public string? Severity { get; set; } }

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    /// <summary>Reads and validates a rules file; every problem names the entry so it can be fixed.</summary>
    public static RuleSet Load(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"Rules file not found: {path}. It ships next to KapeAnalyser.WPF.exe.", path);

        FileDto dto;
        try { dto = JsonSerializer.Deserialize<FileDto>(File.ReadAllText(path), Json) ?? new FileDto(); }
        catch (JsonException ex) { throw new FormatException($"{FileName} is not valid JSON (line {ex.LineNumber + 1}): {ex.Message}", ex); }

        var errors = new List<string>();
        var tools = new List<ToolRule>();
        foreach (var (t, i) in (dto.Tools ?? new()).Select((t, i) => (t, i + 1)))
        {
            if (string.IsNullOrWhiteSpace(t.Name)) { errors.Add($"tools #{i}: name is empty"); continue; }
            if (!TryParseSeverity(t.Severity, out var sev)) { errors.Add($"tools #{i} ({t.Name}): severity '{t.Severity}' is not Critical, High, Medium or Suspicious"); continue; }
            tools.Add(new ToolRule(t.Name.Trim().ToLowerInvariant(), string.IsNullOrWhiteSpace(t.Category) ? "Known tool" : t.Category.Trim(), sev));
        }

        var staging = new List<StagingRule>();
        foreach (var (s, i) in (dto.StagingFolders ?? new()).Select((s, i) => (s, i + 1)))
        {
            var rx = Compile(s.Pattern, $"stagingFolders #{i}", errors);
            if (rx != null) staging.Add(new StagingRule(rx, string.IsNullOrWhiteSpace(s.Label) ? s.Pattern! : s.Label.Trim()));
        }

        var commands = new List<CommandRule>();
        foreach (var (c, i) in (dto.CommandLines ?? new()).Select((c, i) => (c, i + 1)))
        {
            var where = $"commandLines #{i}" + (string.IsNullOrWhiteSpace(c.Label) ? "" : $" ({c.Label})");
            if (!TryParseSeverity(c.Severity, out var sev)) { errors.Add($"{where}: severity '{c.Severity}' is not Critical, High, Medium or Suspicious"); continue; }
            var rx = Compile(c.Pattern, where, errors);
            if (rx != null) commands.Add(new CommandRule(rx, string.IsNullOrWhiteSpace(c.Label) ? "Command-line pattern" : c.Label.Trim(), sev));
        }

        var folders = string.IsNullOrWhiteSpace(dto.ShellbagFolderNames) ? null : Compile(dto.ShellbagFolderNames, "shellbagFolderNames", errors);

        var webAttacks = new List<LabelRule>();
        foreach (var (w, i) in (dto.WebAttacks ?? new()).Select((w, i) => (w, i + 1)))
        {
            var rx = Compile(w.Pattern, $"webAttacks #{i}" + (string.IsNullOrWhiteSpace(w.Label) ? "" : $" ({w.Label})"), errors);
            if (rx != null) webAttacks.Add(new LabelRule(rx, string.IsNullOrWhiteSpace(w.Label) ? "Web attack" : w.Label.Trim()));
        }
        var scanners = new List<LabelRule>();
        foreach (var (w, i) in (dto.WebScanners ?? new()).Select((w, i) => (w, i + 1)))
        {
            var rx = Compile(w.Pattern, $"webScanners #{i}" + (string.IsNullOrWhiteSpace(w.Tool) ? "" : $" ({w.Tool})"), errors);
            if (rx != null) scanners.Add(new LabelRule(rx, string.IsNullOrWhiteSpace(w.Tool) ? "scanner" : w.Tool.Trim()));
        }
        var domains = new List<DomainRule>();
        foreach (var (d, i) in (dto.SuspiciousDomains ?? new()).Select((d, i) => (d, i + 1)))
        {
            var where = $"suspiciousDomains #{i}" + (string.IsNullOrWhiteSpace(d.Label) ? "" : $" ({d.Label})");
            if (!TryParseSeverity(d.Severity ?? "Medium", out var sev)) { errors.Add($"{where}: severity '{d.Severity}' is not Critical, High, Medium or Suspicious"); continue; }
            var rx = Compile(d.Pattern, where, errors);
            if (rx != null) domains.Add(new DomainRule(rx, string.IsNullOrWhiteSpace(d.Label) ? "Suspicious domain" : d.Label.Trim(), sev));
        }
        Regex? Optional(string? p, string where) => string.IsNullOrWhiteSpace(p) ? null : Compile(p, where, errors);
        var probe = Optional(dto.WebSensitiveProbe, "webSensitiveProbe");
        var uploadDir = Optional(dto.WebUploadDirScript, "webUploadDirScript");
        var shellNames = Optional(dto.WebShellNames, "webShellNames");
        var cmdParam = Optional(dto.WebCommandParam, "webCommandParam");
        if (cmdParam != null && !cmdParam.GetGroupNames().Contains("cmd")) errors.Add("webCommandParam: needs a (?<cmd>...) group");

        if (errors.Count > 0)
            throw new FormatException($"{FileName} has {errors.Count} problem(s): " + string.Join("; ", errors.Take(5)) + (errors.Count > 5 ? "; …" : ""));
        return new RuleSet(path, tools, staging, commands, folders)
        {
            WebAttacks = webAttacks,
            WebScanners = scanners,
            WebSensitiveProbe = probe,
            WebUploadDirScript = uploadDir,
            WebShellNames = shellNames,
            WebCommandParam = cmdParam,
            SuspiciousDomains = domains,
        };
    }

    private static Regex? Compile(string? pattern, string where, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(pattern)) { errors.Add($"{where}: pattern is empty"); return null; }
        try { return new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromSeconds(2)); }
        catch (ArgumentException ex) { errors.Add($"{where}: invalid pattern ({ex.Message})"); return null; }
    }

    private static bool TryParseSeverity(string? s, out Severity sev) =>
        Enum.TryParse(s?.Trim(), ignoreCase: true, out sev) && Enum.IsDefined(sev);
}
