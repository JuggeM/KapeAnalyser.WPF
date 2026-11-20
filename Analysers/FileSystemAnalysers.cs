using System.Text.RegularExpressions;
using KapeAnalyser.WPF.Core;
using KapeAnalyser.WPF.Models;

namespace KapeAnalyser.WPF.Analysers;

/// <summary>Ransom note names; one name in many folders is a strong ransomware signal.</summary>
internal static class RansomNotes
{
    public static readonly Regex Name = new(
        @"^(.*(readme|read_me|read-me|restore|decrypt|recover|how_to|how-to|howto|instructions?|!!!|ransom).*\.(txt|hta|html?|rtf)|.*\.(hta))$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    public const int MinFolders = 20;
}

/// <summary>
/// MFTECmd $MFT output: files on disk (including deleted entries still in
/// the MFT). Flags known tools, executables in staging folders, internet
/// downloads of executables (Zone.Identifier), timestomping (SI &lt; FN),
/// large archives in staging folders and mass ransom notes.
/// </summary>
public sealed class MftAnalyser : IArtifactAnalyser
{
    public string Source => "MFT";
    public string Module => "MFTECmd ($MFT)";
    public bool Enabled(AnalyserConfig c) => c.AnalyseMft;
    public bool Accepts(string f) => f.EndsWith("_MFTECmd_$MFT_Output.csv", StringComparison.OrdinalIgnoreCase);

    private static readonly Regex Script = new(@"\.(ps1|bat|cmd|vbs|vbe|js|jse|hta)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex ZoneInternet = new(@"ZoneId=(3|4)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex HostUrl = new(@"HostUrl=(\S+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly List<Finding> _pending = new();
    private readonly Dictionary<string, (int Folders, DateTime? First, DateTime? Last)> _notes = new(StringComparer.OrdinalIgnoreCase);
    private DateTime? _newest;

    public void Analyse(string csvPath, AnalysisContext ctx)
    {
        using var csv = new CsvReader(csvPath);
        int cParent = csv.Col("ParentPath"), cName = csv.Col("FileName"), cSize = csv.Col("FileSize"), cDir = csv.Col("IsDirectory"),
            cInUse = csv.Col("InUse"), cSiFn = csv.Col("SI<FN"), cCreated = csv.Col("Created0x10"), cCreatedFn = csv.Col("Created0x30"),
            cModified = csv.Col("LastModified0x10"), cZone = csv.Col("ZoneIdContents"), cIsAds = csv.Col("IsAds");
        if (cName < 0 || cParent < 0) return;
        var cov = ctx.CoverageFor(Source);
        cov.Files.Add(csvPath);
        var artifact = "$MFT";

        while (csv.Read())
        {
            if ((csv.RowNumber & 0x3FFF) == 0) ctx.Cancel.ThrowIfCancellationRequested();
            cov.Rows++;
            if (csv[cDir].Equals("True", StringComparison.OrdinalIgnoreCase) || csv[cIsAds].Equals("True", StringComparison.OrdinalIgnoreCase)) continue;

            var name = csv[cName];
            var created = CsvReader.ParseTime(csv[cCreated]);
            if (created.HasValue && created.Value <= DateTime.UtcNow.AddDays(2) && (_newest == null || created > _newest)) _newest = created;
            cov.See(created);

            var parent = csv[cParent].TrimStart('.');
            var path = parent.TrimEnd('\\') + "\\" + name;
            bool deleted = csv[cInUse].Equals("False", StringComparison.OrdinalIgnoreCase);
            var state = deleted ? " [deleted]" : "";

            if (RansomNotes.Name.IsMatch(name))
            {
                _notes.TryGetValue(name, out var n);
                n.Folders++;
                if (created.HasValue) { if (n.First == null || created < n.First) n.First = created; if (n.Last == null || created > n.Last) n.Last = created; }
                _notes[name] = n;
            }

            if (ctx.Rules.IsWhitelisted(path)) continue;
            bool exe = DetectionRules.IsExecutable(name);
            var zone = csv[cZone];

            var tool = exe ? ctx.Rules.MatchTool(name) : null;
            if (tool != null)
            {
                var dir = ctx.Rules.StagingDir(path);
                var sev = dir != null && tool.Severity > Severity.Critical ? tool.Severity - 1 : tool.Severity;
                _pending.Add(F(sev, created, tool.Category, $"On disk: {name} — {tool.Category}{(dir != null ? $" in {dir}" : "")}{state}", path, artifact));
                continue;
            }

            if (exe)
            {
                var dir = ctx.Rules.StagingDir(path);
                bool timestomp = csv[cSiFn].Equals("True", StringComparison.OrdinalIgnoreCase)
                                 && !path.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase)
                                 && !path.Contains(@"\Program Files", StringComparison.OrdinalIgnoreCase);
                bool internet = ZoneInternet.IsMatch(zone);

                if (timestomp)
                    _pending.Add(F(Severity.Medium, CsvReader.ParseTime(csv[cCreatedFn]) ?? created, "Possible timestomping",
                        $"Possible timestomping: {name} ($SI created {csv[cCreated]} before $FN created {csv[cCreatedFn]}){state}", path, artifact));
                else if (dir != null && (dir != "user Temp" || Script.IsMatch(name)))
                    _pending.Add(F(dir == "user Temp" ? Severity.Suspicious : Severity.Medium, created, $"Executable in {dir}",
                        $"Executable in {dir}: {name}{state}", path, artifact));
                else if (internet && (dir != null || Script.IsMatch(name) || DetectionRules.IsDownloads(path)))
                {
                    var url = HostUrl.Match(zone) is { Success: true } m ? m.Groups[1].Value : "";
                    _pending.Add(F(Severity.Suspicious, created, "Downloaded executable",
                        $"Downloaded from the internet: {name}{(url.Length > 0 ? $" ({EventLogAnalyser.Trunc(url, 120)})" : "")}{state}", path, artifact));
                }
                continue;
            }

            if (DetectionRules.IsArchive(name) && long.TryParse(csv[cSize], out var size) && size >= 100L * 1024 * 1024)
            {
                var dir = ctx.Rules.StagingDir(path) ?? (Regex.IsMatch(path, @"^\\[^\\]+$") ? "drive root" : null);
                if (dir != null)
                    _pending.Add(F(Severity.Medium, created, "Large archive (possible exfil staging)",
                        $"Large archive {name} ({size / (1024 * 1024):N0} MB){(dir != null ? $" in {dir}" : "")}{state}", path, artifact));
            }
        }
    }

    private Finding F(Severity s, DateTime? t, string cat, string text, string detail, string artifact) =>
        new() { Severity = s, TimeUtc = t, Source = Source, Category = cat, Text = text, Detail = detail, Artifact = artifact };

    public void Complete(AnalysisContext ctx)
    {
        int days = ctx.Config.FileSystemRecencyDays;
        var cutoff = days > 0 && _newest.HasValue ? _newest.Value.AddDays(-days) : (DateTime?)null;
        foreach (var f in _pending)
            if (cutoff == null || f.Severity <= Severity.High || (f.TimeUtc.HasValue && f.TimeUtc >= cutoff))
                ctx.Add(f);

        foreach (var (name, n) in _notes.Where(kv => kv.Value.Folders >= RansomNotes.MinFolders))
            ctx.Add(new Finding
            {
                Severity = Severity.Critical, TimeUtc = n.First, LastUtc = n.Last, Count = n.Folders, Source = Source,
                Category = "Possible ransom note", Text = $"Possible ransom note: '{name}' in {n.Folders} folders", Artifact = "$MFT",
            });
        _pending.Clear();
    }
}

/// <summary>
/// MFTECmd $J (USN journal) output: file creates/deletes/renames. Catches
/// tools that were dropped and deleted, and prefetch files created for
/// tools whose .pf has since been removed (evidence of execution).
/// </summary>
public sealed class UsnJournalAnalyser : IArtifactAnalyser
{
    public string Source => "USNJRNL";
    public string Module => "MFTECmd ($J)";
    public bool Enabled(AnalyserConfig c) => c.AnalyseUsnJournal;
    public bool Accepts(string f) => f.EndsWith("_MFTECmd_$J_Output.csv", StringComparison.OrdinalIgnoreCase);

    private static readonly Regex PrefetchName = new(@"^(?<exe>.+)-[0-9A-F]{8}\.pf$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private readonly FindingAggregator _agg = new();
    private readonly Dictionary<string, (int Count, DateTime? First, DateTime? Last)> _notes = new(StringComparer.OrdinalIgnoreCase);

    // ── Encryption signs: many files renamed to one new extension, and bursts of changes ──
    private sealed class RenameExt
    {
        public int Count, DoubleExt;
        public DateTime? First, Last;
        public HashSet<string> Folders = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Samples = new();
    }
    private readonly Dictionary<string, RenameExt> _renames = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<DateTime, int> _changesPerMinute = new();
    private const int MassRename = 100, MassRenameFolders = 3, MassDoubleExt = 50, MassChangesPerMinute = 1000;

    // Extensions that legitimately appear on many renames (temp files, logs, updates, browsers)
    private static readonly HashSet<string> CommonRenameExt = new(StringComparer.OrdinalIgnoreCase)
    {
        ".tmp", ".temp", ".log", ".old", ".bak", ".partial", ".crdownload", ".part", ".download", ".etl", ".dat", ".db", ".ldb",
        ".lock", ".jfm", ".chk", ".pf", ".evtx", ".xml", ".json", ".txt", ".ini", ".cab", ".msi", ".dll", ".exe", ".mui",
        ".cat", ".manifest", ".sqlite", ".sqlite-journal", ".jrs", ".edb", ".regtrans-ms", ".blf", ".cache", ".lnk", ".url",
    };
    // A document-type extension right before the last one: report.docx.locked
    private static readonly Regex DoubleExt = new(
        @"\.(docx?|xlsx?|pptx?|pdf|txt|csv|rtf|odt|ods|jpe?g|png|gif|bmp|zip|rar|7z|sql|mdb|accdb|bak|vmdk|vhdx?|pst|ost|msg|eml|psd|dwg)\.[^.\\]{2,}$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public void Analyse(string csvPath, AnalysisContext ctx)
    {
        using var csv = new CsvReader(csvPath);
        int cName = csv.Col("Name"), cTime = csv.Col("UpdateTimestamp"), cReasons = csv.Col("UpdateReasons"), cParent = csv.Col("ParentPath");
        if (cName < 0 || cTime < 0) return;
        var cov = ctx.CoverageFor(Source);
        cov.Files.Add(csvPath);

        while (csv.Read())
        {
            if ((csv.RowNumber & 0x3FFF) == 0) ctx.Cancel.ThrowIfCancellationRequested();
            cov.Rows++;
            var t = CsvReader.ParseTime(csv[cTime]);
            cov.See(t);
            var name = csv[cName];
            var reasons = csv[cReasons];
            bool create = reasons.Contains("FileCreate", StringComparison.OrdinalIgnoreCase);
            bool delete = reasons.Contains("FileDelete", StringComparison.OrdinalIgnoreCase);
            bool renameNew = reasons.Contains("RenameNewName", StringComparison.OrdinalIgnoreCase);
            bool overwrite = reasons.Contains("DataOverwrite", StringComparison.OrdinalIgnoreCase);
            if ((renameNew || overwrite) && t.HasValue)
            {
                var minute = new DateTime(t.Value.Ticks - t.Value.Ticks % TimeSpan.TicksPerMinute, DateTimeKind.Utc);
                _changesPerMinute[minute] = _changesPerMinute.GetValueOrDefault(minute) + 1;
            }
            if (renameNew) TrackRename(name, csv[cParent], t);
            if (!create && !delete && !renameNew) continue;

            if (create && RansomNotes.Name.IsMatch(name))
            {
                _notes.TryGetValue(name, out var n);
                n.Count++;
                if (t.HasValue) { if (n.First == null || t < n.First) n.First = t; if (n.Last == null || t > n.Last) n.Last = t; }
                _notes[name] = n;
            }

            var pf = PrefetchName.Match(name);
            if (pf.Success && create)
            {
                var tool = ctx.Rules.MatchTool(pf.Groups["exe"].Value);
                if (tool != null)
                    _agg.Add($"pf|{name}", tool.Severity, t, Source, tool.Category,
                        $"Executed: {pf.Groups["exe"].Value} — {tool.Category} (prefetch file created)", name, "$J");
                continue;
            }

            var hit = ctx.Rules.MatchTool(name);
            if (hit == null) continue;
            var parent = csv[cParent];
            var what = delete ? "deleted" : renameNew ? "renamed to" : "created";
            _agg.Add($"{what}|{parent}|{name}", hit.Severity, t, Source, hit.Category,
                $"File {what}: {name} — {hit.Category}", parent.Length > 0 ? parent.TrimEnd('\\') + "\\" + name : name, "$J");
        }
    }

    private void TrackRename(string name, string parent, DateTime? t)
    {
        var ext = Path.GetExtension(name);
        if (ext.Length < 2 || ext.Length > 16 || CommonRenameExt.Contains(ext)) return;
        if (!_renames.TryGetValue(ext, out var r)) _renames[ext] = r = new RenameExt();
        r.Count++;
        if (DoubleExt.IsMatch(name)) r.DoubleExt++;
        if (t.HasValue) { if (r.First == null || t < r.First) r.First = t; if (r.Last == null || t > r.Last) r.Last = t; }
        if (r.Folders.Count < 1000 && parent.Length > 0) r.Folders.Add(parent);
        if (r.Samples.Count < 3) r.Samples.Add(parent.Length > 0 ? parent.TrimEnd('\\') + "\\" + name : name);
    }

    public void Complete(AnalysisContext ctx)
    {
        ctx.AddRange(_agg.Flush());

        foreach (var (ext, r) in _renames.Where(kv => (kv.Value.Count >= MassRename && kv.Value.Folders.Count >= MassRenameFolders) || kv.Value.DoubleExt >= MassDoubleExt)
                                         .OrderByDescending(kv => kv.Value.Count))
        {
            var span = r.First.HasValue && r.Last.HasValue ? $" in {EventLogAnalyser.Dur(r.Last.Value - r.First.Value)}" : "";
            ctx.Add(new Finding
            {
                Severity = Severity.Critical, TimeUtc = r.First, LastUtc = r.Last, Count = r.Count, Source = Source,
                Category = "Mass rename (possible encryption)",
                Text = $"Mass rename to '{ext}': {r.Count} file(s) in {r.Folders.Count} folder(s){span}" +
                       (r.DoubleExt > 0 ? $", {r.DoubleExt} keep their old extension (e.g. .xlsx{ext}) — possible ransomware encryption" : " — possible ransomware encryption"),
                Detail = string.Join(" ; ", r.Samples), Artifact = "$J",
            });
        }

        foreach (var (minute, n) in _changesPerMinute.Where(kv => kv.Value >= MassChangesPerMinute).OrderBy(kv => kv.Key).Take(10))
            ctx.Add(new Finding
            {
                Severity = Severity.High, TimeUtc = minute, Count = n, Source = Source, Category = "Mass file changes",
                Text = $"Mass file changes: {n} files overwritten or renamed between {minute:HH:mm} and {minute.AddMinutes(1):HH:mm} UTC",
                Artifact = "$J",
            });
        _renames.Clear(); _changesPerMinute.Clear();

        foreach (var (name, n) in _notes.Where(kv => kv.Value.Count >= RansomNotes.MinFolders))
            ctx.Add(new Finding
            {
                Severity = Severity.Critical, TimeUtc = n.First, LastUtc = n.Last, Count = n.Count, Source = Source,
                Category = "Possible ransom note", Text = $"Possible ransom note: '{name}' created {n.Count} times", Artifact = "$J",
            });
    }
}

/// <summary>RBCmd output: files the user deleted to the Recycle Bin.</summary>
public sealed class RecycleBinAnalyser : IArtifactAnalyser
{
    public string Source => "RECYCLEBIN";
    public string Module => "RBCmd";
    public bool Enabled(AnalyserConfig c) => c.AnalyseRecycleBin;
    public bool Accepts(string f) => f.EndsWith("_RBCmd_Output.csv", StringComparison.OrdinalIgnoreCase);

    private readonly FindingAggregator _agg = new();

    public void Analyse(string csvPath, AnalysisContext ctx)
    {
        using var csv = new CsvReader(csvPath);
        int cName = csv.Col("FileName"), cTime = csv.Col("DeletedOn"), cSize = csv.Col("FileSize"), cSrc = csv.Col("SourceName");
        if (cName < 0) return;
        var cov = ctx.CoverageFor(Source);
        cov.Files.Add(csvPath);

        while (csv.Read())
        {
            cov.Rows++;
            var t = CsvReader.ParseTime(csv[cTime]);
            cov.See(t);
            var path = csv[cName];
            var score = ctx.Rules.ScoreBinaryPath(path);
            if (score != null)
            {
                _agg.Add($"rb|{path}", score.Value.Sev, t, Source, score.Value.Reason,
                    $"Deleted to Recycle Bin: {DetectionRules.FileNameOf(path)} — {score.Value.Reason}", path, DetectionRules.FileNameOf(csv[cSrc]));
            }
            else if (DetectionRules.IsArchive(path) && long.TryParse(csv[cSize], out var size) && size >= 50L * 1024 * 1024)
            {
                _agg.Add($"rb|{path}", Severity.Suspicious, t, Source, "Large archive deleted",
                    $"Large archive deleted: {DetectionRules.FileNameOf(path)} ({size / (1024 * 1024):N0} MB)", path, DetectionRules.FileNameOf(csv[cSrc]));
            }
        }
    }

    public void Complete(AnalysisContext ctx) => ctx.AddRange(_agg.Flush());
}
